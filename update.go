package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Set at build time by the release workflow, e.g.
//
//	-ldflags "-X main.version=v1.2.0 -X main.repo=owner/p2proxy -X main.updatePublicKey=..."
var (
	version         = "dev"
	repo            = "" // GitHub "owner/name" that publishes releases
	updatePublicKey = "" // base64 ed25519 key that signs each release's checksums
)

// exePath is captured at startup, before an update renames the running file.
var exePath = func() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return p
}()

type release struct {
	Tag    string            `json:"tag"`
	URL    string            `json:"url"`
	Assets map[string]string `json:"-"` // file name -> download URL
}

// githubAPI can be overridden for testing; releases still have to carry a
// valid signature.
func githubAPI() string {
	if v := os.Getenv("P2PX_UPDATE_API"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "https://api.github.com"
}

func updatesEnabled() error {
	if repo == "" || updatePublicKey == "" {
		return errors.New("this build has no update source; download releases manually")
	}
	return nil
}

func latestRelease(ctx context.Context, hc *http.Client) (*release, error) {
	if err := updatesEnabled(); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAPI()+"/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "p2proxy/"+version)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub returned %s", resp.Status)
	}
	var body struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body); err != nil {
		return nil, err
	}
	rel := &release{Tag: body.TagName, URL: body.HTMLURL, Assets: map[string]string{}}
	for _, a := range body.Assets {
		rel.Assets[a.Name] = a.URL
	}
	return rel, nil
}

func parseVersion(v string) (out [3]int, ok bool) {
	v, _, _ = strings.Cut(strings.TrimPrefix(v, "v"), "-")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// newer reports whether version a is strictly newer than b.
func newer(a, b string) bool {
	va, ok := parseVersion(a)
	if !ok {
		return false
	}
	vb, ok := parseVersion(b)
	if !ok {
		return true // a development build is older than any release
	}
	for i := range va {
		if va[i] != vb[i] {
			return va[i] > vb[i]
		}
	}
	return false
}

func assetName() string {
	name := "p2proxy-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// signedMessage is what the release workflow signs: the tag binds the
// checksums to one version, so an old release cannot be replayed as new.
func signedMessage(tag string, sums []byte) []byte {
	return append([]byte("p2proxy release "+tag+"\n"), sums...)
}

// applyUpdate downloads rel's binary for this platform, checks it against the
// signed checksums and swaps it in for the running executable. The new
// version takes effect on the next start (see restartSelf).
func applyUpdate(ctx context.Context, hc *http.Client, rel *release) error {
	if err := updatesEnabled(); err != nil {
		return err
	}
	pub, err := base64.StdEncoding.DecodeString(updatePublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("this build has a malformed update key")
	}
	sums, err := fetch(ctx, hc, rel.Assets["checksums.txt"], 1<<20)
	if err != nil {
		return fmt.Errorf("checksums: %w", err)
	}
	sig, err := fetch(ctx, hc, rel.Assets["checksums.txt.sig"], 4<<10)
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || !ed25519.Verify(pub, signedMessage(rel.Tag, sums), sigBytes) {
		return errors.New("release signature is invalid; refusing to install")
	}
	want := ""
	for line := range strings.Lines(string(sums)) {
		if f := strings.Fields(line); len(f) == 2 && strings.TrimPrefix(f[1], "*") == assetName() {
			want = f[0]
		}
	}
	if want == "" {
		return fmt.Errorf("release %s has no build for %s/%s", rel.Tag, runtime.GOOS, runtime.GOARCH)
	}

	if exePath == "" {
		return errors.New("cannot locate the running executable")
	}
	tmp := exePath + ".new"
	if err := download(ctx, hc, rel.Assets[assetName()], tmp, want); err != nil {
		os.Remove(tmp)
		return err
	}
	// A running executable cannot be overwritten on Windows, but it can be
	// renamed out of the way.
	old := exePath + ".old"
	os.Remove(old)
	if err := os.Rename(exePath, old); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, exePath); err != nil {
		os.Rename(old, exePath)
		return err
	}
	log.Printf("installed %s (was %s)", rel.Tag, version)
	return nil
}

func fetch(ctx context.Context, hc *http.Client, url string, limit int64) ([]byte, error) {
	if url == "" {
		return nil, errors.New("missing from the release")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "p2proxy/"+version)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download returned %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

func download(ctx context.Context, hc *http.Client, url, dst, wantSHA256 string) error {
	if url == "" {
		return fmt.Errorf("%s is missing from the release", assetName())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "p2proxy/"+version)
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned %s", resp.Status)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, 256<<20))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, wantSHA256) {
		return errors.New("downloaded file does not match the signed checksum")
	}
	return nil
}

// restartSelf starts a fresh copy of the executable (after an update or a
// key change) and exits. Under the start-*.bat loop (P2PX_SUPERVISED=1) it
// just exits and lets the loop restart it.
func restartSelf() {
	if os.Getenv("P2PX_SUPERVISED") != "" {
		log.Printf("exiting so the new version starts")
		os.Exit(0)
	}
	cmd := exec.Command(exePath, os.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(), "P2PX_NO_OPEN=1") // the dashboard is already open
	if err := cmd.Start(); err != nil {
		log.Fatalf("could not start the new version (%v); please start p2proxy again", err)
	}
	log.Printf("started the new version (pid %d)", cmd.Process.Pid)
	os.Exit(0)
}

// cleanupOldBinary removes the executable a previous update set aside.
func cleanupOldBinary() {
	if exePath != "" {
		os.Remove(exePath + ".old")
	}
}
