// p2proxy connects two machines directly (UDP hole punching + QUIC) and lets
// the client (A) use the exit node's (B) internet connection through a local
// SOCKS5/HTTP proxy.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
)

const usage = `p2proxy - 点对点网络代理

用法:
  p2proxy                        （直接双击）启动客户端并打开控制面板
  p2proxy genkey                 生成一个共享密钥（A 和 B 用同一个）
  p2proxy server [选项]           在 B（出口机）上运行
  p2proxy client [选项]           在 A（使用 B 网络的机器）上运行
  p2proxy speedtest              测速（需要 A 上的 client 正在运行）
  p2proxy update [-node]         更新到最新版本；-node 表示让 A 远程更新 B
  p2proxy version                显示版本

密钥通过 -key、环境变量 P2PX_KEY，或 p2proxy.exe 同目录的 key.txt 提供；
客户端也可以在控制面板里设置密钥。
运行 "p2proxy server -h" 或 "p2proxy client -h" 查看选项。
`

const defaultUI = "127.0.0.1:1090"

func main() {
	if len(os.Args) < 2 {
		// Double-clicked: be the client and show the dashboard.
		runClientCmd(nil, true)
		return
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "help", "-h", "--help":
		fmt.Print(usage)
	case "genkey":
		fmt.Println(genKey())
	case "version", "-v", "--version":
		fmt.Println("p2proxy", version)
	case "server":
		fs := flag.NewFlagSet("server", flag.ExitOnError)
		key := fs.String("key", os.Getenv("P2PX_KEY"), "共享密钥")
		port := fs.Int("port", 40400, "监听的 UDP 端口")
		advertise := fs.String("advertise", "", "额外告诉客户端的地址，逗号分隔，例如路由器端口转发后的 公网IP:端口 或 DDNS域名:端口")
		signal := fs.String("signal", "https://ntfy.sh", "用于交换地址的 ntfy 服务器；设为空则关闭信令（只能用 -peer 直连）")
		iface := fs.String("iface", "auto", `p2proxy 自身流量走的网卡: auto（自动选物理网卡）、none（跟随系统路由）或网卡名`)
		fs.Parse(args)
		k := mustKeys(*key)
		cleanupOldBinary()
		log.Fatal(runServer(k, serverConfig{
			port:      *port,
			advertise: splitList(*advertise),
			signal:    *signal,
			iface:     *iface,
		}))
	case "client":
		runClientCmd(args, false)
	case "speedtest":
		fs := flag.NewFlagSet("speedtest", flag.ExitOnError)
		ui := fs.String("ui", defaultUI, "client 的控制面板地址")
		fs.Parse(args)
		if err := cliSpeedTest(*ui); err != nil {
			log.Fatal(err)
		}
	case "update":
		fs := flag.NewFlagSet("update", flag.ExitOnError)
		ui := fs.String("ui", defaultUI, "client 的控制面板地址")
		node := fs.Bool("node", false, "通过 A 上运行中的 client 更新出口节点 B")
		fs.Parse(args)
		if err := cliUpdate(*ui, *node); err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

// runClientCmd starts the client. Without a usable key it still serves the
// dashboard, where the key can be entered. doubleClicked means it was started
// from Explorer, so errors wait for Enter instead of closing the window.
func runClientCmd(args []string, doubleClicked bool) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	key := fs.String("key", os.Getenv("P2PX_KEY"), "共享密钥（也可以在控制面板里设置）")
	listen := fs.String("listen", "127.0.0.1:1080", "本地 SOCKS5/HTTP 代理监听地址")
	ui := fs.String("ui", defaultUI, "控制面板地址（密钥、测速、更新）；设为空则关闭")
	peer := fs.String("peer", "", "直接连接 B 的地址 host:port（B 有公网 IPv6 或做了端口转发时可用），不走打洞信令")
	signal := fs.String("signal", "https://ntfy.sh", "用于交换地址的 ntfy 服务器")
	iface := fs.String("iface", "auto", `p2proxy 自身流量走的网卡: auto（自动选物理网卡）、none（跟随系统路由）或网卡名`)
	conns := fs.Int("conns", 1, "到 B 的并行 QUIC 连接数（1-8）；丢包多的长距离线路可以试试 4")
	speedURL := fs.String("speed-url", "", "测速时经 B 下载的大文件地址（例如你自己服务器上的文件）；不设置则只测隧道")
	fs.Parse(args)
	fatal := log.Fatal
	if doubleClicked {
		fatal = func(v ...any) {
			log.Print(v...)
			fmt.Print("\n按回车键关闭窗口…")
			bufio.NewReader(os.Stdin).ReadString('\n')
			os.Exit(1)
		}
		// Started a second time: show the running copy instead.
		if *ui != "" && dashboardRunning(*ui) {
			log.Printf("p2proxy is already running; opening its dashboard")
			openBrowser("http://" + *ui + "/")
			return
		}
	}
	cleanupOldBinary()

	secret := *key
	if secret == "" {
		secret = readKeyFile()
	}
	k, err := newKeys(secret)
	if err != nil {
		if *ui == "" {
			fatal(err)
		}
		log.Printf("no key yet (%v); enter it in the dashboard", err)
		k = nil
	}
	fatal(runClient(k, clientConfig{
		listen:      *listen,
		ui:          *ui,
		peer:        *peer,
		signal:      *signal,
		iface:       *iface,
		conns:       min(max(*conns, 1), 8),
		speedURL:    *speedURL,
		openUI:      doubleClicked || k == nil,
		keyOverride: *key != "",
	}))
}

func dashboardRunning(addr string) bool {
	hc := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
	resp, err := hc.Get("http://" + addr + "/api/status")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// saveKeyFile stores the key in key.txt next to the executable.
func saveKeyFile(secret string) error {
	if exePath == "" {
		return errors.New("cannot locate the executable")
	}
	p := filepath.Join(filepath.Dir(exePath), "key.txt")
	if err := os.WriteFile(p+".tmp", []byte(secret+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("open %s in your browser", url)
	}
}

// dashboard talks to the API of a running client.
type dashboard struct {
	base string
	hc   *http.Client
}

func newDashboard(addr string) *dashboard {
	return &dashboard{
		base: "http://" + addr,
		hc:   &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 15 * time.Minute},
	}
}

func (d *dashboard) call(method, path string, out any) error {
	req, err := http.NewRequest(method, d.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-P2PX", "1")
	resp, err := d.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dashboard returned %s", resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func cliSpeedTest(ui string) error {
	d := newDashboard(ui)
	var r speedResult
	if err := d.call(http.MethodPost, "/api/speedtest", &r); err != nil {
		return fmt.Errorf("cannot reach the running client at %s (%w); start it with: p2proxy client", ui, err)
	}
	names := map[string]string{
		"tunnel_down": "隧道下载 (B→A)",
		"tunnel_up":   "隧道上传 (A→B)",
		"net_down":    "经 B 上网下载",
	}
	for r.Running {
		if r.Phase != "" {
			fmt.Printf("\r%-18s %8s Mbps   ", names[r.Phase], formatMbps(r.LiveMbps))
		}
		time.Sleep(500 * time.Millisecond)
		if err := d.call(http.MethodGet, "/api/speedtest", &r); err != nil {
			return err
		}
	}
	fmt.Print("\r                                        \r")
	if r.Error != "" {
		return errors.New(r.Error)
	}
	fmt.Printf("延迟           %8.0f ms\n", r.RTTms)
	fmt.Printf("上行丢包       %8.2f %%\n", r.LossPct)
	fmt.Printf("隧道下载 (B→A) %8s Mbps\n", formatMbps(r.TunnelDown))
	fmt.Printf("隧道上传 (A→B) %8s Mbps\n", formatMbps(r.TunnelUp))
	if r.NetSkipped {
		fmt.Println("经 B 上网下载       未测（没有设置 -speed-url）")
	} else {
		fmt.Printf("经 B 上网下载  %8s Mbps\n", formatMbps(r.NetDown))
	}
	return nil
}

// cliUpdate prefers asking the running client, whose downloads go through
// the tunnel. Without one (on B, or with A stopped) it updates this copy
// directly.
func cliUpdate(ui string, node bool) error {
	d := newDashboard(ui)
	target := "client"
	if node {
		target = "node"
	}
	var r apiResult
	err := d.call(http.MethodPost, "/api/update?target="+target, &r)
	if err == nil {
		if r.Error != "" {
			return errors.New(r.Error)
		}
		fmt.Println(r.Message)
		return nil
	}
	if node {
		return fmt.Errorf("cannot reach the running client at %s (%w)", ui, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	rel, err := latestRelease(ctx, http.DefaultClient)
	if err != nil {
		return err
	}
	if !newer(rel.Tag, version) {
		fmt.Println("already running the latest version:", version)
		return nil
	}
	if err := applyUpdate(ctx, http.DefaultClient, rel); err != nil {
		return err
	}
	fmt.Printf("updated to %s; restart p2proxy to use it\n", rel.Tag)
	return nil
}

// mustKeys uses -key or P2PX_KEY, falling back to key.txt next to the
// executable.
func mustKeys(secret string) *keys {
	if secret == "" {
		secret = readKeyFile()
	}
	k, err := newKeys(secret)
	if err != nil {
		log.Fatal(err)
	}
	return k
}

func readKeyFile() string {
	if exePath == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(exePath), "key.txt"))
	if err != nil {
		return ""
	}
	// Windows PowerShell 5 writes UTF-16 with a BOM; Notepad may add a UTF-8 BOM.
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		u := make([]uint16, (len(b)-2)/2)
		for i := range u {
			u[i] = uint16(b[2+2*i]) | uint16(b[3+2*i])<<8
		}
		return strings.TrimSpace(string(utf16.Decode(u)))
	}
	return strings.TrimSpace(strings.TrimPrefix(string(b), string(rune(0xFEFF))))
}

func splitList(s string) []string {
	var out []string
	for v := range strings.SplitSeq(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
