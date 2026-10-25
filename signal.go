package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Before the tunnel exists, the two peers swap candidate addresses through an
// ntfy topic (https://ntfy.sh by default, self-hostable). The topic name is
// derived from the shared key and every message is encrypted with it, so the
// relay only ever sees opaque blobs.

type signalMsg struct {
	// "offer" from the client, "answer" from the server, and "hello" when
	// the server starts.
	Type  string   `json:"t"`
	SID   string   `json:"s"` // session id chosen by the client
	TS    int64    `json:"ts"`
	Cands []string `json:"c"`
}

const signalMaxAge = 2 * time.Minute

type signaler struct {
	base   string
	k      *keys
	post   *http.Client
	stream *http.Client
}

func newSignaler(base string, k *keys, env *netEnv) *signaler {
	tr := &http.Transport{
		DialContext:         env.dialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
	}
	return &signaler{
		base:   strings.TrimRight(base, "/"),
		k:      k,
		post:   &http.Client{Transport: tr, Timeout: 15 * time.Second},
		stream: &http.Client{Transport: tr},
	}
}

func (s *signaler) publish(ctx context.Context, m signalMsg) error {
	m.TS = time.Now().Unix()
	body, _ := json.Marshal(m)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/"+s.k.topic, strings.NewReader(s.k.seal(body)))
	if err != nil {
		return err
	}
	resp, err := s.post.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return errors.New("signaling server rate limit reached (ntfy.sh allows a limited number of messages per day); will retry later")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("signaling server returned %s", resp.Status)
	}
	return nil
}

// subscribe passes every valid message to fn until ctx ends, reconnecting as
// needed. Messages published before the Unix time since are skipped.
// onConnect, if set, runs each time the subscription is (re)established,
// which also tells the caller that the network works again.
func (s *signaler) subscribe(ctx context.Context, since int64, fn func(signalMsg), onConnect func()) {
	cursor := strconv.FormatInt(since, 10)
	for {
		err := s.listen(ctx, &cursor, fn, onConnect)
		if ctx.Err() != nil {
			return
		}
		log.Printf("signaling: %v; reconnecting", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

func (s *signaler) listen(ctx context.Context, cursor *string, fn func(signalMsg), onConnect func()) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+"/"+s.k.topic+"/json?since="+*cursor, nil)
	if err != nil {
		return err
	}
	resp, err := s.stream.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("signaling server returned %s", resp.Status)
	}
	if onConnect != nil {
		onConnect()
	}
	// ntfy sends a keepalive every 45s; a longer silence means a dead connection.
	watchdog := time.AfterFunc(90*time.Second, cancel)
	defer watchdog.Stop()

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		watchdog.Reset(90 * time.Second)
		var ev struct {
			ID      string `json:"id"`
			Event   string `json:"event"`
			Message string `json:"message"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) != nil || ev.Event != "message" {
			continue
		}
		*cursor = ev.ID
		plain, err := s.k.open(ev.Message)
		if err != nil {
			continue // not encrypted with our key
		}
		var m signalMsg
		if json.Unmarshal(plain, &m) != nil {
			continue
		}
		if age := time.Since(time.Unix(m.TS, 0)); age > signalMaxAge || age < -signalMaxAge {
			continue
		}
		fn(m)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return io.ErrUnexpectedEOF
}
