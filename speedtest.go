package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// The speed test separates the legs of the path so the bottleneck is
// visible:
//
//	tunnel  A <-> B only (B's upload, A's download and the path between them)
//	net     A -> B -> internet: downloading speedURL, what A actually gets
//
// The net leg needs a large file the user may download, set with -speed-url;
// without one only the tunnel is measured. An internet upload test would add
// little: A's uploads are bounded by the tunnel upload and by B's upload,
// which the tunnel download already uses.
const (
	speedStreams = 4
	speedPhase   = 8 * time.Second
)

type speedResult struct {
	Running    bool    `json:"running"`
	Phase      string  `json:"phase,omitempty"` // tunnel_down, tunnel_up, net_down
	Error      string  `json:"error,omitempty"`
	LiveMbps   float64 `json:"live_mbps"`
	RTTms      float64 `json:"rtt_ms"`
	LossPct    float64 `json:"loss_pct"` // packets A sent that were lost
	TunnelDown float64 `json:"tunnel_down_mbps"`
	TunnelUp   float64 `json:"tunnel_up_mbps"`
	NetDown    float64 `json:"net_down_mbps"`
	NetSkipped bool    `json:"net_skipped,omitempty"` // no -speed-url configured
	Finished   int64   `json:"finished,omitempty"`
}

type speedTest struct {
	mu  sync.Mutex
	res speedResult
}

func (t *speedTest) update(f func(*speedResult)) {
	t.mu.Lock()
	f(&t.res)
	t.mu.Unlock()
}

func (t *speedTest) snapshot() speedResult {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.res
}

// startSpeedTest starts a test in the background unless one is running.
func (c *client) startSpeedTest() bool {
	c.speed.mu.Lock()
	defer c.speed.mu.Unlock()
	if c.speed.res.Running {
		return false
	}
	c.speed.res = speedResult{Running: true}
	go c.runSpeedTest()
	return true
}

func (c *client) connStats() (rtt time.Duration, sent, lost uint64) {
	c.mu.Lock()
	conns := c.conns
	c.mu.Unlock()
	for i, conn := range conns {
		s := conn.ConnectionStats()
		if i == 0 {
			rtt = s.SmoothedRTT
		}
		sent += s.PacketsSent
		lost += s.PacketsLost
	}
	return
}

func (c *client) runSpeedTest() {
	t := &c.speed
	err := c.speedPhases()
	t.update(func(r *speedResult) {
		r.Running, r.Phase, r.LiveMbps, r.Finished = false, "", 0, time.Now().Unix()
		if err != nil {
			r.Error = err.Error()
		}
	})
}

func (c *client) speedPhases() error {
	t := &c.speed
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, err := c.pick(ctx)
	cancel()
	if err != nil {
		return err
	}
	_, sent0, lost0 := c.connStats()
	defer func() {
		rtt, sent, lost := c.connStats()
		t.update(func(r *speedResult) {
			r.RTTms = float64(rtt.Microseconds()) / 1000
			if sent > sent0 {
				r.LossPct = float64(lost-lost0) * 100 / float64(sent-sent0)
			}
		})
	}()

	down, err := c.measure("tunnel_down", func(ctx context.Context, add func(int)) error {
		sc, err := c.open(ctx, kindSpeedDown, "")
		if err != nil {
			return err
		}
		return readUntilDone(ctx, sc, add)
	})
	if err != nil {
		return fmt.Errorf("tunnel download: %w", err)
	}
	t.update(func(r *speedResult) { r.TunnelDown = down })

	// Upload: the live figure counts what we wrote, the result what the
	// exit node says it received.
	var mu sync.Mutex
	var gotBytes, maxNanos uint64
	_, err = c.measure("tunnel_up", func(ctx context.Context, add func(int)) error {
		conn, err := c.open(ctx, kindSpeedUp, "")
		if err != nil {
			return err
		}
		sc := conn.(*streamConn)
		defer sc.Close()
		deadline, _ := ctx.Deadline()
		sc.SetWriteDeadline(deadline)
		for {
			n, err := sc.Write(filler)
			add(n)
			if err != nil {
				break
			}
		}
		sc.SetWriteDeadline(time.Time{})
		sc.CloseWrite()
		sc.SetReadDeadline(time.Now().Add(20 * time.Second))
		var rep [16]byte
		if _, err := io.ReadFull(sc, rep[:]); err != nil {
			return err
		}
		mu.Lock()
		gotBytes += binary.BigEndian.Uint64(rep[0:])
		maxNanos = max(maxNanos, binary.BigEndian.Uint64(rep[8:]))
		mu.Unlock()
		return nil
	})
	if err != nil {
		return fmt.Errorf("tunnel upload: %w", err)
	}
	up := 0.0
	if maxNanos > 0 {
		up = float64(gotBytes) * 8 / (float64(maxNanos) / 1e9) / 1e6
	}
	t.update(func(r *speedResult) { r.TunnelUp = up })

	if c.cfg.speedURL == "" {
		t.update(func(r *speedResult) { r.NetSkipped = true })
		return nil
	}
	netDown, err := c.measure("net_down", func(ctx context.Context, add func(int)) error {
		for ctx.Err() == nil {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.speedURL, nil)
			req.Header.Set("User-Agent", "p2proxy/"+version)
			resp, err := c.tunnelHTTP.Do(req)
			if err != nil {
				return ignoreDone(ctx, err)
			}
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				return fmt.Errorf("%s returned %s; choose another file with -speed-url", req.URL.Host, resp.Status)
			}
			err = readUntilDone(ctx, resp.Body, add)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("internet download via exit node: %w", err)
	}
	t.update(func(r *speedResult) { r.NetDown = netDown })
	return nil
}

// measure runs work on parallel streams for speedPhase, publishing a live
// rate, and returns the average in Mbit/s over all but the first second
// (while the connection ramps up). It fails only if every stream fails.
func (c *client) measure(phase string, work func(ctx context.Context, add func(int)) error) (float64, error) {
	c.speed.update(func(r *speedResult) { r.Phase, r.LiveMbps = phase, 0 })
	ctx, cancel := context.WithTimeout(context.Background(), speedPhase)
	defer cancel()
	var total atomic.Int64
	add := func(n int) { total.Add(int64(n)) }
	errc := make(chan error, speedStreams)
	for range speedStreams {
		go func() { errc <- work(ctx, add) }()
	}

	start := time.Now()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	var last, warmBytes int64
	warmAt := start
	var firstErr error
	failed := 0
	for pending := speedStreams; pending > 0; {
		select {
		case err := <-errc:
			pending--
			if err != nil {
				failed++
				if firstErr == nil {
					firstErr = err
				}
			}
		case <-tick.C:
			now := total.Load()
			live := float64(now-last) * 8 / 0.5 / 1e6
			last = now
			c.speed.update(func(r *speedResult) { r.LiveMbps = live })
			if warmAt == start && time.Since(start) >= time.Second {
				warmBytes, warmAt = now, time.Now()
			}
		}
	}
	if failed == speedStreams {
		return 0, firstErr
	}
	if total.Load() == 0 {
		return 0, errors.New("no data was transferred")
	}
	secs := time.Since(warmAt).Seconds()
	return float64(total.Load()-warmBytes) * 8 / secs / 1e6, nil
}

// readUntilDone reads r until ctx ends, then closes it.
func readUntilDone(ctx context.Context, r io.ReadCloser, add func(int)) error {
	stop := context.AfterFunc(ctx, func() { r.Close() })
	defer stop()
	defer r.Close()
	buf := make([]byte, 64<<10)
	for {
		n, err := r.Read(buf)
		add(n)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return ignoreDone(ctx, err)
		}
	}
}

func ignoreDone(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func formatMbps(v float64) string {
	if v >= 100 {
		return strconv.FormatFloat(v, 'f', 0, 64)
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}
