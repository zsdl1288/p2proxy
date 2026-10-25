package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

type clientConfig struct {
	listen   string
	ui       string
	peer     string
	signal   string
	iface    string
	conns    int
	speedURL string // large file downloaded through the tunnel by the speed test

	openUI      bool // open the dashboard in the browser at startup
	keyOverride bool // the key came from -key or P2PX_KEY, not key.txt
}

// client keeps the tunnel to the exit node alive and serves the local proxy
// port. While the tunnel is down, proxy requests fail instead of going out
// directly.
type client struct {
	cfg  clientConfig
	k    *keys // nil until a key is set in the dashboard
	env  *netEnv
	sig  *signaler
	tlsc *tls.Config

	wake chan struct{} // cuts a retry delay short

	answersMu sync.Mutex
	answers   map[string]chan []string // offer session id -> answer

	// Used only by the maintain goroutine.
	sock     *clientSocket
	failures int
	lastGood string // exit node address that worked last time

	mu      sync.Mutex
	conns   []*quic.Conn
	changed chan struct{} // closed and replaced whenever conns changes
	lastErr string
	upSince time.Time
	node    *nodeInfo
	next    atomic.Uint32

	relMu    sync.Mutex
	latest   *release
	checkErr string
	updating atomic.Bool

	// HTTP through the tunnel, for release checks, updates and speed tests.
	tunnelHTTP *http.Client
	speed      speedTest
}

// clientSocket is the UDP socket all tunnel connections run over. It is
// reused across reconnects so the NAT mappings opened by hole punching
// survive a short outage.
type clientSocket struct {
	udp *net.UDPConn
	tr  *quic.Transport
	mux *udpMux
}

func (s *clientSocket) close() {
	s.tr.Close()
	s.udp.Close()
}

func runClient(k *keys, cfg clientConfig) error {
	env, err := newNetEnv(cfg.iface)
	if err != nil {
		return err
	}
	c := &client{
		cfg:     cfg,
		k:       k,
		env:     env,
		wake:    make(chan struct{}, 1),
		answers: map[string]chan []string{},
		changed: make(chan struct{}),
	}
	c.tunnelHTTP = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return c.open(ctx, kindTCP, addr)
		},
		IdleConnTimeout: 30 * time.Second,
	}}
	// Without a key only the dashboard is useful; saving one there restarts us.
	if k != nil {
		c.tlsc = k.clientTLS()
		if cfg.peer == "" {
			if cfg.signal == "" {
				return errors.New("need either -peer or a signaling server")
			}
			c.sig = newSignaler(cfg.signal, k, env)
			// Always subscribed: answers arrive here, and so does the exit
			// node's "hello" when it restarts. A successful (re)subscription
			// also means our network is back, which is worth an immediate retry.
			go c.sig.subscribe(context.Background(), time.Now().Add(-5*time.Second).Unix(), c.onSignal, c.nudge)
		}
	}
	ln, err := retryListen(func() (net.Listener, error) { return net.Listen("tcp", cfg.listen) })
	if err != nil {
		return err
	}
	log.Printf("p2proxy %s: local SOCKS5/HTTP proxy listening on %s", version, ln.Addr())
	if cfg.ui != "" {
		uiLn, err := retryListen(func() (net.Listener, error) { return net.Listen("tcp", cfg.ui) })
		if err != nil {
			return fmt.Errorf("dashboard: %w", err)
		}
		url := "http://" + uiLn.Addr().String() + "/"
		log.Printf("dashboard: %s", url)
		go c.serveUI(uiLn)
		// P2PX_NO_OPEN: restarted by ourselves; the page is already open.
		if cfg.openUI && os.Getenv("P2PX_NO_OPEN") == "" {
			openBrowser(url)
		}
	}
	if k != nil {
		go c.maintain()
		go c.checkLoop()
	}
	return serveProxy(ln, c.open)
}

func (c *client) nudge() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *client) onSignal(m signalMsg) {
	switch m.Type {
	case "hello":
		log.Printf("exit node announced that it started")
		c.mu.Lock()
		conns, up := c.conns, c.upSince
		c.mu.Unlock()
		if len(conns) > 0 && up.Unix() < m.TS {
			// It restarted after our connection was made, so that connection
			// is dead; don't wait for the idle timeout to notice.
			for _, conn := range conns {
				conn.CloseWithError(0, "exit node restarted")
			}
		}
		c.nudge()
	case "answer":
		c.answersMu.Lock()
		ch := c.answers[m.SID]
		c.answersMu.Unlock()
		if ch != nil {
			select {
			case ch <- m.Cands:
			default:
			}
		}
	}
}

func (c *client) maintain() {
	backoff := time.Second
	// Each retry through signaling costs a message from the ntfy.sh quota,
	// so retries slow down a lot; a hello from the exit node or the network
	// coming back cuts the wait short.
	maxBackoff := 5 * time.Minute
	if c.cfg.peer != "" {
		maxBackoff = 30 * time.Second
	}
	for {
		conns, err := c.connect()
		if err != nil {
			c.setConns(nil, err)
			log.Printf("could not connect to exit node: %v; retrying in %s", err, backoff)
			select {
			case <-time.After(backoff):
			case <-c.wake:
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		backoff = time.Second
		select {
		case <-c.wake: // stale
		default:
		}
		c.setConns(conns, nil)
		log.Printf("tunnel up: %d connection(s) to exit node at %s", len(conns), conns[0].RemoteAddr())
		go c.fetchNodeInfo()

		lost := make(chan *quic.Conn, len(conns))
		for _, conn := range conns {
			go func() {
				<-conn.Context().Done()
				lost <- conn
			}()
		}
		dead := <-lost
		cause := context.Cause(dead.Context())
		c.setConns(nil, fmt.Errorf("connection lost: %v", cause))
		for _, conn := range conns {
			conn.CloseWithError(0, "reconnecting")
		}
		log.Printf("tunnel down: %v", cause)
	}
}

// connect establishes the tunnel: first straight to the address that worked
// last time (no signaling needed after a short outage), then through
// signaling and hole punching.
func (c *client) connect() ([]*quic.Conn, error) {
	ctx := context.Background()
	s, err := c.socket()
	if err != nil {
		return nil, err
	}
	var first *quic.Conn
	if c.cfg.peer != "" {
		first, err = c.race(ctx, s, []string{c.cfg.peer}, 12*time.Second)
	} else {
		if c.lastGood != "" {
			first, err = c.race(ctx, s, []string{c.lastGood}, 4*time.Second)
		}
		if first == nil {
			var cands []string
			if cands, err = c.exchange(ctx, s.mux); err == nil {
				go s.mux.punch(ctx, cands, 5*time.Second)
				first, err = c.race(ctx, s, cands, 12*time.Second)
			}
		}
	}
	if err != nil {
		c.failures++
		return nil, err
	}
	c.failures = 0
	c.lastGood = first.RemoteAddr().String()

	conns := []*quic.Conn{first}
	if c.cfg.conns > 1 {
		// More connections over the path that is now open. Each has its own
		// congestion control, which helps on lossy long-distance paths.
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		extra := make(chan *quic.Conn, c.cfg.conns-1)
		for range c.cfg.conns - 1 {
			go func() {
				conn, err := s.tr.Dial(ctx, first.RemoteAddr(), c.tlsc, quicConfig())
				if err != nil {
					conn = nil
				}
				extra <- conn
			}()
		}
		for range c.cfg.conns - 1 {
			if conn := <-extra; conn != nil {
				conns = append(conns, conn)
			}
		}
	}
	return conns, nil
}

// socket returns the UDP socket to dial from, opening a new one at first use,
// after the network interface changed, or after repeated failures.
func (c *client) socket() (*clientSocket, error) {
	changed := c.env.refresh()
	if c.sock != nil && !changed && c.failures < 3 {
		return c.sock, nil
	}
	if c.sock != nil {
		c.sock.close()
		c.sock = nil
	}
	udp, err := c.env.listenUDP(0)
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{Conn: udp, StatelessResetKey: c.k.clientReset}
	c.sock = &clientSocket{udp: udp, tr: tr, mux: newUDPMux(tr, c.env)}
	c.failures = 0
	return c.sock, nil
}

// exchange publishes our candidates and waits for the exit node's answer.
func (c *client) exchange(ctx context.Context, mux *udpMux) ([]string, error) {
	mine := mux.candidates(ctx, nil)
	if len(mine) == 0 {
		return nil, errors.New("no usable local address (STUN failed and no LAN/IPv6 address)")
	}
	offer := signalMsg{Type: "offer", SID: randomID(), Cands: mine}
	ch := make(chan []string, 1)
	c.answersMu.Lock()
	c.answers[offer.SID] = ch
	c.answersMu.Unlock()
	defer func() {
		c.answersMu.Lock()
		delete(c.answers, offer.SID)
		c.answersMu.Unlock()
	}()
	if err := c.sig.publish(ctx, offer); err != nil {
		return nil, fmt.Errorf("signaling: %w", err)
	}
	select {
	case cands := <-ch:
		return cands, nil
	case <-time.After(15 * time.Second):
		return nil, errors.New("exit node did not answer (is it running, with the same key?)")
	}
}

func (c *client) race(ctx context.Context, s *clientSocket, cands []string, timeout time.Duration) (*quic.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type result struct {
		conn *quic.Conn
		err  error
	}
	results := make(chan result, len(cands))
	for _, cand := range cands {
		go func() {
			addr, err := c.env.resolveUDP(ctx, "ip", cand)
			if err != nil {
				results <- result{err: err}
				return
			}
			conn, err := s.tr.Dial(ctx, addr, c.tlsc, quicConfig())
			results <- result{conn, err}
		}()
	}
	var winner *quic.Conn
	var firstErr error
	for range cands {
		r := <-results
		switch {
		case r.err != nil:
			if firstErr == nil {
				firstErr = r.err
			}
		case winner == nil:
			winner = r.conn
			cancel() // the context only governs handshakes, not the established connection
		default:
			r.conn.CloseWithError(0, "duplicate")
		}
	}
	if winner == nil {
		return nil, fmt.Errorf("no candidate reachable (%s): %w", strings.Join(cands, ", "), firstErr)
	}
	return winner, nil
}

func (c *client) setConns(conns []*quic.Conn, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conns = conns
	if conns != nil {
		c.upSince = time.Now()
		c.lastErr = ""
	} else if err != nil {
		c.lastErr = err.Error()
	}
	close(c.changed)
	c.changed = make(chan struct{})
}

// pick returns a live tunnel connection, waiting for one while reconnecting.
// Streams are spread round-robin over the connections.
func (c *client) pick(ctx context.Context) (*quic.Conn, error) {
	for {
		c.mu.Lock()
		conns, changed := c.conns, c.changed
		c.mu.Unlock()
		if len(conns) > 0 {
			return conns[int(c.next.Add(1))%len(conns)], nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, errors.New("tunnel to exit node is down")
		}
	}
}

// open asks the exit node for a TCP connection to target, a UDP relay or one
// of the control requests.
func (c *client) open(ctx context.Context, kind byte, target string) (net.Conn, error) {
	return c.request(ctx, kind, target, 15*time.Second)
}

// request is open with a custom limit on how long the exit node may take to
// answer.
func (c *client) request(ctx context.Context, kind byte, target string, wait time.Duration) (net.Conn, error) {
	if c.k == nil {
		return nil, errors.New("no key set yet; enter it in the dashboard")
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	conn, err := c.pick(ctx)
	if err != nil {
		return nil, err
	}
	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	sc := &streamConn{Stream: st, local: conn.LocalAddr(), remote: conn.RemoteAddr()}
	deadline, _ := ctx.Deadline()
	st.SetDeadline(deadline)
	if err := writeHeader(st, kind, target); err != nil {
		sc.Close()
		return nil, err
	}
	if err := readStatus(st); err != nil {
		sc.Close()
		return nil, err
	}
	st.SetDeadline(time.Time{})
	return sc, nil
}

func (c *client) fetchNodeInfo() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sc, err := c.open(ctx, kindInfo, "")
	if err != nil {
		log.Printf("exit node info: %v", err)
		return
	}
	defer sc.Close()
	sc.SetReadDeadline(time.Now().Add(10 * time.Second))
	var info nodeInfo
	if err := json.NewDecoder(sc).Decode(&info); err != nil {
		return
	}
	c.mu.Lock()
	c.node = &info
	c.mu.Unlock()
	if info.Version != version {
		log.Printf("exit node runs p2proxy %s, this client %s", info.Version, version)
	}
}

// checkLoop looks for new releases once the tunnel is up, then every 6 hours.
func (c *client) checkLoop() {
	if updatesEnabled() != nil {
		return
	}
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		_, err := c.pick(ctx)
		cancel()
		if err == nil {
			if rel, err := c.checkRelease(); err == nil && newer(rel.Tag, version) {
				log.Printf("p2proxy %s is available (running %s); update from the dashboard or with: p2proxy update", rel.Tag, version)
			}
		}
		time.Sleep(6 * time.Hour)
	}
}

// checkRelease asks GitHub for the latest release. Like all other traffic
// from this machine, the request goes through the tunnel.
func (c *client) checkRelease() (*release, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	rel, err := latestRelease(ctx, c.tunnelHTTP)
	c.relMu.Lock()
	defer c.relMu.Unlock()
	if err != nil {
		c.checkErr = err.Error()
		return nil, err
	}
	c.latest, c.checkErr = rel, ""
	return rel, nil
}

// updateSelf installs the latest release on this machine. The caller restarts.
func (c *client) updateSelf() error {
	if !c.updating.CompareAndSwap(false, true) {
		return errors.New("an update is already running")
	}
	defer c.updating.Store(false)
	rel, err := c.checkRelease()
	if err != nil {
		return err
	}
	if !newer(rel.Tag, version) {
		return fmt.Errorf("already running the latest version (%s)", version)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return applyUpdate(ctx, c.tunnelHTTP, rel)
}

// updateNode asks the exit node to install the latest release and restart.
func (c *client) updateNode() error {
	sc, err := c.request(context.Background(), kindUpdate, "", 10*time.Minute)
	if err != nil {
		return err
	}
	sc.Close()
	return nil
}
