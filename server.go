package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

type serverConfig struct {
	port      int
	advertise []string
	signal    string
	iface     string
}

// nodeInfo describes the exit node to the client (kindInfo).
type nodeInfo struct {
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Started int64  `json:"started"`
}

// filler is the payload of speed tests.
var filler = func() []byte {
	b := make([]byte, 64<<10)
	rand.Read(b)
	return b
}()

type server struct {
	cfg      serverConfig
	mux      *udpMux
	info     nodeInfo
	updating sync.Mutex
}

// runServer runs the exit node (B): it accepts tunnels from the client and
// opens the requested connections from this machine.
func runServer(k *keys, cfg serverConfig) error {
	env, err := newNetEnv(cfg.iface)
	if err != nil {
		return err
	}
	udp, err := retryListen(func() (*net.UDPConn, error) { return env.listenUDP(cfg.port) })
	if err != nil {
		return err
	}
	tr := &quic.Transport{Conn: udp, StatelessResetKey: k.serverReset}
	s := &server{
		cfg:  cfg,
		mux:  newUDPMux(tr, env),
		info: nodeInfo{Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH, Started: time.Now().Unix()},
	}
	ln, err := tr.Listen(k.serverTLS(), quicConfig())
	if err != nil {
		return err
	}
	log.Printf("p2proxy %s exit node listening on UDP port %d", version, udp.LocalAddr().(*net.UDPAddr).Port)

	ctx := context.Background()
	if cfg.signal != "" {
		sig := newSignaler(cfg.signal, k, env)
		go sig.subscribe(ctx, time.Now().Unix(), s.offerHandler(ctx, sig), nil)
		go func() {
			log.Printf("this node can be reached at: %s", strings.Join(s.mux.candidates(ctx, cfg.advertise), ", "))
			// Tell a waiting client we are (back) up, so it reconnects at once
			// instead of waiting out its retry delay.
			if err := sig.publish(ctx, signalMsg{Type: "hello", SID: randomID()}); err != nil {
				log.Printf("signaling: %v", err)
			}
		}()
		log.Printf("waiting for clients via %s", cfg.signal)
	} else {
		go func() {
			log.Printf("this node can be reached at: %s", strings.Join(s.mux.candidates(ctx, cfg.advertise), ", "))
		}()
	}

	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return err
		}
		go s.serveConn(conn)
	}
}

func (s *server) offerHandler(ctx context.Context, sig *signaler) func(signalMsg) {
	var mu sync.Mutex
	seen := map[string]time.Time{}
	return func(m signalMsg) {
		if m.Type != "offer" {
			return
		}
		mu.Lock()
		for sid, t := range seen {
			if time.Since(t) > 2*signalMaxAge {
				delete(seen, sid)
			}
		}
		_, dup := seen[m.SID]
		seen[m.SID] = time.Now()
		mu.Unlock()
		if dup {
			return
		}
		log.Printf("client is connecting (session %s) from %s", m.SID, strings.Join(m.Cands, ", "))
		go s.mux.punch(ctx, m.Cands, 10*time.Second)
		go func() {
			answer := signalMsg{Type: "answer", SID: m.SID, Cands: s.mux.candidates(ctx, s.cfg.advertise)}
			if err := sig.publish(ctx, answer); err != nil {
				log.Printf("signaling: could not answer: %v", err)
			}
		}()
	}
}

func (s *server) serveConn(conn *quic.Conn) {
	log.Printf("client connected from %s", conn.RemoteAddr())
	for {
		st, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("client %s disconnected: %v", conn.RemoteAddr(), err)
			return
		}
		go s.serveStream(&streamConn{Stream: st, local: conn.LocalAddr(), remote: conn.RemoteAddr()})
	}
}

func (s *server) serveStream(sc *streamConn) {
	sc.SetReadDeadline(time.Now().Add(10 * time.Second))
	kind, target, err := readHeader(sc)
	if err != nil {
		sc.Close()
		return
	}
	sc.SetReadDeadline(time.Time{})
	switch kind {
	case kindTCP:
		up, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			writeStatus(sc, err)
			sc.Close()
			return
		}
		if writeStatus(sc, nil) != nil {
			up.Close()
			sc.Close()
			return
		}
		relay(sc, up)
	case kindUDP:
		serveUDP(sc)
	case kindInfo:
		if writeStatus(sc, nil) == nil {
			json.NewEncoder(sc).Encode(s.info)
		}
		sc.Close()
	case kindSpeedDown:
		if writeStatus(sc, nil) == nil {
			sc.SetWriteDeadline(time.Now().Add(speedTestLimit))
			for {
				if _, err := sc.Write(filler); err != nil {
					break
				}
			}
		}
		sc.Close()
	case kindSpeedUp:
		serveSpeedUp(sc)
	case kindUpdate:
		err := s.update()
		writeStatus(sc, err)
		sc.Close()
		if err == nil {
			time.Sleep(time.Second) // let the reply reach the client
			restartSelf()
		}
	default:
		writeStatus(sc, errors.New("unknown request; is the exit node older than the client?"))
		sc.Close()
	}
}

// update installs the latest release on this node, on the client's request.
func (s *server) update() error {
	if !s.updating.TryLock() {
		return errors.New("an update is already running")
	}
	defer s.updating.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	rel, err := latestRelease(ctx, http.DefaultClient)
	if err != nil {
		return err
	}
	if !newer(rel.Tag, version) {
		return fmt.Errorf("already running the latest version (%s)", version)
	}
	log.Printf("client requested an update to %s", rel.Tag)
	return applyUpdate(ctx, http.DefaultClient, rel)
}

// serveSpeedUp swallows the client's upload and reports what arrived:
// [bytes:8][nanoseconds from first to last byte:8].
func serveSpeedUp(sc *streamConn) {
	defer sc.Close()
	if writeStatus(sc, nil) != nil {
		return
	}
	sc.SetReadDeadline(time.Now().Add(speedTestLimit))
	buf := make([]byte, 64<<10)
	var n int64
	var first, last time.Time
	for {
		k, err := sc.Read(buf)
		if k > 0 {
			last = time.Now()
			if first.IsZero() {
				first = last
			}
			n += int64(k)
		}
		if err != nil {
			break
		}
	}
	var rep [16]byte
	binary.BigEndian.PutUint64(rep[0:], uint64(n))
	binary.BigEndian.PutUint64(rep[8:], uint64(last.Sub(first)))
	sc.SetWriteDeadline(time.Now().Add(5 * time.Second))
	sc.Write(rep[:])
}

// serveUDP relays datagrams for one SOCKS5 UDP association.
func serveUDP(sc *streamConn) {
	defer sc.Close()
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		writeStatus(sc, err)
		return
	}
	defer pc.Close()
	if writeStatus(sc, nil) != nil {
		return
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				sc.Close()
				return
			}
			if writeDatagram(sc, from.String(), buf[:n]) != nil {
				pc.Close()
				return
			}
		}
	}()
	resolved := map[string]*net.UDPAddr{}
	br := bufio.NewReader(sc)
	for {
		addr, data, err := readDatagram(br)
		if err != nil {
			return
		}
		to := resolved[addr]
		if to == nil {
			if to, err = net.ResolveUDPAddr("udp", addr); err != nil {
				continue
			}
			if len(resolved) >= 1024 {
				clear(resolved)
			}
			resolved[addr] = to
		}
		pc.WriteToUDP(data, to)
	}
}

func randomID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
