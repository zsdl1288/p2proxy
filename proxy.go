package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// opener asks the exit node for a connection (see client.open).
type opener func(ctx context.Context, kind byte, target string) (net.Conn, error)

// serveProxy speaks SOCKS5 and HTTP on the same local port, telling them
// apart by the first byte the application sends.
func serveProxy(ln net.Listener, open opener) error {
	httpLn := &chanListener{addr: ln.Addr(), ch: make(chan net.Conn)}
	hp := &httpProxy{open: open, transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return open(ctx, kindTCP, addr)
		},
		DisableCompression:  true, // pass bodies through untouched
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     60 * time.Second,
	}}
	srv := &http.Server{Handler: hp, ReadHeaderTimeout: 30 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	go srv.Serve(httpLn)

	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			br := bufio.NewReader(c)
			c.SetReadDeadline(time.Now().Add(30 * time.Second))
			first, err := br.Peek(1)
			c.SetReadDeadline(time.Time{})
			if err != nil {
				c.Close()
				return
			}
			pc := &peekedConn{Conn: c, r: br}
			if first[0] == 5 {
				handleSOCKS5(pc, open)
			} else {
				httpLn.ch <- pc
			}
		}()
	}
}

// peekedConn is a connection whose first bytes were already buffered.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func (c *peekedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// chanListener feeds connections already accepted elsewhere to an http.Server.
type chanListener struct {
	addr net.Addr
	ch   chan net.Conn
}

func (l *chanListener) Accept() (net.Conn, error) { return <-l.ch, nil }
func (l *chanListener) Close() error              { return nil }
func (l *chanListener) Addr() net.Addr            { return l.addr }

// ---- HTTP proxy ----

type httpProxy struct {
	open      opener
	transport *http.Transport
}

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func removeHopHeaders(h http.Header) {
	for _, f := range h.Values("Connection") {
		for name := range strings.SplitSeq(f, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range hopHeaders {
		h.Del(name)
	}
}

func (p *httpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	if !r.URL.IsAbs() {
		http.Error(w, "p2proxy: this is a proxy server", http.StatusBadRequest)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	removeHopHeaders(out.Header)
	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		http.Error(w, "p2proxy: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	removeHopHeaders(resp.Header)
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			rc.Flush()
		}
		if err != nil {
			return
		}
	}
}

func (p *httpProxy) connect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	up, err := p.open(r.Context(), kindTCP, target)
	if err != nil {
		log.Printf("http: %s: %v", target, err)
		http.Error(w, "p2proxy: "+err.Error(), http.StatusBadGateway)
		return
	}
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		up.Close()
		return
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		up.Close()
		conn.Close()
		return
	}
	if n := brw.Reader.Buffered(); n > 0 {
		b, _ := brw.Reader.Peek(n)
		up.Write(b)
	}
	relay(conn, up)
}

// ---- SOCKS5 (RFC 1928): CONNECT and UDP ASSOCIATE, no authentication ----

func handleSOCKS5(c net.Conn, open opener) {
	c.SetDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 256)
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		c.Close()
		return
	}
	methods := buf[:buf[1]]
	if _, err := io.ReadFull(c, methods); err != nil {
		c.Close()
		return
	}
	if !bytes.Contains(methods, []byte{0}) {
		c.Write([]byte{5, 0xff})
		c.Close()
		return
	}
	c.Write([]byte{5, 0})

	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		c.Close()
		return
	}
	cmd := buf[1]
	target, err := readSOCKSAddr(c, buf[3])
	if err != nil {
		c.Close()
		return
	}
	switch cmd {
	case 1: // CONNECT
		up, err := open(context.Background(), kindTCP, target)
		if err != nil {
			log.Printf("socks: %s: %v", target, err)
			socksReply(c, 1, "")
			c.Close()
			return
		}
		if socksReply(c, 0, "") != nil {
			up.Close()
			c.Close()
			return
		}
		c.SetDeadline(time.Time{})
		relay(c, up)
	case 3: // UDP ASSOCIATE
		handleSOCKS5UDP(c, open)
	default:
		socksReply(c, 7, "") // command not supported
		c.Close()
	}
}

// handleSOCKS5UDP serves a UDP ASSOCIATE: datagrams the application sends to
// our UDP port travel over one tunnel stream, and replies come back the same
// way. The association lasts as long as the TCP control connection.
func handleSOCKS5UDP(c net.Conn, open opener) {
	defer c.Close()
	appIP := c.RemoteAddr().(*net.TCPAddr).IP
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: c.LocalAddr().(*net.TCPAddr).IP})
	if err != nil {
		socksReply(c, 1, "")
		return
	}
	defer pc.Close()
	up, err := open(context.Background(), kindUDP, "")
	if err != nil {
		log.Printf("socks udp: %v", err)
		socksReply(c, 1, "")
		return
	}
	defer up.Close()
	if socksReply(c, 0, pc.LocalAddr().String()) != nil {
		return
	}
	c.SetDeadline(time.Time{})

	go func() {
		io.Copy(io.Discard, c) // returns when the application closes the control connection
		up.Close()
		pc.Close()
	}()

	var app atomic.Pointer[net.UDPAddr]
	go func() {
		br := bufio.NewReader(up)
		for {
			from, data, err := readDatagram(br)
			if err != nil {
				pc.Close()
				return
			}
			if to := app.Load(); to != nil {
				pkt := appendSOCKSAddr([]byte{0, 0, 0}, from)
				pc.WriteToUDP(append(pkt, data...), to)
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Only the application that opened the association may use it, and
		// fragmented datagrams (FRAG != 0) are not supported.
		if !from.IP.Equal(appIP) || n < 4 || buf[2] != 0 {
			continue
		}
		app.Store(from)
		r := bytes.NewReader(buf[4:n])
		target, err := readSOCKSAddr(r, buf[3])
		if err != nil {
			continue
		}
		if writeDatagram(up, target, buf[n-r.Len():n]) != nil {
			return
		}
	}
}

func readSOCKSAddr(r io.Reader, atyp byte) (string, error) {
	var host string
	switch atyp {
	case 1, 4:
		ip := make([]byte, 4)
		if atyp == 4 {
			ip = make([]byte, 16)
		}
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return "", err
		}
		host = string(name)
	default:
		return "", errors.New("unsupported address type")
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))), nil
}

func appendSOCKSAddr(b []byte, addr string) []byte {
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			b = append(b, 1)
		} else {
			b = append(b, 4)
		}
		b = append(b, ip.AsSlice()...)
	} else {
		b = append(b, 3, byte(len(host)))
		b = append(b, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port))
}

func socksReply(w io.Writer, rep byte, bind string) error {
	if bind == "" {
		bind = "0.0.0.0:0"
	}
	_, err := w.Write(appendSOCKSAddr([]byte{5, rep, 0}, bind))
	return err
}
