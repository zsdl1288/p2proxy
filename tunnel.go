package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Every proxied connection is one QUIC stream. The client opens it with
//
//	[kind:1][len:1][target:len]     target is "host:port" (empty for UDP)
//
// and the server answers
//
//	[status:1][len:1][message:len]  status 0 means connected
//
// after which the stream carries what the kind calls for.
const (
	kindTCP       = 1 // raw TCP bytes to and from target
	kindUDP       = 2 // framed UDP datagrams (see writeDatagram)
	kindInfo      = 3 // the server sends a JSON nodeInfo
	kindSpeedDown = 4 // the server sends filler until the client stops reading
	kindSpeedUp   = 5 // the client sends filler; the server replies with a speedReport
	kindUpdate    = 6 // the server installs the latest release and restarts
)

// speedTestLimit caps how long a single speed-test stream may run.
const speedTestLimit = 30 * time.Second

func quicConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: 8 * time.Second,
		MaxIdleTimeout:       20 * time.Second,
		KeepAlivePeriod:      5 * time.Second, // also keeps NAT mappings open
		MaxIncomingStreams:   4096,
		// Large windows let one stream fill a long, fast path (1 Gbit/s at
		// 80 ms needs ~10 MB in flight). They grow on demand from the initial
		// values.
		InitialStreamReceiveWindow:     2 << 20,
		MaxStreamReceiveWindow:         32 << 20,
		InitialConnectionReceiveWindow: 4 << 20,
		MaxConnectionReceiveWindow:     128 << 20,
	}
}

func writeHeader(w io.Writer, kind byte, target string) error {
	if len(target) > 255 {
		return errors.New("target address too long")
	}
	_, err := w.Write(append([]byte{kind, byte(len(target))}, target...))
	return err
}

func readHeader(r io.Reader) (kind byte, target string, err error) {
	var h [2]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return
	}
	b := make([]byte, h[1])
	if _, err = io.ReadFull(r, b); err != nil {
		return
	}
	return h[0], string(b), nil
}

func writeStatus(w io.Writer, status error) error {
	if status == nil {
		_, err := w.Write([]byte{0, 0})
		return err
	}
	msg := status.Error()
	if len(msg) > 255 {
		msg = msg[:255]
	}
	_, err := w.Write(append([]byte{1, byte(len(msg))}, msg...))
	return err
}

func readStatus(r io.Reader) error {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return err
	}
	msg := make([]byte, h[1])
	if _, err := io.ReadFull(r, msg); err != nil {
		return err
	}
	if h[0] != 0 {
		return errors.New("exit node: " + string(msg))
	}
	return nil
}

// A datagram on a kindUDP stream: [addrLen:1][addr][dataLen:2][data].
// addr is the destination client→server and the source server→client.
func writeDatagram(w io.Writer, addr string, data []byte) error {
	if len(addr) > 255 || len(data) > 65535 {
		return errors.New("datagram too large")
	}
	buf := make([]byte, 0, 3+len(addr)+len(data))
	buf = append(buf, byte(len(addr)))
	buf = append(buf, addr...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(data)))
	buf = append(buf, data...)
	_, err := w.Write(buf)
	return err
}

func readDatagram(r *bufio.Reader) (addr string, data []byte, err error) {
	n, err := r.ReadByte()
	if err != nil {
		return
	}
	a := make([]byte, n)
	if _, err = io.ReadFull(r, a); err != nil {
		return
	}
	var l [2]byte
	if _, err = io.ReadFull(r, l[:]); err != nil {
		return
	}
	data = make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err = io.ReadFull(r, data); err != nil {
		return
	}
	return string(a), data, nil
}

// streamConn adapts a QUIC stream to net.Conn.
type streamConn struct {
	*quic.Stream
	local, remote net.Addr
}

func (s *streamConn) LocalAddr() net.Addr  { return s.local }
func (s *streamConn) RemoteAddr() net.Addr { return s.remote }

// CloseWrite sends FIN, like a TCP half-close.
func (s *streamConn) CloseWrite() error { return s.Stream.Close() }

// Close shuts down both directions.
func (s *streamConn) Close() error {
	s.Stream.CancelRead(0)
	return s.Stream.Close()
}

// relay copies between a and b in both directions, forwarding half-closes,
// and returns once both directions are done. Errors tear down both sides.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok && err == nil {
			cw.CloseWrite()
			return
		}
		a.Close()
		b.Close()
	}
	wg.Go(func() { cp(a, b) })
	wg.Go(func() { cp(b, a) })
	wg.Wait()
	a.Close()
	b.Close()
}
