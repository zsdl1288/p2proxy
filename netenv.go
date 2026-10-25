package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

// DNS-over-TLS servers for p2proxy's own lookups while its traffic is pinned
// to a physical interface. The system resolver is unusable then: under a
// TUN-mode proxy such as Clash it answers with fake IPs, and Clash's strict
// route blocks plain DNS (port 53) outside the TUN.
var bootstrapDNS = []struct{ addr, name string }{
	{"1.1.1.1:853", "cloudflare-dns.com"},
	{"8.8.8.8:853", "dns.google"},
}

// netEnv decides how p2proxy's own traffic (STUN, signaling and the tunnel
// itself) leaves this machine. With an interface selected, every socket is
// pinned to it, so that traffic bypasses a TUN-mode proxy instead of looping
// back into it.
type netEnv struct {
	auto  bool         // re-detect the physical interface on refresh
	index atomic.Int32 // pinned interface; 0 follows the OS routing table
	dot   *net.Resolver
}

func newNetEnv(name string) (*netEnv, error) {
	e := &netEnv{}
	var next atomic.Uint32
	e.dot = &net.Resolver{
		PreferGo: true,
		// Returning a stream (not a PacketConn) makes the Go resolver use
		// length-prefixed TCP framing, which is exactly DNS-over-TLS.
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			// Rotate so the resolver's retries reach a different server.
			s := bootstrapDNS[int(next.Add(1))%len(bootstrapDNS)]
			c, err := e.dialer().DialContext(ctx, "tcp", s.addr)
			if err != nil {
				return nil, err
			}
			return tls.Client(c, &tls.Config{ServerName: s.name}), nil
		},
	}
	switch name {
	case "", "none":
	case "auto":
		e.auto = bindSupported
		e.refresh()
	default:
		if !bindSupported {
			return nil, errors.New("-iface is only supported on Windows")
		}
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("interface %q: %w", name, err)
		}
		e.index.Store(int32(ifi.Index))
		log.Printf("p2proxy's own traffic is pinned to interface %q", ifi.Name)
	}
	return e, nil
}

// refresh re-detects the physical interface in auto mode and reports whether
// it changed (for example after switching from Wi-Fi to Ethernet).
func (e *netEnv) refresh() bool {
	if !e.auto {
		return false
	}
	var index int32
	ifi, err := physicalInterface()
	if err != nil {
		log.Printf("could not detect the physical network interface (%v); following the OS routing table", err)
	} else {
		index = int32(ifi.Index)
	}
	if e.index.Swap(index) == index {
		return false
	}
	if ifi != nil {
		log.Printf("p2proxy's own traffic is pinned to interface %q", ifi.Name)
	}
	return true
}

func (e *netEnv) resolver() *net.Resolver {
	if e.index.Load() == 0 {
		return net.DefaultResolver
	}
	return e.dot
}

func (e *netEnv) control(network, address string, c syscall.RawConn) error {
	if index := int(e.index.Load()); index != 0 {
		return bindControl(index)(network, address, c)
	}
	return nil
}

func (e *netEnv) dialer() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, Control: e.control}
}

func (e *netEnv) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := e.dialer()
	d.Resolver = e.resolver()
	return d.DialContext(ctx, network, addr)
}

func (e *netEnv) listenUDP(port int) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: e.control}
	pc, err := lc.ListenPacket(context.Background(), "udp", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// resolveUDP turns a "host:port" candidate into an address. network is "ip"
// or "ip4".
func (e *netEnv) resolveUDP(ctx context.Context, network, addr string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("bad port in %q", addr)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return &net.UDPAddr{IP: ip.AsSlice(), Port: p, Zone: ip.Zone()}, nil
	}
	ips, err := e.resolver().LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: ips[0], Port: p}, nil
}

// localIPs lists the addresses of the pinned interface, or of every interface.
func (e *netEnv) localIPs() []net.IP {
	var addrs []net.Addr
	if index := int(e.index.Load()); index != 0 {
		if ifi, err := net.InterfaceByIndex(index); err == nil {
			addrs, _ = ifi.Addrs()
		}
	} else {
		addrs, _ = net.InterfaceAddrs()
	}
	var ips []net.IP
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			ips = append(ips, n.IP)
		}
	}
	return ips
}

// retryListen keeps trying to bind for a few seconds, so a freshly updated
// copy can start while the old process is still releasing its ports.
func retryListen[T any](listen func() (T, error)) (T, error) {
	var v T
	var err error
	for range 20 {
		if v, err = listen(); err == nil {
			return v, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return v, err
}
