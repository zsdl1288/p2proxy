package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

var stunServers = []string{"stun.cloudflare.com:3478", "stun.l.google.com:19302"}

const stunMagic = 0x2112A442

// Hole-punching probe. Its first byte keeps quic-go from treating it as QUIC.
var punchPacket = []byte("\x00p2px-punch")

// udpMux shares one UDP socket between QUIC and the extra packets NAT
// traversal needs: STUN requests and responses, and hole-punching probes.
// quic-go hands every packet whose two top bits are zero to
// ReadNonQUICPacket, and STUN messages always start that way (RFC 7983).
type udpMux struct {
	tr  *quic.Transport
	env *netEnv

	mu      sync.Mutex
	pending map[[12]byte]chan *net.UDPAddr
}

func newUDPMux(tr *quic.Transport, env *netEnv) *udpMux {
	m := &udpMux{tr: tr, env: env, pending: map[[12]byte]chan *net.UDPAddr{}}
	go m.readLoop()
	return m
}

func (m *udpMux) readLoop() {
	buf := make([]byte, 1500)
	for {
		n, _, err := m.tr.ReadNonQUICPacket(context.Background(), buf)
		if err != nil {
			return
		}
		// Punch probes only need to arrive; anything that is not a STUN
		// response is dropped here.
		txid, addr, ok := parseSTUNResponse(buf[:n])
		if !ok {
			continue
		}
		m.mu.Lock()
		ch := m.pending[txid]
		m.mu.Unlock()
		if ch != nil {
			select {
			case ch <- addr:
			default:
			}
		}
	}
}

// stun asks a STUN server which public address our socket is mapped to.
func (m *udpMux) stun(ctx context.Context, server string) (*net.UDPAddr, error) {
	raddr, err := m.env.resolveUDP(ctx, "ip4", server)
	if err != nil {
		return nil, err
	}
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:], 0x0001) // Binding Request
	binary.BigEndian.PutUint32(req[4:], stunMagic)
	var txid [12]byte
	rand.Read(txid[:])
	copy(req[8:], txid[:])

	ch := make(chan *net.UDPAddr, 1)
	m.mu.Lock()
	m.pending[txid] = ch
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.pending, txid)
		m.mu.Unlock()
	}()

	for range 3 {
		if _, err := m.tr.WriteTo(req, raddr); err != nil {
			return nil, err
		}
		select {
		case a := <-ch:
			return a, nil
		case <-time.After(800 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("no response from %s", server)
}

func parseSTUNResponse(b []byte) (txid [12]byte, addr *net.UDPAddr, ok bool) {
	if len(b) < 20 || binary.BigEndian.Uint16(b[0:]) != 0x0101 || binary.BigEndian.Uint32(b[4:]) != stunMagic {
		return
	}
	copy(txid[:], b[8:20])
	n := int(binary.BigEndian.Uint16(b[2:]))
	attrs := b[20:]
	if len(attrs) < n {
		return
	}
	attrs = attrs[:n]
	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs[0:])
		l := int(binary.BigEndian.Uint16(attrs[2:]))
		if len(attrs) < 4+l {
			return
		}
		v := attrs[4 : 4+l]
		// 0x0020 XOR-MAPPED-ADDRESS (preferred), 0x0001 MAPPED-ADDRESS.
		if (typ == 0x0020 || typ == 0x0001) && len(v) >= 8 {
			port := binary.BigEndian.Uint16(v[2:])
			var ip net.IP
			switch {
			case v[1] == 1:
				ip = net.IP(append([]byte(nil), v[4:8]...))
			case v[1] == 2 && len(v) >= 20:
				ip = net.IP(append([]byte(nil), v[4:20]...))
			default:
				return
			}
			if typ == 0x0020 {
				port ^= stunMagic >> 16
				key := make([]byte, 16) // magic cookie followed by transaction ID
				binary.BigEndian.PutUint32(key, stunMagic)
				copy(key[4:], b[8:20])
				for i := range ip {
					ip[i] ^= key[i]
				}
			}
			addr = &net.UDPAddr{IP: ip, Port: int(port)}
			if typ == 0x0020 {
				return txid, addr, true
			}
		}
		next := 4 + (l+3)&^3 // attributes are padded to 4 bytes
		if next > len(attrs) {
			break
		}
		attrs = attrs[next:]
	}
	return txid, addr, addr != nil
}

// candidates lists the addresses the peer can try to reach this socket at:
// public IPv4 mappings reported by STUN, global IPv6 addresses (normally
// reachable without NAT), and LAN addresses in case both machines share a
// network. extra addresses go first.
func (m *udpMux) candidates(ctx context.Context, extra []string) []string {
	port := m.tr.Conn.LocalAddr().(*net.UDPAddr).Port
	var out []string
	seen := map[string]bool{}
	add := func(a string) {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, a := range extra {
		add(a)
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	mapped := make([]*net.UDPAddr, len(stunServers))
	var wg sync.WaitGroup
	for i, s := range stunServers {
		wg.Go(func() {
			a, err := m.stun(ctx, s)
			if err != nil {
				log.Printf("STUN %s: %v", s, err)
				return
			}
			mapped[i] = a
		})
	}
	wg.Wait()
	var first string
	for _, a := range mapped {
		if a == nil {
			continue
		}
		if first == "" {
			first = a.String()
		} else if a.String() != first {
			log.Printf("warning: this network has a symmetric NAT (STUN saw %s and %s); hole punching may fail", first, a)
		}
		add(a.String())
	}

	v6 := 0
	for _, ip := range m.env.localIPs() {
		if ip.To4() != nil {
			if !ip.IsPrivate() {
				continue // a public IPv4 on the adapter is already covered by STUN
			}
		} else if !ip.IsGlobalUnicast() || ip.IsPrivate() || v6 >= 4 {
			continue
		} else {
			v6++
		}
		add(net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	}
	return out
}

// punch sends probes to every peer candidate for a while. Our outgoing packets
// open a mapping in our own NAT and firewall, so the peer's packets get in.
func (m *udpMux) punch(ctx context.Context, cands []string, d time.Duration) {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	var addrs []*net.UDPAddr
	for _, c := range cands {
		if a, err := m.env.resolveUDP(ctx, "ip", c); err == nil {
			addrs = append(addrs, a)
		}
	}
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	for {
		for _, a := range addrs {
			m.tr.WriteTo(punchPacket, a)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
