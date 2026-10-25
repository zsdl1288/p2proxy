//go:build windows

package main

import (
	"errors"
	"math/bits"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const bindSupported = true

const (
	ipUnicastIf   = 31 // IP_UNICAST_IF
	ipv6UnicastIf = 31 // IPV6_UNICAST_IF
)

// bindControl pins a socket to one interface with IP_UNICAST_IF and
// IPV6_UNICAST_IF, the same mechanism Clash uses for its own outbound traffic.
// Pinned sockets ignore the default route a TUN adapter installs.
func bindControl(index int) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var err4, err6 error
		err := c.Control(func(fd uintptr) {
			h := syscall.Handle(fd)
			// The IPv4 option takes the index in network byte order.
			err4 = syscall.SetsockoptInt(h, syscall.IPPROTO_IP, ipUnicastIf, int(bits.ReverseBytes32(uint32(index))))
			err6 = syscall.SetsockoptInt(h, syscall.IPPROTO_IPV6, ipv6UnicastIf, index)
		})
		if err != nil {
			return err
		}
		// An IPv4-only socket rejects the IPv6 option and vice versa.
		if err4 != nil && err6 != nil {
			return err4
		}
		return nil
	}
}

// physicalInterface returns the Ethernet or Wi-Fi adapter holding the default
// gateway with the best metric. Virtual adapters (Clash's TUN, VPNs) are
// skipped, so this finds the real uplink even while a TUN owns the default
// route.
func physicalInterface() (*net.Interface, error) {
	size := uint32(16 << 10)
	var buf []byte
	for {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_INCLUDE_GATEWAYS|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, err
		}
	}
	var best *windows.IpAdapterAddresses
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		if a.OperStatus != windows.IfOperStatusUp || a.FirstGatewayAddress == nil {
			continue
		}
		switch a.IfType {
		case 6, 71, 23: // Ethernet, Wi-Fi, PPP
		default:
			continue
		}
		if best == nil || a.Ipv4Metric < best.Ipv4Metric {
			best = a
		}
	}
	if best == nil {
		return nil, errors.New("no Ethernet or Wi-Fi adapter with a default gateway")
	}
	index := best.IfIndex
	if index == 0 {
		index = best.Ipv6IfIndex
	}
	return net.InterfaceByIndex(int(index))
}
