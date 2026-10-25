#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <windows.h>

#include <optional>
#include <string>
#include <vector>

#ifndef SIO_UDP_CONNRESET // ignore ICMP port unreachable on UDP sockets
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

namespace p2px {

struct WinsockInit {
  WinsockInit();
  ~WinsockInit();
};

struct PhysIface {
  int index = 0;
  std::string name;
  in_addr ip{};
};

// The Ethernet or Wi-Fi adapter holding the default gateway with the best
// metric. Virtual adapters (Clash's TUN, VPNs) are skipped, so this finds the
// real uplink even while a TUN owns the default route.
std::optional<PhysIface> physicalInterface();

// Pins a socket to one interface with IP_UNICAST_IF, so its traffic bypasses
// the default route a TUN adapter installs.
void bindToInterface(SOCKET s, int ifIndex);

std::string addrStr(const sockaddr_in& a);
bool parseAddr(const std::string& s, sockaddr_in& out); // "1.2.3.4:5678"
bool sameAddr(const sockaddr_in& a, const sockaddr_in& b);
bool isPrivate(const in_addr& a);

// Connects with a timeout; host may be a name. INVALID_SOCKET on failure.
SOCKET tcpConnect(const std::string& host, uint16_t port, int timeoutMs, std::string& err);
bool sendAll(SOCKET s, const void* p, size_t n);
bool recvAll(SOCKET s, void* p, size_t n);

} // namespace p2px
