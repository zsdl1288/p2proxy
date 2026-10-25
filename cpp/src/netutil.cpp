#include "netutil.h"

#include <iphlpapi.h>
#include <mstcpip.h>

#include <cstring>

#include "util.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace p2px {

WinsockInit::WinsockInit() {
  WSADATA d;
  WSAStartup(MAKEWORD(2, 2), &d);
}
WinsockInit::~WinsockInit() { WSACleanup(); }

std::optional<PhysIface> physicalInterface() {
  ULONG size = 32 * 1024;
  std::vector<uint8_t> buf;
  ULONG rc;
  for (int i = 0; i < 4; i++) {
    buf.resize(size);
    rc = GetAdaptersAddresses(AF_INET,
                              GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                  GAA_FLAG_SKIP_DNS_SERVER,
                              nullptr, (IP_ADAPTER_ADDRESSES*)buf.data(), &size);
    if (rc != ERROR_BUFFER_OVERFLOW) break;
  }
  if (rc != NO_ERROR) return std::nullopt;

  IP_ADAPTER_ADDRESSES* best = nullptr;
  in_addr bestIp{};
  for (auto* a = (IP_ADAPTER_ADDRESSES*)buf.data(); a; a = a->Next) {
    if (a->OperStatus != IfOperStatusUp || !a->FirstGatewayAddress) continue;
    if (a->IfType != IF_TYPE_ETHERNET_CSMACD && a->IfType != IF_TYPE_IEEE80211 && a->IfType != IF_TYPE_PPP) continue;
    in_addr ip{};
    for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
      auto* sin = (sockaddr_in*)u->Address.lpSockaddr;
      if (sin->sin_family != AF_INET) continue;
      if ((ntohl(sin->sin_addr.s_addr) >> 16) == 0xA9FE) continue; // 169.254/16
      ip = sin->sin_addr;
      break;
    }
    if (ip.s_addr == 0) continue;
    if (!best || a->Ipv4Metric < best->Ipv4Metric) {
      best = a;
      bestIp = ip;
    }
  }
  if (!best) return std::nullopt;
  return PhysIface{(int)best->IfIndex, toUtf8(best->FriendlyName), bestIp};
}

void bindToInterface(SOCKET s, int ifIndex) {
  if (ifIndex <= 0) return;
  DWORD idx = htonl((u_long)ifIndex); // the IPv4 option takes network byte order
  setsockopt(s, IPPROTO_IP, IP_UNICAST_IF, (const char*)&idx, sizeof idx);
}

std::string addrStr(const sockaddr_in& a) {
  char ip[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &a.sin_addr, ip, sizeof ip);
  return std::string(ip) + ":" + std::to_string(ntohs(a.sin_port));
}

bool parseAddr(const std::string& s, sockaddr_in& out) {
  auto colon = s.rfind(':');
  if (colon == std::string::npos) return false;
  memset(&out, 0, sizeof out);
  out.sin_family = AF_INET;
  if (inet_pton(AF_INET, s.substr(0, colon).c_str(), &out.sin_addr) != 1) return false;
  int port = atoi(s.c_str() + colon + 1);
  if (port <= 0 || port > 65535) return false;
  out.sin_port = htons((u_short)port);
  return true;
}

bool sameAddr(const sockaddr_in& a, const sockaddr_in& b) {
  return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
}

bool isPrivate(const in_addr& a) {
  uint32_t v = ntohl(a.s_addr);
  return (v >> 24) == 10 || (v >> 20) == 0xAC1 || (v >> 16) == 0xC0A8;
}

SOCKET tcpConnect(const std::string& host, uint16_t port, int timeoutMs, std::string& err) {
  addrinfo hints{}, *res = nullptr;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  if (int rc = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res); rc != 0) {
    err = "cannot resolve " + host;
    return INVALID_SOCKET;
  }
  SOCKET result = INVALID_SOCKET;
  err = "connection to " + host + " failed";
  for (auto* ai = res; ai && result == INVALID_SOCKET; ai = ai->ai_next) {
    SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s == INVALID_SOCKET) continue;
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) != 0 && WSAGetLastError() == WSAEWOULDBLOCK) {
      fd_set w, e;
      FD_ZERO(&w);
      FD_ZERO(&e);
      FD_SET(s, &w);
      FD_SET(s, &e);
      timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
      if (select(0, nullptr, &w, &e, &tv) == 1 && FD_ISSET(s, &w)) {
        int soerr = 0, len = sizeof soerr;
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&soerr, &len);
        if (soerr == 0) result = s;
        else if (soerr == WSAECONNREFUSED) err = "connection refused by " + host;
      } else {
        err = "connection to " + host + " timed out";
      }
    }
    if (result == INVALID_SOCKET) {
      closesocket(s);
      continue;
    }
    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);
    BOOL one = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof one);
  }
  freeaddrinfo(res);
  return result;
}

bool sendAll(SOCKET s, const void* p, size_t n) {
  auto* b = (const char*)p;
  while (n > 0) {
    int k = send(s, b, (int)std::min<size_t>(n, 1 << 20), 0);
    if (k <= 0) return false;
    b += k;
    n -= k;
  }
  return true;
}

bool recvAll(SOCKET s, void* p, size_t n) {
  auto* b = (char*)p;
  while (n > 0) {
    int k = recv(s, b, (int)n, 0);
    if (k <= 0) return false;
    b += k;
    n -= k;
  }
  return true;
}

} // namespace p2px
