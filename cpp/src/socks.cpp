#include "socks.h"

#include <atomic>

#include "tunnel.h"

namespace p2px {

namespace {

// Reads ATYP's address and port; returns "host:port".
bool readAddr(SOCKET s, uint8_t atyp, std::string& out) {
  std::string host;
  if (atyp == 1 || atyp == 4) {
    uint8_t ip[16];
    int n = atyp == 1 ? 4 : 16;
    if (!recvAll(s, ip, n)) return false;
    char buf[INET6_ADDRSTRLEN] = {};
    inet_ntop(atyp == 1 ? AF_INET : AF_INET6, ip, buf, sizeof buf);
    host = atyp == 1 ? buf : "[" + std::string(buf) + "]";
  } else if (atyp == 3) {
    uint8_t len;
    if (!recvAll(s, &len, 1)) return false;
    host.assign(len, '\0');
    if (!recvAll(s, host.data(), len)) return false;
  } else {
    return false;
  }
  uint8_t p[2];
  if (!recvAll(s, p, 2)) return false;
  out = host + ":" + std::to_string(p[0] << 8 | p[1]);
  return true;
}

// Same, from a UDP datagram; returns bytes consumed or 0.
size_t parseAddr(const uint8_t* b, size_t n, std::string& out) {
  if (n < 1) return 0;
  uint8_t atyp = b[0];
  size_t i = 1;
  std::string host;
  if (atyp == 1 || atyp == 4) {
    size_t len = atyp == 1 ? 4 : 16;
    if (n < i + len + 2) return 0;
    char buf[INET6_ADDRSTRLEN] = {};
    inet_ntop(atyp == 1 ? AF_INET : AF_INET6, b + i, buf, sizeof buf);
    host = atyp == 1 ? buf : "[" + std::string(buf) + "]";
    i += len;
  } else if (atyp == 3) {
    if (n < 2 || n < 2 + b[1] + 2u) return 0;
    host.assign((const char*)b + 2, b[1]);
    i = 2 + b[1];
  } else {
    return 0;
  }
  out = host + ":" + std::to_string(b[i] << 8 | b[i + 1]);
  return i + 2;
}

// Encodes "host:port" as ATYP + address + port.
void appendAddr(Bytes& b, const std::string& addr) {
  std::string host;
  uint16_t port = 0;
  splitHostPort(addr, host, port);
  in_addr v4;
  in6_addr v6;
  if (inet_pton(AF_INET, host.c_str(), &v4) == 1) {
    b.push_back(1);
    auto* p = (uint8_t*)&v4;
    b.insert(b.end(), p, p + 4);
  } else if (inet_pton(AF_INET6, host.c_str(), &v6) == 1) {
    b.push_back(4);
    auto* p = (uint8_t*)&v6;
    b.insert(b.end(), p, p + 16);
  } else {
    b.push_back(3);
    b.push_back((uint8_t)host.size());
    b.insert(b.end(), host.begin(), host.end());
  }
  b.push_back(uint8_t(port >> 8));
  b.push_back(uint8_t(port));
}

bool reply(SOCKET s, uint8_t rep, const std::string& bind = "0.0.0.0:0") {
  Bytes b{5, rep, 0};
  appendAddr(b, bind);
  return sendAll(s, b.data(), b.size());
}

} // namespace

bool SocksServer::start(uint16_t port, Opener open, std::string& err) {
  open_ = std::move(open);
  ls_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = htons(port);
  BOOL excl = TRUE;
  setsockopt(ls_, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&excl, sizeof excl);
  if (bind(ls_, (sockaddr*)&a, sizeof a) != 0 || listen(ls_, SOMAXCONN) != 0) {
    err = "port 127.0.0.1:" + std::to_string(port) + " is in use";
    closesocket(ls_);
    ls_ = INVALID_SOCKET;
    return false;
  }
  port_ = port;
  stop_ = false;
  th_ = std::thread([this] { acceptLoop(); });
  return true;
}

void SocksServer::stop() {
  stop_ = true;
  if (ls_ != INVALID_SOCKET) closesocket(ls_);
  ls_ = INVALID_SOCKET;
  if (th_.joinable()) th_.join();
}

void SocksServer::acceptLoop() {
  while (!stop_) {
    SOCKET c = accept(ls_, nullptr, nullptr);
    if (c == INVALID_SOCKET) {
      if (stop_) break;
      Sleep(10);
      continue;
    }
    BOOL one = TRUE;
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof one);
    std::thread([this, c] { handle(c); }).detach();
  }
}

void SocksServer::handle(SOCKET c) {
  DWORD tmo = 30000;
  setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof tmo);
  uint8_t h[4];
  uint8_t methods[255];
  if (!recvAll(c, h, 2) || h[0] != 5 || !recvAll(c, methods, h[1])) return (void)closesocket(c);
  bool noAuth = false;
  for (int i = 0; i < h[1]; i++) noAuth |= methods[i] == 0;
  uint8_t sel[2] = {5, uint8_t(noAuth ? 0 : 0xFF)};
  if (!sendAll(c, sel, 2) || !noAuth) return (void)closesocket(c);

  std::string target;
  if (!recvAll(c, h, 4) || h[0] != 5 || !readAddr(c, h[3], target)) return (void)closesocket(c);
  if (h[1] == 3) return handleUdp(c);
  if (h[1] != 1) {
    reply(c, 7); // command not supported
    return (void)closesocket(c);
  }
  std::string err;
  auto st = open_(kTcp, target, err);
  if (!st) {
    logf("socks: %s: %s", target.c_str(), err.c_str());
    reply(c, 1);
    return (void)closesocket(c);
  }
  if (!reply(c, 0)) {
    st->abort();
    return (void)closesocket(c);
  }
  tmo = 0;
  setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof tmo);
  relay(c, st);
}

// UDP ASSOCIATE: datagrams the application sends to our UDP port travel over
// one tunnel stream, and replies come back the same way. The association
// lasts as long as the TCP control connection.
void SocksServer::handleUdp(SOCKET c) {
  SOCKET u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  int al = sizeof a;
  if (u == INVALID_SOCKET || bind(u, (sockaddr*)&a, sizeof a) != 0 || getsockname(u, (sockaddr*)&a, &al) != 0) {
    reply(c, 1);
    if (u != INVALID_SOCKET) closesocket(u);
    return (void)closesocket(c);
  }
  BOOL off = FALSE;
  DWORD ret = 0;
  WSAIoctl(u, SIO_UDP_CONNRESET, &off, sizeof off, nullptr, 0, &ret, nullptr, nullptr);
  std::string err;
  auto st = open_(kUdp, "", err);
  if (!st || !reply(c, 0, addrStr(a))) {
    if (st) st->abort();
    logf("socks udp: %s", err.c_str());
    reply(c, 1);
    closesocket(u);
    return (void)closesocket(c);
  }
  DWORD tmo = 0;
  setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof tmo);

  struct Shared {
    std::atomic<bool> haveApp{false}, closed{false};
    sockaddr_in app{};
    SOCKET u = INVALID_SOCKET;
    void closeUdp() { // also wakes the recvfrom loop below
      if (!closed.exchange(true)) closesocket(u);
    }
  };
  auto sh = std::make_shared<Shared>();
  sh->u = u;
  // Replies from the exit node back to the application.
  std::thread back([u, st, sh] {
    std::string from;
    Bytes data;
    while (readDatagram(*st, from, data)) {
      if (!sh->haveApp) continue;
      Bytes pkt{0, 0, 0};
      appendAddr(pkt, from);
      pkt.insert(pkt.end(), data.begin(), data.end());
      sendto(u, (const char*)pkt.data(), (int)pkt.size(), 0, (const sockaddr*)&sh->app, sizeof sh->app);
    }
    sh->closeUdp();
  });
  // The association ends when the application closes the control connection.
  std::thread ctrl([c, st, sh] {
    char b[256];
    while (recv(c, b, sizeof b, 0) > 0) {
    }
    st->abort();
    sh->closeUdp();
  });
  std::vector<uint8_t> buf(65536);
  for (;;) {
    sockaddr_in from{};
    int fl = sizeof from;
    int n = recvfrom(u, (char*)buf.data(), (int)buf.size(), 0, (sockaddr*)&from, &fl);
    if (n < 0) break;
    // Only loopback applications, and no fragmentation (FRAG must be 0).
    if (from.sin_addr.s_addr != htonl(INADDR_LOOPBACK) || n < 4 || buf[2] != 0) continue;
    sh->app = from;
    sh->haveApp = true;
    std::string target;
    size_t used = parseAddr(buf.data() + 3, n - 3, target);
    if (!used) continue;
    if (!writeDatagram(*st, target, buf.data() + 3 + used, n - 3 - used)) break;
  }
  st->abort();
  sh->closeUdp();
  shutdown(c, SD_BOTH);
  back.join();
  ctrl.join();
  closesocket(c);
}

} // namespace p2px
