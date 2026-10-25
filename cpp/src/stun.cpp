#include "stun.h"

#include <cstring>
#include <set>

#include "crypto.h"
#include "signal.h"

namespace p2px {

namespace {

constexpr uint32_t kMagic = 0x2112A442;
constexpr char kProbeTag[4] = {'P', '2', 'X', '2'};
enum : uint8_t { kProbe = 1, kAck = 2 };

void put16(uint8_t* p, uint16_t v) {
  p[0] = uint8_t(v >> 8);
  p[1] = uint8_t(v);
}
void put32(uint8_t* p, uint32_t v) {
  for (int i = 0; i < 4; i++) p[i] = uint8_t(v >> (24 - 8 * i));
}
uint16_t get16(const uint8_t* p) { return uint16_t(p[0] << 8 | p[1]); }
uint32_t get32(const uint8_t* p) { return uint32_t(p[0]) << 24 | p[1] << 16 | p[2] << 8 | p[3]; }

// Parses a STUN Binding success response; returns the mapped address.
bool parseStun(const uint8_t* b, int n, const uint8_t* txid, sockaddr_in& out) {
  if (n < 20 || get16(b) != 0x0101 || get32(b + 4) != kMagic || memcmp(b + 8, txid, 12) != 0) return false;
  int len = get16(b + 2);
  const uint8_t* a = b + 20;
  const uint8_t* end = b + std::min(n, 20 + len);
  while (a + 4 <= end) {
    uint16_t type = get16(a), alen = get16(a + 2);
    const uint8_t* v = a + 4;
    if (v + alen > end) break;
    if ((type == 0x0020 || type == 0x0001) && alen >= 8 && v[1] == 1) { // IPv4 only
      uint16_t port = get16(v + 2);
      uint32_t ip = get32(v + 4);
      if (type == 0x0020) {
        port ^= kMagic >> 16;
        ip ^= kMagic;
      }
      memset(&out, 0, sizeof out);
      out.sin_family = AF_INET;
      out.sin_port = htons(port);
      out.sin_addr.s_addr = htonl(ip);
      if (type == 0x0020) return true;
    }
    a = v + ((alen + 3) & ~3);
  }
  return out.sin_family == AF_INET;
}

// Waits up to ms for a datagram.
int recvTimeout(SOCKET s, uint8_t* buf, int cap, sockaddr_in& from, int ms) {
  fd_set r;
  FD_ZERO(&r);
  FD_SET(s, &r);
  timeval tv{ms / 1000, (ms % 1000) * 1000};
  if (select(0, &r, nullptr, nullptr, &tv) != 1) return 0;
  int fl = sizeof from;
  int n = recvfrom(s, (char*)buf, cap, 0, (sockaddr*)&from, &fl);
  return n > 0 ? n : 0;
}

} // namespace

bool Prober::open(const std::optional<PhysIface>& iface, std::string& err) {
  close();
  s_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (s_ == INVALID_SOCKET) {
    err = "cannot create UDP socket";
    return false;
  }
  // Ignore ICMP port-unreachable, which would otherwise fail later recvfrom calls.
  BOOL off = FALSE;
  DWORD ret = 0;
  WSAIoctl(s_, SIO_UDP_CONNRESET, &off, sizeof off, nullptr, 0, &ret, nullptr, nullptr);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  if (iface) {
    a.sin_addr = iface->ip; // bound to the physical address: bypasses a TUN
    bindToInterface(s_, iface->index);
  }
  if (bind(s_, (sockaddr*)&a, sizeof a) != 0) {
    err = "cannot bind UDP socket";
    close();
    return false;
  }
  int len = sizeof local_;
  getsockname(s_, (sockaddr*)&local_, &len);
  return true;
}

void Prober::close() {
  if (s_ != INVALID_SOCKET) closesocket(s_);
  s_ = INVALID_SOCKET;
}

std::vector<std::string> Prober::gather(const std::vector<sockaddr_in>& servers, bool& symmetric) {
  symmetric = false;
  std::vector<std::string> out;
  std::set<std::string> seen;
  auto add = [&](const std::string& c) {
    if (seen.insert(c).second) out.push_back(c);
  };

  std::vector<Bytes> txids;
  for (auto& srv : servers) {
    Bytes tx = randomBytes(12);
    txids.push_back(tx);
    uint8_t req[20] = {};
    put16(req, 0x0001);
    put32(req + 4, kMagic);
    memcpy(req + 8, tx.data(), 12);
    for (int i = 0; i < 2; i++) sendto(s_, (const char*)req, 20, 0, (const sockaddr*)&srv, sizeof srv);
  }
  std::vector<std::string> mapped;
  uint64_t deadline = msNow() + 2500;
  uint8_t buf[1500];
  while (msNow() < deadline && mapped.size() < servers.size()) {
    sockaddr_in from{};
    int n = recvTimeout(s_, buf, sizeof buf, from, 100);
    for (size_t i = 0; n > 0 && i < txids.size(); i++) {
      sockaddr_in m{};
      if (parseStun(buf, n, txids[i].data(), m)) {
        mapped.push_back(addrStr(m));
        txids[i].assign(12, 0); // count each server once
        break;
      }
    }
  }
  for (size_t i = 1; i < mapped.size(); i++)
    if (mapped[i] != mapped[0]) symmetric = true;
  for (auto& m : mapped) add(m);
  if (isPrivate(local_.sin_addr)) add(addrStr(local_));
  return out;
}

std::optional<sockaddr_in> Prober::punch(const std::vector<std::string>& peerCands, const Bytes& sid,
                                         int timeoutMs, const std::atomic<bool>& cancel) {
  std::vector<sockaddr_in> targets;
  for (auto& c : peerCands) {
    sockaddr_in a{};
    if (parseAddr(c, a)) targets.push_back(a);
  }
  auto packet = [&](uint8_t type) {
    Bytes p(4 + 1 + sid.size());
    memcpy(p.data(), kProbeTag, 4);
    p[4] = type;
    memcpy(p.data() + 5, sid.data(), sid.size());
    return p;
  };
  Bytes probe = packet(kProbe), ack = packet(kAck);

  std::optional<sockaddr_in> found;
  uint64_t start = msNow(), lastSend = 0, foundAt = 0;
  uint8_t buf[1500];
  while (!cancel && msNow() - start < (uint64_t)timeoutMs) {
    if (found && msNow() - foundAt > 400) break; // the peer has had time to see our acks
    if (msNow() - lastSend >= 100) {
      lastSend = msNow();
      if (found) {
        sendto(s_, (const char*)ack.data(), (int)ack.size(), 0, (const sockaddr*)&*found, sizeof(sockaddr_in));
      } else {
        for (auto& t : targets) sendto(s_, (const char*)probe.data(), (int)probe.size(), 0, (const sockaddr*)&t, sizeof t);
      }
    }
    sockaddr_in from{};
    int n = recvTimeout(s_, buf, sizeof buf, from, 20);
    if (n != (int)probe.size() || memcmp(buf, kProbeTag, 4) != 0 || memcmp(buf + 5, sid.data(), sid.size()) != 0)
      continue;
    if (buf[4] == kProbe) sendto(s_, (const char*)ack.data(), (int)ack.size(), 0, (const sockaddr*)&from, sizeof from);
    if (!found) {
      found = from;
      foundAt = msNow();
    }
  }
  return found;
}

std::vector<sockaddr_in> stunServers() {
  std::vector<sockaddr_in> out;
  const std::pair<const char*, uint16_t> list[] = {{"stun.cloudflare.com", 3478}, {"stun.l.google.com", 19302}};
  for (auto& [host, port] : list) {
    auto ips = resolveIPv4(host);
    if (ips.empty()) continue;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr = ips[0];
    a.sin_port = htons(port);
    out.push_back(a);
  }
  return out;
}

} // namespace p2px
