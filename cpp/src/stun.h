#pragma once
#include <atomic>
#include <optional>
#include <string>
#include <vector>

#include "netutil.h"
#include "util.h"

namespace p2px {

// NAT traversal on a plain UDP socket: STUN to learn our public address, then
// probes in both directions until a path opens ("hole punching"). Once a path
// works the socket is closed and msquic binds the same local port, so the NAT
// mappings the probes opened carry the QUIC connection.
class Prober {
public:
  ~Prober() { close(); }
  bool open(const std::optional<PhysIface>& iface, std::string& err);
  void close();
  uint16_t port() const { return ntohs(local_.sin_port); }
  sockaddr_in local() const { return local_; }

  // Addresses the peer can try: public mappings from STUN, then LAN.
  // symmetric is set when two STUN servers saw different ports, which makes
  // hole punching unlikely to work.
  std::vector<std::string> gather(const std::vector<sockaddr_in>& stunServers, bool& symmetric);

  // Probes every peer candidate until one answers; returns the peer address
  // that works (which may differ from the candidates behind some NATs).
  std::optional<sockaddr_in> punch(const std::vector<std::string>& peerCands, const Bytes& sid, int timeoutMs,
                                   const std::atomic<bool>& cancel);

private:
  SOCKET s_ = INVALID_SOCKET;
  sockaddr_in local_{};
};

// STUN servers, resolved without the system resolver (see resolveIPv4).
std::vector<sockaddr_in> stunServers();

} // namespace p2px
