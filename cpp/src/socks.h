#pragma once
#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#include "quic.h"

namespace p2px {

// Local SOCKS5 server (RFC 1928): CONNECT and UDP ASSOCIATE, no
// authentication, loopback only. Each request becomes one tunnel stream.
class SocksServer {
public:
  using Opener = std::function<std::shared_ptr<Stream>(uint8_t kind, const std::string& target, std::string& err)>;
  ~SocksServer() { stop(); }
  bool start(uint16_t port, Opener open, std::string& err);
  void stop();
  uint16_t port() const { return port_; }

private:
  void acceptLoop();
  void handle(SOCKET c);
  void handleUdp(SOCKET c);

  SOCKET ls_ = INVALID_SOCKET;
  uint16_t port_ = 0;
  std::thread th_;
  Opener open_;
  std::atomic<bool> stop_{false};
};

} // namespace p2px
