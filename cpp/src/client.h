#pragma once
#include <atomic>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>

#include "signal.h"
#include "socks.h"
#include "tunnel.h"

namespace p2px {

// A client (A). Keeps one tunnel to the exit node alive and serves a local
// SOCKS5 port for Clash. While the tunnel is down, requests fail instead of
// going out directly.
class Client : public std::enable_shared_from_this<Client> {
public:
  ~Client();
  bool start(const std::string& key, uint16_t socksPort, std::string& err);
  void stop();
  json state();
  std::shared_ptr<Stream> open(uint8_t kind, const std::string& target, int waitMs, std::string& err);

  bool startSpeedTest();
  json speedState();

  // Downloads a GitHub URL through the exit node (see update.h).
  bool fetch(const std::string& url, std::string& body, std::string& err);
  // Asks the exit node to install the latest release and restart.
  bool updateNode(std::string& err);
  std::string nodeVersion();

private:
  void maintain();
  std::shared_ptr<Connection> connectOnce(std::string& err);
  void fetchNodeInfo();
  void onSignal(const json& m);
  void wakeUp();
  void runSpeedTest();
  double measure(const char* phase, const std::function<void(uint64_t deadline, std::atomic<uint64_t>& bytes)>& work,
                 std::string& err);

  std::optional<Keys> keys_;
  std::unique_ptr<Signaler> sig_;
  SocksServer socks_;
  std::thread maint_;
  std::atomic<bool> stopping_{false};

  std::mutex mu_;
  std::condition_variable cv_;
  std::shared_ptr<Connection> conn_;
  int64_t upSince_ = 0;
  std::string lastErr_, remote_, nodeVersion_;
  bool wake_ = false;
  int64_t helloTs_ = 0; // when the exit node last announced a (re)start
  std::map<std::string, json> answers_; // offer session id -> answer (null while waiting)
  std::vector<sockaddr_in> stun_;

  std::mutex speedMu_;
  json speed_ = {{"running", false}};
  std::thread speedTh_;
};

} // namespace p2px
