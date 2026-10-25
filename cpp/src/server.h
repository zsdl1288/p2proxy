#pragma once
#include <atomic>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <optional>

#include "cert.h"
#include "signal.h"
#include "tunnel.h"

namespace p2px {

// The exit node (B). One per key: at startup it asks whether another exit
// node already answers on the topic and refuses to run if one does. Any
// number of clients may connect.
class Server : public std::enable_shared_from_this<Server> {
public:
  ~Server();
  bool start(const std::string& key, std::string& err);
  void stop();
  json state();

private:
  struct Client {
    std::string name, addr;
    int64_t since = 0;
    std::shared_ptr<Connection> conn;
  };
  // One client's connection attempt (one signaling offer).
  struct Session {
    std::string token, name;
    std::mutex mu;
    std::condition_variable cv;
    bool authed = false, taken = false;
  };

  void onSignal(const json& m);
  void announce();
  void handleOffer(json m);
  bool accept(HQUIC h, const sockaddr_in& remote, std::shared_ptr<Session> sess);
  void serveStream(std::shared_ptr<Session> sess, std::weak_ptr<Client> client, std::shared_ptr<Stream> st);
  void serveUdp(std::shared_ptr<Stream> st);
  void serveSpeedUp(std::shared_ptr<Stream> st);
  void watch(std::shared_ptr<Client> c);

  std::optional<Keys> keys_;
  std::unique_ptr<Signaler> sig_;
  ServerCert cert_;
  HQUIC cfg_ = nullptr;
  std::string id_;
  int64_t started_ = 0;
  std::atomic<bool> stopping_{false}, ready_{false}, conflict_{false};

  std::mutex mu_;
  std::string status_ = "starting", error_;
  std::map<std::string, int64_t> seen_;
  std::vector<std::shared_ptr<Client>> clients_;
  std::vector<std::string> cands_;
  std::vector<sockaddr_in> stun_;
  bool symmetric_ = false;
};

} // namespace p2px
