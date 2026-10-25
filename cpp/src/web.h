#pragma once
#include <memory>
#include <string>
#include <thread>

namespace httplib {
class Server;
}

namespace p2px {

// Local HTTP server on 127.0.0.1: the app's UI (shown in the window), its
// JSON API, and the Clash subscription.
class WebServer {
public:
  WebServer();
  ~WebServer();
  bool start(uint16_t port, std::string& err);
  void stop();

private:
  std::unique_ptr<httplib::Server> srv_;
  std::thread th_;
};

} // namespace p2px
