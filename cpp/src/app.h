#pragma once
#include <memory>
#include <mutex>
#include <string>

#include "client.h"
#include "server.h"

namespace p2px {

// The whole application: which role this computer plays, its keys
// (DPAPI-protected on disk), and the running server or client.
class App {
public:
  static App& get();
  void load();
  void startRole();
  void shutdown();

  json state();
  bool setRole(const std::string& role, std::string& err); // "server", "client" or "" to choose again
  bool setClientKey(const std::string& key, std::string& err);
  void regenerateServerKey();
  bool setAutostart(bool on);
  bool autostart();
  std::shared_ptr<Client> client();
  // Clash (mihomo) profile that sends everything through our SOCKS port.
  bool subscription(const std::string& token, std::string& yaml);

  uint16_t uiPort = 1090, socksPort = 1080; // set from the command line before load()

private:
  void save();
  void stopRole();
  std::string subscriptionUrl();

  std::mutex mu_;
  std::string role_, serverKey_, clientKey_, subToken_, roleError_;
  std::shared_ptr<Server> server_;
  std::shared_ptr<Client> client_;
};

} // namespace p2px
