#pragma once
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include "client.h"
#include "server.h"
#include "update.h"

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
  bool setCongestionControl(const std::string& cc, std::string& err); // "bbr" or "cubic"
  bool setAutostart(bool on);
  bool autostart();
  std::shared_ptr<Client> client();
  // Clash (mihomo) profile that sends everything through our SOCKS port.
  bool subscription(const std::string& token, std::string& yaml);

  // Updates. A client checks and downloads through its exit node.
  bool checkUpdates(std::string& err);
  bool updateSelf(std::string& err); // installs, then restarts the app
  bool updateNode(std::string& err); // client: asks the exit node to update
  void startUpdateChecks();          // checks in the background every few hours
  void setRestartHook(std::function<void()> hook) { restartHook_ = std::move(hook); }

  uint16_t uiPort = 1090, socksPort = 1080; // set from the command line before load()

private:
  void save();
  void stopRole();
  std::string subscriptionUrl();
  Fetcher fetcher();
  json updateState();

  std::mutex mu_;
  std::string role_, serverKey_, clientKey_, subToken_, roleError_, cc_ = "bbr";
  std::shared_ptr<Server> server_;
  std::shared_ptr<Client> client_;

  std::mutex updMu_;
  Release latest_;
  std::string checkErr_;
  std::atomic<bool> updating_{false}, stopChecks_{false};
  std::function<void()> restartHook_;
};

} // namespace p2px
