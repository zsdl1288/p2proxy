#pragma once
#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>

#include <atomic>
#include <functional>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <vector>

#include "crypto.h"

namespace p2px {

using json = nlohmann::json;

// A small WinHTTP client for p2proxy's own control traffic (signaling, DNS).
// It never uses the system proxy, which may point back into the tunnel.
struct HttpResult {
  DWORD status = 0;
  std::string body;
  std::string err;
};
HttpResult httpRequest(const std::string& method, const std::string& url, const std::string& body,
                       const std::vector<std::string>& headers, int timeoutMs);

// Resolves a name with DNS-over-HTTPS (1.1.1.1), so a TUN-mode proxy's fake
// IPs never reach us; falls back to the system resolver.
std::vector<in_addr> resolveIPv4(const std::string& host);

// Before a tunnel exists the peers swap addresses through an ntfy topic
// derived from the shared key. Every message is encrypted with that key, so
// the relay only sees opaque blobs.
class Signaler {
public:
  explicit Signaler(Keys k, std::string base = "https://ntfy.sh");
  ~Signaler();
  bool publish(json msg, std::string& err);
  // Delivers decrypted messages newer than since; onConnect runs on every
  // (re)subscription, which also means the network works again.
  void start(int64_t since, std::function<void(const json&)> onMsg, std::function<void()> onConnect);
  void stop();

private:
  void loop(std::function<void(const json&)> onMsg, std::function<void()> onConnect);
  bool listenOnce(const std::function<void(const json&)>& onMsg, const std::function<void()>& onConnect,
                  std::string& err);

  Keys k_;
  std::string base_;
  std::string cursor_;
  std::thread th_;
  std::atomic<bool> stop_{false};
  std::mutex mu_;
  HINTERNET req_ = nullptr; // the open subscription, closed by stop()
};

constexpr int64_t kSignalMaxAge = 120;

} // namespace p2px
