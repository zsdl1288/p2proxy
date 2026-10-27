#pragma once
#include <atomic>
#include <functional>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>

#include "crypto.h"
#include "https.h"

namespace p2px {

using json = nlohmann::json;

// Before a tunnel exists the peers swap addresses through an ntfy topic
// derived from the shared key. Every message is encrypted with that key, so
// the relay only sees opaque blobs. Like the tunnel itself, this traffic goes
// out over the physical adapter (see HttpsRequest), never through a TUN.
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
  std::atomic<bool> stop_{false}; // also aborts the open subscription
};

constexpr int64_t kSignalMaxAge = 120;

} // namespace p2px
