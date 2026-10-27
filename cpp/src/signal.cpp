#include "signal.h"

#include "util.h"

namespace p2px {

Signaler::Signaler(Keys k, std::string base) : k_(std::move(k)), base_(std::move(base)) {}

Signaler::~Signaler() { stop(); }

bool Signaler::publish(json msg, std::string& err) {
  msg["ts"] = unixNow();
  std::string plain = msg.dump();
  std::string body = base64(aesGcmSeal(k_.aead, Bytes(plain.begin(), plain.end())));
  auto r = httpsRequest("POST", base_ + "/" + k_.topic, body, {}, 15000);
  if (r.status == 200) return true;
  if (r.status == 429)
    err = "signaling rate limit reached (ntfy.sh allows a limited number of messages per day)";
  else
    err = r.err.empty() ? "signaling server returned " + std::to_string(r.status) : r.err;
  return false;
}

void Signaler::start(int64_t since, std::function<void(const json&)> onMsg, std::function<void()> onConnect) {
  cursor_ = std::to_string(since);
  stop_ = false;
  th_ = std::thread([this, onMsg, onConnect] { loop(onMsg, onConnect); });
}

void Signaler::stop() {
  stop_ = true; // a blocked read notices within a fraction of a second
  if (th_.joinable()) th_.join();
}

void Signaler::loop(std::function<void(const json&)> onMsg, std::function<void()> onConnect) {
  while (!stop_) {
    std::string err;
    listenOnce(onMsg, onConnect, err);
    if (stop_) break;
    logf("signaling: %s; reconnecting", err.c_str());
    for (int i = 0; i < 30 && !stop_; i++) Sleep(100);
  }
}

bool Signaler::listenOnce(const std::function<void(const json&)>& onMsg, const std::function<void()>& onConnect,
                          std::string& err) {
  HttpsRequest req;
  // ntfy sends a keepalive every 45s; a 90s read timeout catches dead connections.
  if (!req.open("GET", base_ + "/" + k_.topic + "/json?since=" + cursor_, "", {}, 90000, &stop_, err)) return false;
  if (req.status() != 200) {
    err = "signaling server returned " + std::to_string(req.status());
    return false;
  }
  if (onConnect) onConnect();

  std::string pending;
  while (!stop_ && req.read(pending)) {
    size_t nl;
    while ((nl = pending.find('\n')) != std::string::npos) {
      std::string line = pending.substr(0, nl);
      pending.erase(0, nl + 1);
      try {
        json ev = json::parse(line);
        if (ev.value("event", "") != "message") continue;
        cursor_ = ev.value("id", cursor_);
        Bytes sealed, plain;
        if (!unbase64(ev.value("message", ""), sealed) || !aesGcmOpen(k_.aead, sealed, plain)) continue;
        json m = json::parse(std::string(plain.begin(), plain.end()));
        int64_t age = unixNow() - m.value("ts", (int64_t)0);
        if (age > kSignalMaxAge || age < -kSignalMaxAge) continue;
        onMsg(m);
      } catch (...) {
      }
    }
  }
  if (stop_) err = "stopped";
  else err = "subscription ended (" + (req.err().empty() ? std::string("closed by the server") : req.err()) + ")";
  return false;
}

} // namespace p2px
