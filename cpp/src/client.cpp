#include "client.h"

#include "stun.h"

namespace p2px {

Client::~Client() { stop(); }

bool Client::start(const std::string& key, uint16_t socksPort, std::string& err) {
  keys_ = Keys::derive(key);
  if (!keys_) {
    err = "this does not look like a p2proxy key";
    return false;
  }
  std::weak_ptr<Client> weak = shared_from_this();
  if (!socks_.start(socksPort, [weak](uint8_t kind, const std::string& target, std::string& e) -> std::shared_ptr<Stream> {
        auto c = weak.lock();
        if (!c) {
          e = "client stopped";
          return nullptr;
        }
        return c->open(kind, target, 15000, e);
      }, err))
    return false;
  sig_ = std::make_unique<Signaler>(*keys_);
  // Always subscribed: answers arrive here, and so does the exit node's
  // "hello" when it (re)starts. A successful (re)subscription also means our
  // network works again, which is worth an immediate retry.
  sig_->start(
      unixNow() - 5,
      [weak](const json& m) {
        if (auto c = weak.lock()) c->onSignal(m);
      },
      [weak] {
        if (auto c = weak.lock()) c->wakeUp();
      });
  maint_ = std::thread([self = shared_from_this()] { self->maintain(); });
  logf("client started; SOCKS5 proxy on 127.0.0.1:%u", socksPort);
  return true;
}

void Client::stop() {
  if (stopping_.exchange(true)) return;
  cv_.notify_all();
  socks_.stop();
  if (sig_) sig_->stop();
  std::shared_ptr<Connection> c;
  {
    std::lock_guard lk(mu_);
    c = conn_;
  }
  if (c) c->shutdown();
  if (maint_.joinable()) {
    if (maint_.get_id() == std::this_thread::get_id())
      maint_.detach();
    else
      maint_.join();
  }
  if (speedTh_.joinable()) speedTh_.detach();
}

void Client::wakeUp() {
  {
    std::lock_guard lk(mu_);
    wake_ = true;
  }
  cv_.notify_all();
}

void Client::onSignal(const json& m) {
  std::string t = m.value("t", "");
  if (t == "answer") {
    std::lock_guard lk(mu_);
    auto it = answers_.find(m.value("s", ""));
    if (it != answers_.end() && it->second.is_null()) {
      it->second = m;
      cv_.notify_all();
    }
  } else if (t == "hello") {
    logf("exit node announced that it started");
    std::shared_ptr<Connection> stale;
    {
      std::lock_guard lk(mu_);
      hellos_++; // also ends a wait for an answer it can no longer send
      // It restarted after our connection was made, so that connection is
      // dead; don't wait for the idle timeout to notice.
      if (conn_ && upSince_ < m.value("ts", (int64_t)0)) stale = conn_;
    }
    if (stale) stale->shutdown();
    wakeUp();
  }
}

void Client::maintain() {
  // Each attempt costs two messages of the signaling server's free quota, so
  // retries slow down a lot; "hello" or the network returning cuts the wait.
  int backoffMs = 1000;
  while (!stopping_) {
    std::string err;
    auto c = connectOnce(err);
    if (!c) {
      if (stopping_) break;
      {
        std::lock_guard lk(mu_);
        lastErr_ = err;
      }
      logf("could not connect to exit node: %s; retrying in %d s", err.c_str(), backoffMs / 1000);
      std::unique_lock lk(mu_);
      cv_.wait_for(lk, std::chrono::milliseconds(backoffMs), [&] { return wake_ || stopping_.load(); });
      wake_ = false;
      backoffMs = std::min(backoffMs * 2, 300000);
      continue;
    }
    backoffMs = 1000;
    {
      std::lock_guard lk(mu_);
      conn_ = c;
      upSince_ = unixNow();
      lastErr_.clear();
      wake_ = false;
    }
    cv_.notify_all();
    logf("tunnel up: connected to exit node at %s", c->remote().c_str());
    while (!stopping_ && !c->waitClosed(1000)) {
    }
    {
      std::lock_guard lk(mu_);
      conn_.reset();
      lastErr_ = c->reason();
    }
    logf("tunnel down: %s", c->reason().c_str());
  }
}

std::shared_ptr<Connection> Client::connectOnce(std::string& err) {
  Prober p;
  if (!p.open(physicalInterface(), err)) return nullptr;
  if (stun_.empty()) stun_ = stunServers();
  bool sym = false;
  auto mine = p.gather(stun_, sym);
  if (mine.empty()) {
    err = "no usable network address (no internet?)";
    return nullptr;
  }
  if (sym) logf("warning: this network has a symmetric NAT; hole punching may fail");

  Bytes sidBytes = randomBytes(16);
  std::string sid = hex(sidBytes), token = hex(randomBytes(32)), name = computerName();
  {
    std::lock_guard lk(mu_);
    answers_[sid] = nullptr;
  }
  json answer;
  uint64_t hellos;
  {
    std::lock_guard lk(mu_);
    hellos = hellos_;
  }
  if (!sig_->publish({{"t", "offer"}, {"s", sid}, {"c", mine}, {"tok", token}, {"name", name}}, err)) {
    std::lock_guard lk(mu_);
    answers_.erase(sid);
    return nullptr;
  }
  {
    // An exit node that was still starting ignores offers; its "hello"
    // means it is ready now, so stop waiting and offer again.
    std::unique_lock lk(mu_);
    cv_.wait_for(lk, std::chrono::seconds(10),
                 [&] { return !answers_[sid].is_null() || hellos_ != hellos || stopping_; });
    answer = answers_[sid];
    answers_.erase(sid);
    if (answer.is_null() && hellos_ != hellos) {
      err = "exit node just started; trying again";
      return nullptr;
    }
  }
  if (answer.is_null()) {
    err = "exit node did not answer (is it running, with the same key?)";
    return nullptr;
  }
  auto peer = p.punch(answer.value("c", std::vector<std::string>{}), sidBytes, 12000, stopping_);
  if (!peer) {
    err = "could not open a direct path to the exit node (hole punching failed)";
    return nullptr;
  }
  sockaddr_in local = p.local();
  p.close(); // msquic takes the same port, which the probes opened in the NAT
  Sleep(200); // give the exit node a moment to start listening
  auto c = Connection::connect(local, *peer, answer.value("fp", ""), 10000, err);
  if (!c) return nullptr;
  auto st = c->openStream(err);
  if (!st || !writeHeader(*st, kHello, token + "\n" + name) || !readStatus(*st, err, 10000)) {
    if (err.empty()) err = "exit node did not accept us";
    c->shutdown();
    return nullptr;
  }
  st->finish();
  return c;
}

std::shared_ptr<Stream> Client::open(uint8_t kind, const std::string& target, int waitMs, std::string& err) {
  std::shared_ptr<Connection> c;
  {
    std::unique_lock lk(mu_);
    cv_.wait_for(lk, std::chrono::milliseconds(waitMs), [&] { return conn_ || stopping_.load(); });
    c = conn_;
  }
  if (!c) {
    err = "tunnel to exit node is down";
    return nullptr;
  }
  auto st = c->openStream(err);
  if (!st) return nullptr;
  if (!writeHeader(*st, kind, target)) {
    err = "tunnel write failed";
    st->abort();
    return nullptr;
  }
  if (!readStatus(*st, err, waitMs)) {
    st->abort();
    return nullptr;
  }
  return st;
}

json Client::state() {
  std::lock_guard lk(mu_);
  json j = {{"connected", conn_ != nullptr}, {"error", lastErr_}, {"socks_port", socks_.port()}};
  if (conn_) {
    auto s = conn_->stats();
    j["remote"] = conn_->remote();
    j["since"] = upSince_;
    j["rtt_ms"] = s.Rtt / 1000.0;
    j["sent"] = s.SendTotalBytes;
    j["received"] = s.RecvTotalBytes;
  }
  return j;
}

// ---- speed test ----

bool Client::startSpeedTest() {
  std::lock_guard lk(speedMu_);
  if (speed_.value("running", false)) return false;
  speed_ = {{"running", true}, {"phase", ""}, {"live_mbps", 0}};
  if (speedTh_.joinable()) speedTh_.join();
  speedTh_ = std::thread([self = shared_from_this()] { self->runSpeedTest(); });
  return true;
}

json Client::speedState() {
  std::lock_guard lk(speedMu_);
  return speed_;
}

// Runs work on four streams for eight seconds and returns Mbit/s over all but
// the first second, while the connection ramps up.
double Client::measure(const char* phase,
                       const std::function<void(uint64_t deadline, std::atomic<uint64_t>& bytes)>& work,
                       std::string& err) {
  {
    std::lock_guard lk(speedMu_);
    speed_["phase"] = phase;
    speed_["live_mbps"] = 0;
  }
  std::atomic<uint64_t> bytes{0};
  uint64_t start = msNow(), deadline = start + 8000;
  std::vector<std::thread> ws;
  for (int i = 0; i < 4; i++) ws.emplace_back([&] { work(deadline, bytes); });
  uint64_t last = 0, warmBytes = 0, warmAt = 0;
  while (msNow() < deadline + 200) {
    Sleep(500);
    uint64_t now = bytes.load();
    double live = (now - last) * 8 / 0.5 / 1e6;
    last = now;
    {
      std::lock_guard lk(speedMu_);
      speed_["live_mbps"] = live;
    }
    if (!warmAt && msNow() - start >= 1000) {
      warmBytes = now;
      warmAt = msNow();
    }
  }
  for (auto& w : ws) w.join();
  if (bytes.load() == 0) {
    err = "no data was transferred";
    return 0;
  }
  double secs = (msNow() - (warmAt ? warmAt : start)) / 1000.0;
  return (bytes.load() - warmBytes) * 8 / secs / 1e6;
}

void Client::runSpeedTest() {
  std::string err;
  std::shared_ptr<Connection> c;
  {
    std::lock_guard lk(mu_);
    c = conn_;
  }
  auto finish = [&](const std::string& e) {
    std::lock_guard lk(speedMu_);
    speed_["running"] = false;
    speed_["phase"] = "";
    speed_["live_mbps"] = 0;
    speed_["finished"] = unixNow();
    if (!e.empty()) speed_["error"] = e;
  };
  if (!c) return finish("tunnel to exit node is down");
  auto s0 = c->stats();

  double down = measure("tunnel_down", [&](uint64_t deadline, std::atomic<uint64_t>& bytes) {
    std::string e;
    auto st = open(kSpeedDown, "", 10000, e);
    if (!st) return;
    std::vector<uint8_t> buf(256 << 10);
    for (;;) {
      int left = (int)(deadline - msNow());
      if (left <= 0) break;
      int n = st->read(buf.data(), buf.size(), left);
      if (n <= 0) break;
      bytes += n;
    }
    st->abort();
  }, err);
  {
    std::lock_guard lk(speedMu_);
    speed_["tunnel_down_mbps"] = down;
  }
  if (!err.empty()) return finish("tunnel download: " + err);

  // Upload: the live figure counts what we wrote; the result is what the exit
  // node says arrived.
  std::mutex rm;
  uint64_t gotBytes = 0, maxNs = 0;
  measure("tunnel_up", [&](uint64_t deadline, std::atomic<uint64_t>& bytes) {
    std::string e;
    auto st = open(kSpeedUp, "", 10000, e);
    if (!st) return;
    const Bytes& f = filler();
    while (msNow() < deadline && st->write(f.data(), f.size())) bytes += f.size();
    st->finish();
    uint8_t rep[16];
    if (!st->readFull(rep, 16, 20000)) return;
    uint64_t b = 0, ns = 0;
    for (int i = 0; i < 8; i++) {
      b = b << 8 | rep[i];
      ns = ns << 8 | rep[8 + i];
    }
    std::lock_guard lk(rm);
    gotBytes += b;
    maxNs = std::max(maxNs, ns);
  }, err);
  double up = maxNs ? gotBytes * 8 / (maxNs / 1e9) / 1e6 : 0;
  auto s1 = c->stats();
  {
    std::lock_guard lk(speedMu_);
    speed_["tunnel_up_mbps"] = up;
    speed_["rtt_ms"] = s1.MinRtt / 1000.0;
    uint64_t sent = s1.SendTotalPackets - s0.SendTotalPackets;
    speed_["loss_pct"] = sent ? (s1.SendSuspectedLostPackets - s0.SendSuspectedLostPackets) * 100.0 / sent : 0.0;
  }
  finish(err.empty() ? "" : "tunnel upload: " + err);
}

} // namespace p2px
