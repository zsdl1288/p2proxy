#include "server.h"

#include <thread>

#include "stun.h"
#include "update.h"

namespace p2px {

Server::~Server() {
  stop();
  for (HQUIC cfg : cfgs_)
    if (cfg) MsQuic->ConfigurationClose(cfg);
  freeServerCert(cert_);
}

bool Server::start(const std::string& key, std::string& err) {
  keys_ = Keys::derive(key);
  if (!keys_) {
    err = "invalid key";
    return false;
  }
  if (!createServerCert(cert_, err)) return false;
  for (Cc cc : {Cc::Bbr, Cc::Cubic})
    if (!(cfgs_[(int)cc] = Quic::serverConfig(cert_.ctx, cc, err))) return false;
  id_ = hex(randomBytes(8));
  started_ = unixNow();
  sig_ = std::make_unique<Signaler>(*keys_);
  std::weak_ptr<Server> weak = shared_from_this();
  sig_->start(unixNow() - 5, [weak](const json& m) {
    if (auto s = weak.lock()) s->onSignal(m);
  }, nullptr);
  std::thread([self = shared_from_this()] { self->announce(); }).detach();
  logf("exit node starting");
  return true;
}

void Server::stop() {
  stopping_ = true;
  if (sig_) sig_->stop();
  std::vector<std::shared_ptr<Client>> cs;
  {
    std::lock_guard lk(mu_);
    cs = clients_;
  }
  for (auto& c : cs) c->conn->shutdown();
}

// Asks whether another exit node is already running with this key, then
// tells waiting clients that we are up so they connect at once.
void Server::announce() {
  std::string err;
  if (!sig_->publish({{"t", "probe"}, {"id", id_}}, err)) logf("signaling: %s", err.c_str());
  for (int i = 0; i < 40 && !stopping_ && !conflict_; i++) Sleep(100);
  if (stopping_) return;
  if (conflict_) {
    std::lock_guard lk(mu_);
    status_ = "conflict";
    error_ = "another computer is already the exit node for this key";
    logf("refusing to start: %s", error_.c_str());
    return;
  }
  stun_ = stunServers();
  {
    Prober p;
    if (p.open(physicalInterface(), err)) {
      bool sym = false;
      auto c = p.gather(stun_, sym);
      std::lock_guard lk(mu_);
      cands_ = c;
      symmetric_ = sym;
    }
  }
  {
    std::lock_guard lk(mu_);
    status_ = "running";
  }
  ready_ = true;
  logf("exit node running");
  if (!sig_->publish({{"t", "hello"}, {"id", id_}}, err)) logf("signaling: %s", err.c_str());
}

void Server::onSignal(const json& m) {
  std::string t = m.value("t", ""), from = m.value("id", "");
  if (t == "probe" && from != id_) {
    if (conflict_) return;
    // Another exit node is starting with our key: tell it we are here.
    std::thread([self = shared_from_this(), from] {
      std::string err;
      self->sig_->publish({{"t", "present"}, {"id", self->id_}, {"to", from}}, err);
    }).detach();
    logf("another computer tried to start as exit node with this key; it was refused");
  } else if (t == "present" && m.value("to", "") == id_ && from != id_) {
    conflict_ = true;
  } else if (t == "offer" && ready_ && !conflict_) {
    std::string sid = m.value("s", "");
    {
      std::lock_guard lk(mu_);
      int64_t now = unixNow();
      for (auto it = seen_.begin(); it != seen_.end();) it = now - it->second > 2 * kSignalMaxAge ? seen_.erase(it) : ++it;
      if (!seen_.emplace(sid, now).second) return;
    }
    std::thread([self = shared_from_this(), m] { self->handleOffer(m); }).detach();
  }
}

void Server::handleOffer(json m) {
  std::string sid = m.value("s", ""), name = m.value("name", "client");
  Bytes sidBytes;
  if (!unhex(sid, sidBytes) || sidBytes.size() != 16) return;
  auto peerCands = m.value("c", std::vector<std::string>{});
  logf("%s is connecting from %zu address(es)", name.c_str(), peerCands.size());

  std::string err;
  Prober p;
  if (!p.open(physicalInterface(), err)) {
    logf("%s: %s", name.c_str(), err.c_str());
    return;
  }
  if (stun_.empty()) stun_ = stunServers();
  bool sym = false;
  auto mine = p.gather(stun_, sym);
  if (!sig_->publish({{"t", "answer"}, {"s", sid}, {"c", mine}, {"fp", cert_.fingerprint}}, err)) {
    logf("%s: could not answer: %s", name.c_str(), err.c_str());
    return;
  }
  auto peer = p.punch(peerCands, sidBytes, 12000, stopping_);
  if (!peer) {
    logf("%s: no direct path (hole punching failed)", name.c_str());
    return;
  }
  sockaddr_in local = p.local();
  p.close(); // msquic takes the same port, which the probes opened in the NAT

  auto sess = std::make_shared<Session>();
  sess->token = m.value("tok", "");
  sess->cc = parseCc(m.value("cc", "bbr")); // older clients send none: BBR
  sess->name = name;
  std::weak_ptr<Server> weak = shared_from_this();
  auto listener = Listener::start(
      local,
      [weak, sess](HQUIC h, const sockaddr_in& remote) {
        auto s = weak.lock();
        return s && s->accept(h, remote, sess);
      },
      err);
  if (!listener) {
    logf("%s: %s", name.c_str(), err.c_str());
    return;
  }
  std::unique_lock lk(sess->mu);
  if (!sess->cv.wait_for(lk, std::chrono::seconds(15), [&] { return sess->authed || stopping_; }))
    logf("%s: did not finish connecting", name.c_str());
  lk.unlock();
  listener.reset(); // stop listening; the connection keeps the port
}

bool Server::accept(HQUIC h, const sockaddr_in& remote, std::shared_ptr<Session> sess) {
  {
    std::lock_guard lk(sess->mu);
    if (sess->taken) return false; // one connection per offer
    sess->taken = true;
  }
  auto client = std::make_shared<Client>();
  client->name = sess->name;
  client->addr = addrStr(remote);
  std::weak_ptr<Server> weak = shared_from_this();
  std::weak_ptr<Client> wc = client;
  client->cc = sess->cc;
  client->conn = Connection::adopt(h, cfgs_[(int)sess->cc], remote, [weak, sess, wc](std::shared_ptr<Stream> st) {
    auto s = weak.lock();
    if (!s) {
      st->abort();
      return;
    }
    std::thread([s, sess, wc, st] { s->serveStream(sess, wc, st); }).detach();
  });
  if (!client->conn) return false;
  // Kept alive by the session until authenticated; afterwards by watch().
  std::thread([self = shared_from_this(), client, sess] {
    {
      std::unique_lock lk(sess->mu);
      sess->cv.wait_for(lk, std::chrono::seconds(20), [&] { return sess->authed; });
      if (!sess->authed) {
        lk.unlock();
        client->conn->shutdown();
        return;
      }
    }
    self->watch(client);
  }).detach();
  return true;
}

void Server::watch(std::shared_ptr<Client> c) {
  c->since = unixNow();
  {
    std::lock_guard lk(mu_);
    clients_.push_back(c);
  }
  logf("%s connected from %s (%s)", c->name.c_str(), c->addr.c_str(), ccName(c->cc));
  // Sample what we send to this client, for its loss rate.
  while (!c->conn->waitClosed(2000)) {
    auto s = c->conn->stats();
    c->meter.addCounters(s.SendTotalPackets, lostPackets(s.SendSuspectedLostPackets, s.SendSpuriousLostPackets));
  }
  logf("%s disconnected: %s", c->name.c_str(), c->conn->reason().c_str());
  std::lock_guard lk(mu_);
  std::erase(clients_, c);
}

void Server::serveStream(std::shared_ptr<Session> sess, std::weak_ptr<Client> wc, std::shared_ptr<Stream> st) {
  uint8_t kind = 0;
  std::string target;
  if (!readHeader(*st, kind, target, 10000)) {
    st->abort();
    return;
  }
  if (kind == kHello) {
    std::string token = target.substr(0, target.find('\n'));
    if (token.empty() || token != sess->token) {
      writeStatus(*st, "bad session token");
      st->finish();
      if (auto c = wc.lock()) c->conn->shutdown();
      return;
    }
    writeStatus(*st, "");
    st->finish();
    {
      std::lock_guard lk(sess->mu);
      sess->authed = true;
    }
    sess->cv.notify_all();
    return;
  }
  {
    std::lock_guard lk(sess->mu);
    if (!sess->authed) {
      writeStatus(*st, "not authenticated");
      st->abort();
      return;
    }
  }
  switch (kind) {
  case kTcp: {
    std::string host, err;
    uint16_t port = 0;
    if (!splitHostPort(target, host, port)) {
      writeStatus(*st, "bad target");
      st->finish();
      return;
    }
    SOCKET s = tcpConnect(host, port, 10000, err);
    if (s == INVALID_SOCKET) {
      writeStatus(*st, err);
      st->finish();
      return;
    }
    if (!writeStatus(*st, "")) {
      closesocket(s);
      st->abort();
      return;
    }
    relay(s, st);
    return;
  }
  case kUdp:
    serveUdp(st);
    return;
  case kInfo: {
    size_t n;
    {
      std::lock_guard lk(mu_);
      n = clients_.size();
    }
    json info = {{"version", P2PX_VERSION}, {"started", started_}, {"clients", n}};
    std::string s = info.dump();
    writeStatus(*st, "");
    st->write(s.data(), s.size());
    st->finish();
    return;
  }
  case kSpeedDown: {
    // A test opens several streams at once; log the start once.
    auto c = wc.lock();
    if (c && c->speedStreams++ == 0 && unixNow() - c->speedLogged > 20) {
      c->speedLogged = unixNow();
      logf("%s started a speed test", c->name.c_str());
    }
    writeStatus(*st, "");
    uint64_t end = msNow() + kSpeedTestLimitMs;
    const Bytes& f = filler();
    while (msNow() < end && st->write(f.data(), f.size())) {
    }
    st->finish();
    if (c) c->speedStreams--;
    return;
  }
  case kFetch: {
    // Clients update through us, so their downloads never go out directly.
    // They verify signatures themselves; we only carry the bytes.
    std::string body, err;
    if (!allowedFetchUrl(target)) {
      writeStatus(*st, "only GitHub downloads are allowed");
    } else if (!directFetcher()(target, body, err)) {
      writeStatus(*st, err);
    } else if (writeStatus(*st, "")) {
      st->write(body.data(), body.size());
    }
    st->finish();
    return;
  }
  case kUpdate: {
    std::string name = "a client";
    if (auto c = wc.lock()) name = c->name;
    logf("%s asked this exit node to update", name.c_str());
    std::string err = onUpdateRequest ? onUpdateRequest() : "updates are not available here";
    writeStatus(*st, err);
    st->finish();
    return;
  }
  case kStats: {
    // The client tells us its side of the link and gets ours back.
    auto c = wc.lock();
    json reply = {{"loss", nullptr}};
    if (c) {
      try {
        json r = json::parse(target);
        auto num = [&](const char* k) {
          auto it = r.find(k);
          return it != r.end() && it->is_number() ? it->get<double>() : -1.0;
        };
        c->peerLoss = num("loss");
        c->peerRtt = num("rtt");
        c->peerJitter = num("jitter");
      } catch (...) {
      }
      if (double l = c->meter.lossPct(); l >= 0) reply["loss"] = l;
    }
    writeStatus(*st, "");
    std::string s = reply.dump();
    st->write(s.data(), s.size());
    st->finish();
    return;
  }
  case kSpeedReport: {
    std::string name = "client";
    if (auto c = wc.lock()) name = c->name;
    try {
      json r = json::parse(target);
      logf("%s speed test: download %.1f Mbps, upload %.1f Mbps, latency %.0f ms, loss %.2f%%", name.c_str(),
           r.value("down", 0.0), r.value("up", 0.0), r.value("rtt", 0.0), r.value("loss", 0.0));
    } catch (...) {
    }
    writeStatus(*st, "");
    st->finish();
    return;
  }
  case kSpeedUp:
    serveSpeedUp(st);
    return;
  default:
    writeStatus(*st, "unknown request; is the exit node older than the client?");
    st->finish();
  }
}

void Server::serveSpeedUp(std::shared_ptr<Stream> st) {
  writeStatus(*st, "");
  std::vector<uint8_t> buf(256 << 10);
  uint64_t total = 0, first = 0, last = 0, end = msNow() + kSpeedTestLimitMs;
  LARGE_INTEGER freq, t;
  QueryPerformanceFrequency(&freq);
  for (;;) {
    int left = (int)(end - msNow());
    if (left <= 0) break;
    int n = st->read(buf.data(), buf.size(), left);
    if (n <= 0) break;
    QueryPerformanceCounter(&t);
    if (!first) first = t.QuadPart;
    last = t.QuadPart;
    total += n;
  }
  uint64_t ns = first ? (uint64_t)((last - first) * 1e9 / freq.QuadPart) : 0;
  uint8_t rep[16];
  for (int i = 0; i < 8; i++) {
    rep[i] = uint8_t(total >> (56 - 8 * i));
    rep[8 + i] = uint8_t(ns >> (56 - 8 * i));
  }
  st->write(rep, sizeof rep);
  st->finish();
}

void Server::serveUdp(std::shared_ptr<Stream> st) {
  SOCKET u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  sockaddr_in any{};
  any.sin_family = AF_INET;
  if (u == INVALID_SOCKET || bind(u, (sockaddr*)&any, sizeof any) != 0) {
    writeStatus(*st, "cannot open UDP socket");
    st->finish();
    if (u != INVALID_SOCKET) closesocket(u);
    return;
  }
  BOOL off = FALSE;
  DWORD ret = 0;
  WSAIoctl(u, SIO_UDP_CONNRESET, &off, sizeof off, nullptr, 0, &ret, nullptr, nullptr);
  writeStatus(*st, "");
  std::thread back([u, st] {
    std::vector<uint8_t> buf(65536);
    for (;;) {
      sockaddr_in from{};
      int fl = sizeof from;
      int n = recvfrom(u, (char*)buf.data(), (int)buf.size(), 0, (sockaddr*)&from, &fl);
      if (n < 0 || !writeDatagram(*st, addrStr(from), buf.data(), n)) break;
    }
    st->abort();
  });
  std::map<std::string, sockaddr_in> resolved;
  std::string addr;
  Bytes data;
  while (readDatagram(*st, addr, data)) {
    auto it = resolved.find(addr);
    if (it == resolved.end()) {
      std::string host;
      uint16_t port = 0;
      if (!splitHostPort(addr, host, port)) continue;
      addrinfo hints{}, *res = nullptr;
      hints.ai_family = AF_INET;
      hints.ai_socktype = SOCK_DGRAM;
      if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) continue;
      sockaddr_in a = *(sockaddr_in*)res->ai_addr;
      freeaddrinfo(res);
      if (resolved.size() > 1024) resolved.clear();
      it = resolved.emplace(addr, a).first;
    }
    sendto(u, (const char*)data.data(), (int)data.size(), 0, (const sockaddr*)&it->second, sizeof(sockaddr_in));
  }
  closesocket(u);
  back.join();
}

json Server::state() {
  std::lock_guard lk(mu_);
  json cs = json::array();
  auto orNull = [](double v) { return v >= 0 ? json(v) : json(nullptr); };
  for (auto& c : clients_) {
    auto s = c->conn->stats();
    cs.push_back({{"name", c->name},
                  {"addr", c->addr},
                  {"since", c->since},
                  {"rtt_ms", c->peerRtt >= 0 ? c->peerRtt.load() : s.Rtt / 1000.0},
                  {"jitter_ms", orNull(c->peerJitter)},
                  {"loss_to_client_pct", orNull(c->meter.lossPct())},
                  {"loss_from_client_pct", orNull(c->peerLoss)},
                  {"cc", ccName(c->cc)},
                  {"sent", s.SendTotalBytes},
                  {"received", s.RecvTotalBytes}});
  }
  return {{"status", status_}, {"error", error_},     {"started", started_},
          {"candidates", cands_}, {"symmetric_nat", symmetric_}, {"clients", cs}};
}

} // namespace p2px
