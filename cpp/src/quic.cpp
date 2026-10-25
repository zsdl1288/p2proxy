#include "quic.h"

#include <chrono>
#include <cstring>

#include "cert.h"

namespace p2px {

const QUIC_API_TABLE* MsQuic = nullptr;
HQUIC Quic::reg = nullptr;
HQUIC Quic::clientCfg[2] = {nullptr, nullptr};

namespace {

const QUIC_BUFFER kAlpn = {sizeof("p2px2") - 1, (uint8_t*)"p2px2"};

constexpr size_t kRxHigh = 8 << 20, kRxLow = 2 << 20; // receive buffer high/low water marks
constexpr size_t kTxLimit = 4 << 20;                  // unacknowledged sends per stream
constexpr size_t kSendChunk = 256 << 10;

QUIC_SETTINGS baseSettings(Cc cc) {
  QUIC_SETTINGS s{};
  s.IdleTimeoutMs = 20000;
  s.IsSet.IdleTimeoutMs = TRUE;
  s.KeepAliveIntervalMs = 5000; // also keeps NAT mappings open
  s.IsSet.KeepAliveIntervalMs = TRUE;
  s.HandshakeIdleTimeoutMs = 8000;
  s.IsSet.HandshakeIdleTimeoutMs = TRUE;
  s.CongestionControlAlgorithm =
      cc == Cc::Cubic ? QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC : QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
  s.IsSet.CongestionControlAlgorithm = TRUE;
  s.StreamRecvWindowDefault = 16 << 20;
  s.IsSet.StreamRecvWindowDefault = TRUE;
  s.ConnFlowControlWindow = 64 << 20;
  s.IsSet.ConnFlowControlWindow = TRUE;
  s.SendBufferingEnabled = TRUE;
  s.IsSet.SendBufferingEnabled = TRUE;
  return s;
}

struct SendCtx {
  QUIC_BUFFER qb;
  uint8_t data[1];
};

QUIC_STATUS QUIC_API ignoreConnectionEvents(HQUIC, void*, QUIC_CONNECTION_EVENT*) { return QUIC_STATUS_SUCCESS; }

std::string statusText(QUIC_STATUS st) {
  char b[32];
  snprintf(b, sizeof b, "0x%08lx", (unsigned long)st);
  return b;
}

} // namespace

bool Quic::init(std::string& err) {
  if (QUIC_FAILED(MsQuicOpen2(&MsQuic))) {
    err = "MsQuicOpen2 failed";
    return false;
  }
  const QUIC_REGISTRATION_CONFIG rc = {"p2proxy", QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT};
  if (QUIC_FAILED(MsQuic->RegistrationOpen(&rc, &reg))) {
    err = "RegistrationOpen failed";
    return false;
  }
  for (Cc cc : {Cc::Bbr, Cc::Cubic}) {
    QUIC_SETTINGS s = baseSettings(cc);
    HQUIC& cfg = clientCfg[(int)cc];
    if (QUIC_FAILED(MsQuic->ConfigurationOpen(reg, &kAlpn, 1, &s, sizeof s, nullptr, &cfg))) {
      err = "ConfigurationOpen failed";
      return false;
    }
    QUIC_CREDENTIAL_CONFIG cred{};
    cred.Type = QUIC_CREDENTIAL_TYPE_NONE;
    // The certificate is checked against the fingerprint from signaling instead.
    cred.Flags = QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION |
                 QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
    if (QUIC_STATUS st = MsQuic->ConfigurationLoadCredential(cfg, &cred); QUIC_FAILED(st)) {
      err = "client credentials: " + statusText(st);
      return false;
    }
  }
  return true;
}

void Quic::cleanup() {
  if (!MsQuic) return;
  for (HQUIC cfg : clientCfg)
    if (cfg) MsQuic->ConfigurationClose(cfg);
  if (reg) MsQuic->RegistrationClose(reg);
  MsQuicClose(MsQuic);
  MsQuic = nullptr;
}

HQUIC Quic::serverConfig(PCCERT_CONTEXT cert, Cc cc, std::string& err) {
  QUIC_SETTINGS s = baseSettings(cc);
  s.PeerBidiStreamCount = 8192;
  s.IsSet.PeerBidiStreamCount = TRUE;
  HQUIC cfg = nullptr;
  if (QUIC_FAILED(MsQuic->ConfigurationOpen(reg, &kAlpn, 1, &s, sizeof s, nullptr, &cfg))) {
    err = "server ConfigurationOpen failed";
    return nullptr;
  }
  QUIC_CREDENTIAL_CONFIG cred{};
  cred.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT;
  cred.CertificateContext = (QUIC_CERTIFICATE*)cert;
  cred.Flags = QUIC_CREDENTIAL_FLAG_NONE;
  if (QUIC_STATUS st = MsQuic->ConfigurationLoadCredential(cfg, &cred); QUIC_FAILED(st)) {
    err = "server credentials: " + statusText(st);
    MsQuic->ConfigurationClose(cfg);
    return nullptr;
  }
  return cfg;
}

// ---- Stream ----

Stream::~Stream() {
  if (h_) MsQuic->StreamClose(h_);
}

std::shared_ptr<Stream> Stream::open(HQUIC conn, std::string& err) {
  std::shared_ptr<Stream> s(new Stream());
  if (QUIC_STATUS st = MsQuic->StreamOpen(conn, QUIC_STREAM_OPEN_FLAG_NONE, callback, s.get(), &s->h_);
      QUIC_FAILED(st)) {
    s->h_ = nullptr;
    err = "StreamOpen failed: " + statusText(st);
    return nullptr;
  }
  s->self_ = s;
  if (QUIC_STATUS st = MsQuic->StreamStart(s->h_, QUIC_STREAM_START_FLAG_IMMEDIATE); QUIC_FAILED(st)) {
    s->self_.reset();
    err = "StreamStart failed: " + statusText(st);
    return nullptr;
  }
  return s;
}

std::shared_ptr<Stream> Stream::adopt(HQUIC h) {
  std::shared_ptr<Stream> s(new Stream());
  s->h_ = h;
  s->self_ = s;
  MsQuic->SetCallbackHandler(h, (void*)callback, s.get());
  return s;
}

QUIC_STATUS QUIC_API Stream::callback(HQUIC, void* ctx, QUIC_STREAM_EVENT* e) {
  auto* s = (Stream*)ctx;
  switch (e->Type) {
  case QUIC_STREAM_EVENT_RECEIVE: {
    bool pause = false;
    {
      std::lock_guard lk(s->mu_);
      for (uint32_t i = 0; i < e->RECEIVE.BufferCount; i++) {
        const QUIC_BUFFER& b = e->RECEIVE.Buffers[i];
        if (b.Length) {
          s->rx_.emplace_back(b.Buffer, b.Buffer + b.Length);
          s->rxBytes_ += b.Length;
        }
      }
      if (e->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) s->rxFin_ = true;
      if (s->rxBytes_ > kRxHigh && !s->paused_) pause = s->paused_ = true;
    }
    s->cv_.notify_all();
    if (pause) MsQuic->StreamReceiveSetEnabled(s->h_, FALSE);
    return QUIC_STATUS_SUCCESS;
  }
  case QUIC_STREAM_EVENT_SEND_COMPLETE: {
    auto* sc = (SendCtx*)e->SEND_COMPLETE.ClientContext;
    {
      std::lock_guard lk(s->mu_);
      s->txPending_ -= sc->qb.Length;
    }
    free(sc);
    s->cv_.notify_all();
    break;
  }
  case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN: {
    std::lock_guard lk(s->mu_);
    s->rxFin_ = true;
    s->cv_.notify_all();
    break;
  }
  case QUIC_STREAM_EVENT_PEER_SEND_ABORTED: {
    std::lock_guard lk(s->mu_);
    s->rxAbort_ = true;
    s->cv_.notify_all();
    break;
  }
  case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED: {
    std::lock_guard lk(s->mu_);
    s->txAbort_ = true;
    s->cv_.notify_all();
    break;
  }
  case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
    std::shared_ptr<Stream> keep;
    {
      std::lock_guard lk(s->mu_);
      s->done_ = true;
      keep = std::move(s->self_); // may destroy us (and close the handle) when this returns
    }
    s->cv_.notify_all();
    break;
  }
  default:
    break;
  }
  return QUIC_STATUS_SUCCESS;
}

int Stream::read(uint8_t* buf, size_t cap, int timeoutMs) {
  std::unique_lock lk(mu_);
  auto ready = [&] { return !rx_.empty() || rxFin_ || rxAbort_ || done_; };
  if (timeoutMs < 0)
    cv_.wait(lk, ready);
  else if (!cv_.wait_for(lk, std::chrono::milliseconds(timeoutMs), ready))
    return -2;
  if (rx_.empty()) return (rxFin_ && !rxAbort_) ? 0 : -1;
  size_t n = 0;
  while (n < cap && !rx_.empty()) {
    Bytes& front = rx_.front();
    size_t k = std::min(cap - n, front.size() - rxOff_);
    memcpy(buf + n, front.data() + rxOff_, k);
    n += k;
    rxOff_ += k;
    if (rxOff_ == front.size()) {
      rx_.pop_front();
      rxOff_ = 0;
    }
  }
  rxBytes_ -= n;
  bool resume = paused_ && rxBytes_ < kRxLow;
  if (resume) paused_ = false;
  lk.unlock();
  if (resume) MsQuic->StreamReceiveSetEnabled(h_, TRUE);
  return (int)n;
}

bool Stream::readFull(void* buf, size_t n, int timeoutMs) {
  auto* p = (uint8_t*)buf;
  uint64_t deadline = msNow() + timeoutMs;
  while (n > 0) {
    int left = (int)(deadline - msNow());
    if (left <= 0) return false;
    int k = read(p, n, left);
    if (k <= 0) return false;
    p += k;
    n -= k;
  }
  return true;
}

bool Stream::write(const void* data, size_t n) {
  auto* p = (const uint8_t*)data;
  while (n > 0) {
    size_t chunk = std::min(n, kSendChunk);
    {
      std::unique_lock lk(mu_);
      cv_.wait(lk, [&] { return txPending_ < kTxLimit || txAbort_ || done_; });
      if (txAbort_ || done_) return false;
      txPending_ += chunk;
    }
    auto* sc = (SendCtx*)malloc(sizeof(SendCtx) + chunk);
    sc->qb.Length = (uint32_t)chunk;
    sc->qb.Buffer = sc->data;
    memcpy(sc->data, p, chunk);
    if (QUIC_FAILED(MsQuic->StreamSend(h_, &sc->qb, 1, QUIC_SEND_FLAG_NONE, sc))) {
      free(sc);
      std::lock_guard lk(mu_);
      txPending_ -= chunk;
      return false;
    }
    p += chunk;
    n -= chunk;
  }
  return true;
}

void Stream::finish() { MsQuic->StreamShutdown(h_, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0); }

void Stream::abort() { MsQuic->StreamShutdown(h_, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0); }

// ---- Connection ----

Connection::~Connection() {
  if (h_) MsQuic->ConnectionClose(h_);
}

std::shared_ptr<Connection> Connection::connect(const sockaddr_in& local, const sockaddr_in& remote,
                                                const std::string& fingerprint, Cc cc, int timeoutMs,
                                                std::string& err) {
  std::shared_ptr<Connection> c(new Connection());
  c->fingerprint_ = fingerprint;
  c->remote_ = remote;
  if (QUIC_FAILED(MsQuic->ConnectionOpen(Quic::reg, callback, c.get(), &c->h_))) {
    c->h_ = nullptr;
    err = "ConnectionOpen failed";
    return nullptr;
  }
  QUIC_ADDR la{}, ra{};
  la.Ipv4 = local;
  ra.Ipv4 = remote;
  MsQuic->SetParam(c->h_, QUIC_PARAM_CONN_LOCAL_ADDRESS, sizeof la, &la);
  MsQuic->SetParam(c->h_, QUIC_PARAM_CONN_REMOTE_ADDRESS, sizeof ra, &ra);
  c->self_ = c;
  if (QUIC_STATUS st = MsQuic->ConnectionStart(c->h_, Quic::clientCfg[(int)cc], QUIC_ADDRESS_FAMILY_INET, "p2proxy",
                                               ntohs(remote.sin_port));
      QUIC_FAILED(st)) {
    c->self_.reset();
    err = "ConnectionStart failed: " + statusText(st);
    return nullptr;
  }
  std::unique_lock lk(c->mu_);
  c->cv_.wait_for(lk, std::chrono::milliseconds(timeoutMs), [&] { return c->connected_ || c->done_; });
  if (!c->connected_) {
    err = c->reason_.empty() ? "QUIC handshake timed out" : c->reason_;
    lk.unlock();
    c->shutdown();
    return nullptr;
  }
  return c;
}

std::shared_ptr<Connection> Connection::adopt(HQUIC h, HQUIC cfg, const sockaddr_in& remote, StreamHandler onStream) {
  std::shared_ptr<Connection> c(new Connection());
  c->h_ = h;
  c->remote_ = remote;
  c->onStream_ = std::move(onStream);
  c->self_ = c;
  MsQuic->SetCallbackHandler(h, (void*)callback, c.get());
  if (QUIC_FAILED(MsQuic->ConnectionSetConfiguration(h, cfg))) {
    // The listener callback rejects it and msquic closes it; route any
    // further events away from this object.
    MsQuic->SetCallbackHandler(h, (void*)ignoreConnectionEvents, nullptr);
    c->h_ = nullptr;
    c->self_.reset();
    return nullptr;
  }
  return c;
}

QUIC_STATUS QUIC_API Connection::callback(HQUIC, void* ctx, QUIC_CONNECTION_EVENT* e) {
  auto* c = (Connection*)ctx;
  switch (e->Type) {
  case QUIC_CONNECTION_EVENT_CONNECTED: {
    std::lock_guard lk(c->mu_);
    c->connected_ = true;
    c->cv_.notify_all();
    break;
  }
  case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED: {
    auto* cert = (PCCERT_CONTEXT)e->PEER_CERTIFICATE_RECEIVED.Certificate;
    if (!cert || certFingerprint(cert) != c->fingerprint_) {
      std::lock_guard lk(c->mu_);
      c->reason_ = "exit node certificate does not match (wrong key?)";
      return QUIC_STATUS_BAD_CERTIFICATE;
    }
    break;
  }
  case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT: {
    std::lock_guard lk(c->mu_);
    if (c->reason_.empty()) {
      QUIC_STATUS st = e->SHUTDOWN_INITIATED_BY_TRANSPORT.Status;
      c->reason_ = st == QUIC_STATUS_CONNECTION_IDLE ? "no response from peer (idle timeout)"
                                                     : "connection lost (" + statusText(st) + ")";
    }
    break;
  }
  case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER: {
    std::lock_guard lk(c->mu_);
    if (c->reason_.empty()) c->reason_ = "closed by peer";
    break;
  }
  case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
    auto st = Stream::adopt(e->PEER_STREAM_STARTED.Stream);
    if (c->onStream_)
      c->onStream_(st);
    else
      st->abort();
    break;
  }
  case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE: {
    std::shared_ptr<Connection> keep;
    {
      std::lock_guard lk(c->mu_);
      c->done_ = true;
      if (c->reason_.empty()) c->reason_ = "closed";
      keep = std::move(c->self_);
    }
    c->cv_.notify_all();
    break;
  }
  default:
    break;
  }
  return QUIC_STATUS_SUCCESS;
}

std::shared_ptr<Stream> Connection::openStream(std::string& err) {
  if (closed()) {
    err = "tunnel is closed";
    return nullptr;
  }
  return Stream::open(h_, err);
}

void Connection::shutdown() { MsQuic->ConnectionShutdown(h_, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0); }

bool Connection::waitClosed(int timeoutMs) {
  std::unique_lock lk(mu_);
  if (timeoutMs < 0) {
    cv_.wait(lk, [&] { return done_; });
    return true;
  }
  return cv_.wait_for(lk, std::chrono::milliseconds(timeoutMs), [&] { return done_; });
}

bool Connection::closed() {
  std::lock_guard lk(mu_);
  return done_;
}

std::string Connection::reason() {
  std::lock_guard lk(mu_);
  return reason_;
}

QUIC_STATISTICS_V2 Connection::stats() {
  QUIC_STATISTICS_V2 s{};
  uint32_t len = sizeof s;
  MsQuic->GetParam(h_, QUIC_PARAM_CONN_STATISTICS_V2, &len, &s);
  return s;
}

// ---- Listener ----

std::unique_ptr<Listener> Listener::start(const sockaddr_in& local, NewConnection onNew, std::string& err) {
  std::unique_ptr<Listener> l(new Listener());
  l->onNew_ = std::move(onNew);
  if (QUIC_FAILED(MsQuic->ListenerOpen(Quic::reg, callback, l.get(), &l->h_))) {
    l->h_ = nullptr;
    err = "ListenerOpen failed";
    return nullptr;
  }
  QUIC_ADDR a{};
  a.Ipv4 = local;
  if (QUIC_STATUS st = MsQuic->ListenerStart(l->h_, &kAlpn, 1, &a); QUIC_FAILED(st)) {
    err = "cannot listen on " + addrStr(local) + ": " + statusText(st);
    return nullptr;
  }
  return l;
}

Listener::~Listener() {
  if (h_) MsQuic->ListenerClose(h_); // waits for the listener to stop
}

QUIC_STATUS QUIC_API Listener::callback(HQUIC, void* ctx, QUIC_LISTENER_EVENT* e) {
  auto* l = (Listener*)ctx;
  if (e->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
    sockaddr_in remote{};
    if (const QUIC_ADDR* ra = e->NEW_CONNECTION.Info->RemoteAddress; ra && ra->si_family == AF_INET)
      remote = ra->Ipv4;
    return l->onNew_(e->NEW_CONNECTION.Connection, remote) ? QUIC_STATUS_SUCCESS : QUIC_STATUS_CONNECTION_REFUSED;
  }
  return QUIC_STATUS_SUCCESS;
}

} // namespace p2px
