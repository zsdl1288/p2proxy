#include "https.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>

#include "util.h"

namespace p2px {

namespace {

constexpr int kSliceMs = 200; // how often a wait looks at the cancel flag

struct Url {
  std::string host, path;
  uint16_t port = 443;
};

bool parseUrl(const std::string& url, Url& out) {
  const std::string scheme = "https://";
  if (url.rfind(scheme, 0) != 0) return false;
  size_t slash = url.find('/', scheme.size());
  std::string authority = url.substr(scheme.size(), slash == std::string::npos ? slash : slash - scheme.size());
  out.path = slash == std::string::npos ? "/" : url.substr(slash);
  size_t colon = authority.find(':');
  out.host = authority.substr(0, colon);
  if (colon != std::string::npos) {
    int port = atoi(authority.c_str() + colon + 1);
    if (port <= 0 || port > 65535) return false;
    out.port = (uint16_t)port;
  }
  return !out.host.empty();
}

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)tolower(c); });
  return s;
}

std::string tlsError(SECURITY_STATUS ss) {
  switch (ss) {
  case SEC_E_UNTRUSTED_ROOT:
    return "certificate is not trusted";
  case SEC_E_WRONG_PRINCIPAL:
    return "certificate is for another name";
  case SEC_E_CERT_EXPIRED:
    return "certificate has expired";
  }
  char buf[32];
  snprintf(buf, sizeof buf, "error 0x%08lX", (unsigned long)ss);
  return buf;
}

std::mutex dnsMu;
struct CachedIps {
  std::vector<in_addr> ips;
  uint64_t expiresMs;
};
std::map<std::string, CachedIps> dnsCache;

void forgetIPv4(const std::string& host) {
  std::lock_guard lk(dnsMu);
  dnsCache.erase(host);
}

// Cloudflare and AliDNS answer in the same JSON format.
std::vector<in_addr> dohLookup(const std::string& url, int64_t& ttl, std::string& err) {
  std::vector<in_addr> out;
  auto r = httpsRequest("GET", url, "", {"Accept: application/dns-json"}, 4000);
  if (r.status != 200 || !r.err.empty()) {
    err = !r.err.empty() ? r.err : "HTTP " + std::to_string(r.status);
    return out;
  }
  try {
    for (auto& a : nlohmann::json::parse(r.body).value("Answer", nlohmann::json::array())) {
      if (a.value("type", 0) != 1) continue;
      in_addr ip{};
      if (inet_pton(AF_INET, a.value("data", "").c_str(), &ip) != 1) continue;
      out.push_back(ip);
      ttl = std::min<int64_t>(ttl, a.value("TTL", ttl));
    }
  } catch (...) {
  }
  if (out.empty()) err = "no address in the answer";
  return out;
}

} // namespace

HttpsRequest::~HttpsRequest() { close(); }

void HttpsRequest::close() {
  if (haveCtx_) DeleteSecurityContext(&ctx_);
  if (haveCred_) FreeCredentialsHandle(&cred_);
  haveCtx_ = haveCred_ = false;
  if (s_ != INVALID_SOCKET) closesocket(s_);
  s_ = INVALID_SOCKET;
  enc_.clear();
}

bool HttpsRequest::open(const std::string& method, const std::string& url, const std::string& body,
                        const std::vector<std::string>& headers, int timeoutMs, const std::atomic<bool>* cancel,
                        std::string& err) {
  timeoutMs_ = timeoutMs;
  cancel_ = cancel;
  Url u;
  if (!parseUrl(url, u)) {
    err = "bad URL";
    return false;
  }
  in_addr literal{};
  bool isIp = inet_pton(AF_INET, u.host.c_str(), &literal) == 1;
  std::vector<in_addr> ips = isIp ? std::vector<in_addr>{literal} : resolveIPv4(u.host);
  if (ips.empty()) {
    err = "cannot resolve " + u.host;
    return false;
  }
  bool connected = false;
  for (size_t i = 0; i < ips.size() && i < 3 && !connected && !(cancel_ && *cancel_); i++)
    connected = connect(ips[i], u.port, u.host, err);
  if (!connected) {
    if (!isIp) forgetIPv4(u.host); // the address may have changed
    return false;
  }

  std::string req = method + " " + u.path + " HTTP/1.1\r\nHost: " + u.host +
                    (u.port != 443 ? ":" + std::to_string(u.port) : "") +
                    "\r\nUser-Agent: p2proxy/2\r\nConnection: close\r\n";
  for (auto& h : headers) req += h + "\r\n";
  if (!body.empty() || method == "POST") req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
  req += "\r\n" + body;
  if (!sendTls(req, err)) return false;

  std::string head;
  size_t end;
  while ((end = head.find("\r\n\r\n")) == std::string::npos) {
    if (head.size() > 65536) {
      err = "response from " + u.host + " is not HTTP";
      return false;
    }
    int k = recvTls(head, err);
    if (k == 0) err = u.host + " closed the connection without answering";
    if (k <= 0) return false;
  }
  raw_ = head.substr(end + 4);
  head.resize(end);
  size_t sp = head.find(' ');
  status_ = head.rfind("HTTP/", 0) == 0 && sp != std::string::npos ? atoi(head.c_str() + sp + 1) : 0;
  if (status_ < 100) {
    err = "response from " + u.host + " is not HTTP";
    return false;
  }
  bool chunked = false, hasLength = false;
  for (size_t pos = head.find("\r\n"); pos != std::string::npos;) {
    size_t next = head.find("\r\n", pos + 2);
    std::string line = head.substr(pos + 2, next == std::string::npos ? next : next - pos - 2);
    pos = next;
    size_t colon = line.find(':');
    if (colon == std::string::npos) continue;
    std::string name = lower(trim(line.substr(0, colon))), value = lower(trim(line.substr(colon + 1)));
    if (name == "transfer-encoding" && value.find("chunked") != std::string::npos) chunked = true;
    if (name == "content-length") {
      hasLength = true;
      left_ = strtoull(value.c_str(), nullptr, 10);
    }
  }
  framing_ = chunked ? Framing::Chunked : hasLength ? Framing::Length : Framing::UntilClose;
  if (chunked) left_ = 0;
  done_ = framing_ == Framing::Length && left_ == 0;
  return true;
}

bool HttpsRequest::read(std::string& out) {
  while (!done_) {
    size_t before = out.size();
    if (!decode(out)) return false;
    if (out.size() > before) return true;
    if (done_) break;
    int k = recvTls(raw_, err_);
    if (k == 0 && framing_ == Framing::UntilClose) break;
    if (k == 0) err_ = "connection closed in the middle of the response";
    if (k <= 0) return false;
  }
  done_ = true;
  return false;
}

// Moves body bytes from raw_ to out; false if the chunked framing is broken.
bool HttpsRequest::decode(std::string& out) {
  if (framing_ == Framing::UntilClose) {
    out += raw_;
    raw_.clear();
    return true;
  }
  if (framing_ == Framing::Length) {
    size_t n = (size_t)std::min<uint64_t>(left_, raw_.size());
    out.append(raw_, 0, n);
    raw_.erase(0, n);
    left_ -= n;
    done_ = left_ == 0;
    return true;
  }
  while (!done_) {
    if (left_ > 0) {
      size_t n = (size_t)std::min<uint64_t>(left_, raw_.size());
      out.append(raw_, 0, n);
      raw_.erase(0, n);
      left_ -= n;
      if (left_ > 0) return true;
      chunkCrlf_ = true;
    }
    if (chunkCrlf_) {
      if (raw_.size() < 2) return true;
      raw_.erase(0, 2);
      chunkCrlf_ = false;
    }
    size_t eol = raw_.find("\r\n");
    if (eol == std::string::npos) {
      if (raw_.size() <= 1024) return true;
      err_ = "malformed chunked response";
      return false;
    }
    char* endp = nullptr;
    uint64_t size = strtoull(raw_.c_str(), &endp, 16);
    if (endp == raw_.c_str()) {
      err_ = "malformed chunked response";
      return false;
    }
    raw_.erase(0, eol + 2);
    left_ = size;
    done_ = size == 0; // trailers, if any, are ignored
  }
  return true;
}

bool HttpsRequest::connect(const in_addr& ip, uint16_t port, const std::string& host, std::string& err) {
  close();
  char ipStr[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &ip, ipStr, sizeof ipStr);
  std::string who = host == ipStr ? host : host + " (" + ipStr + ")";
  s_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s_ == INVALID_SOCKET) {
    err = "cannot create socket";
    return false;
  }
  if (auto iface = physicalInterface()) {
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr = iface->ip; // bound to the physical address: bypasses a TUN
    bindToInterface(s_, iface->index);
    bind(s_, (sockaddr*)&local, sizeof local);
  }
  u_long nb = 1;
  ioctlsocket(s_, FIONBIO, &nb);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr = ip;
  a.sin_port = htons(port);
  std::string why;
  if (::connect(s_, (sockaddr*)&a, sizeof a) != 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
    err = "connection to " + who + " failed (error " + std::to_string(WSAGetLastError()) + ")";
    return false;
  }
  if (!wait(true, why)) {
    err = "connection to " + who + ": " + why;
    return false;
  }
  int soerr = 0, len = sizeof soerr;
  getsockopt(s_, SOL_SOCKET, SO_ERROR, (char*)&soerr, &len);
  if (soerr != 0) {
    err = "connection to " + who + " failed (error " + std::to_string(soerr) + ")";
    return false;
  }
  BOOL one = TRUE;
  setsockopt(s_, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof one);
  if (!handshake(host, why)) {
    err = "TLS with " + who + ": " + why;
    return false;
  }
  return true;
}

bool HttpsRequest::handshake(const std::string& host, std::string& err) {
  SCHANNEL_CRED sc{};
  sc.dwVersion = SCHANNEL_CRED_VERSION;
  sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
  // Schannel validates the chain and the name (IP addresses too) itself.
  sc.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;
  SECURITY_STATUS ss = AcquireCredentialsHandleW(nullptr, (LPWSTR)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, nullptr, &sc,
                                                 nullptr, nullptr, &cred_, nullptr);
  if (ss != SEC_E_OK) {
    err = tlsError(ss);
    return false;
  }
  haveCred_ = true;

  std::wstring target = toWide(host);
  const DWORD want = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                     ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
  for (bool first = true;; first = false) {
    SecBuffer in[2] = {{(ULONG)enc_.size(), SECBUFFER_TOKEN, enc_.data()}, {0, SECBUFFER_EMPTY, nullptr}};
    SecBufferDesc inDesc{SECBUFFER_VERSION, 2, in};
    SecBuffer out{0, SECBUFFER_TOKEN, nullptr};
    SecBufferDesc outDesc{SECBUFFER_VERSION, 1, &out};
    DWORD attrs = 0;
    ss = InitializeSecurityContextW(&cred_, first ? nullptr : &ctx_, target.data(), want, 0, 0,
                                    first ? nullptr : &inDesc, 0, first ? &ctx_ : nullptr, &outDesc, &attrs, nullptr);
    if (first) haveCtx_ = ss == SEC_I_CONTINUE_NEEDED || ss == SEC_E_OK;
    if (out.cbBuffer > 0 && out.pvBuffer) {
      bool sent = sendRaw((const char*)out.pvBuffer, out.cbBuffer, err);
      FreeContextBuffer(out.pvBuffer);
      if (!sent) return false;
    }
    if (ss == SEC_E_INCOMPLETE_MESSAGE) {
      int k = recvRaw(enc_, err);
      if (k == 0) err = "connection closed during the handshake";
      if (k <= 0) return false;
      continue;
    }
    if (ss != SEC_E_OK && ss != SEC_I_CONTINUE_NEEDED) {
      err = tlsError(ss);
      return false;
    }
    // Leftover bytes start the server's next handshake message or first record.
    if (!first && in[1].BufferType == SECBUFFER_EXTRA) enc_.erase(0, enc_.size() - in[1].cbBuffer);
    else enc_.clear();
    if (ss == SEC_E_OK) break;
    if (enc_.empty()) {
      int k = recvRaw(enc_, err);
      if (k == 0) err = "connection closed during the handshake";
      if (k <= 0) return false;
    }
  }
  ss = QueryContextAttributesW(&ctx_, SECPKG_ATTR_STREAM_SIZES, &sizes_);
  if (ss != SEC_E_OK) {
    err = tlsError(ss);
    return false;
  }
  return true;
}

// Waits until the socket can be written (or read), in slices so that a cancel
// is noticed quickly.
bool HttpsRequest::wait(bool write, std::string& err) {
  for (int waited = 0; waited < timeoutMs_; waited += kSliceMs) {
    if (cancel_ && *cancel_) {
      err = "cancelled";
      return false;
    }
    fd_set ready, failed;
    FD_ZERO(&ready);
    FD_ZERO(&failed);
    FD_SET(s_, &ready);
    FD_SET(s_, &failed);
    timeval tv{0, kSliceMs * 1000};
    int n = select(0, write ? nullptr : &ready, write ? &ready : nullptr, &failed, &tv);
    if (n != 0) return true; // ready, or an error the next call reports
  }
  err = "timed out";
  return false;
}

bool HttpsRequest::sendRaw(const char* p, size_t n, std::string& err) {
  while (n > 0) {
    int k = send(s_, p, (int)std::min<size_t>(n, 1 << 16), 0);
    if (k > 0) {
      p += k;
      n -= k;
      continue;
    }
    if (WSAGetLastError() != WSAEWOULDBLOCK) {
      err = "send failed (error " + std::to_string(WSAGetLastError()) + ")";
      return false;
    }
    if (!wait(true, err)) return false;
  }
  return true;
}

int HttpsRequest::recvRaw(std::string& into, std::string& err) {
  char buf[16384];
  for (;;) {
    int k = recv(s_, buf, sizeof buf, 0);
    if (k > 0) {
      into.append(buf, k);
      return 1;
    }
    if (k == 0) return 0;
    if (WSAGetLastError() != WSAEWOULDBLOCK) {
      err = "connection reset (error " + std::to_string(WSAGetLastError()) + ")";
      return -1;
    }
    if (!wait(false, err)) return -1;
  }
}

bool HttpsRequest::sendTls(const std::string& data, std::string& err) {
  for (size_t off = 0; off < data.size();) {
    size_t n = std::min<size_t>(data.size() - off, sizes_.cbMaximumMessage);
    std::string rec(sizes_.cbHeader + n + sizes_.cbTrailer, '\0');
    memcpy(rec.data() + sizes_.cbHeader, data.data() + off, n);
    SecBuffer b[4] = {{sizes_.cbHeader, SECBUFFER_STREAM_HEADER, rec.data()},
                      {(ULONG)n, SECBUFFER_DATA, rec.data() + sizes_.cbHeader},
                      {sizes_.cbTrailer, SECBUFFER_STREAM_TRAILER, rec.data() + sizes_.cbHeader + n},
                      {0, SECBUFFER_EMPTY, nullptr}};
    SecBufferDesc d{SECBUFFER_VERSION, 4, b};
    if (SECURITY_STATUS ss = EncryptMessage(&ctx_, 0, &d, 0); ss != SEC_E_OK) {
      err = "TLS " + tlsError(ss);
      return false;
    }
    if (!sendRaw(rec.data(), b[0].cbBuffer + b[1].cbBuffer + b[2].cbBuffer, err)) return false;
    off += n;
  }
  return true;
}

int HttpsRequest::recvTls(std::string& out, std::string& err) {
  for (;;) {
    if (!enc_.empty()) {
      SecBuffer b[4] = {{(ULONG)enc_.size(), SECBUFFER_DATA, enc_.data()},
                        {0, SECBUFFER_EMPTY, nullptr},
                        {0, SECBUFFER_EMPTY, nullptr},
                        {0, SECBUFFER_EMPTY, nullptr}};
      SecBufferDesc d{SECBUFFER_VERSION, 4, b};
      SECURITY_STATUS ss = DecryptMessage(&ctx_, &d, 0, nullptr);
      if (ss == SEC_E_OK) {
        // Decryption works in place; unread records stay at the end of enc_.
        size_t before = out.size(), extra = 0;
        for (auto& x : b) {
          if (x.BufferType == SECBUFFER_DATA) out.append((const char*)x.pvBuffer, x.cbBuffer);
          if (x.BufferType == SECBUFFER_EXTRA) extra = x.cbBuffer;
        }
        enc_.erase(0, enc_.size() - extra);
        if (out.size() > before) return 1;
        continue;
      }
      if (ss == SEC_I_CONTEXT_EXPIRED) return 0; // the server's close_notify
      if (ss != SEC_E_INCOMPLETE_MESSAGE) {
        err = "TLS " + tlsError(ss);
        return -1;
      }
    }
    if (int k = recvRaw(enc_, err); k <= 0) return k;
  }
}

HttpResult httpsRequest(const std::string& method, const std::string& url, const std::string& body,
                        const std::vector<std::string>& headers, int timeoutMs) {
  HttpResult r;
  HttpsRequest req;
  if (!req.open(method, url, body, headers, timeoutMs, nullptr, r.err)) return r;
  r.status = req.status();
  while (req.read(r.body)) {
    if (r.body.size() > (1 << 20)) {
      r.err = "response too large";
      return r;
    }
  }
  r.err = req.err();
  return r;
}

std::vector<in_addr> resolveIPv4(const std::string& host) {
  {
    std::lock_guard lk(dnsMu);
    if (auto it = dnsCache.find(host); it != dnsCache.end() && it->second.expiresMs > msNow()) return it->second.ips;
  }
  const std::string resolvers[] = {"https://1.1.1.1/dns-query?type=A&name=" + host,
                                   "https://223.5.5.5/resolve?type=1&name=" + host};
  std::string err;
  for (auto& url : resolvers) {
    int64_t ttl = 600;
    auto ips = dohLookup(url, ttl, err);
    if (ips.empty()) continue;
    std::lock_guard lk(dnsMu);
    dnsCache[host] = {ips, msNow() + (uint64_t)std::clamp<int64_t>(ttl, 60, 600) * 1000};
    return ips;
  }
  logf("DNS-over-HTTPS lookup of %s failed (%s); trying the system resolver", host.c_str(), err.c_str());
  std::vector<in_addr> out;
  addrinfo hints{}, *res = nullptr;
  hints.ai_family = AF_INET;
  if (getaddrinfo(host.c_str(), nullptr, &hints, &res) == 0) {
    for (auto* ai = res; ai; ai = ai->ai_next) {
      in_addr ip = ((sockaddr_in*)ai->ai_addr)->sin_addr;
      if ((ntohl(ip.s_addr) >> 17) != (0xC612 >> 1)) out.push_back(ip); // skip 198.18/15 fake IPs
    }
    freeaddrinfo(res);
  }
  return out;
}

} // namespace p2px
