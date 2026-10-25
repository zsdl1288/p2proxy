#include "signal.h"

#include <ws2tcpip.h>

#include "util.h"

#pragma comment(lib, "winhttp.lib")

namespace p2px {

namespace {

struct Handle {
  HINTERNET h = nullptr;
  Handle(HINTERNET x = nullptr) : h(x) {}
  ~Handle() {
    if (h) WinHttpCloseHandle(h);
  }
  operator HINTERNET() const { return h; }
};

HINTERNET session() {
  static HINTERNET s = [] {
    HINTERNET h = WinHttpOpen(L"p2proxy/2", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
                              WINHTTP_NO_PROXY_BYPASS, 0);
    DWORD proto = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(h, WINHTTP_OPTION_SECURE_PROTOCOLS, &proto, sizeof proto);
    return h;
  }();
  return s;
}

struct Url {
  std::wstring host, path;
  INTERNET_PORT port = 0;
  bool https = false;
};

bool crack(const std::string& url, Url& out) {
  std::wstring w = toWide(url);
  URL_COMPONENTS uc{};
  uc.dwStructSize = sizeof uc;
  uc.dwHostNameLength = uc.dwUrlPathLength = uc.dwExtraInfoLength = (DWORD)-1;
  if (!WinHttpCrackUrl(w.c_str(), 0, 0, &uc)) return false;
  out.host.assign(uc.lpszHostName, uc.dwHostNameLength);
  out.path.assign(uc.lpszUrlPath, uc.dwUrlPathLength);
  if (uc.dwExtraInfoLength) out.path.append(uc.lpszExtraInfo, uc.dwExtraInfoLength);
  out.port = uc.nPort;
  out.https = uc.nScheme == INTERNET_SCHEME_HTTPS;
  return true;
}

// Opens and sends a request; the caller reads the response.
HINTERNET openRequest(const std::string& method, const std::string& url, const std::string& body,
                      const std::vector<std::string>& headers, int timeoutMs, Handle& conn, std::string& err) {
  Url u;
  if (!crack(url, u)) {
    err = "bad URL";
    return nullptr;
  }
  conn.h = WinHttpConnect(session(), u.host.c_str(), u.port, 0);
  if (!conn) {
    err = "connect failed";
    return nullptr;
  }
  HINTERNET req = WinHttpOpenRequest(conn, toWide(method).c_str(), u.path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES, u.https ? WINHTTP_FLAG_SECURE : 0);
  if (!req) {
    err = "request failed";
    return nullptr;
  }
  WinHttpSetTimeouts(req, timeoutMs, timeoutMs, timeoutMs, timeoutMs);
  for (auto& h : headers) WinHttpAddRequestHeaders(req, toWide(h).c_str(), (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
  if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)body.data(), (DWORD)body.size(),
                          (DWORD)body.size(), 0) ||
      !WinHttpReceiveResponse(req, nullptr)) {
    err = "HTTP request to " + toUtf8(u.host) + " failed (error " + std::to_string(GetLastError()) + ")";
    WinHttpCloseHandle(req);
    return nullptr;
  }
  return req;
}

DWORD statusOf(HINTERNET req) {
  DWORD status = 0, len = sizeof status;
  WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                      &status, &len, WINHTTP_NO_HEADER_INDEX);
  return status;
}

} // namespace

HttpResult httpRequest(const std::string& method, const std::string& url, const std::string& body,
                       const std::vector<std::string>& headers, int timeoutMs) {
  HttpResult r;
  Handle conn;
  Handle req(openRequest(method, url, body, headers, timeoutMs, conn, r.err));
  if (!req) return r;
  r.status = statusOf(req);
  char buf[16384];
  DWORD n = 0;
  while (WinHttpReadData(req, buf, sizeof buf, &n) && n > 0) {
    r.body.append(buf, n);
    if (r.body.size() > (8 << 20)) break;
  }
  return r;
}

std::vector<in_addr> resolveIPv4(const std::string& host) {
  std::vector<in_addr> out;
  auto r = httpRequest("GET", "https://1.1.1.1/dns-query?name=" + host + "&type=A", "",
                       {"Accept: application/dns-json"}, 8000);
  if (r.status == 200) {
    try {
      for (auto& a : json::parse(r.body).value("Answer", json::array())) {
        if (a.value("type", 0) != 1) continue;
        in_addr ip{};
        if (inet_pton(AF_INET, a.value("data", "").c_str(), &ip) == 1) out.push_back(ip);
      }
    } catch (...) {
    }
  }
  if (!out.empty()) return out;
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

Signaler::Signaler(Keys k, std::string base) : k_(std::move(k)), base_(std::move(base)) {}

Signaler::~Signaler() { stop(); }

bool Signaler::publish(json msg, std::string& err) {
  msg["ts"] = unixNow();
  std::string plain = msg.dump();
  std::string body = base64(aesGcmSeal(k_.aead, Bytes(plain.begin(), plain.end())));
  auto r = httpRequest("POST", base_ + "/" + k_.topic, body, {}, 15000);
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
  stop_ = true;
  {
    std::lock_guard lk(mu_);
    if (req_) WinHttpCloseHandle(req_); // aborts a blocked read
    req_ = nullptr;
  }
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
  Handle conn;
  // ntfy sends a keepalive every 45s; a 90s read timeout catches dead connections.
  HINTERNET req = openRequest("GET", base_ + "/" + k_.topic + "/json?since=" + cursor_, "", {}, 90000, conn, err);
  if (!req) return false;
  {
    std::lock_guard lk(mu_);
    if (stop_) {
      WinHttpCloseHandle(req);
      return false;
    }
    req_ = req;
  }
  auto release = [&] {
    std::lock_guard lk(mu_);
    if (req_) WinHttpCloseHandle(req_);
    req_ = nullptr;
  };
  if (DWORD st = statusOf(req); st != 200) {
    err = "signaling server returned " + std::to_string(st);
    release();
    return false;
  }
  if (onConnect) onConnect();

  std::string pending;
  char buf[8192];
  DWORD avail = 0, n = 0;
  // QueryDataAvailable returns as soon as anything arrives; ReadData alone
  // may wait to fill the whole buffer, which a quiet stream never does.
  while (!stop_ && WinHttpQueryDataAvailable(req, &avail) && avail > 0 &&
         WinHttpReadData(req, buf, std::min<DWORD>(avail, sizeof buf), &n) && n > 0) {
    pending.append(buf, n);
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
  err = stop_ ? "stopped" : "subscription ended (error " + std::to_string(GetLastError()) + ")";
  release();
  return false;
}

} // namespace p2px
