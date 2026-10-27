#pragma once
#include "netutil.h"

#define SECURITY_WIN32
#include <wincrypt.h>
#include <schannel.h>
#include <security.h>

#include <atomic>
#include <string>
#include <vector>

namespace p2px {

// A small HTTPS/1.1 client for p2proxy's own control traffic (signaling and
// DNS-over-HTTPS). Its sockets are pinned to the physical adapter, like the
// tunnel's UDP socket, so a TUN-mode proxy such as Clash never sees them: no
// proxy rule, fake IP or proxy DNS is involved, and a restarted client can
// reach the exit node while the TUN still routes everything else into the
// (not yet running) tunnel. TLS is Windows' own Schannel.
class HttpsRequest {
public:
  HttpsRequest() = default;
  ~HttpsRequest();
  HttpsRequest(const HttpsRequest&) = delete;
  HttpsRequest& operator=(const HttpsRequest&) = delete;

  // Connects, sends the request and reads the response head. timeoutMs bounds
  // the connect and every later wait for data; setting *cancel aborts within
  // a fraction of a second.
  bool open(const std::string& method, const std::string& url, const std::string& body,
            const std::vector<std::string>& headers, int timeoutMs, const std::atomic<bool>* cancel,
            std::string& err);
  int status() const { return status_; }
  // Appends the next piece of the body (chunked encoding removed). False at
  // the end of the body, or on an error, which err() then names.
  bool read(std::string& out);
  const std::string& err() const { return err_; }

private:
  bool connect(const in_addr& ip, uint16_t port, const std::string& host, std::string& err);
  bool handshake(const std::string& host, std::string& err);
  bool wait(bool write, std::string& err);
  bool sendRaw(const char* p, size_t n, std::string& err);
  bool sendTls(const std::string& data, std::string& err);
  // These append what arrives: 1 if anything did, 0 when the server closed
  // the connection, -1 on an error.
  int recvRaw(std::string& into, std::string& err);
  int recvTls(std::string& out, std::string& err);
  bool decode(std::string& out);
  void close();

  SOCKET s_ = INVALID_SOCKET;
  int timeoutMs_ = 0;
  const std::atomic<bool>* cancel_ = nullptr;
  CredHandle cred_{};
  CtxtHandle ctx_{};
  bool haveCred_ = false, haveCtx_ = false;
  SecPkgContext_StreamSizes sizes_{};
  std::string enc_; // received TLS records not yet decrypted
  std::string raw_; // decrypted body bytes not yet decoded

  int status_ = 0;
  enum class Framing { Length, Chunked, UntilClose } framing_ = Framing::UntilClose;
  uint64_t left_ = 0;      // bytes left in the body (Length) or current chunk (Chunked)
  bool chunkCrlf_ = false; // a chunk's data is done; its CRLF is next
  bool done_ = false;
  std::string err_;
};

struct HttpResult {
  int status = 0;
  std::string body;
  std::string err;
};
// A whole request (bodies up to 1 MB) without cancellation.
HttpResult httpsRequest(const std::string& method, const std::string& url, const std::string& body,
                        const std::vector<std::string>& headers, int timeoutMs);

// Resolves a name with DNS-over-HTTPS over the physical adapter, so a TUN
// proxy's fake IPs never reach us: Cloudflare (1.1.1.1) first, then AliDNS
// (223.5.5.5), which stays reachable where 1.1.1.1 is blocked or throttled.
// Falls back to the system resolver, skipping fake IPs. Results are cached.
std::vector<in_addr> resolveIPv4(const std::string& host);

} // namespace p2px
