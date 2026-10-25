#pragma once
#include "netutil.h" // winsock2.h before windows.h
#include <wincrypt.h>
#include <msquic.h>

#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include "util.h"

namespace p2px {

extern const QUIC_API_TABLE* MsQuic;

// Congestion control. BBR fills long, fast paths; CUBIC backs off on loss,
// which can be steadier where the path polices or drops traffic. The client
// picks one and the exit node uses the same for that connection.
enum class Cc { Bbr, Cubic };
inline Cc parseCc(const std::string& s) { return s == "cubic" ? Cc::Cubic : Cc::Bbr; }
inline const char* ccName(Cc c) { return c == Cc::Cubic ? "cubic" : "bbr"; }

// Process-wide msquic state.
struct Quic {
  static bool init(std::string& err);
  static void cleanup();
  static HQUIC reg;
  static HQUIC clientCfg[2]; // indexed by Cc
  static HQUIC serverConfig(PCCERT_CONTEXT cert, Cc cc, std::string& err); // caller closes it
};

// A QUIC stream with a blocking API for worker threads. Received data is
// buffered, and receiving pauses above a high-water mark, which pushes back
// on the peer through QUIC flow control; sends are bounded the same way.
class Stream {
public:
  ~Stream();
  static std::shared_ptr<Stream> open(HQUIC conn, std::string& err); // we start it
  static std::shared_ptr<Stream> adopt(HQUIC h);                     // the peer started it

  int read(uint8_t* buf, size_t cap, int timeoutMs = -1); // >0 bytes, 0 end of stream, -1 error, -2 timeout
  bool readFull(void* buf, size_t n, int timeoutMs);
  bool write(const void* p, size_t n);
  void finish(); // graceful end of our sending direction
  void abort();  // both directions

private:
  Stream() = default;
  static QUIC_STATUS QUIC_API callback(HQUIC h, void* ctx, QUIC_STREAM_EVENT* e);

  HQUIC h_ = nullptr;
  std::mutex mu_;
  std::condition_variable cv_;
  std::deque<Bytes> rx_;
  size_t rxOff_ = 0, rxBytes_ = 0, txPending_ = 0;
  bool rxFin_ = false, rxAbort_ = false, txAbort_ = false, done_ = false, paused_ = false;
  std::shared_ptr<Stream> self_; // keeps us alive until msquic reports shutdown complete
};

class Connection {
public:
  ~Connection();
  using StreamHandler = std::function<void(std::shared_ptr<Stream>)>;

  // Client: connects from a local address (the port hole punching opened) and
  // accepts the server only if its certificate has the expected fingerprint.
  static std::shared_ptr<Connection> connect(const sockaddr_in& local, const sockaddr_in& remote,
                                             const std::string& fingerprint, Cc cc, int timeoutMs,
                                             std::string& err);
  // Server: takes over a new connection from a listener (call from its callback).
  static std::shared_ptr<Connection> adopt(HQUIC h, HQUIC cfg, const sockaddr_in& remote, StreamHandler onStream);

  std::shared_ptr<Stream> openStream(std::string& err);
  void shutdown();
  bool waitClosed(int timeoutMs); // true once closed
  bool closed();
  std::string reason();
  std::string remote() const { return addrStr(remote_); }
  QUIC_STATISTICS_V2 stats();

private:
  Connection() = default;
  static QUIC_STATUS QUIC_API callback(HQUIC h, void* ctx, QUIC_CONNECTION_EVENT* e);

  HQUIC h_ = nullptr;
  std::mutex mu_;
  std::condition_variable cv_;
  bool connected_ = false, done_ = false;
  std::string fingerprint_, reason_;
  sockaddr_in remote_{};
  StreamHandler onStream_;
  std::shared_ptr<Connection> self_;
};

// Accepts connections on one local address; onNew must adopt each one.
class Listener {
public:
  using NewConnection = std::function<bool(HQUIC conn, const sockaddr_in& remote)>;
  static std::unique_ptr<Listener> start(const sockaddr_in& local, NewConnection onNew, std::string& err);
  ~Listener();

private:
  Listener() = default;
  static QUIC_STATUS QUIC_API callback(HQUIC h, void* ctx, QUIC_LISTENER_EVENT* e);
  HQUIC h_ = nullptr;
  NewConnection onNew_;
};

} // namespace p2px
