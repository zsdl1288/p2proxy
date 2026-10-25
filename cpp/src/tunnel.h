#pragma once
#include "quic.h"

namespace p2px {

// Every proxied connection is one QUIC stream. The client opens it with
//   [kind:1][len:1][target:len]
// and the server answers
//   [status:1][len:1][message:len]   status 0 means OK
// after which the stream carries what the kind calls for.
enum Kind : uint8_t {
  kTcp = 1,       // raw TCP bytes to and from target ("host:port")
  kUdp = 2,       // framed UDP datagrams (writeDatagram)
  kInfo = 3,      // the server sends a JSON description of itself
  kSpeedDown = 4, // the server sends filler until the client stops reading
  kSpeedUp = 5,   // the client sends filler; the server replies [bytes:8][nanoseconds:8]
  kSpeedReport = 6, // target is the client's speed test result as JSON, for the server's log
  kFetch = 7,       // the server downloads target (a GitHub URL) and sends the body
  kUpdate = 8,      // the server installs the latest release, answers, then restarts
  kHello = 16,    // first stream: target is "<session token>\n<client name>"
};

constexpr int kSpeedTestLimitMs = 30000;

bool writeHeader(Stream& s, uint8_t kind, const std::string& target);
bool readHeader(Stream& s, uint8_t& kind, std::string& target, int timeoutMs);
bool writeStatus(Stream& s, const std::string& err); // empty means OK
bool readStatus(Stream& s, std::string& err, int timeoutMs);

// UDP datagram on a kUdp stream: [addrLen:1][addr][dataLen:2][data]. addr is
// the destination going out and the source coming back.
bool writeDatagram(Stream& s, const std::string& addr, const uint8_t* data, size_t n);
bool readDatagram(Stream& s, std::string& addr, Bytes& data);

// Copies between a TCP socket and a stream in both directions, passing on
// half-closes, until both directions are done. Closes the socket.
void relay(SOCKET sock, std::shared_ptr<Stream> st);

bool splitHostPort(const std::string& target, std::string& host, uint16_t& port);

// Filler for speed tests.
const Bytes& filler();

} // namespace p2px
