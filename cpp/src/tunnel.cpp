#include "tunnel.h"

#include <thread>

#include "crypto.h"

namespace p2px {

bool writeHeader(Stream& s, uint8_t kind, const std::string& target) {
  if (target.size() > 255) return false;
  Bytes b{kind, (uint8_t)target.size()};
  b.insert(b.end(), target.begin(), target.end());
  return s.write(b.data(), b.size());
}

bool readHeader(Stream& s, uint8_t& kind, std::string& target, int timeoutMs) {
  uint8_t h[2];
  if (!s.readFull(h, 2, timeoutMs)) return false;
  kind = h[0];
  target.assign(h[1], '\0');
  return h[1] == 0 || s.readFull(target.data(), h[1], timeoutMs);
}

bool writeStatus(Stream& s, const std::string& err) {
  std::string msg = err.substr(0, 255);
  Bytes b{(uint8_t)(err.empty() ? 0 : 1), (uint8_t)msg.size()};
  b.insert(b.end(), msg.begin(), msg.end());
  return s.write(b.data(), b.size());
}

bool readStatus(Stream& s, std::string& err, int timeoutMs) {
  uint8_t h[2];
  if (!s.readFull(h, 2, timeoutMs)) {
    err = "exit node did not answer";
    return false;
  }
  std::string msg(h[1], '\0');
  if (h[1] && !s.readFull(msg.data(), h[1], timeoutMs)) {
    err = "exit node did not answer";
    return false;
  }
  if (h[0] != 0) {
    err = "exit node: " + msg;
    return false;
  }
  return true;
}

bool writeDatagram(Stream& s, const std::string& addr, const uint8_t* data, size_t n) {
  if (addr.size() > 255 || n > 65535) return false;
  Bytes b;
  b.reserve(3 + addr.size() + n);
  b.push_back((uint8_t)addr.size());
  b.insert(b.end(), addr.begin(), addr.end());
  b.push_back(uint8_t(n >> 8));
  b.push_back(uint8_t(n));
  b.insert(b.end(), data, data + n);
  return s.write(b.data(), b.size());
}

bool readDatagram(Stream& s, std::string& addr, Bytes& data) {
  uint8_t len;
  if (!s.readFull(&len, 1, 600000)) return false;
  addr.assign(len, '\0');
  if (len && !s.readFull(addr.data(), len, 10000)) return false;
  uint8_t l2[2];
  if (!s.readFull(l2, 2, 10000)) return false;
  data.resize(size_t(l2[0]) << 8 | l2[1]);
  return data.empty() || s.readFull(data.data(), data.size(), 10000);
}

void relay(SOCKET sock, std::shared_ptr<Stream> st) {
  // stream -> socket
  std::thread down([sock, st] {
    std::vector<uint8_t> buf(64 << 10);
    for (;;) {
      int n = st->read(buf.data(), buf.size());
      if (n == 0) {
        shutdown(sock, SD_SEND); // pass the half-close on
        break;
      }
      if (n < 0 || !sendAll(sock, buf.data(), n)) {
        st->abort();
        shutdown(sock, SD_BOTH); // also wakes the other direction
        break;
      }
    }
  });
  // socket -> stream
  std::vector<uint8_t> buf(64 << 10);
  for (;;) {
    int n = recv(sock, (char*)buf.data(), (int)buf.size(), 0);
    if (n == 0) {
      st->finish();
      break;
    }
    if (n < 0 || !st->write(buf.data(), n)) {
      st->abort();
      break;
    }
  }
  down.join();
  closesocket(sock);
}

bool splitHostPort(const std::string& target, std::string& host, uint16_t& port) {
  auto colon = target.rfind(':');
  if (colon == std::string::npos || colon == 0) return false;
  host = target.substr(0, colon);
  if (host.size() > 2 && host.front() == '[' && host.back() == ']') host = host.substr(1, host.size() - 2);
  int p = atoi(target.c_str() + colon + 1);
  if (p <= 0 || p > 65535) return false;
  port = (uint16_t)p;
  return true;
}

const Bytes& filler() {
  static Bytes b = randomBytes(256 << 10);
  return b;
}

} // namespace p2px
