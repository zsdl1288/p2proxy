#pragma once
#include <optional>
#include <string>

#include "util.h"

namespace p2px {

Bytes randomBytes(size_t n);
Bytes sha256(const uint8_t* p, size_t n);
Bytes hmacSha256(const Bytes& key, const std::string& msg);

// AES-256-GCM; the sealed form is nonce(12) || ciphertext || tag(16).
Bytes aesGcmSeal(const Bytes& key, const Bytes& plain);
bool aesGcmOpen(const Bytes& key, const Bytes& sealed, Bytes& plain);

// DPAPI, bound to the current Windows user. Used for keys stored on disk.
Bytes dpapiProtect(const Bytes& plain);
bool dpapiUnprotect(const Bytes& sealed, Bytes& plain);

// A fresh shared key: 32 random bytes, URL-safe base64.
std::string generateKey();

// Everything both sides derive from the shared key. Nothing else is shared.
struct Keys {
  std::string secret;
  std::string topic; // ntfy topic for signaling
  Bytes aead;        // encrypts and authenticates signaling messages
  static std::optional<Keys> derive(const std::string& secret);
};

} // namespace p2px
