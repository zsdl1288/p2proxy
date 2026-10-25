#include "crypto.h"

#include <windows.h>
#include <bcrypt.h>
#include <dpapi.h>

#include <cstring>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace p2px {

namespace {

// Algorithm handles are thread-safe and opened once.
struct Algs {
  BCRYPT_ALG_HANDLE sha = nullptr, hmac = nullptr, aes = nullptr;
  Algs() {
    BCryptOpenAlgorithmProvider(&sha, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    BCryptOpenAlgorithmProvider(&hmac, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BCryptOpenAlgorithmProvider(&aes, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(aes, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
  }
};

Algs& algs() {
  static Algs a;
  return a;
}

} // namespace

Bytes randomBytes(size_t n) {
  Bytes b(n);
  BCryptGenRandom(nullptr, b.data(), (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  return b;
}

Bytes sha256(const uint8_t* p, size_t n) {
  Bytes out(32);
  BCryptHash(algs().sha, nullptr, 0, (PUCHAR)p, (ULONG)n, out.data(), 32);
  return out;
}

Bytes hmacSha256(const Bytes& key, const std::string& msg) {
  Bytes out(32);
  BCryptHash(algs().hmac, (PUCHAR)key.data(), (ULONG)key.size(), (PUCHAR)msg.data(), (ULONG)msg.size(), out.data(),
             32);
  return out;
}

Bytes aesGcmSeal(const Bytes& key, const Bytes& plain) {
  BCRYPT_KEY_HANDLE k = nullptr;
  if (BCryptGenerateSymmetricKey(algs().aes, &k, nullptr, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0) != 0)
    return {};
  Bytes out(12 + plain.size() + 16);
  Bytes nonce = randomBytes(12);
  memcpy(out.data(), nonce.data(), 12);
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
  BCRYPT_INIT_AUTH_MODE_INFO(info);
  info.pbNonce = out.data();
  info.cbNonce = 12;
  info.pbTag = out.data() + 12 + plain.size();
  info.cbTag = 16;
  ULONG done = 0;
  NTSTATUS st = BCryptEncrypt(k, (PUCHAR)plain.data(), (ULONG)plain.size(), &info, nullptr, 0, out.data() + 12,
                              (ULONG)plain.size(), &done, 0);
  BCryptDestroyKey(k);
  if (st != 0) return {};
  return out;
}

bool aesGcmOpen(const Bytes& key, const Bytes& sealed, Bytes& plain) {
  if (sealed.size() < 28) return false;
  BCRYPT_KEY_HANDLE k = nullptr;
  if (BCryptGenerateSymmetricKey(algs().aes, &k, nullptr, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0) != 0)
    return false;
  size_t n = sealed.size() - 28;
  plain.assign(n, 0);
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
  BCRYPT_INIT_AUTH_MODE_INFO(info);
  info.pbNonce = (PUCHAR)sealed.data();
  info.cbNonce = 12;
  info.pbTag = (PUCHAR)sealed.data() + 12 + n;
  info.cbTag = 16;
  ULONG done = 0;
  NTSTATUS st = BCryptDecrypt(k, (PUCHAR)sealed.data() + 12, (ULONG)n, &info, nullptr, 0, plain.data(), (ULONG)n,
                              &done, 0);
  BCryptDestroyKey(k);
  return st == 0;
}

Bytes dpapiProtect(const Bytes& plain) {
  DATA_BLOB in{(DWORD)plain.size(), (BYTE*)plain.data()}, out{};
  if (!CryptProtectData(&in, L"p2proxy", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) return {};
  Bytes b(out.pbData, out.pbData + out.cbData);
  LocalFree(out.pbData);
  return b;
}

bool dpapiUnprotect(const Bytes& sealed, Bytes& plain) {
  DATA_BLOB in{(DWORD)sealed.size(), (BYTE*)sealed.data()}, out{};
  if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) return false;
  plain.assign(out.pbData, out.pbData + out.cbData);
  LocalFree(out.pbData);
  return true;
}

std::string generateKey() { return base64(randomBytes(32), true); }

std::optional<Keys> Keys::derive(const std::string& secretIn) {
  std::string secret = trim(secretIn);
  if (secret.size() < 16) return std::nullopt;
  Bytes s(secret.begin(), secret.end());
  Keys k;
  k.secret = secret;
  // "p2px2_" keeps v2 signaling apart from the Go v1 topics.
  k.topic = "p2px2_" + hex(hmacSha256(s, "signal-topic")).substr(0, 40);
  k.aead = hmacSha256(s, "signal-aead");
  return k;
}

} // namespace p2px
