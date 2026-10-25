// p2proxy-sign manages the key that signs releases.
//
//   p2proxy-sign genkey
//       prints a new private key (keep it secret: GitHub secret UPDATE_SIGNING_KEY)
//       and its public key (GitHub variable UPDATE_PUBLIC_KEY)
//   p2proxy-sign -tag v2.1.0 checksums.txt
//       signs the checksums for that tag with the key in UPDATE_SIGNING_KEY,
//       writing checksums.txt.sig
//   p2proxy-sign pubkey
//       prints the public key that belongs to UPDATE_SIGNING_KEY
//   p2proxy-sign verify -tag v2.1.0 checksums.txt PUBLIC_KEY
//       checks checksums.txt.sig the way the app does before updating
//
// Keys are standard Ed25519: the private key is the base64 32-byte seed, so
// keys made by the old Go tool keep working.
#include <sodium.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

static std::string b64(const unsigned char* p, size_t n) {
  std::string s(sodium_base64_encoded_len(n, sodium_base64_VARIANT_ORIGINAL), '\0');
  sodium_bin2base64(s.data(), s.size(), p, n, sodium_base64_VARIANT_ORIGINAL);
  s.resize(strlen(s.c_str()));
  return s;
}

static bool readFile(const std::string& path, std::string& out) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return false;
  std::stringstream ss;
  ss << in.rdbuf();
  out = ss.str();
  return true;
}

int main(int argc, char** argv) {
  if (sodium_init() < 0) return 1;
  unsigned char seed[crypto_sign_SEEDBYTES], pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];

  if (argc == 6 && strcmp(argv[1], "verify") == 0 && strcmp(argv[2], "-tag") == 0) {
    std::string sums, sigText;
    unsigned char sig[crypto_sign_BYTES];
    size_t pkLen = 0, sigLen = 0;
    if (!readFile(argv[4], sums) || !readFile(std::string(argv[4]) + ".sig", sigText) ||
        sodium_base642bin(pk, sizeof pk, argv[5], strlen(argv[5]), " \r\n", &pkLen, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0 ||
        sodium_base642bin(sig, sizeof sig, sigText.data(), sigText.size(), " \r\n", &sigLen, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0 ||
        pkLen != sizeof pk || sigLen != sizeof sig) {
      fprintf(stderr, "cannot read the checksums, signature or public key\n");
      return 1;
    }
    std::string msg = std::string("p2proxy release ") + argv[3] + "\n" + sums;
    bool ok = crypto_sign_verify_detached(sig, (const unsigned char*)msg.data(), msg.size(), pk) == 0;
    printf("%s\n", ok ? "signature OK" : "signature INVALID");
    return ok ? 0 : 1;
  }

  if (argc == 2 && strcmp(argv[1], "genkey") == 0) {
    randombytes_buf(seed, sizeof seed);
    crypto_sign_seed_keypair(pk, sk, seed);
    printf("private (secret UPDATE_SIGNING_KEY): %s\n", b64(seed, sizeof seed).c_str());
    printf("public  (variable UPDATE_PUBLIC_KEY): %s\n", b64(pk, sizeof pk).c_str());
    return 0;
  }
  bool pubOnly = argc == 2 && strcmp(argv[1], "pubkey") == 0;
  if (!pubOnly && (argc != 4 || strcmp(argv[1], "-tag") != 0)) {
    fprintf(stderr, "usage: p2proxy-sign genkey | pubkey | -tag TAG FILE | verify -tag TAG FILE PUBLIC_KEY\n");
    return 2;
  }
  const char* key = getenv("UPDATE_SIGNING_KEY");
  size_t len = 0;
  if (!key || sodium_base642bin(seed, sizeof seed, key, strlen(key), " \r\n", &len, nullptr,
                                sodium_base64_VARIANT_ORIGINAL) != 0 ||
      len != sizeof seed) {
    fprintf(stderr, "UPDATE_SIGNING_KEY is missing or malformed\n");
    return 1;
  }
  crypto_sign_seed_keypair(pk, sk, seed);
  if (pubOnly) {
    printf("%s\n", b64(pk, sizeof pk).c_str());
    return 0;
  }
  std::string sums;
  if (!readFile(argv[3], sums)) {
    fprintf(stderr, "cannot read %s\n", argv[3]);
    return 1;
  }
  // Must match signedMessage in src/update.cpp.
  std::string msg = std::string("p2proxy release ") + argv[2] + "\n" + sums;
  unsigned char sig[crypto_sign_BYTES];
  crypto_sign_detached(sig, nullptr, (const unsigned char*)msg.data(), msg.size(), sk);
  std::ofstream out(std::string(argv[3]) + ".sig", std::ios::binary | std::ios::trunc);
  out << b64(sig, sizeof sig) << "\n";
  return out.good() ? 0 : 1;
}
