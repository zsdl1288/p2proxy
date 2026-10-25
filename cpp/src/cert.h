#pragma once
#include <windows.h>
#include <wincrypt.h>

#include <string>

namespace p2px {

// The exit node's TLS certificate. It is self-signed; clients trust it
// because its SHA-256 fingerprint arrives in the key-authenticated signaling
// answer, not because of a certificate chain.
struct ServerCert {
  PCCERT_CONTEXT ctx = nullptr;
  std::string fingerprint; // hex SHA-256 of the DER certificate
};

bool createServerCert(ServerCert& out, std::string& err);
void freeServerCert(ServerCert& c);
std::string certFingerprint(PCCERT_CONTEXT c);

} // namespace p2px
