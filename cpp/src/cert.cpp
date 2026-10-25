#include "cert.h"

#include <ncrypt.h>

#include "crypto.h"

#pragma comment(lib, "ncrypt.lib")

namespace p2px {

namespace {

// Schannel does the private-key work in LSASS, which cannot reach keys that
// live only in our process, so the key is persisted in the user's key store
// (the same approach msquic uses for its self-signed certificates).
constexpr wchar_t kContainer[] = L"p2proxy-server-key";

bool persistedKey(NCRYPT_KEY_HANDLE& key, std::string& err) {
  NCRYPT_PROV_HANDLE prov = 0;
  if (NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) {
    err = "cannot open the key storage provider";
    return false;
  }
  SECURITY_STATUS st = NCryptOpenKey(prov, &key, kContainer, 0, NCRYPT_SILENT_FLAG);
  if (st != ERROR_SUCCESS) {
    st = NCryptCreatePersistedKey(prov, &key, NCRYPT_RSA_ALGORITHM, kContainer, 0, NCRYPT_OVERWRITE_KEY_FLAG);
    if (st == ERROR_SUCCESS) {
      DWORD bits = 2048, usage = NCRYPT_ALLOW_ALL_USAGES;
      NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, sizeof bits, 0);
      NCryptSetProperty(key, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&usage, sizeof usage, 0);
      st = NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG);
    }
  }
  NCryptFreeObject(prov);
  if (st != ERROR_SUCCESS) {
    err = "cannot create the TLS key (" + std::to_string(st) + ")";
    return false;
  }
  return true;
}

} // namespace

std::string certFingerprint(PCCERT_CONTEXT c) { return hex(sha256(c->pbCertEncoded, c->cbCertEncoded)); }

bool createServerCert(ServerCert& out, std::string& err) {
  NCRYPT_KEY_HANDLE key = 0;
  if (!persistedKey(key, err)) return false;

  BYTE nameBuf[256];
  DWORD nameLen = sizeof nameBuf;
  if (!CertStrToNameW(X509_ASN_ENCODING, L"CN=p2proxy", CERT_X500_NAME_STR, nullptr, nameBuf, &nameLen, nullptr)) {
    NCryptFreeObject(key);
    err = "CertStrToName failed";
    return false;
  }
  CERT_NAME_BLOB subject{nameLen, nameBuf};

  CRYPT_KEY_PROV_INFO prov{};
  prov.pwszContainerName = (LPWSTR)kContainer;
  prov.pwszProvName = (LPWSTR)MS_KEY_STORAGE_PROVIDER;
  prov.dwFlags = NCRYPT_SILENT_FLAG;
  prov.dwKeySpec = AT_KEYEXCHANGE;

  CRYPT_ALGORITHM_IDENTIFIER alg{};
  alg.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;

  // Server-authentication EKU, as TLS stacks expect on a server certificate.
  LPSTR ekuOid = (LPSTR)szOID_PKIX_KP_SERVER_AUTH;
  CERT_ENHKEY_USAGE eku{1, &ekuOid};
  BYTE ekuBuf[64];
  DWORD ekuLen = sizeof ekuBuf;
  CryptEncodeObject(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, &eku, ekuBuf, &ekuLen);
  CERT_EXTENSION ext{(LPSTR)szOID_ENHANCED_KEY_USAGE, FALSE, {ekuLen, ekuBuf}};
  CERT_EXTENSIONS exts{1, &ext};

  SYSTEMTIME start, end;
  GetSystemTime(&start);
  FILETIME ft;
  SystemTimeToFileTime(&start, &ft);
  ULARGE_INTEGER t{ft.dwLowDateTime, ft.dwHighDateTime};
  t.QuadPart -= 24ull * 3600 * 10000000;            // valid since yesterday (clock skew)
  ft = {t.LowPart, t.HighPart};
  FileTimeToSystemTime(&ft, &start);
  t.QuadPart += 10ull * 365 * 24 * 3600 * 10000000; // ten years
  ft = {t.LowPart, t.HighPart};
  FileTimeToSystemTime(&ft, &end);

  out.ctx = CertCreateSelfSignCertificate(key, &subject, 0, &prov, &alg, &start, &end, &exts);
  NCryptFreeObject(key);
  if (!out.ctx) {
    err = "CertCreateSelfSignCertificate failed (" + std::to_string(GetLastError()) + ")";
    return false;
  }
  out.fingerprint = certFingerprint(out.ctx);
  return true;
}

void freeServerCert(ServerCert& c) {
  if (c.ctx) CertFreeCertificateContext(c.ctx);
  c.ctx = nullptr;
}

} // namespace p2px
