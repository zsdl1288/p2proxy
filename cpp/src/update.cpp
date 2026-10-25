#include "update.h"

#include <sodium.h>

#include <cstring>
#include <fstream>
#include <vector>

#include "crypto.h"
#include "signal.h"

namespace p2px {

namespace {

// The files that make up an installation, each published as its own release
// asset next to the zip.
const char* const kFiles[] = {"p2proxy.exe", "msquic.dll", "msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll"};

// P2PX_UPDATE_API replaces the GitHub API for tests; releases still need a
// valid signature.
std::string apiBase() {
  char buf[512];
  DWORD n = GetEnvironmentVariableA("P2PX_UPDATE_API", buf, sizeof buf);
  return n > 0 && n < sizeof buf ? std::string(buf, n) : "https://api.github.com";
}

std::wstring installDir() {
  std::wstring p = exePath();
  return p.substr(0, p.find_last_of(L"\\/"));
}

bool parseVersion(const std::string& v, int out[3]) {
  return sscanf_s(v.c_str(), "v%d.%d.%d", &out[0], &out[1], &out[2]) == 3;
}

bool startsWith(const std::string& s, const std::string& prefix) { return s.rfind(prefix, 0) == 0; }

// What the release workflow signs: the tag binds the checksums to one
// version, so an old release cannot be replayed as a new one.
std::string signedMessage(const std::string& tag, const std::string& sums) {
  return "p2proxy release " + tag + "\n" + sums;
}

} // namespace

bool updatesEnabled() { return strlen(P2PX_REPO) > 0 && strlen(P2PX_UPDATE_PUBKEY) > 0; }

bool allowedFetchUrl(const std::string& url) {
  return startsWith(url, "https://github.com/") || startsWith(url, "https://api.github.com/") ||
         startsWith(url, apiBase() + "/");
}

Fetcher directFetcher() {
  return [](const std::string& url, std::string& body, std::string& err) {
    auto r = httpRequest("GET", url, "", {"Accept: application/vnd.github+json"}, 60000);
    if (r.status != 200) {
      err = !r.err.empty() ? r.err : "download failed (HTTP " + std::to_string(r.status) + ")";
      return false;
    }
    body = std::move(r.body);
    return true;
  };
}

bool newerVersion(const std::string& a, const std::string& b) {
  int va[3], vb[3];
  if (!parseVersion(a, va)) return false;
  if (!parseVersion(b, vb)) return true;
  for (int i = 0; i < 3; i++)
    if (va[i] != vb[i]) return va[i] > vb[i];
  return false;
}

bool latestRelease(const Fetcher& fetch, Release& out, std::string& err) {
  if (!updatesEnabled()) {
    err = "this is a development build without updates";
    return false;
  }
  std::string body;
  if (!fetch(apiBase() + "/repos/" + P2PX_REPO + "/releases?per_page=30", body, err)) return false;
  try {
    bool found = false;
    for (auto& r : json::parse(body)) {
      std::string tag = r.value("tag_name", "");
      int v[3];
      if (r.value("draft", false) || r.value("prerelease", false) || !parseVersion(tag, v) || v[0] != 2) continue;
      if (found && !newerVersion(tag, out.tag)) continue;
      out = {tag, r.value("html_url", ""), {}};
      for (auto& a : r.value("assets", json::array()))
        out.assets[a.value("name", "")] = a.value("browser_download_url", "");
      found = true;
    }
    if (!found) err = "no v2 release found";
    return found;
  } catch (...) {
    err = "unexpected answer from GitHub";
    return false;
  }
}

bool installRelease(const Fetcher& fetch, const Release& rel, std::string& err) {
  Bytes pub;
  if (!updatesEnabled() || !unbase64(P2PX_UPDATE_PUBKEY, pub) || pub.size() != crypto_sign_PUBLICKEYBYTES) {
    err = "this build cannot verify updates";
    return false;
  }
  auto url = [&](const std::string& name) {
    auto it = rel.assets.find(name);
    return it == rel.assets.end() ? std::string() : it->second;
  };
  std::string sums, sig;
  if (url("checksums.txt").empty() || url("checksums.txt.sig").empty()) {
    err = "the release has no signed checksums";
    return false;
  }
  if (!fetch(url("checksums.txt"), sums, err) || !fetch(url("checksums.txt.sig"), sig, err)) return false;
  Bytes sigBytes;
  std::string msg = signedMessage(rel.tag, sums);
  if (sodium_init() < 0 || !unbase64(trim(sig), sigBytes) || sigBytes.size() != crypto_sign_BYTES ||
      crypto_sign_verify_detached(sigBytes.data(), (const unsigned char*)msg.data(), msg.size(), pub.data()) != 0) {
    err = "release signature is invalid; refusing to install";
    return false;
  }
  std::map<std::string, std::string> want; // file -> sha256
  size_t pos = 0;
  while (pos < sums.size()) {
    size_t nl = sums.find('\n', pos);
    std::string line = trim(sums.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos));
    pos = nl == std::string::npos ? sums.size() : nl + 1;
    size_t sp = line.find("  ");
    if (sp != std::string::npos) want[line.substr(sp + 2)] = line.substr(0, sp);
  }

  // Download and verify everything before touching the installation.
  std::wstring dir = installDir();
  std::vector<std::string> staged;
  auto unstage = [&] {
    for (auto& f : staged) DeleteFileW((dir + L"\\" + toWide(f) + L".new").c_str());
  };
  for (const char* f : kFiles) {
    if (!want.count(f) || url(f).empty()) {
      if (strcmp(f, "p2proxy.exe") == 0) {
        err = "the release has no p2proxy.exe";
        unstage();
        return false;
      }
      continue; // e.g. runtime DLLs left out of a release
    }
    std::string body;
    if (!fetch(url(f), body, err)) {
      err = std::string(f) + ": " + err;
      unstage();
      return false;
    }
    if (_stricmp(hex(sha256((const uint8_t*)body.data(), body.size())).c_str(), want[f].c_str()) != 0) {
      err = std::string(f) + " does not match the signed checksum; refusing to install";
      unstage();
      return false;
    }
    std::ofstream out(dir + L"\\" + toWide(f) + L".new", std::ios::binary | std::ios::trunc);
    out.write(body.data(), body.size());
    if (!out.good()) {
      err = "cannot write to " + toUtf8(dir) + " (move p2proxy to a folder you can write to)";
      unstage();
      return false;
    }
    staged.push_back(f);
  }

  // Running files cannot be overwritten on Windows, but they can be renamed
  // out of the way.
  std::vector<std::string> swapped;
  for (auto& f : staged) {
    std::wstring cur = dir + L"\\" + toWide(f);
    DeleteFileW((cur + L".old").c_str());
    bool had = GetFileAttributesW(cur.c_str()) != INVALID_FILE_ATTRIBUTES;
    if ((had && !MoveFileExW(cur.c_str(), (cur + L".old").c_str(), MOVEFILE_REPLACE_EXISTING)) ||
        !MoveFileExW((cur + L".new").c_str(), cur.c_str(), MOVEFILE_REPLACE_EXISTING)) {
      err = "could not replace " + f + " (error " + std::to_string(GetLastError()) + ")";
      for (auto& s : swapped) { // put the old files back
        std::wstring c = dir + L"\\" + toWide(s);
        MoveFileExW(c.c_str(), (c + L".new").c_str(), MOVEFILE_REPLACE_EXISTING);
        MoveFileExW((c + L".old").c_str(), c.c_str(), MOVEFILE_REPLACE_EXISTING);
      }
      if (had) MoveFileExW((cur + L".old").c_str(), cur.c_str(), MOVEFILE_REPLACE_EXISTING);
      unstage();
      return false;
    }
    swapped.push_back(f);
  }
  logf("installed %s (was %s)", rel.tag.c_str(), P2PX_VERSION);
  return true;
}

void cleanupOldFiles() {
  std::wstring dir = installDir();
  for (const char* f : kFiles) {
    std::wstring p = dir + L"\\" + toWide(f);
    DeleteFileW((p + L".old").c_str()); // fails harmlessly while the old process still runs
    DeleteFileW((p + L".new").c_str());
  }
}

} // namespace p2px
