#include "util.h"

#include <windows.h>
#include <shlobj.h>

#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <deque>
#include <mutex>

namespace p2px {

std::string toUtf8(const std::wstring& w) {
  if (w.empty()) return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
  std::string s(n, '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
  return s;
}

std::wstring toWide(const std::string& s) {
  if (s.empty()) return {};
  int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
  std::wstring w(n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
  return w;
}

std::string hex(const uint8_t* p, size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s(n * 2, '0');
  for (size_t i = 0; i < n; i++) {
    s[2 * i] = d[p[i] >> 4];
    s[2 * i + 1] = d[p[i] & 15];
  }
  return s;
}

bool unhex(const std::string& s, Bytes& out) {
  if (s.size() % 2) return false;
  out.clear();
  auto val = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < s.size(); i += 2) {
    int a = val(s[i]), b = val(s[i + 1]);
    if (a < 0 || b < 0) return false;
    out.push_back(uint8_t(a << 4 | b));
  }
  return true;
}

std::string base64(const uint8_t* p, size_t n, bool url) {
  const char* a = url ? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                      : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string s;
  size_t i = 0;
  for (; i + 2 < n; i += 3) {
    uint32_t v = (p[i] << 16) | (p[i + 1] << 8) | p[i + 2];
    s += a[v >> 18];
    s += a[(v >> 12) & 63];
    s += a[(v >> 6) & 63];
    s += a[v & 63];
  }
  if (i < n) {
    uint32_t v = p[i] << 16;
    if (i + 1 < n) v |= p[i + 1] << 8;
    s += a[v >> 18];
    s += a[(v >> 12) & 63];
    if (i + 1 < n) s += a[(v >> 6) & 63];
    if (!url) s += (i + 1 < n) ? "=" : "==";
  }
  return s;
}

bool unbase64(const std::string& s, Bytes& out) {
  out.clear();
  uint32_t v = 0;
  int bits = 0;
  for (char c : s) {
    int d;
    if (c >= 'A' && c <= 'Z') d = c - 'A';
    else if (c >= 'a' && c <= 'z') d = c - 'a' + 26;
    else if (c >= '0' && c <= '9') d = c - '0' + 52;
    else if (c == '+' || c == '-') d = 62;
    else if (c == '/' || c == '_') d = 63;
    else if (c == '=' || c == '\r' || c == '\n') continue;
    else return false;
    v = (v << 6) | d;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(uint8_t(v >> bits));
    }
  }
  return true;
}

int64_t unixNow() {
  using namespace std::chrono;
  return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

uint64_t msNow() { return GetTickCount64(); }

std::string trim(const std::string& s) {
  size_t a = s.find_first_not_of(" \t\r\n");
  if (a == std::string::npos) return {};
  size_t b = s.find_last_not_of(" \t\r\n");
  return s.substr(a, b - a + 1);
}

std::string computerName() {
  wchar_t buf[256];
  DWORD n = 256;
  if (!GetComputerNameW(buf, &n)) return "unknown";
  return toUtf8(std::wstring(buf, n));
}

namespace {
std::wstring g_profile;
}

void setProfile(const std::wstring& p) { g_profile = p; }
const std::wstring& profile() { return g_profile; }

std::wstring appDataDir() {
  PWSTR path = nullptr;
  std::wstring dir;
  if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &path))) {
    dir = std::wstring(path) + L"\\p2proxy" + (g_profile.empty() ? L"" : L"-" + g_profile);
    CoTaskMemFree(path);
  } else {
    dir = L".\\p2proxy-data";
  }
  CreateDirectoryW(dir.c_str(), nullptr);
  return dir;
}

std::wstring exePath() {
  wchar_t buf[MAX_PATH * 2];
  DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH * 2);
  return std::wstring(buf, n);
}

namespace {
std::mutex logMu;
std::deque<std::string> logLines;
FILE* logFile = nullptr;
} // namespace

void initLog() {
  std::wstring path = appDataDir() + L"\\p2proxy.log";
  WIN32_FILE_ATTRIBUTE_DATA fa;
  bool big = GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fa) && fa.nFileSizeLow > 5 * 1024 * 1024;
  logFile = _wfopen(path.c_str(), big ? L"w" : L"a");
}

void logf(const char* fmt, ...) {
  char msg[2048];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof msg, fmt, ap);
  va_end(ap);
  SYSTEMTIME t;
  GetLocalTime(&t);
  char line[2100];
  snprintf(line, sizeof line, "%04d-%02d-%02d %02d:%02d:%02d %s", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute,
           t.wSecond, msg);
  std::lock_guard lk(logMu);
  logLines.emplace_back(line);
  while (logLines.size() > 500) logLines.pop_front();
  if (logFile) {
    fprintf(logFile, "%s\n", line);
    fflush(logFile);
  }
  OutputDebugStringA(line);
  OutputDebugStringA("\n");
}

std::vector<std::string> recentLogs(size_t max) {
  std::lock_guard lk(logMu);
  size_t start = logLines.size() > max ? logLines.size() - max : 0;
  return {logLines.begin() + start, logLines.end()};
}

} // namespace p2px
