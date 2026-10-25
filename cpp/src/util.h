#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace p2px {

using Bytes = std::vector<uint8_t>;

std::string toUtf8(const std::wstring& w);
std::wstring toWide(const std::string& s);

std::string hex(const uint8_t* p, size_t n);
inline std::string hex(const Bytes& b) { return hex(b.data(), b.size()); }
bool unhex(const std::string& s, Bytes& out);
std::string base64(const uint8_t* p, size_t n, bool url = false);
inline std::string base64(const Bytes& b, bool url = false) { return base64(b.data(), b.size(), url); }
bool unbase64(const std::string& s, Bytes& out); // accepts standard and URL alphabets

int64_t unixNow();
uint64_t msNow(); // monotonic milliseconds
std::string trim(const std::string& s);
std::string computerName();

// Folder for config, logs and WebView2 data: %APPDATA%\p2proxy, or
// %APPDATA%\p2proxy-<profile> with --profile (several copies on one machine).
std::wstring appDataDir();
void setProfile(const std::wstring& profile);
const std::wstring& profile();
std::wstring exePath();

// Log lines are kept in memory for the UI and appended to p2proxy.log.
void initLog();
void logf(const char* fmt, ...);
std::vector<std::string> recentLogs(size_t max);

} // namespace p2px
