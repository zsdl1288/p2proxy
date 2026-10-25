#pragma once
#include <functional>
#include <map>
#include <string>

namespace p2px {

struct Release {
  std::string tag, url;
  std::map<std::string, std::string> assets; // file name -> download URL
};

// Downloads one URL. A client fetches through its exit node, so updating
// sends nothing directly; the exit node fetches directly.
using Fetcher = std::function<bool(const std::string& url, std::string& body, std::string& err)>;
Fetcher directFetcher();

// Updates need the repository and signing key compiled in (release builds).
bool updatesEnabled();
// What an exit node agrees to download on a client's behalf.
bool allowedFetchUrl(const std::string& url);

// Finds the newest v2.x release that is neither a draft nor a prerelease.
bool latestRelease(const Fetcher& fetch, Release& out, std::string& err);
// Whether version a is newer than b; a development build is older than any release.
bool newerVersion(const std::string& a, const std::string& b);

// Downloads the release's files, checks them against the signed checksums and
// swaps them in for the running ones. The new version runs after a restart.
bool installRelease(const Fetcher& fetch, const Release& rel, std::string& err);
// Deletes the files a previous update set aside.
void cleanupOldFiles();

} // namespace p2px
