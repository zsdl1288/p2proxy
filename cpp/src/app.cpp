#include "app.h"

#include <fstream>
#include <sstream>
#include <thread>

namespace p2px {

namespace {

constexpr wchar_t kRunKey[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t kRunValue[] = L"p2proxy";

std::wstring configPath() { return appDataDir() + L"\\config.json"; }

std::string protect(const std::string& s) {
  if (s.empty()) return {};
  return base64(dpapiProtect(Bytes(s.begin(), s.end())));
}

std::string unprotect(const std::string& s) {
  Bytes sealed, plain;
  if (s.empty() || !unbase64(s, sealed) || !dpapiUnprotect(sealed, plain)) return {};
  return std::string(plain.begin(), plain.end());
}

std::string exeName() {
  std::wstring p = exePath();
  return toUtf8(p.substr(p.find_last_of(L"\\/") + 1));
}

} // namespace

App& App::get() {
  static App app;
  return app;
}

void App::load() {
  std::lock_guard lk(mu_);
  std::ifstream f(configPath());
  if (f) {
    try {
      json j = json::parse(f);
      role_ = j.value("role", "");
      serverKey_ = unprotect(j.value("server_key", ""));
      clientKey_ = unprotect(j.value("client_key", ""));
      subToken_ = j.value("sub_token", "");
    } catch (...) {
      logf("config.json is unreadable; starting fresh");
    }
  }
  if (subToken_.empty()) subToken_ = hex(randomBytes(12));
}

void App::save() {
  json j = {{"role", role_},
            {"server_key", protect(serverKey_)},
            {"client_key", protect(clientKey_)},
            {"sub_token", subToken_}};
  std::ofstream f(configPath(), std::ios::trunc);
  f << j.dump(2);
}

void App::startRole() {
  std::lock_guard lk(mu_);
  roleError_.clear();
  std::string err;
  if (role_ == "server") {
    if (serverKey_.empty()) {
      serverKey_ = generateKey();
      save();
    }
    server_ = std::make_shared<Server>();
    server_->onUpdateRequest = [this] {
      std::string e;
      return updateSelf(e) ? std::string() : e;
    };
    if (!server_->start(serverKey_, err)) {
      roleError_ = err;
      logf("cannot start exit node: %s", err.c_str());
      server_.reset();
    }
  } else if (role_ == "client" && !clientKey_.empty()) {
    client_ = std::make_shared<Client>();
    if (!client_->start(clientKey_, socksPort, err)) {
      roleError_ = err;
      logf("cannot start client: %s", err.c_str());
      client_.reset();
    }
  }
}

void App::stopRole() {
  std::shared_ptr<Server> s;
  std::shared_ptr<Client> c;
  {
    std::lock_guard lk(mu_);
    s = std::move(server_);
    c = std::move(client_);
  }
  if (s) s->stop();
  if (c) c->stop();
}

void App::shutdown() {
  stopChecks_ = true;
  stopRole();
}

Fetcher App::fetcher() {
  std::shared_ptr<Client> c;
  {
    std::lock_guard lk(mu_);
    if (role_ == "client") c = client_;
    if (role_ == "client" && !c)
      return [](const std::string&, std::string&, std::string& err) {
        err = "not connected to an exit node";
        return false;
      };
  }
  if (!c) return directFetcher();
  // Nothing goes out directly from a client: the exit node downloads for us.
  return [c](const std::string& url, std::string& body, std::string& err) { return c->fetch(url, body, err); };
}

bool App::checkUpdates(std::string& err) {
  Release rel;
  bool ok = latestRelease(fetcher(), rel, err);
  std::lock_guard lk(updMu_);
  if (ok) {
    if (newerVersion(rel.tag, P2PX_VERSION) && rel.tag != latest_.tag)
      logf("p2proxy %s is available (running %s)", rel.tag.c_str(), P2PX_VERSION);
    latest_ = rel;
    checkErr_.clear();
  } else {
    checkErr_ = err;
  }
  return ok;
}

bool App::updateSelf(std::string& err) {
  if (updating_.exchange(true)) {
    err = "an update is already running";
    return false;
  }
  Release rel;
  bool ok = latestRelease(fetcher(), rel, err);
  if (ok && !newerVersion(rel.tag, P2PX_VERSION)) {
    err = std::string("already running the latest version (") + P2PX_VERSION + ")";
    ok = false;
  }
  if (ok) {
    logf("updating to %s", rel.tag.c_str());
    ok = installRelease(fetcher(), rel, err);
  }
  if (!ok) {
    logf("update failed: %s", err.c_str());
    updating_ = false;
    return false;
  }
  // Restart a moment later, so the answer to whoever asked gets out first.
  std::thread([this] {
    Sleep(1500);
    if (restartHook_) restartHook_();
  }).detach();
  return true;
}

bool App::updateNode(std::string& err) {
  auto c = client();
  if (!c) {
    err = "not connected to an exit node";
    return false;
  }
  if (!c->updateNode(err)) return false;
  logf("the exit node installed the update and is restarting");
  return true;
}

void App::startUpdateChecks() {
  if (!updatesEnabled()) return;
  std::thread([this] {
    for (int wait = 30; !stopChecks_;) {
      for (int i = 0; i < wait * 10 && !stopChecks_; i++) Sleep(100);
      if (stopChecks_) break;
      std::string err;
      // Hourly retries after a failure (e.g. the tunnel was down), else every 6 hours.
      wait = checkUpdates(err) ? 6 * 3600 : 3600;
    }
  }).detach();
}

json App::updateState() {
  std::lock_guard lk(updMu_);
  json j = {{"enabled", updatesEnabled()},
            {"current", P2PX_VERSION},
            {"latest", latest_.tag},
            {"latest_url", latest_.url},
            {"check_error", checkErr_},
            {"updating", updating_.load()}};
  if (auto c = client()) j["node_version"] = c->nodeVersion();
  return j;
}

bool App::setRole(const std::string& role, std::string& err) {
  if (role != "server" && role != "client" && !role.empty()) {
    err = "unknown role";
    return false;
  }
  stopRole();
  {
    std::lock_guard lk(mu_);
    role_ = role;
    save();
  }
  logf("role changed to %s", role.empty() ? "(none)" : role.c_str());
  startRole();
  return true;
}

bool App::setClientKey(const std::string& keyIn, std::string& err) {
  std::string key = trim(keyIn);
  if (!Keys::derive(key)) {
    err = "this does not look like a p2proxy key (copy it from the exit node)";
    return false;
  }
  stopRole();
  {
    std::lock_guard lk(mu_);
    clientKey_ = key;
    save();
  }
  startRole();
  return true;
}

void App::regenerateServerKey() {
  stopRole();
  {
    std::lock_guard lk(mu_);
    serverKey_ = generateKey();
    save();
  }
  logf("generated a new key; clients need the new key to connect");
  startRole();
}

bool App::autostart() {
  wchar_t buf[1024];
  DWORD len = sizeof buf;
  return RegGetValueW(HKEY_CURRENT_USER, kRunKey, kRunValue, RRF_RT_REG_SZ, nullptr, buf, &len) == ERROR_SUCCESS;
}

bool App::setAutostart(bool on) {
  if (!on) return RegDeleteKeyValueW(HKEY_CURRENT_USER, kRunKey, kRunValue) == ERROR_SUCCESS || !autostart();
  std::wstring cmd = L"\"" + exePath() + L"\" --minimized";
  return RegSetKeyValueW(HKEY_CURRENT_USER, kRunKey, kRunValue, REG_SZ, cmd.c_str(),
                         DWORD((cmd.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
}

std::shared_ptr<Client> App::client() {
  std::lock_guard lk(mu_);
  return client_;
}

std::string App::subscriptionUrl() {
  return "http://127.0.0.1:" + std::to_string(uiPort) + "/sub/" + subToken_ + ".yaml";
}

json App::state() {
  std::shared_ptr<Server> s;
  std::shared_ptr<Client> c;
  json j;
  {
    std::lock_guard lk(mu_);
    s = server_;
    c = client_;
    j = {{"version", P2PX_VERSION}, {"role", role_}, {"role_error", roleError_}};
    if (role_ == "server") j["server_key"] = serverKey_;
    if (role_ == "client") {
      j["client_key_set"] = !clientKey_.empty();
      j["subscription_url"] = subscriptionUrl();
    }
  }
  j["autostart"] = autostart();
  j["update"] = updateState();
  if (s) j["server"] = s->state();
  if (c) j["client"] = c->state();
  j["logs"] = recentLogs(150);
  return j;
}

bool App::subscription(const std::string& token, std::string& yaml) {
  {
    std::lock_guard lk(mu_);
    if (role_ != "client" || token != subToken_) return false;
  }
  std::ostringstream y;
  y << "# p2proxy " << P2PX_VERSION << ": all traffic goes through the exit node.\n"
    << "# If the tunnel drops, connections fail instead of going out directly.\n"
    << "mode: rule\n"
    << "log-level: info\n"
    << "ipv6: true\n"
    << "find-process-mode: always\n"
    << "tun:\n"
    << "  enable: true\n"
    << "  stack: mixed\n"
    << "  auto-route: true\n"
    << "  auto-detect-interface: true\n"
    << "  strict-route: true\n"
    << "  dns-hijack:\n"
    << "    - any:53\n"
    << "    - tcp://any:53\n"
    << "dns:\n"
    << "  enable: true\n"
    << "  ipv6: true\n"
    << "  enhanced-mode: fake-ip\n"
    << "  fake-ip-range: 198.18.0.1/16\n"
    << "  # Names are resolved on the exit node; the rare real lookup goes through the tunnel too.\n"
    << "  nameserver:\n"
    << "    - https://1.1.1.1/dns-query#P2P\n"
    << "  # Only for DIRECT, which is p2proxy's own connection to the exit node.\n"
    << "  direct-nameserver:\n"
    << "    - tls://1.1.1.1\n"
    << "proxies:\n"
    << "  - name: P2P\n"
    << "    type: socks5\n"
    << "    server: 127.0.0.1\n"
    << "    port: " << socksPort << "\n"
    << "    udp: true\n"
    << "proxy-groups:\n"
    << "  - name: p2proxy\n"
    << "    type: select\n"
    << "    proxies:\n"
    << "      - P2P\n"
    << "rules:\n"
    << "  - PROCESS-NAME," << exeName() << ",DIRECT\n"
    << "  - MATCH,p2proxy\n";
  yaml = y.str();
  return true;
}

} // namespace p2px
