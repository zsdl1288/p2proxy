#include "app.h"

#include <fstream>
#include <sstream>

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

void App::shutdown() { stopRole(); }

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
