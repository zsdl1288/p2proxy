#include "netutil.h" // winsock2.h before windows.h

#include <httplib.h>

#include "app.h"
#include "web.h"

namespace p2px {

namespace {

std::string_view uiPage() {
  HRSRC r = FindResourceW(nullptr, MAKEINTRESOURCEW(101), RT_RCDATA);
  if (!r) return "ui.html is missing";
  HGLOBAL g = LoadResource(nullptr, r);
  return {(const char*)LockResource(g), SizeofResource(nullptr, r)};
}

void sendJson(httplib::Response& res, const json& j) {
  res.set_header("Cache-Control", "no-store");
  res.set_content(j.dump(), "application/json");
}

json body(const httplib::Request& req) {
  try {
    return json::parse(req.body);
  } catch (...) {
    return json::object();
  }
}

json result(bool ok, const std::string& err) {
  json j = {{"ok", ok}};
  if (!ok) j["error"] = err;
  return j;
}

} // namespace

WebServer::WebServer() = default;
WebServer::~WebServer() { stop(); }

bool WebServer::start(uint16_t port, std::string& err) {
  srv_ = std::make_unique<httplib::Server>();
  auto& s = *srv_;

  // Only our own page may drive the API: the Host check defeats DNS
  // rebinding, and the custom header on POSTs cannot be sent by other
  // websites without a CORS preflight, which is never approved.
  s.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
    std::string host = req.get_header_value("Host");
    host = host.substr(0, host.rfind(':'));
    if (host != "127.0.0.1" && host != "localhost") {
      res.status = 403;
      return httplib::Server::HandlerResponse::Handled;
    }
    if (req.method == "POST" && req.get_header_value("X-P2PX") != "1") {
      res.status = 403;
      return httplib::Server::HandlerResponse::Handled;
    }
    return httplib::Server::HandlerResponse::Unhandled;
  });

  s.Get("/", [](const httplib::Request&, httplib::Response& res) {
    auto page = uiPage();
    res.set_header("Cache-Control", "no-store");
    res.set_content(page.data(), page.size(), "text/html; charset=utf-8");
  });
  s.Get("/api/state", [](const httplib::Request&, httplib::Response& res) { sendJson(res, App::get().state()); });
  s.Post("/api/role", [](const httplib::Request& req, httplib::Response& res) {
    std::string err;
    bool ok = App::get().setRole(body(req).value("role", ""), err);
    sendJson(res, result(ok, err));
  });
  s.Post("/api/client/key", [](const httplib::Request& req, httplib::Response& res) {
    std::string err;
    bool ok = App::get().setClientKey(body(req).value("key", ""), err);
    sendJson(res, result(ok, err));
  });
  s.Post("/api/server/regenerate", [](const httplib::Request&, httplib::Response& res) {
    App::get().regenerateServerKey();
    sendJson(res, result(true, ""));
  });
  s.Post("/api/cc", [](const httplib::Request& req, httplib::Response& res) {
    std::string err;
    bool ok = App::get().setCongestionControl(body(req).value("cc", ""), err);
    sendJson(res, result(ok, err));
  });
  s.Post("/api/autostart", [](const httplib::Request& req, httplib::Response& res) {
    bool ok = App::get().setAutostart(body(req).value("enabled", false));
    sendJson(res, result(ok, "could not change the startup setting"));
  });
  s.Post("/api/update/check", [](const httplib::Request&, httplib::Response& res) {
    std::string err;
    bool ok = App::get().checkUpdates(err);
    sendJson(res, result(ok, err));
  });
  s.Post("/api/update/self", [](const httplib::Request&, httplib::Response& res) {
    std::string err;
    bool ok = App::get().updateSelf(err);
    sendJson(res, result(ok, err));
  });
  s.Post("/api/update/node", [](const httplib::Request&, httplib::Response& res) {
    std::string err;
    bool ok = App::get().updateNode(err);
    sendJson(res, result(ok, err));
  });
  s.Get("/api/speedtest", [](const httplib::Request&, httplib::Response& res) {
    auto c = App::get().client();
    sendJson(res, c ? c->speedState() : json{{"running", false}});
  });
  s.Post("/api/speedtest", [](const httplib::Request&, httplib::Response& res) {
    auto c = App::get().client();
    if (c) c->startSpeedTest();
    sendJson(res, c ? c->speedState() : json{{"running", false}, {"error", "not connected"}});
  });
  s.Get(R"(/sub/([0-9a-f]+)\.yaml)", [](const httplib::Request& req, httplib::Response& res) {
    std::string yaml;
    if (!App::get().subscription(req.matches[1], yaml)) {
      res.status = 404;
      return;
    }
    res.set_header("Content-Disposition", "attachment; filename=p2proxy.yaml");
    res.set_header("profile-update-interval", "24");
    res.set_content(yaml, "text/yaml; charset=utf-8");
  });

  if (!s.bind_to_port("127.0.0.1", port)) {
    err = "port 127.0.0.1:" + std::to_string(port) + " is in use (is p2proxy already running?)";
    return false;
  }
  th_ = std::thread([this] { srv_->listen_after_bind(); });
  return true;
}

void WebServer::stop() {
  if (srv_) srv_->stop();
  if (th_.joinable()) th_.join();
}

} // namespace p2px
