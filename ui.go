package main

import (
	_ "embed"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"time"
)

//go:embed ui.html
var uiPage []byte

// serveUI runs the local dashboard: status, speed test and updates.
func (c *client) serveUI(ln net.Listener) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(uiPage)
	})
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, c.status())
	})
	mux.HandleFunc("GET /api/speedtest", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, c.speed.snapshot())
	})
	mux.HandleFunc("POST /api/speedtest", func(w http.ResponseWriter, r *http.Request) {
		c.startSpeedTest()
		writeJSON(w, c.speed.snapshot())
	})
	mux.HandleFunc("POST /api/check", func(w http.ResponseWriter, r *http.Request) {
		if _, err := c.checkRelease(); err != nil {
			writeJSON(w, apiResult{Error: err.Error()})
			return
		}
		writeJSON(w, apiResult{OK: true})
	})
	mux.HandleFunc("POST /api/update", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("target") {
		case "client":
			if err := c.updateSelf(); err != nil {
				writeJSON(w, apiResult{Error: err.Error()})
				return
			}
			writeJSON(w, apiResult{OK: true, Message: "updated; restarting"})
			go func() {
				time.Sleep(time.Second)
				restartSelf()
			}()
		case "node":
			if err := c.updateNode(); err != nil {
				writeJSON(w, apiResult{Error: err.Error()})
				return
			}
			writeJSON(w, apiResult{OK: true, Message: "exit node updated; it is restarting"})
		default:
			http.Error(w, "unknown target", http.StatusBadRequest)
		}
	})
	srv := &http.Server{Handler: localOnly(mux), ReadHeaderTimeout: 10 * time.Second}
	log.Printf("dashboard stopped: %v", srv.Serve(ln))
}

// localOnly admits only our own page. The Host check defeats DNS rebinding;
// the custom header on state-changing requests cannot be added by another
// website without a CORS preflight, which is never approved.
func localOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if host != "127.0.0.1" && host != "localhost" && host != "::1" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-P2PX") != "1" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

type apiResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

type clientStatus struct {
	Version    string    `json:"version"`
	Connected  bool      `json:"connected"`
	Error      string    `json:"error,omitempty"`
	Remote     string    `json:"remote,omitempty"`
	Conns      int       `json:"conns"`
	UpSince    int64     `json:"up_since,omitempty"`
	RTTms      float64   `json:"rtt_ms"`
	Sent       uint64    `json:"sent"`
	Received   uint64    `json:"received"`
	Node       *nodeInfo `json:"node,omitempty"`
	Updates    bool      `json:"updates"`
	Latest     *release  `json:"latest,omitempty"`
	CheckError string    `json:"check_error,omitempty"`
	Updating   bool      `json:"updating"`
}

func (c *client) status() clientStatus {
	s := clientStatus{Version: version, Updates: updatesEnabled() == nil, Updating: c.updating.Load()}
	c.mu.Lock()
	conns := c.conns
	s.Error, s.Node = c.lastErr, c.node
	if len(conns) > 0 {
		s.Connected, s.Conns, s.Remote = true, len(conns), conns[0].RemoteAddr().String()
		s.UpSince = c.upSince.Unix()
	}
	c.mu.Unlock()
	for i, conn := range conns {
		st := conn.ConnectionStats()
		if i == 0 {
			s.RTTms = float64(st.SmoothedRTT.Microseconds()) / 1000
		}
		s.Sent += st.BytesSent
		s.Received += st.BytesReceived
	}
	c.relMu.Lock()
	s.Latest, s.CheckError = c.latest, c.checkErr
	c.relMu.Unlock()
	return s
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}
