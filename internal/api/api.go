// Package api implements the REST HTTP API (docs/API.md) and serves the
// embedded web UI.
package api

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"palog/internal/receiver"
	"palog/internal/store"
	"palog/web"
)

type Server struct {
	Store   *store.Store
	RX      *receiver.Receiver
	Started time.Time
	DBPath  string
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/stats", s.handleStats)
	mux.HandleFunc("GET /api/logs", s.handleLogs)
	mux.HandleFunc("GET /api/logs/{id}", s.handleLogByID)
	mux.HandleFunc("GET /api/config", s.handleConfigGet)
	mux.HandleFunc("PUT /api/config", s.handleConfigPut)
	mux.HandleFunc("POST /api/maintenance/retention", s.handleRetention)
	mux.Handle("/", http.FileServer(http.FS(web.FS)))
	return logMiddleware(mux)
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			return
		}
		slog.Info("http", "method", r.Method, "path", r.URL.Path,
			"dur", time.Since(start).Round(time.Millisecond).String())
	})
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) counters() store.Counters {
	return store.Counters{
		Packets:     s.RX.Packets,
		Records:     s.RX.Records,
		ParseErrors: s.RX.ParseErrors,
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":           true,
		"uptime_sec":   int64(time.Since(s.Started).Seconds()),
		"packets":      s.RX.Packets,
		"records":      s.RX.Records,
		"parse_errors": s.RX.ParseErrors,
		"dropped":      s.RX.Dropped,
		"listen_udp":   s.RX.Addr(),
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	st, err := s.Store.Stats(s.counters(), time.Since(s.Started))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func parseTimeParam(v string, def int64) (int64, error) {
	if v == "" {
		return def, nil
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return n, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return 0, fmt.Errorf("bad time %q: %w", v, err)
	}
	return t.Unix(), nil
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	lq := store.LogQuery{
		Kind:   q.Get("kind"),
		Q:      q.Get("q"),
		SrcIP:  q.Get("src_ip"),
		DstIP:  q.Get("dst_ip"),
		Domain: q.Get("domain"),
		Order:  q.Get("order"),
	}
	var err error
	if lq.Limit, err = strconv.Atoi(q.Get("limit")); err != nil || lq.Limit <= 0 {
		lq.Limit = 100
	}
	if lq.Offset, err = strconv.Atoi(q.Get("offset")); err != nil || lq.Offset < 0 {
		lq.Offset = 0
	}
	if lq.From, err = parseTimeParam(q.Get("from"), 0); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if lq.To, err = parseTimeParam(q.Get("to"), 0); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	total, items, err := s.Store.Query(lq)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":  total,
		"limit":  lq.Limit,
		"offset": lq.Offset,
		"items":  items,
	})
}

func (s *Server) handleLogByID(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	e, err := s.Store.Get(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if e == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.Store.GetConfig(s.DBPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleConfigPut(w http.ResponseWriter, r *http.Request) {
	var in store.Config
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if err := s.Store.SetConfig(in); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cfg, err := s.Store.GetConfig(s.DBPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	restartRequired := false
	if in.ListenUDP != "" {
		s.RX.SetAddr(cfg.ListenUDP)
	}
	if in.HTTPAddr != "" {
		restartRequired = true // HTTP addr cannot hot-swap in-process
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"config":           cfg,
		"restart_required": restartRequired,
	})
}

func (s *Server) handleRetention(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.Store.GetConfig(s.DBPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	deleted, err := s.Store.ApplyRetention(cfg.RetentionDays)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"deleted": deleted})
}

// ServeStaticFiles proxies embed.FS overhead through fs.FS for tests.
var _ = fs.FS(web.FS)