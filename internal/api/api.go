// Package api implements the REST HTTP API (docs/API.md) and serves the
// embedded web UI. All API endpoints except /api/login and /api/health
// require a bearer session token; admin-only endpoints enforce the admin role
// and user-scoped queries filter by the user's allowed devices.
package api

import (
	"context"
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

const sessionTTL = 12 * time.Hour

// minPasswordLen is the minimum acceptable password length (enforced on
// self-service password change; admin creation keeps its own policy).
const minPasswordLen = 6

// Server wires the store, receiver and HTTP console together.
type Server struct {
	Store   *store.Store
	RX      *receiver.Receiver
	Started time.Time
	DBPath  string
}

type ctxKey int

const userKey ctxKey = 0

// userFrom extracts the authenticated user from the request context.
func userFrom(r *http.Request) *store.User {
	u, _ := r.Context().Value(userKey).(*store.User)
	return u
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// public
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("GET /api/health", s.handleHealth)
	// authenticated
	mux.HandleFunc("POST /api/logout", s.auth(s.handleLogout))
	mux.HandleFunc("GET /api/me", s.auth(s.handleMe))
	mux.HandleFunc("PUT /api/me/password", s.auth(s.handleChangePassword))
	mux.HandleFunc("GET /api/stats", s.auth(s.handleStats))
	mux.HandleFunc("GET /api/logs", s.auth(s.handleLogs))
	mux.HandleFunc("GET /api/logs/{id}", s.auth(s.handleLogByID))
	mux.HandleFunc("GET /api/devices", s.auth(s.handleDevicesGet))
	// admin
	mux.HandleFunc("PUT /api/devices", s.admin(s.handleDevicesPut))
	mux.HandleFunc("DELETE /api/devices/{id}", s.admin(s.handleDevicesDelete))
	mux.HandleFunc("GET /api/users", s.admin(s.handleUsersGet))
	mux.HandleFunc("PUT /api/users", s.admin(s.handleUsersPut))
	mux.HandleFunc("DELETE /api/users/{id}", s.admin(s.handleUsersDelete))
	mux.HandleFunc("PUT /api/users/{id}", s.admin(s.handleUsersUpdate))
	mux.HandleFunc("GET /api/config", s.admin(s.handleConfigGet))
	mux.HandleFunc("PUT /api/config", s.admin(s.handleConfigPut))
	mux.HandleFunc("POST /api/maintenance/retention", s.admin(s.handleRetention))
	mux.Handle("/", http.FileServer(http.FS(web.FS)))
	return logMiddleware(mux)
}

/* ---------------- auth middleware ---------------- */

// auth requires a valid bearer token.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken(r)
		if tok == "" {
			writeErr(w, http.StatusUnauthorized, "missing token")
			return
		}
		u, err := s.Store.GetUserByToken(tok)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if u == nil {
			writeErr(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		ctx := context.WithValue(r.Context(), userKey, u)
		next(w, r.WithContext(ctx))
	}
}

// admin requires an admin-role session.
func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request) {
		u := userFrom(r)
		if u.Role != store.RoleAdmin {
			writeErr(w, http.StatusForbidden, "admin required")
			return
		}
		next(w, r)
	})
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return ""
}

// allowedDevices returns the user's device scope: nil = unrestricted (admin
// or "*"), otherwise the allowed device names.
func allowedDevices(u *store.User) []string {
	if u == nil || u.Role == store.RoleAdmin {
		return nil
	}
	devs := strings.TrimSpace(u.Devices)
	if devs == "" || devs == "*" {
		return nil
	}
	var out []string
	for _, d := range strings.Split(devs, ",") {
		d = strings.TrimSpace(d)
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

/* ---------------- helpers ---------------- */

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

/* ---------------- auth handlers ---------------- */

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	u, err := s.Store.GetUserByUsername(strings.TrimSpace(in.Username))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if u == nil || !store.CheckPassword(u.PassHash, in.Password) {
		writeErr(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	tok, err := s.Store.CreateSession(u.ID, sessionTTL)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("login", "user", u.Username)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token": tok,
		"user":  publicUser(u),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	tok := bearerToken(r)
	if tok != "" {
		s.Store.DeleteSession(tok)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, publicUser(userFrom(r)))
}

// handleChangePassword lets an authenticated user change their own password.
// The old password must be supplied (verified against the stored hash) and
// the new password must meet the minimum length. All other sessions of the
// user are revoked so a stolen token dies with the old password.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	u := userFrom(r)
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	// GetUserByToken blanks PassHash, so fetch the hash-carrying row to
	// verify the current password.
	full, err := s.Store.GetUserByUsername(u.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if full == nil || in.OldPassword == "" || !store.CheckPassword(full.PassHash, in.OldPassword) {
		writeErr(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	if len(in.NewPassword) < minPasswordLen {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("new password must be at least %d characters", minPasswordLen))
		return
	}
	if in.NewPassword == in.OldPassword {
		writeErr(w, http.StatusBadRequest, "new password must differ from the current password")
		return
	}
	if err := s.Store.UpdateUser(u.ID, "", "", in.NewPassword); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Keep the current session, revoke every other one.
	tok := bearerToken(r)
	if tok != "" {
		if err := s.Store.DeleteSessionsExcept(u.ID, tok); err != nil {
			slog.Warn("change password: revoke other sessions", "user", u.Username, "err", err)
		}
	}
	slog.Info("password changed", "user", u.Username)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func publicUser(u *store.User) map[string]interface{} {
	return map[string]interface{}{
		"id":       u.ID,
		"username": u.Username,
		"role":     u.Role,
		"devices":  u.Devices,
	}
}

/* ---------------- data handlers ---------------- */

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":           true,
		"uptime_sec":   int64(time.Since(s.Started).Seconds()),
		"packets":      s.RX.Packets,
		"records":      s.RX.Records,
		"parse_errors": s.RX.ParseErrors,
		"dropped":      s.RX.Dropped,
		"listeners":    s.RX.Listeners(),
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	scope := allowedDevices(userFrom(r))
	// Optional ?device= narrows to one device (must be in scope).
	if d := r.URL.Query().Get("device"); d != "" {
		if scope != nil && !contains(scope, d) {
			writeErr(w, http.StatusForbidden, "device not in your scope")
			return
		}
		scope = []string{d}
	}
	st, err := s.Store.Stats(s.counters(), time.Since(s.Started), scope)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
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
	u := userFrom(r)
	scope := allowedDevices(u)
	lq := store.LogQuery{
		Kind:   q.Get("kind"),
		Q:      q.Get("q"),
		SrcIP:  q.Get("src_ip"),
		DstIP:  q.Get("dst_ip"),
		Domain: q.Get("domain"),
		Order:  q.Get("order"),
	}
	if d := q.Get("device"); d != "" {
		if scope != nil && !contains(scope, d) {
			writeErr(w, http.StatusForbidden, "device not in your scope")
			return
		}
		lq.Device = d
	} else if scope != nil {
		lq.Devices = scope
	}
	var err error
	if lq.Limit, err = strconv.Atoi(q.Get("limit")); err != nil || lq.Limit <= 0 {
		lq.Limit = 100
	}
	if lq.Offset, err = strconv.Atoi(q.Get("offset")); err != nil || lq.Offset < 0 {
		lq.Offset = 0
	}
	// Default the lower time bound to the last hour when the caller does not
	// ask for one, so a bare /api/logs cannot trigger a full-table scan.
	// Pass from=0 (or any explicit value) to override, e.g. to browse history.
	if q.Get("from") == "" {
		lq.From = time.Now().Add(-time.Hour).Unix()
	} else if lq.From, err = parseTimeParam(q.Get("from"), 0); err != nil {
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
	// Scope check: a user may not read rows of devices they cannot see.
	if scope := allowedDevices(userFrom(r)); scope != nil && !contains(scope, e.Device) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, e)
}

/* ---------------- device CRUD ---------------- */

func (s *Server) handleDevicesGet(w http.ResponseWriter, r *http.Request) {
	devs, err := s.Store.ListDevices()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	scope := allowedDevices(userFrom(r))
	var out []store.Device
	for _, d := range devs {
		if scope != nil && !contains(scope, d.Name) {
			out = append(out, store.Device{ID: d.ID, Name: d.Name, Enabled: d.Enabled})
			continue // hide port details of out-of-scope devices
		}
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"devices": out})
}

func (s *Server) handleDevicesPut(w http.ResponseWriter, r *http.Request) {
	var d store.Device
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	if _, err := s.Store.UpsertDevice(d); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	slog.Info("device upsert", "name", d.Name, "port", d.Port, "enabled", d.Enabled)
	writeJSON(w, http.StatusOK, map[string]interface{}{"device": d})
}

func (s *Server) handleDevicesDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	if name, err := s.Store.DeleteDevice(id); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	} else {
		slog.Info("device deleted", "id", id, "name", name)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

/* ---------------- user CRUD (admin) ---------------- */

func (s *Server) handleUsersGet(w http.ResponseWriter, r *http.Request) {
	users, err := s.Store.ListUsers()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"users": users})
}

func (s *Server) handleUsersPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
		Devices  string `json:"devices"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	devs := strings.TrimSpace(in.Devices)
	if devs != "" && devs != "*" {
		devs = strings.Trim(devs, ",")
	}
	u, err := s.Store.CreateUser(store.User{
		Username: in.Username,
		Role:     in.Role,
		Devices:  devs,
	}, in.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	slog.Info("user created", "username", u.Username, "role", u.Role)
	writeJSON(w, http.StatusOK, map[string]interface{}{"user": publicUser(&u)})
}

func (s *Server) handleUsersUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var in struct {
		Role    string `json:"role"`
		Devices string `json:"devices"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	devs := strings.TrimSpace(in.Devices)
	if devs != "" && devs != "*" {
		devs = strings.Trim(devs, ",")
	}
	badDevice := ""
	if devs != "" && devs != "*" {
		// validate device names exist
		all, err := s.Store.ListDevices()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		names := map[string]bool{}
		for _, d := range all {
			names[d.Name] = true
		}
		for _, d := range strings.Split(devs, ",") {
			if !names[strings.TrimSpace(d)] {
				badDevice = d
				break
			}
		}
	}
	if badDevice != "" {
		writeErr(w, http.StatusBadRequest, "unknown device: "+badDevice)
		return
	}
	if err := s.Store.UpdateUser(id, in.Role, devs, in.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	slog.Info("user updated", "id", id)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleUsersDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	me := userFrom(r)
	if me.ID == id {
		writeErr(w, http.StatusBadRequest, "cannot delete your own account")
		return
	}
	if err := s.Store.DeleteUser(id); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	slog.Info("user deleted", "id", id)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

/* ---------------- config / maintenance ---------------- */

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
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"config":           cfg,
		"restart_required": in.HTTPAddr != "",
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