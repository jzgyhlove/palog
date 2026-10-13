package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"palog/internal/receiver"
	"palog/internal/store"
)

// newTestServer builds a full api.Server backed by a temp DB with two devices
// and two users (admin + scoped user).
func newTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	if _, err := st.UpsertDevice(store.Device{Name: "fw-1", Port: 40200, Enabled: true}); err != nil {
		t.Fatalf("device fw-1: %v", err)
	}
	if _, err := st.UpsertDevice(store.Device{Name: "fw-2", Port: 40201, Enabled: true}); err != nil {
		t.Fatalf("device fw-2: %v", err)
	}

	if _, err := st.CreateUser(store.User{Username: "admin", Role: store.RoleAdmin, Devices: "*"}, "adminpw"); err != nil {
		t.Fatalf("admin: %v", err)
	}
	if _, err := st.CreateUser(store.User{Username: "user1", Role: store.RoleUser, Devices: "fw-1"}, "userpw"); err != nil {
		t.Fatalf("user1: %v", err)
	}

	// seed rows: 2 on fw-1, 1 on fw-2
	now := time.Now().Unix()
	rows := []store.Entry{
		{Device: "fw-1", Kind: "dnsquery", TS: now, RecvTS: now, SrcIP: "10.0.0.1", DstIP: "8.8.8.8", DstPort: 53, Proto: 17, Domain: "a.fw1.test"},
		{Device: "fw-1", Kind: "http", TS: now - 10, RecvTS: now, SrcIP: "10.0.0.1", DstIP: "1.2.3.4", DstPort: 80, Proto: 6, Host: "b.fw1.test", Method: "GET"},
		{Device: "fw-2", Kind: "dnsquery", TS: now - 20, RecvTS: now, SrcIP: "10.0.0.2", DstIP: "9.9.9.9", DstPort: 53, Proto: 17, Domain: "c.fw2.test"},
	}
	if err := st.InsertBatch(rows); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rx := receiver.New(st, 128)
	srv := &Server{Store: st, RX: rx, Started: time.Now(), DBPath: "t.db"}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, st
}

func login(t *testing.T, ts *httptest.Server, user, pw string) (string, http.Header) {
	t.Helper()
	body := bytes.NewBufferString(`{"username":"` + user + `","password":"` + pw + `"}`)
	resp, err := http.Post(ts.URL+"/api/login", "application/json", body)
	if err != nil {
		t.Fatalf("login %s: %v", user, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login %s status %d", user, resp.StatusCode)
	}
	var out struct{ Token string }
	json.NewDecoder(resp.Body).Decode(&out)
	if out.Token == "" {
		t.Fatalf("login %s: empty token", user)
	}
	return out.Token, resp.Header
}

func doAuth(t *testing.T, method, url, token string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

func decode[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

func TestLoginAndAuth(t *testing.T) {
	ts, _ := newTestServer(t)

	// good login
	tokA, _ := login(t, ts, "admin", "adminpw")
	if len(tokA) < 32 {
		t.Fatalf("token too short: %q", tokA)
	}
	// wrong password
	resp := postJSON(ts.URL+"/api/login", `{"username":"admin","password":"nope"}`)
	if resp.StatusCode != 401 {
		t.Fatalf("wrong pw status %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// health is public
	resp2, _ := http.Get(ts.URL + "/api/health")
	if resp2.StatusCode != 200 {
		t.Fatalf("health status %d", resp2.StatusCode)
	}
	resp2.Body.Close()

	// stats requires auth
	resp3, _ := http.Get(ts.URL + "/api/stats")
	if resp3.StatusCode != 401 {
		t.Fatalf("stats without token status %d, want 401", resp3.StatusCode)
	}
	resp3.Body.Close()
	// garbage token
	resp4 := doAuth(t, "GET", ts.URL+"/api/stats", "bogus-token", nil)
	if resp4.StatusCode != 401 {
		t.Fatalf("stats with bogus token status %d, want 401", resp4.StatusCode)
	}
	resp4.Body.Close()

	// me round-trip
	me := decode[map[string]any](t, doAuth(t, "GET", ts.URL+"/api/me", tokA, nil))
	if me["username"] != "admin" || me["role"] != "admin" {
		t.Fatalf("me: %v", me)
	}

	// logout invalidates
	logoutResp := doAuth(t, "POST", ts.URL+"/api/logout", tokA, nil)
	logoutResp.Body.Close()
	resp5 := doAuth(t, "GET", ts.URL+"/api/me", tokA, nil)
	if resp5.StatusCode != 401 {
		t.Fatalf("me after logout status %d, want 401", resp5.StatusCode)
	}
	resp5.Body.Close()
}

func postJSON(url, body string) *http.Response {
	resp, err := http.Post(url, "application/json", bytes.NewBufferString(body))
	if err != nil {
		return resp
	}
	return resp
}

func TestOfficialStats(t *testing.T) {
	ts, st := newTestServer(t)
	atok, _ := login(t, ts, "admin", "adminpw")
	utok, _ := login(t, ts, "user1", "userpw")

	// seed a session row with known bytes and appid for ranking checks
	now := time.Now().Unix()
	if err := st.InsertBatch([]store.Entry{
		{Device: "fw-1", Kind: "session", TS: now, RecvTS: now,
			SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Proto: 6, Appid: 42,
			BytesIn: 1000, BytesOut: 2000},
		{Device: "fw-1", Kind: "session", TS: now, RecvTS: now,
			SrcIP: "10.0.0.2", DstIP: "2.2.2.2", Proto: 6, Appid: 42,
			BytesIn: 5000, BytesOut: 6000},
		{Device: "fw-1", Kind: "session", TS: now, RecvTS: now,
			SrcIP: "10.0.0.3", DstIP: "3.3.3.3", Proto: 6, Appid: 23,
			BytesIn: 100, BytesOut: 200},
	}); err != nil {
		t.Fatalf("seed session rows: %v", err)
	}

	// admin: cheap default (系统概况 auto-refresh path) — only the ts-bounded
	// COUNT+SUM and the tiny by_kind/by_device GROUP BYs plus the index-bounded
	// top-domain/top-src_ip probes run; rankings and recent-rows materialization
	// are skipped so the 10 s auto-refresh stays cheap on a large 1h row set.
	r := decode[map[string]any](t, doAuth(t, "GET", ts.URL+"/api/official-stats", atok, nil))
	traffic := r["traffic"].(map[string]any)
	if traffic["total_records"].(float64) < 5 {
		t.Fatalf("traffic.total_records = %v, want >= 5", traffic["total_records"])
	}
	// bytes_in should be at least 6000 (1000+5000 from the two session rows)
	if traffic["bytes_in"].(float64) < 6000 {
		t.Fatalf("traffic.bytes_in = %v, want >= 6000", traffic["bytes_in"])
	}
	// cheap default computes by_kind (small cardinality GROUP BY) so the
	// 日志类型分布 panel has data by default.
	if bk, ok := traffic["by_kind"].(map[string]any); !ok || len(bk) == 0 {
		t.Fatalf("cheap default must compute by_kind: %v", traffic["by_kind"])
	}
	// by_device / top domains / top src ip are computed on the cheap path too.
	if bd, ok := r["by_device"].(map[string]any); !ok || len(bd) == 0 {
		t.Fatalf("cheap default must compute by_device: %v", r["by_device"])
	}
	if td, ok := r["top_domains"].([]any); !ok || len(td) == 0 {
		t.Fatalf("cheap default must compute top_domains: %v", r["top_domains"])
	}
	if tsip, ok := r["top_src_ip"].([]any); !ok || len(tsip) == 0 {
		t.Fatalf("cheap default must compute top_src_ip: %v", r["top_src_ip"])
	}
	if ipr, ok := r["ip_ranking"].([]any); ok && len(ipr) != 0 {
		t.Fatalf("cheap default must skip ip_ranking: %v", r["ip_ranking"])
	}
	if appr, ok := r["app_ranking"].([]any); ok && len(appr) != 0 {
		t.Fatalf("cheap default must skip app_ranking: %v", r["app_ranking"])
	}
	if rc, ok := r["recent"].([]any); ok && len(rc) != 0 {
		t.Fatalf("cheap default must skip recent rows: %v", rc)
	}

	// admin: rank deep-dive (?rank=1) — by_kind + rankings present, recent
	// rows absent (bounded to the trailing hour without an explicit window).
	rr := decode[map[string]any](t, doAuth(t, "GET", ts.URL+"/api/official-stats?rank=1", atok, nil))
	if rrBK, ok := rr["traffic"].(map[string]any)["by_kind"].(map[string]any); !ok || len(rrBK) == 0 {
		t.Fatalf("?rank=1 must compute by_kind: %v", rr["traffic"])
	}
	if rrIPs, ok := rr["ip_ranking"].([]any); !ok || len(rrIPs) == 0 {
		t.Fatalf("?rank=1 must compute ip_ranking: %v", rr["ip_ranking"])
	}
	if rrEx, ok := rr["recent"].([]any); ok && len(rrEx) != 0 {
		t.Fatalf("?rank=1 without full must skip recent rows: %v", rrEx)
	}

	// 流量分析 path: explicit window + rank -> rankings computed within
	// the window, recent rows skipped.
	rw := decode[map[string]any](t, doAuth(t, "GET",
		ts.URL+"/api/official-stats?from="+strconv.FormatInt(now-3600, 10)+
			"&to="+strconv.FormatInt(now, 10)+"&rank=1", atok, nil))
	wTraffic := rw["traffic"].(map[string]any)
	if wTraffic["total_records"].(float64) < 5 {
		t.Fatalf("windowed total_records = %v, want >= 5", wTraffic["total_records"])
	}
	if rwIPs, ok := rw["ip_ranking"].([]any); ok && len(rwIPs) == 0 {
		t.Fatalf("windowed ?rank=1 call must compute ip_ranking")
	}
	if rwEx, ok := rw["recent"].([]any); ok && len(rwEx) != 0 {
		t.Fatalf("windowed call without full must skip recent rows: %v", rwEx)
	}

	// admin: full deep-dive (?full=1) — rankings + extras present.
	rf := decode[map[string]any](t, doAuth(t, "GET", ts.URL+"/api/official-stats?full=1", atok, nil))
	// ip_ranking: 10.0.0.2 should be present (5000 bytes in + 6000 out = 11000)
	ipRanking := rf["ip_ranking"].([]any)
	found := false
	for _, iv := range ipRanking {
		m := iv.(map[string]any)
		if m["ip"] == "10.0.0.2" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ip_ranking missing 10.0.0.2: %v", ipRanking)
	}
	// app_ranking: appid 42 (unmapped) should appear as the raw id;
	// appid 23 (mapped) should appear as its official name
	appRanking := rf["app_ranking"].([]any)
	appFound := false
	mappedFound := false
	for _, av := range appRanking {
		m := av.(map[string]any)
		if m["value"] == "42" {
			appFound = true
		}
		if m["value"] == "SMTP" {
			mappedFound = true
		}
	}
	if !appFound {
		t.Fatalf("app_ranking missing appid 42: %v", appRanking)
	}
	if !mappedFound {
		t.Fatalf("app_ranking missing mapped name for appid 23: %v", appRanking)
	}
	if rfEx, ok := rf["top_domains"].([]any); ok && len(rfEx) == 0 {
		t.Fatalf("?full=1 must compute top_domains: %v", rf)
	}

	// scoped user (fw-1 only): fw-2 rows must be excluded
	r2 := decode[map[string]any](t, doAuth(t, "GET", ts.URL+"/api/official-stats", utok, nil))
	traffic2 := r2["traffic"].(map[string]any)
	// fw-2 has one dnsquery row; scoped user should not see it in total_records
	// total_records should reflect only fw-1 rows (3 seed + 3 session)
	if traffic2["total_records"].(float64) > 6 {
		t.Fatalf("scoped total_records = %v, want <= 6 (fw-1 only)", traffic2["total_records"])
	}

	// out-of-scope device -> 403
	resp := doAuth(t, "GET", ts.URL+"/api/official-stats?device=fw-2", utok, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("official-stats device=fw-2 for user1 status %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestUserScopeIsolation(t *testing.T) {
	ts, _ := newTestServer(t)
	utok, _ := login(t, ts, "user1", "userpw")

	// user sees only fw-1 logs (2 of 3 rows)
	stats := decode[map[string]any](t, doAuth(t, "GET", ts.URL+"/api/stats", utok, nil))
	if stats["total"].(float64) != 2 {
		t.Fatalf("scoped stats total = %v, want 2 (only fw-1)", stats["total"])
	}
	// explicit out-of-scope device query -> 403
	resp := doAuth(t, "GET", ts.URL+"/api/stats?device=fw-2", utok, nil)
	if resp.StatusCode != 403 {
		t.Fatalf("stats device=fw-2 for user1 status %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
	// in-scope device query ok
	resp = doAuth(t, "GET", ts.URL+"/api/stats?device=fw-1", utok, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("stats device=fw-1 for user1 status %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// logs list: only fw-1 rows
	logs := decode[map[string]any](t, doAuth(t, "GET", ts.URL+"/api/logs", utok, nil))
	if logs["total"].(float64) != 2 {
		t.Fatalf("logs total = %v, want 2", logs["total"])
	}
	// admin sees all 3
	atok, _ := login(t, ts, "admin", "adminpw")
	logsA := decode[map[string]any](t, doAuth(t, "GET", ts.URL+"/api/logs", atok, nil))
	if logsA["total"].(float64) != 3 {
		t.Fatalf("admin logs total = %v, want 3", logsA["total"])
	}

	// detail in-scope available
	items := logs["items"].([]any)
	id := int64(items[0].(map[string]any)["id"].(float64))
	rOK := doAuth(t, "GET", ts.URL+"/api/logs/"+strconv.FormatInt(id, 10), utok, nil)
	if rOK.StatusCode != 200 {
		t.Fatalf("in-scope detail status %d", rOK.StatusCode)
	}
	rOK.Body.Close()

	// find the fw-2 row id via admin; out-of-scope detail -> 404 (privacy)
	itemsA := logsA["items"].([]any)
	var fw2id int64
	for _, it := range itemsA {
		m := it.(map[string]any)
		if m["device"] == "fw-2" {
			fw2id = int64(m["id"].(float64))
		}
	}
	if fw2id == 0 {
		t.Fatal("fw-2 row not found")
	}
	r404 := doAuth(t, "GET", ts.URL+"/api/logs/"+strconv.FormatInt(fw2id, 10), utok, nil)
	if r404.StatusCode != 404 {
		t.Fatalf("out-of-scope detail status %d, want 404", r404.StatusCode)
	}
	r404.Body.Close()

	// devices list for user: out-of-scope device must not expose port
	devs := decode[map[string]any](t, doAuth(t, "GET", ts.URL+"/api/devices", utok, nil))
	for _, dAny := range devs["devices"].([]any) {
		d := dAny.(map[string]any)
		if d["name"] == "fw-2" {
			if _, hasPort := d["port"]; hasPort {
				t.Fatalf("fw-2 port leaked to scoped user: %v", d)
			}
		}
	}
}

func TestLogsDefaultWindow(t *testing.T) {
	ts, st := newTestServer(t)
	atok, _ := login(t, ts, "admin", "adminpw")

	// seed an old row (2h ago) alongside the recent seeds
	old := time.Now().Add(-2 * time.Hour).Unix()
	if err := st.InsertBatch([]store.Entry{
		{Device: "fw-1", Kind: "dnsquery", TS: old, RecvTS: old, SrcIP: "10.0.0.9", DstIP: "8.8.8.8", DstPort: 53, Proto: 17, Domain: "old.fw1.test"},
	}); err != nil {
		t.Fatalf("seed old row: %v", err)
	}

	// bare /api/logs: default window = last 1h -> old row excluded
	logs := decode[map[string]any](t, doAuth(t, "GET", ts.URL+"/api/logs", atok, nil))
	if n := int(logs["total"].(float64)); n != 3 {
		t.Fatalf("default window total = %d, want 3 (old row excluded)", n)
	}
	for _, it := range logs["items"].([]any) {
		m := it.(map[string]any)
		if m["domain"] == "old.fw1.test" {
			t.Fatalf("old row leaked into default window: %v", m)
		}
	}

	// explicit from=0 -> no lower bound, old row visible again
	logsAll := decode[map[string]any](t, doAuth(t, "GET", ts.URL+"/api/logs?from=0", atok, nil))
	if n := int(logsAll["total"].(float64)); n != 4 {
		t.Fatalf("from=0 total = %d, want 4", n)
	}
}

func TestAdminEndpoints(t *testing.T) {
	ts, _ := newTestServer(t)
	utok, _ := login(t, ts, "user1", "userpw")
	atok, _ := login(t, ts, "admin", "adminpw")

	// non-admin -> all admin routes forbidden
	for _, route := range []struct{ m, p string }{
		{"GET", "/api/users"},
		{"PUT", "/api/users"},
		{"GET", "/api/config"},
		{"PUT", "/api/config"},
		{"DELETE", "/api/devices/1"},
	} {
		resp := doAuth(t, route.m, ts.URL+route.p, utok, nil)
		if resp.StatusCode != 403 {
			t.Fatalf("%s %s as user -> %d, want 403", route.m, route.p, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// admin: add device
	resp := doAuth(t, "PUT", ts.URL+"/api/devices", atok,
		bytes.NewBufferString(`{"name":"fw-3","port":40300,"enabled":true}`))
	if resp.StatusCode != 200 {
		t.Fatalf("add device status %d: %s", resp.StatusCode, readAll(resp.Body))
	}
	resp.Body.Close()
	// duplicate device name -> 400
	resp = doAuth(t, "PUT", ts.URL+"/api/devices", atok,
		bytes.NewBufferString(`{"name":"fw-3","port":40301,"enabled":true}`))
	if resp.StatusCode != 400 {
		t.Fatalf("dup device status %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// admin: user CRUD
	resp = doAuth(t, "PUT", ts.URL+"/api/users", atok,
		bytes.NewBufferString(`{"username":"user2","password":"pw2","role":"user","devices":"fw-1,fw-2"}`))
	if resp.StatusCode != 200 {
		t.Fatalf("create user status %d: %s", resp.StatusCode, readAll(resp.Body))
	}
	resp.Body.Close()

	users := decode[map[string]any](t, doAuth(t, "GET", ts.URL+"/api/users", atok, nil))
	count := len(users["users"].([]any))
	if count != 3 {
		t.Fatalf("users count = %d, want 3", count)
	}
	// users list must not leak pass hashes
	for _, uAny := range users["users"].([]any) {
		u := uAny.(map[string]any)
		if _, has := u["pass_hash"]; has {
			t.Fatalf("pass_hash leaked in users list: %v", u)
		}
	}

	// admin: config get/put
	cfg := decode[map[string]any](t, doAuth(t, "GET", ts.URL+"/api/config", atok, nil))
	if cfg["http_addr"] != ":8080" {
		t.Fatalf("default config http_addr = %v", cfg["http_addr"])
	}
	resp = doAuth(t, "PUT", ts.URL+"/api/config", atok,
		bytes.NewBufferString(`{"retention_days":7}`))
	if resp.StatusCode != 200 {
		t.Fatalf("put config status %d", resp.StatusCode)
	}
	resp.Body.Close()

	// api can't delete your own account
	resp = doAuth(t, "DELETE", ts.URL+"/api/users/1", atok, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("delete own account status %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestDevicesCRUDApi(t *testing.T) {
	ts, _ := newTestServer(t)
	atok, _ := login(t, ts, "admin", "adminpw")

	// list devices
	devs := decode[map[string]any](t, doAuth(t, "GET", ts.URL+"/api/devices", atok, nil))
	if len(devs["devices"].([]any)) != 2 {
		t.Fatalf("devices count %d, want 2", len(devs["devices"].([]any)))
	}

	// update existing device (by id)
	resp := doAuth(t, "PUT", ts.URL+"/api/devices", atok,
		bytes.NewBufferString(`{"id":1,"name":"fw-1","port":41111,"enabled":false}`))
	if resp.StatusCode != 200 {
		t.Fatalf("update device status %d", resp.StatusCode)
	}
	resp.Body.Close()

	// delete device
	resp = doAuth(t, "DELETE", ts.URL+"/api/devices/2", atok, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("delete device status %d", resp.StatusCode)
	}
	resp.Body.Close()
	devs = decode[map[string]any](t, doAuth(t, "GET", ts.URL+"/api/devices", atok, nil))
	rem := devs["devices"].([]any)
	if len(rem) != 1 || rem[0].(map[string]any)["name"] != "fw-1" {
		t.Fatalf("after delete: %v", rem)
	}

	// delete missing -> 400
	resp = doAuth(t, "DELETE", ts.URL+"/api/devices/99", atok, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("delete missing status %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestChangePassword(t *testing.T) {
	ts, _ := newTestServer(t)
	utok, _ := login(t, ts, "user1", "userpw")

	// wrong current password -> 401
	resp := doAuth(t, "PUT", ts.URL+"/api/me/password", utok,
		bytes.NewBufferString(`{"old_password":"nope","new_password":"newpw123"}`))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong old pw status %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// new password too short -> 400
	resp = doAuth(t, "PUT", ts.URL+"/api/me/password", utok,
		bytes.NewBufferString(`{"old_password":"userpw","new_password":"abc"}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("short new pw status %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// new password equals old -> 400
	resp = doAuth(t, "PUT", ts.URL+"/api/me/password", utok,
		bytes.NewBufferString(`{"old_password":"userpw","new_password":"userpw"}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("same pw status %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// no auth -> 401
	resp = doAuth(t, "PUT", ts.URL+"/api/me/password", "",
		bytes.NewBufferString(`{"old_password":"userpw","new_password":"newpw123"}`))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth status %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// good change -> 200
	resp = doAuth(t, "PUT", ts.URL+"/api/me/password", utok,
		bytes.NewBufferString(`{"old_password":"userpw","new_password":"newpw123"}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("good change status %d, want 200: %s", resp.StatusCode, readAll(resp.Body))
	}
	resp.Body.Close()

	// old password no longer works → login returns 401
	resp = postJSON(ts.URL+"/api/login", `{"username":"user1","password":"userpw"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old pw login status %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// new password works
	tok2, _ := login(t, ts, "user1", "newpw123")
	if len(tok2) < 32 {
		t.Fatalf("new pw login token too short")
	}

	// subsequent wrong-old password attempts still rejected under new token
	resp = doAuth(t, "PUT", ts.URL+"/api/me/password", tok2,
		bytes.NewBufferString(`{"old_password":"userpw","new_password":"another1"}`))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-change old pw status %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// second login token dies after a password change: open two sessions,
	// change the password, other session must be revoked.
	tokA, _ := login(t, ts, "user1", "newpw123")
	tokB, _ := login(t, ts, "user1", "newpw123")
	resp = doAuth(t, "PUT", ts.URL+"/api/me/password", tokA,
		bytes.NewBufferString(`{"old_password":"newpw123","new_password":"finalpw99"}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second change status %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
	// tokA (the changer) stays valid
	resp = doAuth(t, "GET", ts.URL+"/api/me", tokA, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("changer token revoked, want 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	// tokB (other session) must be revoked
	resp = doAuth(t, "GET", ts.URL+"/api/me", tokB, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("other session token still valid, want 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func readAll(r io.Reader) string {
	b, _ := io.ReadAll(r)
	return strings.TrimSpace(string(b))
}

/* ---------------- two-factor (TOTP) ---------------- */

// TestTOTPVectors pins totpAt to the RFC 6238 appendix B SHA1 seed (the ASCII
// string "12345678901234567890"), truncated to the 6 digits the UI asks for.
func TestTOTPVectors(t *testing.T) {
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, c := range cases {
		got, err := totpAt(secret, time.Unix(c.unix, 0))
		if err != nil {
			t.Fatalf("totpAt(%d): %v", c.unix, err)
		}
		if got != c.want {
			t.Errorf("totpAt(%d) = %s, want %s", c.unix, got, c.want)
		}
	}
}

func TestTOTPRoundTrip(t *testing.T) {
	secret, err := newTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 32 {
		t.Fatalf("secret length = %d, want 32 (160-bit base32)", len(secret))
	}
	code, err := totpAt(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !verifyTOTP(secret, code) {
		t.Fatalf("current code %s rejected", code)
	}
	if verifyTOTP(secret, "abcdef") {
		t.Fatal("non-numeric code accepted")
	}
	if verifyTOTP(secret, "12345") {
		t.Fatal("short code accepted")
	}
	uri := otpauthURI("alice", secret)
	if !strings.HasPrefix(uri, "otpauth://totp/") || !strings.Contains(uri, "secret="+secret) {
		t.Fatalf("bad otpauth uri: %q", uri)
	}
	qr, err := qrDataURI(uri)
	if err != nil {
		t.Fatalf("qr: %v", err)
	}
	if !strings.HasPrefix(qr, "data:image/png;base64,") {
		t.Fatalf("qr not a png data uri: %.40s", qr)
	}
}

/* ---------------- login captcha ---------------- */

func mustGet(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

// solveCaptcha evaluates the "a + b = ?" style question the server issues.
func solveCaptcha(t *testing.T, q string) string {
	t.Helper()
	f := strings.Fields(q)
	if len(f) < 3 {
		t.Fatalf("bad captcha question %q", q)
	}
	a, err1 := strconv.Atoi(f[0])
	b, err2 := strconv.Atoi(f[2])
	if err1 != nil || err2 != nil {
		t.Fatalf("bad captcha operands %q", q)
	}
	var v int
	switch f[1] {
	case "+":
		v = a + b
	case "-":
		v = a - b
	case "×":
		v = a * b
	default:
		t.Fatalf("bad captcha op %q", f[1])
	}
	return strconv.Itoa(v)
}

func TestCaptchaFlow(t *testing.T) {
	ts, st := newTestServer(t)

	// off by default: the endpoint says so and login needs no challenge.
	r := decode[map[string]any](t, mustGet(t, ts.URL+"/api/captcha"))
	if r["enabled"] != false {
		t.Fatalf("captcha default enabled = %v, want false", r["enabled"])
	}
	login(t, ts, "admin", "adminpw")

	// enable it (the admin form persists the whole config in one PUT).
	if err := st.SetConfig(store.Config{HTTPAddr: ":8080", RetentionDays: 30, Captcha: true}); err != nil {
		t.Fatal(err)
	}
	r = decode[map[string]any](t, mustGet(t, ts.URL+"/api/captcha"))
	if r["enabled"] != true {
		t.Fatalf("captcha still disabled after enabling: %v", r)
	}
	id, _ := r["id"].(string)
	if id == "" || r["question"] == "" {
		t.Fatalf("captcha missing id/question: %v", r)
	}

	// login without the challenge -> 400
	resp := postJSON(ts.URL+"/api/login", `{"username":"admin","password":"adminpw"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("login without captcha status %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// wrong answer -> 400
	resp = postJSON(ts.URL+"/api/login",
		`{"username":"admin","password":"adminpw","captcha_id":"`+id+`","captcha_answer":"-99999"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("login wrong captcha status %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// fresh challenge + correct answer -> 200
	r = decode[map[string]any](t, mustGet(t, ts.URL+"/api/captcha"))
	id2, _ := r["id"].(string)
	ans := solveCaptcha(t, r["question"].(string))
	body := `{"username":"admin","password":"adminpw","captcha_id":"` + id2 + `","captcha_answer":"` + ans + `"}`
	resp = postJSON(ts.URL+"/api/login", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login with captcha status %d, want 200: %s", resp.StatusCode, readAll(resp.Body))
	}
	resp.Body.Close()

	// the challenge is single-use: replaying the same id -> 400
	resp = postJSON(ts.URL+"/api/login", body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("reused captcha status %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}

/* ---------------- two-factor enrollment / login ---------------- */

func TestTFAEndpoints(t *testing.T) {
	ts, st := newTestServer(t)
	utok, _ := login(t, ts, "user1", "userpw")
	atok, _ := login(t, ts, "admin", "adminpw")

	// enroll: setup returns a secret + QR but does NOT persist it.
	setup := decode[map[string]any](t, doAuth(t, "POST", ts.URL+"/api/me/tfa/setup", utok, nil))
	secret, _ := setup["secret"].(string)
	if secret == "" {
		t.Fatalf("setup missing secret: %v", setup)
	}
	if qr, _ := setup["qr"].(string); !strings.HasPrefix(qr, "data:image/png;base64,") {
		t.Fatalf("setup qr not a data uri: %v", setup["qr"])
	}

	// wrong code -> 400 and still not enrolled.
	resp := doAuth(t, "POST", ts.URL+"/api/me/tfa/enable", utok,
		bytes.NewBufferString(`{"secret":"`+secret+`","code":"000000"}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("enable wrong code status %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
	if me := decode[map[string]any](t, doAuth(t, "GET", ts.URL+"/api/me", utok, nil)); me["tfa_enabled"] != false {
		t.Fatalf("tfa_enabled true after failed enable: %v", me)
	}

	// correct code -> enrolled.
	code, _ := totpAt(secret, time.Now())
	resp = doAuth(t, "POST", ts.URL+"/api/me/tfa/enable", utok,
		bytes.NewBufferString(`{"secret":"`+secret+`","code":"`+code+`"}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable status %d, want 200: %s", resp.StatusCode, readAll(resp.Body))
	}
	resp.Body.Close()

	// login now demands a TOTP code.
	resp = postJSON(ts.URL+"/api/login", `{"username":"user1","password":"userpw"}`)
	var lr map[string]any
	json.NewDecoder(resp.Body).Decode(&lr)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || lr["totp_required"] != true {
		t.Fatalf("login without totp: status=%d body=%v", resp.StatusCode, lr)
	}
	// wrong code -> 401
	resp = postJSON(ts.URL+"/api/login", `{"username":"user1","password":"userpw","totp":"000000"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login wrong totp status %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
	// correct code -> 200
	code, _ = totpAt(secret, time.Now())
	resp = postJSON(ts.URL+"/api/login", `{"username":"user1","password":"userpw","totp":"`+code+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login with totp status %d, want 200: %s", resp.StatusCode, readAll(resp.Body))
	}
	resp.Body.Close()

	// disable re-checks the password.
	resp = doAuth(t, "POST", ts.URL+"/api/me/tfa/disable", utok, bytes.NewBufferString(`{"password":"wrong"}`))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disable wrong password status %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
	resp = doAuth(t, "POST", ts.URL+"/api/me/tfa/disable", utok, bytes.NewBufferString(`{"password":"userpw"}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disable status %d, want 200: %s", resp.StatusCode, readAll(resp.Body))
	}
	resp.Body.Close()
	// password alone logs in again.
	login(t, ts, "user1", "userpw")

	// admin forces 2FA on a new user -> login signals enrollment is required.
	resp = doAuth(t, "PUT", ts.URL+"/api/users", atok,
		bytes.NewBufferString(`{"username":"user2","password":"pw2","role":"user","devices":"fw-1","tfa_required":true}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create forced user status %d: %s", resp.StatusCode, readAll(resp.Body))
	}
	resp.Body.Close()
	resp = postJSON(ts.URL+"/api/login", `{"username":"user2","password":"pw2"}`)
	json.NewDecoder(resp.Body).Decode(&lr)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || lr["tfa_setup_required"] != true {
		t.Fatalf("forced-tfa login: status=%d body=%v", resp.StatusCode, lr)
	}

	// locate user2, enroll out-of-band, then admin reset clears enrollment
	// but keeps the force flag.
	var id2 int64
	for _, uAny := range decode[map[string]any](t, doAuth(t, "GET", ts.URL+"/api/users", atok, nil))["users"].([]any) {
		u := uAny.(map[string]any)
		if u["username"] == "user2" {
			if u["tfa_required"] != true {
				t.Fatalf("user2 not marked forced: %v", u)
			}
			id2 = int64(u["id"].(float64))
		}
	}
	if id2 == 0 {
		t.Fatal("user2 not found")
	}
	if err := st.SetUserTFASecret(id2, "ABCDEFGHIJKLMNOPQRSTUVWX"); err != nil {
		t.Fatal(err)
	}
	resp = doAuth(t, "PUT", ts.URL+"/api/users/"+strconv.FormatInt(id2, 10), atok,
		bytes.NewBufferString(`{"reset_tfa":true}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset_tfa status %d: %s", resp.StatusCode, readAll(resp.Body))
	}
	resp.Body.Close()
	for _, uAny := range decode[map[string]any](t, doAuth(t, "GET", ts.URL+"/api/users", atok, nil))["users"].([]any) {
		u := uAny.(map[string]any)
		if u["username"] == "user2" {
			if u["tfa_enabled"] != false {
				t.Fatalf("reset_tfa did not clear enrollment: %v", u)
			}
			if u["tfa_required"] != true {
				t.Fatalf("reset_tfa cleared the force flag: %v", u)
			}
		}
	}
}

/* ---------------- TLS config via the API ---------------- */

func TestConfigTLSViaAPI(t *testing.T) {
	ts, _ := newTestServer(t)
	atok, _ := login(t, ts, "admin", "adminpw")

	// the admin form submits the full config in one PUT.
	resp := doAuth(t, "PUT", ts.URL+"/api/config", atok,
		bytes.NewBufferString(`{"http_addr":":8443","retention_days":30,"tls":true,"tls_cert":"CERTPEM","tls_key":"KEYPEM","captcha":false}`))
	rr := decode[map[string]any](t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put tls config status %d: %v", resp.StatusCode, rr)
	}
	if rr["restart_required"] != true {
		t.Fatalf("first TLS save restart_required = %v, want true", rr["restart_required"])
	}
	cfg := decode[map[string]any](t, doAuth(t, "GET", ts.URL+"/api/config", atok, nil))
	if cfg["tls"] != true || cfg["tls_cert"] != "CERTPEM" || cfg["tls_key"] != "KEYPEM" {
		t.Fatalf("tls config not persisted: %v", cfg)
	}

	// an identical save is a no-op and needs no restart.
	resp2 := doAuth(t, "PUT", ts.URL+"/api/config", atok,
		bytes.NewBufferString(`{"http_addr":":8443","retention_days":30,"tls":true,"tls_cert":"CERTPEM","tls_key":"KEYPEM","captcha":false}`))
	rr2 := decode[map[string]any](t, resp2)
	if rr2["restart_required"] != false {
		t.Fatalf("no-op TLS save restart_required = %v, want false", rr2["restart_required"])
	}
}