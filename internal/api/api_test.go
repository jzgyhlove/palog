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