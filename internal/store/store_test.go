package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sampleEntries() []Entry {
	now := time.Now().Unix()
	return []Entry{
		{RecvTS: now, Kind: "dnsquery", TS: now, SrcIP: "10.10.10.222", SrcPort: 53210,
			DstIP: "223.5.5.5", DstPort: 53, Proto: 17, Appid: -1, Domain: "edr.syslog.top",
			MAC: "00:e2:69:13:cd:4e", Raw: "dnsquery3 ..."},
		{RecvTS: now, Kind: "http", TS: now, SrcIP: "10.10.10.222", SrcPort: 51216,
			DstIP: "95.211.79.57", DstPort: 80, Proto: 6, Appid: 714,
			Host: "ehtracker.org", Path: "/announce", Method: "GET", User: "_NULL_USER_"},
		{RecvTS: now, Kind: "session", TS: now - 100, TSEnd: now - 50,
			SrcIP: "172.16.16.83", SrcPort: 64536, DstIP: "223.5.5.5", DstPort: 53,
			Proto: 17, Appid: 23, Iface: "eth2", Iface2: "eth1",
			Domain: "edr.syslog.top", BytesIn: 1794, BytesOut: 643,
			Counters: []uint32{2, 9, 0, 0}, Flags: "0100",
			Extra: map[string]string{"0x13": "c8000000"}, RecType: 0x48},
	}
}

func TestInsertAndQuery(t *testing.T) {
	s := openTest(t)
	if err := s.InsertBatch(sampleEntries()); err != nil {
		t.Fatalf("insert: %v", err)
	}
	total, items, err := s.Query(LogQuery{Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != 3 || len(items) != 3 {
		t.Fatalf("total=%d items=%d, want 3/3", total, len(items))
	}
	// default order: ts desc (session has the oldest ts)
	if items[0].Kind != "http" {
		t.Errorf("first item kind %s, want http", items[0].Kind)
	}
	// round-trip the structured fields
	var sess *Entry
	for i := range items {
		if items[i].Kind == "session" {
			sess = &items[i]
			break
		}
	}
	if sess == nil {
		t.Fatal("no session entry returned")
	}
	if sess.Domain != "edr.syslog.top" || sess.Iface2 != "eth1" || sess.Flags != "0100" {
		t.Errorf("session fields wrong: %+v", sess)
	}
	if len(sess.Counters) != 4 || sess.Counters[1] != 9 {
		t.Errorf("counters wrong: %v", sess.Counters)
	}
	if sess.Extra["0x13"] != "c8000000" {
		t.Errorf("extra wrong: %v", sess.Extra)
	}

	// kind filter
	total, items, err = s.Query(LogQuery{Kind: "dnsquery"})
	if err != nil || total != 1 || items[0].Domain != "edr.syslog.top" {
		t.Fatalf("kind filter: total=%d items=%v err=%v", total, items, err)
	}
	// free text q
	total, _, err = s.Query(LogQuery{Q: "95.211"})
	if err != nil || total != 1 {
		t.Fatalf("q filter: total=%d err=%v", total, err)
	}
	// q must not treat % as wildcard
	total, _, err = s.Query(LogQuery{Q: "%"})
	if err != nil || total != 0 {
		t.Fatalf("q percent escape: total=%d err=%v", total, err)
	}
	// src/dst/domain filters
	if total, _, _ = s.Query(LogQuery{SrcIP: "10.10.10.222"}); total != 2 {
		t.Errorf("src filter total=%d, want 2", total)
	}
	if total, _, _ = s.Query(LogQuery{Domain: "edr.syslog.top"}); total != 2 {
		t.Errorf("domain filter total=%d, want 2", total)
	}
	// pagination
	total, items, _ = s.Query(LogQuery{Limit: 2, Offset: 2})
	if total != 3 || len(items) != 1 {
		t.Errorf("pagination: total=%d len=%d", total, len(items))
	}
	// asc order (session has the oldest ts)
	_, items, _ = s.Query(LogQuery{Order: "asc"})
	if items[0].Kind != "session" {
		t.Errorf("asc order first=%s", items[0].Kind)
	}
	// Get by id
	e, err := s.Get(items[0].ID)
	if err != nil || e == nil || e.Kind != "session" {
		t.Fatalf("get by id: %v %+v", err, e)
	}
	if e2, _ := s.Get(999999); e2 != nil {
		t.Errorf("get missing id should return nil")
	}
}

func TestConfigAndRetention(t *testing.T) {
	s := openTest(t)
	cfg, err := s.GetConfig("/tmp/x.db")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddr != ":8080" || cfg.RetentionDays != 30 || cfg.DBPath != "/tmp/x.db" {
		t.Fatalf("defaults wrong: %+v", cfg)
	}
	if err := s.SetConfig(Config{HTTPAddr: ":9090", RetentionDays: 7}); err != nil {
		t.Fatal(err)
	}
	cfg, _ = s.GetConfig("/tmp/x.db")
	if cfg.HTTPAddr != ":9090" || cfg.RetentionDays != 7 {
		t.Fatalf("after set: %+v", cfg)
	}

	old := time.Now().Unix() - 40*86400
	if err := s.InsertBatch([]Entry{{RecvTS: old, Kind: "http", TS: old}}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertBatch(sampleEntries()); err != nil {
		t.Fatal(err)
	}
	deleted, err := s.ApplyRetention(30)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Errorf("deleted=%d, want 1", deleted)
	}
	total, _, _ := s.Query(LogQuery{})
	if total != 3 {
		t.Errorf("after retention total=%d, want 3", total)
	}
}

func TestStats(t *testing.T) {
	s := openTest(t)
	if err := s.InsertBatch(sampleEntries()); err != nil {
		t.Fatal(err)
	}
	st, err := s.Stats(Counters{Packets: 100, Records: 3, ParseErrors: 1}, 50*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.Total != 3 || st.Packets != 100 || st.ParseErrors != 1 {
		t.Errorf("basic stats wrong: %+v", st)
	}
	if len(st.Hourly) != 24 {
		t.Errorf("hourly buckets=%d, want 24", len(st.Hourly))
	}
}

func TestWarmup(t *testing.T) {
	s := openTest(t)
	if err := s.InsertBatch(sampleEntries()); err != nil {
		t.Fatal(err)
	}
	// Must run clean on an empty DB too (fresh deployment): every probe is
	// a COUNT(*) that returns exactly one row even with zero matches.
	if err := s.Warmup(); err != nil {
		t.Fatalf("warmup on populated db: %v", err)
	}
	empty := openTest(t)
	if err := empty.Warmup(); err != nil {
		t.Fatalf("warmup on empty db: %v", err)
	}
}

// TestWarmupProbesAreIndexBounded locks the invariant behind the live
// incident. Warmup runs on the store's single pooled connection
// (SetMaxOpenConns(1)); a probe that degrades to a full scan does not merely
// run slowly, it pins that connection for the whole scan and starves the
// receiver's per-second device reconcile (no UDP listeners get bound) and every
// DB-backed HTTP handler. The incident: a top-N `GROUP BY domain ... ORDER BY
// COUNT(*) DESC` probe scanned the entire ~19M-row idx_logs_domain (the planner
// ignores (ts, domain) for that shape) and wedged ingest for hours. Every probe
// must therefore be an index SEARCH.
func TestWarmupProbesAreIndexBounded(t *testing.T) {
	s := openTest(t)
	// Populate mostly out-of-window rows so the ts-bounded probes are highly
	// selective: an index is then the only sane plan, and a regression to a
	// full scan shows up plainly as "SCAN logs".
	old := time.Now().Unix() - 10*86400
	batch := make([]Entry, 0, 2000)
	for i := 0; i < 2000; i++ {
		batch = append(batch, Entry{RecvTS: old, Kind: "http", TS: old, Appid: i + 1})
	}
	if err := s.InsertBatch(batch); err != nil {
		t.Fatal(err)
	}

	for _, q := range warmupProbes(time.Now().Unix()-3600, time.Now().Unix()-24*3600) {
		plan := explainPlan(t, s, q)
		t.Logf("warmup probe plan: %s :: %s", plan, q)
		if strings.Contains(plan, "SCAN logs") {
			t.Fatalf("warmup probe must not full-scan logs\nplan: %s\nquery: %s", plan, q)
		}
		if !strings.Contains(plan, "SEARCH") {
			t.Fatalf("warmup probe must be an index SEARCH\nplan: %s\nquery: %s", plan, q)
		}
	}
}

func TestAggregateQueriesAreTsIndexBounded(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cases := []struct {
		q    string
		need string
	}{
		{
			q:    "SELECT kind, COUNT(*) FROM logs INDEXED BY idx_logs_ts_kind WHERE ts>=0 GROUP BY kind",
			need: "idx_logs_ts_kind",
		},
		{
			q:    "SELECT device, COUNT(*) FROM logs INDEXED BY idx_logs_ts_device WHERE ts>=0 AND device!='' GROUP BY device ORDER BY 2 DESC LIMIT 100",
			need: "idx_logs_ts_device",
		},
		{
			q:    "SELECT domain, COUNT(*) AS c FROM logs INDEXED BY idx_logs_ts_domain WHERE ts>=0 AND domain!='' GROUP BY domain ORDER BY c DESC, domain ASC LIMIT 10",
			need: "idx_logs_ts_domain",
		},
		{
			q:    "SELECT src_ip, COUNT(*) AS c FROM logs INDEXED BY idx_logs_ts_src WHERE ts>=0 AND src_ip!='' GROUP BY src_ip ORDER BY c DESC, src_ip ASC LIMIT 10",
			need: "idx_logs_ts_src",
		},
	}
	for _, c := range cases {
		plan := explainPlan(t, s, c.q)
		if !strings.Contains(plan, "SEARCH") {
			t.Fatalf("aggregate must be a SEARCH: plan=%s q=%s", plan, c.q)
		}
		if !strings.Contains(plan, c.need) {
			t.Fatalf("missing expected index %s in plan: plan=%s q=%s", c.need, plan, c.q)
		}
	}
}

// explainPlan returns the joined EXPLAIN QUERY PLAN details for query.
func explainPlan(t *testing.T, s *Store, query string) string {
	t.Helper()
	rows, err := s.db.Query("EXPLAIN QUERY PLAN " + query)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("scan plan row: %v", err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return strings.Join(details, " | ")
}

// TestOpenRecoversPoisonedWAL simulates the live-deployment incident: a
// long-running checkpoint left the WAL in a state where a newly started
// connection deadlocks on the write lock. Re-opening with the recovery
// checkpoint must still succeed and be able to run the startup
// aggregates.
func TestOpenRecoversPoisonedWAL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	// Phase 1: create + populate a WAL db, leaving the WAL file on disk.
	seed, err := Open(path)
	if err != nil {
		t.Fatalf("open seed: %v", err)
	}
	if err := seed.InsertBatch(sampleEntries()); err != nil {
		t.Fatalf("seed rows: %v", err)
	}
	// Leave rows in the WAL so a fresh open has to read it back: a RESTART
	// checkpoint does not truncate the file, it only resets the recovery
	// position — so the fresh Open must replay it and serve the rows.
	if _, err := seed.db.Exec("PRAGMA wal_checkpoint(RESTART);"); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	seed.Close()

	// Phase 2: the store must open cleanly on the persisted WAL and still
	// serve startup aggregates.
	s, err := Open(path)
	if err != nil {
		t.Fatalf("reopen on WAL db: %v", err)
	}
	defer s.Close()
	if err := s.Warmup(); err != nil {
		t.Fatalf("warmup after reopen: %v", err)
	}
	total, items, err := s.Query(LogQuery{Limit: 10})
	if err != nil {
		t.Fatalf("query after reopen: %v", err)
	}
	if total != 3 || len(items) != 3 {
		t.Fatalf("rows lost after reopen: total=%d items=%d, want 3/3", total, len(items))
	}
}

// ---- devices ----

func TestDevices(t *testing.T) {
	s := openTest(t)

	d1, err := s.UpsertDevice(Device{Name: "fw-1", Port: 40200, Enabled: true})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if d1.ID == 0 || d1.Name != "fw-1" || d1.Port != 40200 || !d1.Enabled {
		t.Fatalf("bad device after create: %+v", d1)
	}

	// upsert by same ID = update
	d1.Port = 50200
	d1.Enabled = false
	if _, err := s.UpsertDevice(d1); err != nil {
		t.Fatalf("upsert update: %v", err)
	}
	all, err := s.ListDevices()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Port != 50200 || all[0].Enabled {
		t.Fatalf("after update: %+v", all)
	}
	// disabled -> not in enabled list
	enabled, _ := s.ListEnabledDevices()
	if len(enabled) != 0 {
		t.Fatalf("enabled list: %+v", enabled)
	}
	// re-enable
	d1.Enabled = true
	s.UpsertDevice(d1)
	enabled, _ = s.ListEnabledDevices()
	if len(enabled) != 1 {
		t.Fatalf("enabled list after re-enable: %+v", enabled)
	}

	// duplicate name via new ID -> error from UNIQUE constraint
	if _, err := s.UpsertDevice(Device{Name: "fw-1", Port: 40201, Enabled: true}); err == nil {
		t.Fatal("expected error for duplicate device name")
	}

	// validation
	if _, err := s.UpsertDevice(Device{Name: "", Port: 1}); err == nil {
		t.Fatal("expected error for empty name")
	}
	if _, err := s.UpsertDevice(Device{Name: "x", Port: 70000}); err == nil {
		t.Fatal("expected error for bad port")
	}

	// count + delete
	if n, _ := s.CountDevices(); n != 1 {
		t.Fatalf("count=%d, want 1", n)
	}
	name, err := s.DeleteDevice(d1.ID)
	if err != nil || name != "fw-1" {
		t.Fatalf("delete: name=%q err=%v", name, err)
	}
	if n, _ := s.CountDevices(); n != 0 {
		t.Fatalf("count after delete=%d, want 0", n)
	}
	if _, err := s.DeleteDevice(d1.ID); err == nil {
		t.Fatal("expected error deleting missing device")
	}
}

// ---- users ----

func TestUsers(t *testing.T) {
	s := openTest(t)

	u, err := s.CreateUser(User{Username: "alice", Role: RoleUser, Devices: "fw-1,fw-2"}, "secret")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.ID == 0 {
		t.Fatalf("bad user: %+v", u)
	}
	// hash must be stored (not returned) and verify the password round-trips
	stored, err := s.GetUserByUsername("alice")
	if err != nil || stored == nil {
		t.Fatalf("get stored user: %v", err)
	}
	if stored.PassHash == "" || !CheckPassword(stored.PassHash, "secret") || CheckPassword(stored.PassHash, "nope") {
		t.Fatalf("bad stored hash: %+v", stored)
	}

	// duplicate username
	if _, err := s.CreateUser(User{Username: "alice", Role: RoleUser}, "x"); err == nil {
		t.Fatal("expected error for duplicate username")
	}
	// validation
	if _, err := s.CreateUser(User{Username: "", Role: RoleUser}, "x"); err == nil {
		t.Fatal("expected error for empty username")
	}
	if _, err := s.CreateUser(User{Username: "bob", Role: "root"}, "x"); err == nil {
		t.Fatal("expected error for bad role")
	}
	if _, err := s.CreateUser(User{Username: "bob2", Role: RoleUser}, ""); err == nil {
		t.Fatal("expected error for empty password")
	}

	// lookups
	got, err := s.GetUserByUsername("alice")
	if err != nil || got == nil || got.Role != RoleUser || got.Devices != "fw-1,fw-2" {
		t.Fatalf("get by username: %+v err=%v", got, err)
	}
	if n, _ := s.CountUsers(); n != 1 {
		t.Fatalf("count=%d, want 1", n)
	}
	users, err := s.ListUsers()
	if err != nil || len(users) != 1 {
		t.Fatalf("list users: %v %d", err, len(users))
	}

	// update role/devices/password
	if err := s.UpdateUser(u.ID, RoleAdmin, "fw-9", "newpass"); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = s.GetUser(u.ID)
	if got.Role != RoleAdmin || got.Devices != "fw-9" {
		t.Fatalf("after update: %+v", got)
	}
	// password verification goes through the username lookup (GetUser strips
	// the hash by design)
	withHash, err := s.GetUserByUsername("alice")
	if err != nil || !CheckPassword(withHash.PassHash, "newpass") {
		t.Fatalf("password update failed: %v", err)
	}

	// delete the only admin -> forbidden
	if err := s.DeleteUser(u.ID); err == nil {
		t.Fatal("expected error deleting last admin")
	}
	// add a second admin, then delete the first
	if _, err := s.CreateUser(User{Username: "root2", Role: RoleAdmin, Devices: "*"}, "p"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(u.ID); err != nil {
		t.Fatalf("delete with 2 admins: %v", err)
	}
	if n, _ := s.CountUsers(); n != 1 {
		t.Fatalf("count after delete=%d, want 1", n)
	}
}

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "hunter2") {
		t.Fatal("correct password rejected")
	}
	if CheckPassword(h, "hunter3") {
		t.Fatal("wrong password accepted")
	}
	if CheckPassword("garbage", "hunter2") {
		t.Fatal("malformed hash accepted")
	}
}

// ---- sessions ----

func TestSessions(t *testing.T) {
	s := openTest(t)
	u, err := s.CreateUser(User{Username: "carol", Role: RoleUser, Devices: "*"}, "pw")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.CreateSession(u.ID, time.Hour)
	if err != nil || len(tok) < 32 {
		t.Fatalf("create session: tok=%q err=%v", tok, err)
	}
	got, err := s.GetUserByToken(tok)
	if err != nil || got == nil || got.ID != u.ID {
		t.Fatalf("resolve token: %+v err=%v", got, err)
	}
	// unknown token
	if got, _ := s.GetUserByToken("bogus"); got != nil {
		t.Fatal("bogus token resolved")
	}
	// delete session
	if err := s.DeleteSession(tok); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetUserByToken(tok); got != nil {
		t.Fatal("token alive after delete")
	}
	// expiry: short TTL in the past
	tok2, _ := s.CreateSession(u.ID, -time.Minute)
	if got, _ := s.GetUserByToken(tok2); got != nil {
		t.Fatal("expired token resolved")
	}
	if err := s.CleanExpiredSessions(); err != nil {
		t.Fatal(err)
	}
}

// ---- device-scoped queries / stats ----

func devEntries() []Entry {
	now := time.Now().Unix()
	base := Entry{RecvTS: now, Kind: "dnsquery", TS: now, SrcIP: "10.0.0.1", SrcPort: 53210,
		DstIP: "223.5.5.5", DstPort: 53, Proto: 17, Appid: -1, Domain: "a.example.com"}
	weird := base
	weird.SrcIP = "10.0.0.2"
	weird.Domain = "b.example.com"
	base.Device = "fw-1"
	weird.Device = "fw-2"
	return []Entry{base, weird}
}

func TestDeviceScopedQuery(t *testing.T) {
	s := openTest(t)
	if err := s.InsertBatch(devEntries()); err != nil {
		t.Fatal(err)
	}

	// explicit device filter
	total, items, err := s.Query(LogQuery{Device: "fw-1"})
	if err != nil || total != 1 || items[0].Domain != "a.example.com" {
		t.Fatalf("device filter: total=%d items=%v err=%v", total, items, err)
	}
	// scope list (multi-user permission model)
	total, _, err = s.Query(LogQuery{Devices: []string{"fw-1"}})
	if err != nil || total != 1 {
		t.Fatalf("scope fw-1: total=%d err=%v", total, err)
	}
	total, _, err = s.Query(LogQuery{Devices: []string{"fw-1", "fw-2"}})
	if err != nil || total != 2 {
		t.Fatalf("scope both: total=%d err=%v", total, err)
	}
	total, _, err = s.Query(LogQuery{Devices: []string{"other"}})
	if err != nil || total != 0 {
		t.Fatalf("scope other: total=%d err=%v", total, err)
	}
	// empty Devices = unrestricted
	total, _, err = s.Query(LogQuery{})
	if err != nil || total != 2 {
		t.Fatalf("unrestricted: total=%d err=%v", total, err)
	}

	// stats respect scope
	st, err := s.Stats(Counters{Records: 2}, time.Hour, []string{"fw-1"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Total != 1 {
		t.Fatalf("stats scope total=%d, want 1", st.Total)
	}
	// unrestricted stats see both devices
	st, _ = s.Stats(Counters{Records: 2}, time.Hour, nil)
	if st.Total != 2 {
		t.Fatalf("unrestricted stats: total=%d, want 2", st.Total)
	}
}

// TestMigrateLegacyDB simulates a pre-multi-device database (logs without the
// device column, no devices/users tables) and verifies Open() upgrades it:
// the device column is added, a default "panabit" device is registered and
// existing rows are re-homed to it.
func TestMigrateLegacyDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	// build the old schema with raw sqlite and insert one row the old way
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	legacySchema := `CREATE TABLE logs (
	  id INTEGER PRIMARY KEY AUTOINCREMENT,
	  recv_ts INTEGER NOT NULL,
	  kind TEXT NOT NULL,
	  ts INTEGER NOT NULL,
	  ts_end INTEGER NOT NULL DEFAULT 0,
	  src_ip TEXT NOT NULL DEFAULT '',
	  src_port INTEGER NOT NULL DEFAULT 0,
	  dst_ip TEXT NOT NULL DEFAULT '',
	  dst_port INTEGER NOT NULL DEFAULT 0,
	  proto INTEGER NOT NULL DEFAULT 0,
	  mac TEXT NOT NULL DEFAULT '',
	  iface TEXT NOT NULL DEFAULT '',
	  iface2 TEXT NOT NULL DEFAULT '',
	  appid INTEGER NOT NULL DEFAULT -1,
	  domain TEXT NOT NULL DEFAULT '',
	  host TEXT NOT NULL DEFAULT '',
	  path TEXT NOT NULL DEFAULT '',
	  method TEXT NOT NULL DEFAULT '',
	  user TEXT NOT NULL DEFAULT '',
	  bytes_in INTEGER NOT NULL DEFAULT 0,
	  bytes_out INTEGER NOT NULL DEFAULT 0,
	  counters TEXT NOT NULL DEFAULT '',
	  flags TEXT NOT NULL DEFAULT '',
	  rec_type INTEGER NOT NULL DEFAULT 0,
	  extra TEXT NOT NULL DEFAULT '',
	  raw TEXT NOT NULL DEFAULT ''
	);
	CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
	INSERT INTO kv(key, value) VALUES('listen_udp', ':50444');
	INSERT INTO kv(key, value) VALUES('http_addr', ':9999');
	INSERT INTO kv(key, value) VALUES('retention_days', '30');`
	if _, err := legacy.Exec(legacySchema); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	now := time.Now().Unix()
	if _, err := legacy.Exec(`INSERT INTO logs
	  (recv_ts, kind, ts, src_ip, dst_ip, dst_port, proto, domain)
	  VALUES(?, 'dnsquery', ?, '10.0.0.1', '223.5.5.5', 53, 17, 'old.row.test')`,
		now, now); err != nil {
		t.Fatalf("legacy insert: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy: %v", err)
	}

	// now open with the new store: must migrate, not fail
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open migrated: %v", err)
	}
	defer s.Close()

	// default device created from legacy kv listen_udp
	devs, err := s.ListDevices()
	if err != nil || len(devs) != 1 {
		t.Fatalf("devices after migrate: %v err=%v", devs, err)
	}
	if devs[0].Name != DefaultDevice || devs[0].Port != 50444 || !devs[0].Enabled {
		t.Fatalf("default device wrong: %+v", devs[0])
	}

	// legacy row re-homed to the default device
	total, items, err := s.Query(LogQuery{Device: DefaultDevice})
	if err != nil || total != 1 {
		t.Fatalf("query default device: total=%d err=%v", total, err)
	}
	if items[0].Domain != "old.row.test" || items[0].Device != DefaultDevice {
		t.Fatalf("row not re-homed: %+v", items[0])
	}

	// legacy config survived into the kv store
	var httpAddr string
	if err := s.db.QueryRow(`SELECT value FROM kv WHERE key='http_addr'`).Scan(&httpAddr); err != nil {
		t.Fatalf("http_addr survived: %v", err)
	}
	if httpAddr != ":9999" {
		t.Fatalf("http_addr = %q, want :9999", httpAddr)
	}
}

func TestOfficialStats(t *testing.T) {
	s := openTest(t)
	if err := s.InsertBatch(devEntries()); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()

	// Default cheap (系统概况 auto-refresh): index-bounded aggregates —
	// trailing-hour COUNT+SUM, by_kind / by_device (tiny GROUP BYs the UI
	// panels need by default) and top-domain / top-src_ip probes via the
	// (ts, domain)/(ts, src_ip) composite indexes; no rankings, no
	// recent-rows materialization, so a large 1h row set stays fast.
	def, err := s.OfficialStats(Counters{ParseErrors: 1}, nil, 0, 0, false, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if def.Traffic.TotalRecords != 2 {
		t.Fatalf("default total=%d, want 2 (trailing hour)", def.Traffic.TotalRecords)
	}
	if len(def.IPRanking) != 0 || len(def.AppRanking) != 0 {
		t.Fatalf("cheap path must skip rankings: ip=%d app=%d",
			len(def.IPRanking), len(def.AppRanking))
	}
	if len(def.Recent) != 0 {
		t.Fatalf("cheap path must skip recent rows: %+v", def.Recent)
	}
	// by_kind is computed on the cheap path (small cardinality GROUP BY):
	// both devEntries rows share kind "dnsquery" → one entry, count 2.
	if len(def.Traffic.ByKind) != 1 || def.Traffic.ByKind["dnsquery"] != 2 {
		t.Fatalf("cheap path must compute by_kind: %+v", def.Traffic.ByKind)
	}
	// by_device: both devices present with one record each.
	if def.ByDevice["fw-1"] != 1 || def.ByDevice["fw-2"] != 1 {
		t.Fatalf("cheap path must compute by_device: %v", def.ByDevice)
	}
	// Top domains / top src IPs follow the trailing-hour bound.
	if len(def.TopDomains) != 2 || def.TopDomains[0].Count != 1 {
		t.Fatalf("cheap path must compute top domains: %v", def.TopDomains)
	}
	if len(def.TopSrcIP) != 2 {
		t.Fatalf("cheap path must compute top src ip: %v", def.TopSrcIP)
	}
	// Security.LastHour mirrors the traffic trailing-hour total.
	if def.Security.LastHour != 2 {
		t.Fatalf("security last hour=%d, want 2", def.Security.LastHour)
	}

	// Explicit window, no rank: traffic totals bounded to the window,
	// rankings and recent rows skipped (opt-in); by_kind / by_device /
	// top domains / top src ip follow the window.
	winNoRank, err := s.OfficialStats(Counters{}, nil, now-3600, now, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if winNoRank.Traffic.TotalRecords != 2 {
		t.Fatalf("window total=%d, want 2", winNoRank.Traffic.TotalRecords)
	}
	if len(winNoRank.IPRanking) != 0 || len(winNoRank.AppRanking) != 0 {
		t.Fatalf("window call without rank must skip rankings: %+v", winNoRank)
	}
	if len(winNoRank.Recent) != 0 {
		t.Fatalf("window call without full must skip recent rows: %+v", winNoRank)
	}
	if len(winNoRank.TopDomains) != 2 {
		t.Fatalf("window call must compute top domains: %v", winNoRank.TopDomains)
	}
	if winNoRank.ByDevice["fw-1"] != 1 || winNoRank.ByDevice["fw-2"] != 1 {
		t.Fatalf("window call must compute by_device: %v", winNoRank.ByDevice)
	}
	if winNoRank.Traffic.LastHour != winNoRank.Traffic.TotalRecords {
		t.Fatalf("window last_hour=%d total=%d, want equal",
			winNoRank.Traffic.LastHour, winNoRank.Traffic.TotalRecords)
	}

	// Explicit window + rank: 流量分析 default — rankings present,
	// extras skipped, last_hour mirrors the window total.
	custom, err := s.OfficialStats(Counters{}, nil, now-3600, now, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if custom.Traffic.TotalRecords != 2 {
		t.Fatalf("window total=%d, want 2", custom.Traffic.TotalRecords)
	}
	if len(custom.IPRanking) == 0 {
		t.Fatalf("ranked window call must compute ip ranking: %+v", custom)
	}
	if len(custom.AppRanking) != 0 {
		t.Fatalf("window call with no appid rows: app ranking should be empty, got %+v", custom)
	}
	if len(custom.Recent) != 0 {
		t.Fatalf("window call without full must skip recent rows: %+v", custom)
	}
	// rank path computes by_kind (GROUP BY over the window).
	// Both devEntries rows share kind "dnsquery" → one map entry, count 2.
	if len(custom.Traffic.ByKind) != 1 || custom.Traffic.ByKind["dnsquery"] != 2 {
		t.Fatalf("rank path must compute by_kind: %+v", custom.Traffic.ByKind)
	}
	if custom.Traffic.LastHour != custom.Traffic.TotalRecords {
		t.Fatalf("window last_hour=%d total=%d, want equal",
			custom.Traffic.LastHour, custom.Traffic.TotalRecords)
	}

	// full=true default: 系统概况 deep-dive — rankings + recent rows
	// present, all bounded to the trailing hour.
	fullDef, err := s.OfficialStats(Counters{ParseErrors: 1}, nil, 0, 0, true, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(fullDef.TopDomains) != 2 || fullDef.TopDomains[0].Value != "a.example.com" {
		t.Fatalf("top domains: %v", fullDef.TopDomains)
	}
	if len(fullDef.TopSrcIP) != 2 {
		t.Fatalf("top src ip: %v", fullDef.TopSrcIP)
	}
	if fullDef.ByDevice["fw-1"] != 1 || fullDef.ByDevice["fw-2"] != 1 {
		t.Fatalf("by device: %v", fullDef.ByDevice)
	}
	if len(fullDef.Recent) != 2 {
		t.Fatalf("recent: %d, want 2", len(fullDef.Recent))
	}

	// Out-of-range window: counts fall back to 0, no full-table scan.
	none, err := s.OfficialStats(Counters{}, nil, now-100000, now-99000, false, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if none.Traffic.TotalRecords != 0 || none.Traffic.LastHour != 0 ||
		none.Security.LastHour != 0 {
		t.Fatalf("out-of-range window leaked counts: %+v", none)
	}

	// Device scope still applies to the default path.
	scoped, err := s.OfficialStats(Counters{}, []string{"fw-1"}, 0, 0, true, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if scoped.Traffic.TotalRecords != 1 || scoped.ByDevice["fw-1"] != 1 {
		t.Fatalf("scoped default: total=%d by_device=%v",
			scoped.Traffic.TotalRecords, scoped.ByDevice)
	}
}

func TestAppNameOf(t *testing.T) {
	if got := AppNameOf(23); got != "SMTP" {
		t.Errorf("AppNameOf(23) = %q, want SMTP", got)
	}
	if got := AppNameOf(714); got != "HTTP-Alt" {
		t.Errorf("AppNameOf(714) = %q, want HTTP-Alt", got)
	}
	// unknown ids map to nothing (UI falls back to the raw id)
	if got := AppNameOf(42); got != "" {
		t.Errorf("AppNameOf(42) = %q, want empty", got)
	}
	if got := AppNameOf(-1); got != "" {
		t.Errorf("AppNameOf(-1) = %q, want empty", got)
	}
}

// ---- two-factor (TOTP) user state ----

func TestUserTFA(t *testing.T) {
	s := openTest(t)
	u, err := s.CreateUser(User{Username: "tfa1", Role: RoleUser, Devices: "*", TFARequired: true}, "pw123456")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !u.TFARequired || u.TFAEnabled || u.TFASecret != "" {
		t.Fatalf("created user TFA state: %+v", u)
	}

	// forced-required but not yet enrolled
	got, err := s.GetUser(u.ID)
	if err != nil || got == nil {
		t.Fatalf("get: %v", err)
	}
	if !got.TFARequired || got.TFAEnabled {
		t.Fatalf("pre-enroll user req=%v en=%v", got.TFARequired, got.TFAEnabled)
	}

	// enroll a secret -> TFAEnabled flips true
	if err := s.SetUserTFASecret(u.ID, "ABCDEFGHIJKLMNOP"); err != nil {
		t.Fatalf("set secret: %v", err)
	}
	got, _ = s.GetUser(u.ID)
	if !got.TFAEnabled {
		t.Fatalf("TFAEnabled false after enrolling secret")
	}

	// ListUsers reports the flags and must not leak the secret
	list, err := s.ListUsers()
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %d", err, len(list))
	}
	if !list[0].TFARequired || !list[0].TFAEnabled {
		t.Fatalf("ListUsers TFA flags: %+v", list[0])
	}
	if list[0].TFASecret != "" {
		t.Fatalf("ListUsers leaked secret: %q", list[0].TFASecret)
	}

	// GetUserByUsername carries the secret (login verification needs it)
	full, err := s.GetUserByUsername("tfa1")
	if err != nil || full == nil || full.TFASecret != "ABCDEFGHIJKLMNOP" || !full.TFAEnabled {
		t.Fatalf("by username secret: %+v err=%v", full, err)
	}

	// the force flag toggles independently of enrollment
	if err := s.SetUserTFARequired(u.ID, false); err != nil {
		t.Fatalf("clear required: %v", err)
	}
	got, _ = s.GetUser(u.ID)
	if got.TFARequired || !got.TFAEnabled {
		t.Fatalf("after clearing required: req=%v en=%v", got.TFARequired, got.TFAEnabled)
	}

	// clearing the secret disables enrollment
	if err := s.SetUserTFASecret(u.ID, ""); err != nil {
		t.Fatalf("clear secret: %v", err)
	}
	got, _ = s.GetUser(u.ID)
	if got.TFAEnabled {
		t.Fatalf("TFAEnabled true after clearing secret")
	}
}

// ---- TLS / captcha config ----

func TestConfigTLSAndCaptcha(t *testing.T) {
	s := openTest(t)
	cfg, err := s.GetConfig("/tmp/x.db")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLS || cfg.Captcha || cfg.TLSCert != "" || cfg.TLSKey != "" {
		t.Fatalf("TLS/captcha defaults must be off: %+v", cfg)
	}
	in := Config{
		HTTPAddr: ":8443", RetentionDays: 14,
		TLS: true, TLSCert: "CERTPEM", TLSKey: "KEYPEM", Captcha: true,
	}
	if err := s.SetConfig(in); err != nil {
		t.Fatal(err)
	}
	cfg, _ = s.GetConfig("/tmp/x.db")
	if !cfg.TLS || !cfg.Captcha || cfg.TLSCert != "CERTPEM" || cfg.TLSKey != "KEYPEM" ||
		cfg.HTTPAddr != ":8443" || cfg.RetentionDays != 14 {
		t.Fatalf("TLS/captcha round-trip failed: %+v", cfg)
	}
	// SetConfig is a full write: an empty cert clears it (the admin form
	// submits the whole config on every save).
	if err := s.SetConfig(Config{HTTPAddr: ":8443", RetentionDays: 14}); err != nil {
		t.Fatal(err)
	}
	cfg, _ = s.GetConfig("/tmp/x.db")
	if cfg.TLS || cfg.Captcha || cfg.TLSCert != "" || cfg.TLSKey != "" {
		t.Fatalf("cleared config not persisted: %+v", cfg)
	}
}

// ---- migration: pre-TFA users table ----

func TestMigrateUserTFA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-users.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	legacySchema := `CREATE TABLE users (
	  id INTEGER PRIMARY KEY AUTOINCREMENT,
	  username TEXT NOT NULL UNIQUE,
	  pass_hash TEXT NOT NULL,
	  role TEXT NOT NULL DEFAULT 'user',
	  devices TEXT NOT NULL DEFAULT '*',
	  created_at INTEGER NOT NULL
	);
	CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);`
	if _, err := legacy.Exec(legacySchema); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	hash, err := HashPassword("legacypw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(
		`INSERT INTO users(username, pass_hash, role, devices, created_at) VALUES(?,?,?,?,?)`,
		"olduser", hash, RoleAdmin, "*", time.Now().Unix()); err != nil {
		t.Fatalf("legacy user insert: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy: %v", err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open migrated: %v", err)
	}
	defer s.Close()

	// the legacy row survives with the new columns defaulted off
	u, err := s.GetUserByUsername("olduser")
	if err != nil || u == nil {
		t.Fatalf("legacy user lost: %v", err)
	}
	if u.TFARequired || u.TFAEnabled || u.TFASecret != "" {
		t.Fatalf("migrated user TFA state: %+v", u)
	}
	// the new columns are writable after migration
	if err := s.SetUserTFASecret(u.ID, "SEKRET"); err != nil {
		t.Fatalf("set secret after migrate: %v", err)
	}
	u, _ = s.GetUserByUsername("olduser")
	if !u.TFAEnabled || u.TFASecret != "SEKRET" {
		t.Fatalf("secret not stored after migrate: %+v", u)
	}
}
