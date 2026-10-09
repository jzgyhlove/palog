package store

import (
	"database/sql"
	"path/filepath"
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
	if st.ByKind["dnsquery"] != 1 || st.ByKind["http"] != 1 || st.ByKind["session"] != 1 {
		t.Errorf("by_kind wrong: %v", st.ByKind)
	}
	if len(st.TopDomains) == 0 || st.TopDomains[0].Value != "edr.syslog.top" {
		t.Errorf("top domains wrong: %v", st.TopDomains)
	}
	if len(st.Hourly) != 24 {
		t.Errorf("hourly buckets=%d, want 24", len(st.Hourly))
	}
	if len(st.Recent) != 3 {
		t.Errorf("recent=%d, want 3", len(st.Recent))
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
	if st.ByDevice["fw-1"] != 1 || st.ByDevice["fw-2"] != 0 {
		t.Fatalf("by_device wrong: %v", st.ByDevice)
	}
	// unrestricted stats see both devices
	st, _ = s.Stats(Counters{Records: 2}, time.Hour, nil)
	if st.Total != 2 || st.ByDevice["fw-2"] != 1 {
		t.Fatalf("unrestricted stats: total=%d by_device=%v", st.Total, st.ByDevice)
	}
	// recent rows are scoped too
	st, _ = s.Stats(Counters{Records: 2}, time.Hour, []string{"fw-2"})
	if len(st.Recent) != 1 || st.Recent[0].Device != "fw-2" {
		t.Fatalf("scoped recent: %+v", st.Recent)
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
