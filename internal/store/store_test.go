package store

import (
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
	if cfg.ListenUDP != ":40200" || cfg.RetentionDays != 30 || cfg.DBPath != "/tmp/x.db" {
		t.Fatalf("defaults wrong: %+v", cfg)
	}
	if err := s.SetConfig(Config{ListenUDP: ":5050", RetentionDays: 7}); err != nil {
		t.Fatal(err)
	}
	cfg, _ = s.GetConfig("/tmp/x.db")
	if cfg.ListenUDP != ":5050" || cfg.RetentionDays != 7 || cfg.HTTPAddr != ":8080" {
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
	st, err := s.Stats(Counters{Packets: 100, Records: 3, ParseErrors: 1}, 50*time.Second)
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
