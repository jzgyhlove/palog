// Package store persists normalized log records in SQLite and serves the
// queries required by the REST API (see docs/API.md). It also holds the
// device registry (one UDP port per device), the user registry and the
// auth session table.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"crypto/pbkdf2" // stdlib since Go 1.24

	"palog/internal/xcharset"
	_ "modernc.org/sqlite"
)

// Entry is one normalized log row (both text logs and binary records).
type Entry struct {
	ID        int64              `json:"id"`
	Device    string             `json:"device"`
	RecvTS    int64              `json:"recv_ts"`
	Kind      string             `json:"kind"`
	TS        int64              `json:"ts"`
	TSEnd     int64              `json:"ts_end"`
	SrcIP     string             `json:"src_ip"`
	SrcPort   int                `json:"src_port"`
	DstIP     string             `json:"dst_ip"`
	DstPort   int                `json:"dst_port"`
	Proto     int                `json:"proto"`
	MAC       string             `json:"mac"`
	Iface     string             `json:"iface"`
	Iface2    string             `json:"iface2"`
	Appid     int                `json:"appid"`
	Domain    string             `json:"domain"`
	Host      string             `json:"host"`
	Path      string             `json:"path"`
	Method    string             `json:"method"`
	User      string             `json:"user"`
	BytesIn   int64              `json:"bytes_in"`
	BytesOut  int64              `json:"bytes_out"`
	Counters  []uint32           `json:"counters"`
	Flags     string             `json:"flags"`
	RecType   int                `json:"rec_type"`
	Extra     map[string]string  `json:"extra"`
	Raw       string             `json:"raw"`
}

// LogQuery filters for Query().
type LogQuery struct {
	Kind    string
	Q       string
	SrcIP   string
	DstIP   string
	Domain  string
	Device  string   // explicit device filter ("" = all)
	Devices []string // access scope: allowed device names; empty = unrestricted
	From    int64    // unix seconds, 0 = unset
	To      int64
	Limit   int
	Offset  int
	Order   string // asc | desc
}

// OfficialStats is a compact payload for the official-style pages.
// IPRanking/AppRanking are computed when rank=true (流量分析); the overview
// extras (TopDomains/TopSrcIP/ByDevice/Recent) are computed when full=true
// (系统概况 deep-dive), bounded to the same from/to window (or the trailing
// hour when no window is given).
type OfficialStats struct {
	Traffic struct {
		TotalRecords int64            `json:"total_records"`
		BytesIn      int64            `json:"bytes_in"`
		BytesOut     int64            `json:"bytes_out"`
		LastHour     int64            `json:"last_hour"`
		ByKind       map[string]int64 `json:"by_kind"`
	} `json:"traffic"`
	Security struct {
		ParseErrors int64 `json:"parse_errors"`
		LastHour    int64 `json:"last_hour"`
	} `json:"security"`
	IPRanking []IPRankValue `json:"ip_ranking"`
	AppRanking []CountValue  `json:"app_ranking"`
	// Extra aggregates for the 系统概况 page, all bounded to the same
	// from/to window as the traffic/security sections above.
	TopDomains []CountValue     `json:"top_domains"`
	TopSrcIP   []CountValue     `json:"top_src_ip"`
	ByDevice   map[string]int64 `json:"by_device"`
	Recent     []Entry          `json:"recent"`
	// Warnings names the aggregate panels that could not be computed in time
	// (an oversized window whose scan exceeds aggBudget). The response is
	// still 200 with every panel that did complete, so a heavy range degrades
	// to a partial dashboard instead of failing outright.
	Warnings []string `json:"warnings,omitempty"`
}

type IPRankValue struct {
	IP       string `json:"ip"`
	Bytes    int64  `json:"bytes"`
	Records  int64  `json:"records"`
}

// Stats is the dashboard payload.
type Stats struct {
	Total       int64            `json:"total"`
	LastHour    int64            `json:"last_hour"`
	Packets     int64            `json:"packets"`
	Records     int64            `json:"records"`
	ParseErrors int64            `json:"parse_errors"`
	PPS         float64          `json:"pps"`
	ByKind      map[string]int64 `json:"by_kind"`
	ByDevice    map[string]int64 `json:"by_device"`
	TopDomains  []CountValue     `json:"top_domains"`
	TopSrcIP    []CountValue     `json:"top_src_ip"`
	Hourly      []HourCount      `json:"hourly"`
	Recent      []Entry          `json:"recent"`
	Devices     []Device         `json:"devices"`
}

type CountValue struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

type HourCount struct {
	Hour  string `json:"hour"`
	Count int64  `json:"count"`
}

// Config is the kv-backed service configuration (UDP listening is driven by
// the devices table, not this struct).
type Config struct {
	HTTPAddr      string `json:"http_addr"`
	RetentionDays int    `json:"retention_days"`
	DBPath        string `json:"db_path"`

	// TLS, TLSCert and TLSKey configure the console over HTTPS. When TLS is
	// true the server terminates TLS in-process using the stored PEM
	// certificate chain and private key; a change requires a restart.
	TLS     bool   `json:"tls"`
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`

	// Captcha requires an arithmetic challenge on every login.
	Captcha bool `json:"captcha"`
}

// Device is one log source: a named UDP port.
type Device struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Port    int    `json:"port,omitempty"` // omitted for out-of-scope devices
	Enabled bool   `json:"enabled"`
}

// User is a console account. Devices is "*" (all) or a comma-separated list
// of allowed device names.
type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	PassHash  string `json:"pass_hash,omitempty"`
	Role      string `json:"role"` // admin | user
	Devices   string `json:"devices"`
	CreatedAt int64  `json:"created_at"`

	// TFARequired is the admin-forced "must use two-factor" flag; TFAEnabled
	// reports whether the user has actually enrolled a TOTP secret. TFASecret
	// is the base32 TOTP secret and is never serialized.
	TFARequired bool   `json:"tfa_required"`
	TFAEnabled  bool   `json:"tfa_enabled"`
	TFASecret   string `json:"-"`
}

// Default device name used to stamp rows collected before the device table
// existed (single-socket deployments).
const DefaultDevice = "panabit"

// AppNames maps Panabit application IDs to the names the official Panabit
// log system displays (the official UI renders `appname`, not the bare ID).
// The full table is embedded from web/app_names.json (generated from the
// official Panabit app dictionary); this package loads it at init.
var AppNames map[int]string

func init() {
	// app_names.json is embedded next to the web package; the store package
	// cannot embed it directly (embed must be in the same directory tree),
	// so we accept the map via SetAppNames from the api layer, and default
	// to a small built-in set here to keep the backend working standalone.
	AppNames = map[int]string{
		0:   "未知应用",
		1:   "WWW",
		2:   "SSH",
		3:   "Telnet",
		4:   "FTP",
		5:   "其它HTTPS",
		6:   "DNS",
		7:   "SMTP",
		8:   "DHCP",
		9:   "TFTP",
		10:  "SNMP",
		11:  "BGP",
		12:  "L2TP",
		13:  "PPTP",
		14:  "NFS",
		15:  "NNTP",
		16:  "NTP",
		17:  "CVS",
		18:  "POP3",
		19:  "NETBIOS",
		20:  "Bittorrent",
		23:  "SMTP",
		26:  "Telnet",
		186: "HTTP",
		384: "Bittorrent",
		446: "Skype",
		454: "P2P",
		559: "FTP",
		637: "POP3",
		714: "HTTP-Alt",
		839: "IM",
	}
}

// SetAppNames overrides AppNames with the full dictionary loaded from
// web/app_names.json. The api layer calls this at startup.
func SetAppNames(m map[string]string) {
	if len(m) == 0 {
		return
	}
	nn := make(map[int]string, len(m))
	for k, v := range m {
		id, err := strconv.Atoi(k)
		if err != nil {
			continue
		}
		nn[id] = v
	}
	if len(nn) > 0 {
		AppNames = nn
	}
}

// AppNameOf returns the known name for an appid, or "" if the id is
// unknown/invalid (the UI falls back to rendering the id).
func AppNameOf(appid int) string {
	if appid < 0 {
		return ""
	}
	return AppNames[appid]
}

type Store struct {
	db  *sql.DB
	rdb *sql.DB

	dbPath string
	// qTimeout bounds every read query so a pathological plan (or a huge
	// window) cannot hold a read connection — and its WAL snapshot — open
	// indefinitely. Reads run on rdb, so even a timeout can never block the
	// write connection.
	qTimeout time.Duration

	// mu serializes every logs-table write (INSERT / UPDATE / DELETE /
	// VACUUM) against each other. database/sql pools connections, so the
	// SQLite write lock otherwise races between separate batch
	// transactions: any concurrent reader (a dashboard refresh) makes a
	// checkpoint that grows the WAL until -1, after which every writer
	// waits on the exclusive lock forever and SQLITE_BUSY kills the
	// ingest. The live deployment's WAL grew to 4.7 GB this way, and the
	// same failure shows up when a large GROUP BY overlaps a checkpoint.
	// Readers stay parallel; only writers queue on this mutex.
	wmu sync.Mutex
}

const schema = `
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device TEXT NOT NULL DEFAULT '',
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
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);
CREATE INDEX IF NOT EXISTS idx_logs_kind ON logs(kind);
CREATE INDEX IF NOT EXISTS idx_logs_src ON logs(src_ip);
CREATE INDEX IF NOT EXISTS idx_logs_dst ON logs(dst_ip);
CREATE INDEX IF NOT EXISTS idx_logs_domain ON logs(domain);
CREATE INDEX IF NOT EXISTS idx_logs_device ON logs(device);
CREATE INDEX IF NOT EXISTS idx_logs_ts_kind ON logs(ts, kind);
CREATE INDEX IF NOT EXISTS idx_logs_ts_device ON logs(ts, device);
CREATE INDEX IF NOT EXISTS idx_logs_ts_appid ON logs(ts, appid);
CREATE INDEX IF NOT EXISTS idx_logs_ts_domain ON logs(ts, domain);
CREATE INDEX IF NOT EXISTS idx_logs_ts_src ON logs(ts, src_ip);
CREATE TABLE IF NOT EXISTS kv (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  port INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  pass_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  devices TEXT NOT NULL DEFAULT '*',
  created_at INTEGER NOT NULL,
  tfa_required INTEGER NOT NULL DEFAULT 0,
  tfa_secret TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires);
-- Hourly rollups for the heavy long-window 系统概况 / 流量分析 panels.
-- They are pure derived state: the logs table stays the source of truth, so a
-- lost or stale rollup can always be rebuilt by replaying ids. agg_hour
-- carries the dimensions whose cardinality is tiny (a handful of kinds, a
-- handful of devices) and is enough for totals / by_kind / by_device / the
-- trend. agg_dim carries the value lists (domains, source IPs, the COALESCE IP
-- ranking key, app ids) keyed by hour: measured live cardinality is only
-- ~3400 domains and ~290 source IPs per 24h, so this stays exact -- no Top-K
-- approximation, no sketching -- at roughly 5 percent of the logs table.
-- The primary key is (dim, device, value, hour) so that the dominant query
-- ("top values of one dim over an hour range") reads a contiguous run and
-- aggregates with a streaming scan instead of a temp B-tree.
CREATE TABLE IF NOT EXISTS agg_hour (
  hour INTEGER NOT NULL,
  device TEXT NOT NULL,
  kind TEXT NOT NULL,
  n INTEGER NOT NULL,
  bytes_in INTEGER NOT NULL,
  bytes_out INTEGER NOT NULL,
  PRIMARY KEY (hour, device, kind)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS agg_dim (
  dim TEXT NOT NULL,
  device TEXT NOT NULL,
  value TEXT NOT NULL,
  hour INTEGER NOT NULL,
  n INTEGER NOT NULL,
  bytes INTEGER NOT NULL,
  PRIMARY KEY (dim, device, value, hour)
) WITHOUT ROWID;
-- rollup_state is a single row: the highest logs.id already folded into the
-- rollups. Advancing it happens in the same transaction as the upserts, so a
-- crash mid-batch simply replays that batch (the aggregates are additive and
-- therefore idempotent on replay). Starting from 0 backfills all history.
CREATE TABLE IF NOT EXISTS rollup_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  last_id INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO rollup_state(id, last_id, updated_at) VALUES (1, 0, 0);
CREATE INDEX IF NOT EXISTS idx_agg_hour_hour ON agg_hour(hour);
CREATE INDEX IF NOT EXISTS idx_agg_dim_hour ON agg_dim(hour);`

// Open opens (and migrates) the database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// One shared connection (SQLite is effectively single-connection: its
	// locks are database-wide, so pool concurrency only adds lock
	// contention), fast immediate-rollback reads, and a 60 s busy
	// timeout so overlapping writers wait for a reader instead of
	// failing. The 5 s timeout that shipped earlier let warmup GROUP BYs
	// time out mid-checkpoint, and an aborted checkpoint on a large WAL
	// can poison the shared header (WAL size -1), after which EVERY
	// connection deadlocks on a lock that will never be released —
	// including a freshly started process. That was the live incident:
	// a 5.1 GB WAL stuck the whole service, warmup or not.
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA busy_timeout=60000;",
		"PRAGMA read_uncommitted=1;",
		// Cap WAL growth after a successful checkpoint: without this a
		// burst of long readers can let the WAL grow to GBs (the live
		// incident reached 5.1 GB), which in turn makes startup checkpoints
		// minutes long. journal_size_limit is per-connection (SQLite does
		// not persist it), hence it is set here on the write connection and
		// via the read pool's DSN below.
		"PRAGMA journal_size_limit=67108864;",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("pragma: %w", err)
		}
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	// Reset a poisoned WAL before anything else runs. With no other
	// connection present, wal_checkpoint(TRUNCATE) clears a -1
	// checkpoint-mark and rewrites the -shm index; it is a no-op on a
	// healthy WAL. RESTART (not TRUNCATE) is enough for the reset: it
	// still clears the poisoned mark, but it does not rewrite the whole
	// WAL — on a large un-checkpointed WAL (multi-GB, slow disk) a
	// TRUNCATE checkpoint takes minutes and blocks the HTTP startup
	// path behind it. An abandoned WAL on a healthy database is
	// auto-recovered from maindb pages on first read; the next idle
	// checkpoint (automatic or manual) drains it at leisure.
	if _, err := db.Exec("PRAGMA wal_checkpoint(RESTART);"); err != nil {
		db.Close()
		return nil, fmt.Errorf("recover wal checkpoint: %w", err)
	}
	// Dedicated read-only pool. Reads and the writer must never share a
	// connection: the live incident was a single /api/official-stats read
	// holding the pool's only connection for ~29 minutes and starving the
	// ingest writer (327k dropped records). In WAL mode readers do not
	// block the writer, so a separate pool keeps them independent. The
	// pragmas are per-connection, so they are supplied through the DSN for
	// every pooled connection; query_only additionally makes an accidental
	// write on a read path fail loudly instead of corrupting state.
	rdb, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(60000)&_pragma=query_only(1)&_pragma=journal_size_limit(67108864)")
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("open sqlite (read): %w", err)
	}
	rdb.SetMaxOpenConns(4)
	rdb.SetMaxIdleConns(4)
	s := &Store{db: db, rdb: rdb, dbPath: path, qTimeout: 15 * time.Second}
	// legacy DBs (pre multi-device) lack logs.device; add it before schema
	// so that idx_logs_device can be created.
	if err := s.migrateDeviceColumn(); err != nil {
		rdb.Close()
		db.Close()
		return nil, fmt.Errorf("device column: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		rdb.Close()
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := s.migrateLegacy(); err != nil {
		rdb.Close()
		db.Close()
		return nil, fmt.Errorf("migrate legacy: %w", err)
	}
	if err := s.migrateUserTFA(); err != nil {
		rdb.Close()
		db.Close()
		return nil, fmt.Errorf("migrate user tfa: %w", err)
	}
	return s, nil
}

// migrateUserTFA adds the two-factor columns to pre-TFA databases. Fresh
// databases already get them from schema; an existing users table needs
// ALTER TABLE, which SQLite supports one column at a time.
func (s *Store) migrateUserTFA() error {
	var tbl int
	if err := s.db.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'").Scan(&tbl); err != nil {
		return err
	}
	if tbl == 0 {
		return nil // fresh database: schema creates the columns
	}
	have := map[string]bool{}
	rows, err := s.db.Query("PRAGMA table_info(users)")
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		have[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, c := range []struct{ col, ddl string }{
		{"tfa_required", "ALTER TABLE users ADD COLUMN tfa_required INTEGER NOT NULL DEFAULT 0"},
		{"tfa_secret", "ALTER TABLE users ADD COLUMN tfa_secret TEXT NOT NULL DEFAULT ''"},
	} {
		if have[c.col] {
			continue
		}
		if _, err := s.db.Exec(c.ddl); err != nil {
			return fmt.Errorf("add users.%s: %w", c.col, err)
		}
	}
	return nil
}

// migrateDeviceColumn adds logs.device to pre-device databases. It must run
// before schema, otherwise CREATE INDEX idx_logs_device fails on legacy
// tables that lack the column.
func (s *Store) migrateDeviceColumn() error {
	var tbl int
	if err := s.db.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='logs'").Scan(&tbl); err != nil {
		return err
	}
	if tbl == 0 {
		return nil // fresh database: schema creates the column
	}
	rows, err := s.db.Query("PRAGMA table_info(logs)")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == "device" {
			return nil // already migrated
		}
	}
	if rows.Err() != nil {
		return rows.Err()
	}
	err = s.writeTx(func(tx *sql.Tx) error {
		_, err := tx.Exec("ALTER TABLE logs ADD COLUMN device TEXT NOT NULL DEFAULT ''")
		return err
	})
	if err != nil {
		return fmt.Errorf("add logs.device: %w", err)
	}
	return nil
}

// migrateLegacy upgrades pre-device-table databases: once collected rows get
// the device column default, and a default device is created from kv
// `listen_udp` (or :40200) so the first listener keeps capture continuity.
// Fresh databases (no legacy rows) skip this: the admin registers devices in
// the console instead.
func (s *Store) migrateLegacy() error {
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM devices").Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	var logs int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM logs").Scan(&logs); err != nil {
		return err
	}
	if logs == 0 {
		return nil // brand-new database: no legacy rows to re-home
	}
	port := 40200
	rows, err := s.db.Query("SELECT value FROM kv WHERE key='listen_udp'")
	if err != nil {
		return err
	}
	if rows.Next() {
		var v string
		if err := rows.Scan(&v); err == nil {
			if p, perr := parseUDPPort(v); perr == nil {
				port = p
			}
		}
	}
	rows.Close()
	if err := s.writeTx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(
			"INSERT INTO devices(name, port, enabled) VALUES(?,?,1)", DefaultDevice, port); err != nil {
			return err
		}
		_, err := tx.Exec("UPDATE logs SET device=? WHERE device=''", DefaultDevice)
		return err
	}); err != nil {
		return err
	}
	return nil
}

func parseUDPPort(addr string) (int, error) {
	addr = strings.TrimSpace(addr)
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		addr = addr[i+1:]
	}
	return strconv.Atoi(addr)
}

func (s *Store) Close() error {
	if s.rdb != nil {
		s.rdb.Close()
	}
	return s.db.Close()
}

// aggTimeout bounds a single aggregate query on the heavy 系统概况 /
// 流量分析 path (an explicit from/to window, ?full=1 or ?rank=1). It is far
// larger than qTimeout because these aggregates legitimately run for seconds
// on a multi-GB table — a cold 24h Top-src-IP measures ~27s — and each
// aggregate now gets its own deadline (see OfficialStats) instead of sharing
// one budget with its siblings.
const aggTimeout = 60 * time.Second

// aggBudget bounds the whole heavy fan-out (one 系统概况 / 流量分析 response).
// The aggregates run in parallel waves on the read pool, so without a wall
// budget a window far larger than the page cache can hold would keep every
// lane busy for two or more 60s rounds. Panels that miss the budget are
// named in OfficialStats.Warnings and the response still returns 200 with the
// rest, so an oversized range degrades instead of failing.
const aggBudget = 60 * time.Second

// readCtxT bounds one read query to d. Reads run on the dedicated read pool,
// so this protects the caller (and the WAL snapshot the read holds) from an
// unbounded plan without ever touching the write connection.
func (s *Store) readCtxT(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// readCtx bounds one interactive read query to the Store's qTimeout.
func (s *Store) readCtx() (context.Context, context.CancelFunc) {
	return s.readCtxT(s.qTimeout)
}

// writeTx runs fn holding the write mutex, inside one transaction on a
// dedicated connection.
func (s *Store) writeTx(fn func(tx *sql.Tx) error) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return err
	}
	defer conn.Close()
	tx, err := conn.BeginTx(context.Background(), &sql.TxOptions{})
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// InsertBatch writes entries in one transaction.
func (s *Store) InsertBatch(entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}
	return s.writeTx(func(tx *sql.Tx) error {
		stmt, err := tx.Prepare(`INSERT INTO logs
	  (device, recv_ts, kind, ts, ts_end, src_ip, src_port, dst_ip, dst_port, proto,
	   mac, iface, iface2, appid, domain, host, path, method, user,
	   bytes_in, bytes_out, counters, flags, rec_type, extra, raw)
	  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, e := range entries {
			counters := ""
			if len(e.Counters) > 0 {
				b, err := json.Marshal(e.Counters)
				if err != nil {
					return err
				}
				counters = string(b)
			}
			extra := ""
			if len(e.Extra) > 0 {
				b, err := json.Marshal(e.Extra)
				if err != nil {
					return err
				}
				extra = string(b)
			}
			if _, err := stmt.Exec(e.Device, e.RecvTS, e.Kind, e.TS, e.TSEnd,
				e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.Proto,
				e.MAC, e.Iface, e.Iface2, e.Appid, e.Domain, e.Host, e.Path, e.Method, e.User,
				e.BytesIn, e.BytesOut, counters, e.Flags, e.RecType, extra, e.Raw); err != nil {
				return err
			}
		}
		return nil
	})
}

const logCols = `id, device, recv_ts, kind, ts, ts_end, src_ip, src_port, dst_ip, dst_port,
  proto, mac, iface, iface2, appid, domain, host, path, method, user,
  bytes_in, bytes_out, counters, flags, rec_type, extra, raw`

func scanEntry(scan func(dest ...interface{}) error) (Entry, error) {
	var e Entry
	var counters, extra string
	err := scan(&e.ID, &e.Device, &e.RecvTS, &e.Kind, &e.TS, &e.TSEnd,
		&e.SrcIP, &e.SrcPort, &e.DstIP, &e.DstPort, &e.Proto,
		&e.MAC, &e.Iface, &e.Iface2, &e.Appid, &e.Domain, &e.Host, &e.Path, &e.Method, &e.User,
		&e.BytesIn, &e.BytesOut, &counters, &e.Flags, &e.RecType, &extra, &e.Raw)
	if err != nil {
		return e, err
	}
	if counters != "" {
		json.Unmarshal([]byte(counters), &e.Counters)
	}
	if extra != "" {
		json.Unmarshal([]byte(extra), &e.Extra)
	}
	// normalize legacy GBK/invalid UTF-8 fields on read
	e.Iface = xcharset.ToUTF8(e.Iface)
	e.Iface2 = xcharset.ToUTF8(e.Iface2)
	e.MAC = xcharset.ToUTF8(e.MAC)
	e.Domain = xcharset.ToUTF8(e.Domain)
	e.Host = xcharset.ToUTF8(e.Host)
	e.Path = xcharset.ToUTF8(e.Path)
	e.Method = xcharset.ToUTF8(e.Method)
	e.User = xcharset.ToUTF8(e.User)
	e.Raw = xcharset.ToUTF8(e.Raw)
	e.Device = xcharset.ToUTF8(e.Device)
	return e, nil
}

// scopeCond returns a SQL fragment restricting rows to allowed devices.
// Nil/empty devices = unrestricted.
func scopeCond(devices []string) (string, []interface{}) {
	if len(devices) == 0 {
		return "", nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(devices)), ",")
	args := make([]interface{}, len(devices))
	for i, d := range devices {
		args[i] = d
	}
	return "device IN (" + ph + ")", args
}

func buildWhere(q LogQuery) (string, []interface{}) {
	var conds []string
	var args []interface{}
	add := func(cond string, as ...interface{}) {
		conds = append(conds, cond)
		args = append(args, as...)
	}
	if q.Kind != "" {
		add("kind = ?", q.Kind)
	}
	if q.SrcIP != "" {
		add("src_ip = ?", q.SrcIP)
	}
	if q.DstIP != "" {
		add("dst_ip = ?", q.DstIP)
	}
	if q.Domain != "" {
		add("domain = ?", q.Domain)
	}
	if q.Device != "" {
		add("device = ?", q.Device)
	}
	if len(q.Devices) > 0 {
		cond, as := scopeCond(q.Devices)
		add(cond, as...)
	}
	if q.Q != "" {
		like := "%" + escapeLike(q.Q) + "%"
		add("(src_ip LIKE ? ESCAPE '\\' OR dst_ip LIKE ? ESCAPE '\\' OR domain LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\' OR user LIKE ? ESCAPE '\\')",
			like, like, like, like, like, like)
	}
	if q.From > 0 {
		add("ts >= ?", q.From)
	}
	if q.To > 0 {
		add("ts <= ?", q.To)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	return strings.ReplaceAll(s, "_", `\_`)
}

// Query returns a page of log entries plus the total match count.
func (s *Store) Query(q LogQuery) (int64, []Entry, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	if q.Limit > 1000 {
		q.Limit = 1000
	}
	// Scan guard: a query with no lower time bound cannot use the ts-leading
	// indexes and degenerates into a full scan of every indexed column (the
	// live incident's multi-minute reads). The API always sets a window
	// (default trailing hour); only an explicit from=0 reaches here, and we
	// clamp that to the trailing week rather than scan all history.
	if q.From == 0 {
		q.From = time.Now().Unix() - 7*86400
	}
	where, args := buildWhere(q)

	ctx, cancel := s.readCtx()
	defer cancel()

	// Cap the total. An uncapped COUNT(*) re-scans every matching row and
	// was a large share of the incident's cost; 100001 lets the UI show an
	// exact count for any realistic result and a capped "100000+" beyond it,
	// without an unbounded scan.
	var total int64
	if err := s.rdb.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM (SELECT 1 FROM logs"+where+" LIMIT 100001)", args...).Scan(&total); err != nil {
		return 0, nil, err
	}
	order := "DESC"
	if strings.EqualFold(q.Order, "asc") {
		order = "ASC"
	}
	sqlStr := "SELECT " + logCols + " FROM logs" + where +
		" ORDER BY ts " + order + ", id " + order + " LIMIT ? OFFSET ?"
	rows, err := s.rdb.QueryContext(ctx, sqlStr, append(args, q.Limit, q.Offset)...)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	var items []Entry
	for rows.Next() {
		e, err := scanEntry(rows.Scan)
		if err != nil {
			return 0, nil, err
		}
		items = append(items, e)
	}
	return total, items, rows.Err()
}

// Get returns one entry by id.
func (s *Store) Get(id int64) (*Entry, error) {
	ctx, cancel := s.readCtx()
	defer cancel()
	row := s.rdb.QueryRowContext(ctx, "SELECT "+logCols+" FROM logs WHERE id = ?", id)
	e, err := scanEntry(row.Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// Counters are ingestion statistics kept in memory by the receiver and
// passed in for the health/stats endpoints.
type Counters struct {
	Packets     int64
	Records     int64
	ParseErrors int64
}

// statsWindow bounds every group-by in Stats() to the trailing hour so the
// endpoint stays cheap as the table grows to millions of rows. The hourly
// trend chart is the one exception: it keeps its 24h span because the UI
// trend sparkline needs 24 buckets and that GROUP BY is index-bounded.
const statsWindow = 1 * time.Hour

// Stats aggregates dashboard data. devices limits scope (nil = all).
//
// The UI only consumes Hourly (the 24h trend sparkline, shown when the user
// picks a 24h/all window) and the in-memory counters from this endpoint; every
// other dashboard number comes from /api/official-stats. It therefore computes
// only the 24h hourly bucket GROUP BY (ts-index-bounded) plus Total/LastHour
// counts — no top values, by_kind, by_device or recent-row scans, so the call
// stays cheap even when only used for the trend chart.
func (s *Store) Stats(c Counters, uptime time.Duration, devices []string) (*Stats, error) {
	st := &Stats{
		Packets:     c.Packets,
		Records:     c.Records,
		ParseErrors: c.ParseErrors,
	}
	if uptime.Seconds() > 0 {
		st.PPS = float64(c.Packets) / uptime.Seconds()
	}

	scope, sargs := scopeCond(devices)

	ctx, cancel := s.readCtx()
	defer cancel()

	// 24 contiguous hourly buckets ending at the current hour (UTC labels).
	now := time.Now().UTC()
	curHour := now.Truncate(time.Hour)
	hWhere := " WHERE ts >= ?"
	hArgs := []interface{}{curHour.Add(-23 * time.Hour).Unix()}
	if scope != "" {
		hWhere += " AND " + scope
		hArgs = append(hArgs, sargs...)
	}
	rows, err := s.rdb.QueryContext(ctx, "SELECT (ts/3600)*3600 AS h, COUNT(*) FROM logs"+hWhere+" GROUP BY h", hArgs...)
	if err != nil {
		return nil, err
	}
	buckets := map[int64]int64{}
	for rows.Next() {
		var h, n int64
		if err := rows.Scan(&h, &n); err != nil {
			rows.Close()
			return nil, err
		}
		buckets[h] = n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	st.Hourly = make([]HourCount, 0, 24)
	for i := 23; i >= 0; i-- {
		ht := curHour.Add(-time.Duration(i) * time.Hour)
		st.Hourly = append(st.Hourly, HourCount{
			Hour:  ht.Format(time.RFC3339),
			Count: buckets[ht.Unix()],
		})
	}

	// Total + LastHour over the trailing hour (cheap ts-bounded count; kept
	// for API compatibility with existing consumers).
	from := time.Now().Add(-statsWindow).Unix()
	baseWhere := " WHERE ts >= ?"
	baseArgs := []interface{}{from}
	if scope != "" {
		baseWhere += " AND " + scope
		baseArgs = append(baseArgs, sargs...)
	}
	if err := s.rdb.QueryRowContext(ctx, "SELECT COUNT(*) FROM logs"+baseWhere, baseArgs...).Scan(&st.Total); err != nil {
		return nil, err
	}
	st.LastHour = st.Total

	if st.Devices, err = s.ListDevices(); err != nil {
		return nil, err
	}
	return st, nil
}

// topValues returns the top n values of col for rows matching where (which
// must include a ts guard to stay fast). indexBy names the ts-leading
// composite index to force: left to itself the planner scans the whole
// single-column index and ignores the ts bound (the live incident's
// multi-minute GROUP BYs).
func (s *Store) topValues(ctx context.Context, col, indexBy string, n int, where string, args []interface{}) ([]CountValue, error) {
	// col and indexBy are internal constants, never user input.
	// Append col != '' filter to the provided where clause.
	fullWhere := where
	if fullWhere == "" {
		fullWhere = " WHERE " + col + " != ''"
	} else {
		fullWhere += " AND " + col + " != ''"
	}
	fullArgs := append([]interface{}{}, args...)
	fullArgs = append(fullArgs, n)
	rows, err := s.rdb.QueryContext(ctx,
		"SELECT "+col+", COUNT(*) AS c FROM logs INDEXED BY "+indexBy+fullWhere+" GROUP BY "+col+" ORDER BY c DESC, "+col+" ASC LIMIT ?", fullArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CountValue
	for rows.Next() {
		var v CountValue
		if err := rows.Scan(&v.Value, &v.Count); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

/* ---------------- rollup-backed reads ---------------- */

// rollupWindow is the split of a request window into the whole hours the
// rollups can answer and the partial hours at each edge that must still be read
// from logs. agg_hour is keyed by hourBucket(ts), so a partially requested hour
// can never be served from it without over- or under-counting.
type rollupWindow struct {
	fullFrom, fullTo int64 // inclusive hour starts
	hasFull          bool
	headFrom, headTo int64 // inclusive ts range preceding fullFrom
	hasHead          bool
	tailFrom, tailTo int64 // inclusive ts range following fullTo's hour
	hasTail          bool
}

// rollupFrontierMargin keeps the read path away from the newest folded row.
// Rows are folded in id order while a request window is measured in ts order,
// so an hour this close to the frontier could still receive a late (backdated)
// row. One hour is far beyond the ingest's own reordering.
const rollupFrontierMargin = 3600

// splitRollupWindow divides the inclusive ts window [from,to] into whole hours
// and the partial hours at each edge. The returned parts never overlap and
// together cover exactly [from,to].
func splitRollupWindow(from, to int64) rollupWindow {
	if from <= 0 || to <= 0 || to < from {
		return rollupWindow{}
	}
	firstFull := hourBucket(from)
	lastFull := hourBucket(to)
	if from > firstFull {
		firstFull += 3600 // the hour `from` lands in is only partially requested
	}
	if to < lastFull+3599 {
		lastFull -= 3600 // the hour `to` lands in is only partially requested
	}
	if firstFull > lastFull {
		// Fewer than two whole hours are covered: read the window from logs.
		return rollupWindow{headFrom: from, headTo: to, hasHead: true}
	}
	w := rollupWindow{fullFrom: firstFull, fullTo: lastFull, hasFull: true}
	if from < firstFull {
		w.headFrom, w.headTo, w.hasHead = from, firstFull-1, true
	}
	if to > lastFull+3599 {
		w.tailFrom, w.tailTo, w.hasTail = lastFull+3600, to, true
	}
	return w
}

// rawParts lists the ranges still served from logs (the partial edge hours).
func (w rollupWindow) rawParts() [][2]int64 {
	var out [][2]int64
	if w.hasHead {
		out = append(out, [2]int64{w.headFrom, w.headTo})
	}
	if w.hasTail {
		out = append(out, [2]int64{w.tailFrom, w.tailTo})
	}
	return out
}

// rollupHourFloor is the earliest hour the rollups can answer exactly. Below
// MIN(hour) there is no bucket at all, and MIN(hour) itself may be an hour that
// retention has only partially pruned. 0 means "not usable".
func (s *Store) rollupHourFloor() (int64, error) {
	ctx, cancel := s.readCtx()
	defer cancel()
	var min int64
	if err := s.rdb.QueryRowContext(ctx, "SELECT COALESCE(MIN(hour),0) FROM agg_hour").Scan(&min); err != nil {
		return 0, err
	}
	if min == 0 {
		return 0, nil
	}
	return min + 3600, nil
}

// rollupFrontierTs is the ts of the newest row folded into the rollups; 0 when
// unknown (nothing folded yet, or that row has since been pruned).
func (s *Store) rollupFrontierTs() (int64, error) {
	ctx, cancel := s.readCtx()
	defer cancel()
	var lastID int64
	if err := s.rdb.QueryRowContext(ctx, "SELECT last_id FROM rollup_state WHERE id = 1").Scan(&lastID); err != nil {
		return 0, err
	}
	if lastID == 0 {
		return 0, nil
	}
	var ts int64
	switch err := s.rdb.QueryRowContext(ctx, "SELECT ts FROM logs WHERE id = ?", lastID).Scan(&ts); {
	case err == sql.ErrNoRows:
		return 0, nil
	case err != nil:
		return 0, err
	}
	return ts, nil
}

// rollupReady reports whether every whole hour in w is provably complete in the
// rollups, so serving them instead of scanning logs cannot change a number.
func (s *Store) rollupReady(w rollupWindow) (bool, error) {
	if !w.hasFull {
		return false, nil
	}
	floor, err := s.rollupHourFloor()
	if err != nil || floor == 0 || w.fullFrom < floor {
		return false, err
	}
	frontier, err := s.rollupFrontierTs()
	if err != nil || frontier == 0 {
		return false, err
	}
	// The whole rolled-up range must sit at least one hour behind the newest
	// folded row, otherwise a backdated row could still move one of its hours.
	if w.fullTo+3599 > frontier-rollupFrontierMargin {
		return false, nil
	}
	return true, nil
}

// scoped appends a device-scope predicate to a query that already carries its
// own WHERE ... placeholders.
func scoped(q string, scope string, scopeArgs, args []interface{}) (string, []interface{}) {
	if scope == "" {
		return q, args
	}
	return q + " AND " + scope, append(args, scopeArgs...)
}

// countsRows runs a (text key, integer) GROUP BY and returns it as a map.
func (s *Store) countsRows(ctx context.Context, q string, args ...interface{}) (map[string]int64, error) {
	rows, err := s.rdb.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

// pairRows runs a (text key, integer, integer) GROUP BY into key -> [2]int64.
func (s *Store) pairRows(ctx context.Context, q string, args ...interface{}) (map[string][2]int64, error) {
	rows, err := s.rdb.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][2]int64{}
	for rows.Next() {
		var k string
		var a, b int64
		if err := rows.Scan(&k, &a, &b); err != nil {
			return nil, err
		}
		out[k] = [2]int64{a, b}
	}
	return out, rows.Err()
}

// rawTotals sums the row count and byte totals of logs over an inclusive range.
func (s *Store) rawTotals(ctx context.Context, from, to int64, scope string, scopeArgs []interface{}) (total, in, out int64, err error) {
	q, args := scoped("SELECT COUNT(*), COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0) FROM logs WHERE ts >= ? AND ts <= ?",
		scope, scopeArgs, []interface{}{from, to})
	err = s.rdb.QueryRowContext(ctx, q, args...).Scan(&total, &in, &out)
	return
}

// aggTotals sums the same aggregates from agg_hour over an inclusive hour range.
func (s *Store) aggTotals(ctx context.Context, from, to int64, scope string, scopeArgs []interface{}) (total, in, out int64, err error) {
	q, args := scoped("SELECT COALESCE(SUM(n),0), COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0) FROM agg_hour WHERE hour >= ? AND hour <= ?",
		scope, scopeArgs, []interface{}{from, to})
	err = s.rdb.QueryRowContext(ctx, q, args...).Scan(&total, &in, &out)
	return
}

// rollupHourCounts aggregates agg_hour by col over the rollup's whole hours and
// merges in the partial edge hours read from logs. The raw side is index-hinted
// (an unhinted GROUP BY over the trailing range degenerates into a full
// single-column index scan — the incident behind topValues) and carries no
// LIMIT, because a truncated edge list would corrupt the merge.
func (s *Store) rollupHourCounts(ctx context.Context, w rollupWindow, col, rawIndex string, scope string, scopeArgs []interface{}) (map[string]int64, error) {
	q, args := scoped("SELECT "+col+", SUM(n) FROM agg_hour WHERE hour >= ? AND hour <= ? GROUP BY 1",
		scope, scopeArgs, []interface{}{w.fullFrom, w.fullTo})
	out, err := s.countsRows(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	for _, p := range w.rawParts() {
		rq, rargs := scoped("SELECT "+col+", COUNT(*) FROM logs INDEXED BY "+rawIndex+" WHERE ts >= ? AND ts <= ? GROUP BY 1",
			scope, scopeArgs, []interface{}{p[0], p[1]})
		m, err := s.countsRows(ctx, rq, rargs...)
		if err != nil {
			return nil, err
		}
		for k, v := range m {
			out[k] += v
		}
	}
	return out, nil
}

// rollupDimCounts is rollupHourCounts for an agg_dim partition. rawCol/rawExtra
// describe the logs-side aggregate (e.g. rawCol "domain" with rawExtra
// " AND domain != ''") so the partial hours are read with the same semantics as
// the scan path.
func (s *Store) rollupDimCounts(ctx context.Context, w rollupWindow, dim, rawCol, rawIndex, rawExtra string, scope string, scopeArgs []interface{}) (map[string]int64, error) {
	q, args := scoped("SELECT value, SUM(n) FROM agg_dim WHERE dim = ? AND hour >= ? AND hour <= ? GROUP BY 1",
		scope, scopeArgs, []interface{}{dim, w.fullFrom, w.fullTo})
	out, err := s.countsRows(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	for _, p := range w.rawParts() {
		rq, rargs := scoped("SELECT "+rawCol+", COUNT(*) FROM logs INDEXED BY "+rawIndex+" WHERE ts >= ? AND ts <= ?"+rawExtra+" GROUP BY 1",
			scope, scopeArgs, []interface{}{p[0], p[1]})
		m, err := s.countsRows(ctx, rq, rargs...)
		if err != nil {
			return nil, err
		}
		for k, v := range m {
			out[k] += v
		}
	}
	return out, nil
}

// rollupIPCounts aggregates the IP ranking (records AND bytes) over the rollup's
// whole hours plus the partial edges from logs. The rollup key is the same
// COALESCE expression the scan path groups by.
func (s *Store) rollupIPCounts(ctx context.Context, w rollupWindow, scope string, scopeArgs []interface{}) (map[string][2]int64, error) {
	q, args := scoped("SELECT value, SUM(n), SUM(bytes) FROM agg_dim WHERE dim = ? AND hour >= ? AND hour <= ? GROUP BY 1",
		scope, scopeArgs, []interface{}{rollupDimIP, w.fullFrom, w.fullTo})
	out, err := s.pairRows(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	for _, p := range w.rawParts() {
		rq, rargs := scoped("SELECT COALESCE(NULLIF(src_ip,''), dst_ip), COUNT(*), COALESCE(SUM(bytes_in+bytes_out),0) FROM logs WHERE ts >= ? AND ts <= ? AND (src_ip != '' OR dst_ip != '') GROUP BY 1",
			scope, scopeArgs, []interface{}{p[0], p[1]})
		m, err := s.pairRows(ctx, rq, rargs...)
		if err != nil {
			return nil, err
		}
		for k, v := range m {
			d := out[k]
			d[0] += v[0]
			d[1] += v[1]
			out[k] = d
		}
	}
	return out, nil
}

// topCounts turns a value->count map into the top n CountValues ordered by
// count DESC then value ASC — the same order topValues' raw query uses, so the
// rollup path and the scan path tie-break identically.
func topCounts(m map[string]int64, n int) []CountValue {
	out := make([]CountValue, 0, len(m))
	for k, v := range m {
		if k == "" {
			continue
		}
		out = append(out, CountValue{Value: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Value < out[j].Value
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// topPairs turns an IP -> (records, bytes) map into the top n by bytes.
func topPairs(m map[string][2]int64, n int) []IPRankValue {
	out := make([]IPRankValue, 0, len(m))
	for k, v := range m {
		if k == "" {
			continue
		}
		out = append(out, IPRankValue{IP: k, Records: v[0], Bytes: v[1]})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].IP < out[j].IP
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// appRankingFromCounts maps an appid-string -> count map onto the ranking
// payload, resolving ids through the app dictionary exactly like the scan path.
func appRankingFromCounts(m map[string]int64) []CountValue {
	out := make([]CountValue, 0, len(m))
	for k, n := range m {
		id, err := strconv.Atoi(k)
		if err != nil {
			continue
		}
		name := AppNameOf(id)
		if name == "" {
			name = k
		}
		out = append(out, CountValue{Value: name, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Value < out[j].Value
	})
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

// OfficialStats computes compact aggregates for the official-style pages.
// devices limits scope the same way Stats does. from/to are optional unix
// seconds that further bound the window (0 = unset on that side); when
// either is set, "last_hour" is reported as the whole-window total so it
// stays consistent with the caller's chosen range.
//
// cheap / rank / full select which aggregates are computed:
//   - cheap=true (bare 系统概况 auto-refresh): the index-bounded set —
//     trailing-hour COUNT+SUM via idx_logs_ts, by_kind / by_device via the
//     handful-of-kinds / handful-of-devices partial scans, top domains /
//     top src IP via the (ts, domain)/(ts, src_ip) composite indexes, and
//     the security section. No full-table scan, no rankings: this is what
//     keeps the default 1h view fast on a large table.
//   - rank=true (流量分析): the cheap set plus the LIMIT-20 IP/app
//     rankings (by_bytes / by_count scans bounded by the window).
//   - full=true (opt-in deep-dive, ?full=1): adds the recent-rows list
//     bounded to the window, or to the trailing hour when no window is
//     given. (Top domains / src IP, by_kind and by_device are already in
//     the cheap set and therefore always present.)
//
// The independent aggregates run concurrently (bounded by the read pool),
// each with its own deadline; a panel that cannot finish within aggBudget is
// skipped and named in Warnings instead of failing the call, so an oversized
// window degrades to a partial dashboard rather than returning an error.
func (s *Store) OfficialStats(c Counters, devices []string, from, to int64, full, rank, cheap bool) (*OfficialStats, error) {
	out := &OfficialStats{}
	out.Security.ParseErrors = c.ParseErrors

	scope, sargs := scopeCond(devices)

	// The aggregates below are independent, so each runs on its own goroutine
	// with its own deadline (qd) instead of sharing one context. They used to
	// share a single s.qTimeout (15s) context, so their combined runtime
	// (~25s warm / ~70s cold on a 12GB table) always blew the budget and every
	// windowed/full call failed with "context deadline exceeded" even though
	// no individual query came close to the limit. lanes caps the readers in
	// flight to the read-pool size so a heavy 概况 call cannot starve the
	// other read endpoints.
	qd := s.qTimeout
	var budgetEnd time.Time
	if !cheap {
		qd = aggTimeout
		budgetEnd = time.Now().Add(aggBudget)
	}
	lanes := make(chan struct{}, 4)
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		fail error
	)
	// run schedules one aggregate panel. Its deadline is its own (qd), capped
	// by whatever remains of the overall budget. A panel that runs out of time
	// is recorded in Warnings rather than failing the whole response; any
	// other error stays fatal, so a real SQL failure is never masked as an
	// empty panel.
	run := func(panel string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lanes <- struct{}{}
			defer func() { <-lanes }()
			d := qd
			if !budgetEnd.IsZero() {
				rem := time.Until(budgetEnd)
				if rem <= 0 {
					mu.Lock()
					out.Warnings = append(out.Warnings, panel)
					mu.Unlock()
					return
				}
				if rem < d {
					d = rem
				}
			}
			ctx, cancel := s.readCtxT(d)
			defer cancel()
			if err := fn(ctx); err != nil {
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
					mu.Lock()
					out.Warnings = append(out.Warnings, panel)
					mu.Unlock()
					return
				}
				mu.Lock()
				if fail == nil {
					fail = err
				}
				mu.Unlock()
			}
		}()
	}

	// timeCond + timeArgs: the caller-provided ts window.
	var timeCond string
	var timeArgs []interface{}
	if from > 0 {
		timeCond += " AND ts >= ?"
		timeArgs = append(timeArgs, from)
	}
	if to > 0 {
		timeCond += " AND ts <= ?"
		timeArgs = append(timeArgs, to)
	}
	hasWindow := from > 0 || to > 0

	// Rollup-backed fast path. Only whole hours can come from agg_hour/agg_dim
	// (they are keyed by hourBucket(ts)), so the partial hours at each edge
	// still come from logs, and it is engaged only when the rollups are
	// provably complete for those hours. An unready rollup silently leaves
	// useRollup false and every panel below keeps its original scan query, so
	// this can never change a number.
	var rw rollupWindow
	useRollup := false
	if !cheap && hasWindow && from > 0 && to > 0 {
		rw = splitRollupWindow(from, to)
		if ok, err := s.rollupReady(rw); err == nil && ok {
			useRollup = true
		}
	}

	// cheap (no explicit window): aggregates are all bounded to the
	// trailing hour via idx_logs_ts so the default 概况 call never touches
	// the full table. Windowed calls aggregate over the caller's window.
	effCond := timeCond
	effArgs := timeArgs
	if cheap {
		cutoff := time.Now().Unix() - 3600
		if effCond == "" {
			effCond = " AND ts >= ?"
			effArgs = []interface{}{cutoff}
		} else {
			effCond += " AND ts >= ?"
			effArgs = append([]interface{}{}, effArgs...)
			effArgs = append(effArgs, cutoff)
		}
	}

	// baseWhere: device scope + effective ts window.
	baseWhere := ""
	baseArgs := []interface{}{}
	if scope != "" {
		baseWhere = " WHERE " + scope
		baseArgs = append(baseArgs, sargs...)
	}
	if effCond != "" {
		if baseWhere == "" {
			baseWhere = " WHERE 1=1" + effCond
		} else {
			baseWhere += effCond
		}
		baseArgs = append(baseArgs, effArgs...)
	}

	// lastHourWhere: trailing-hour guard, used when no window is given.
	// When a window is given, LastHour is set to the window total instead.
	// On the cheap path baseWhere already carries the trailing-hour bound,
	// so no extra guard is needed.
	lastHourWhere := baseWhere
	lastHourArgs := append([]interface{}{}, baseArgs...)
	if !hasWindow && !cheap {
		if lastHourWhere == "" {
			lastHourWhere = " WHERE ts >= ?"
			lastHourArgs = []interface{}{time.Now().Unix() - 3600}
		} else {
			lastHourWhere += " AND ts >= ?"
			lastHourArgs = append(lastHourArgs, time.Now().Unix()-3600)
		}
	}

	// Traffic totals + by_kind over the effective window. by_kind stays
	// bounded even without a ts guard: there are only a handful of kinds,
	// so the GROUP BY runs a small partial scan regardless of table size.
	// A bare call (no window, not cheap) aggregates the trailing hour
	// instead of all history, so a 系统概况 deep-dive of the default view
	// cannot scan the full table.
	trafficBase := baseWhere
	trafficArgs := baseArgs
	if !hasWindow && !cheap {
		cutoff := time.Now().Unix() - 3600
		if trafficBase == "" {
			trafficBase = " WHERE ts >= ?"
			trafficArgs = []interface{}{cutoff}
		} else {
			trafficBase += " AND ts >= ?"
			trafficArgs = append(append([]interface{}{}, trafficArgs...), cutoff)
		}
	}
	// traffic totals + last-hour count. security.LastHour is the same
	// trailing-hour (or window) count, so it is derived here rather than in
	// a second goroutine that would have to read this goroutine's result.
	run("traffic", func(ctx context.Context) error {
		var total int64
		var bytesIn, bytesOut int64
		switch {
		case useRollup:
			var in, outB int64
			var err error
			total, in, outB, err = s.aggTotals(ctx, rw.fullFrom, rw.fullTo, scope, sargs)
			if err != nil {
				return err
			}
			bytesIn, bytesOut = in, outB
			for _, p := range rw.rawParts() {
				t, i, o, err := s.rawTotals(ctx, p[0], p[1], scope, sargs)
				if err != nil {
					return err
				}
				total += t
				bytesIn += i
				bytesOut += o
			}
		default:
			if err := s.rdb.QueryRowContext(ctx,
				"SELECT COUNT(*), COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0) FROM logs"+trafficBase,
				trafficArgs...).Scan(&total, &bytesIn, &bytesOut); err != nil {
				return err
			}
		}
		out.Traffic.TotalRecords = total
		out.Traffic.BytesIn = bytesIn
		out.Traffic.BytesOut = bytesOut

		if hasWindow {
			out.Traffic.LastHour = total
			out.Security.LastHour = total
		} else {
			if err := s.rdb.QueryRowContext(ctx, "SELECT COUNT(*) FROM logs"+lastHourWhere, lastHourArgs...).Scan(&out.Traffic.LastHour); err != nil {
				return err
			}
			if out.Security.LastHour == 0 {
				out.Security.LastHour = out.Traffic.LastHour
			}
		}
		return nil
	})

	// by_kind: tiny GROUP BY — the kind column holds a handful of values, so
	// it stays cheap even when the window is large. Computed on every path
	// (including cheap) so the 系统概况 1h view shows 日志类型分布 without
	// the heavy extras.
	run("by_kind", func(ctx context.Context) error {
		out.Traffic.ByKind = map[string]int64{}
		if useRollup {
			m, err := s.rollupHourCounts(ctx, rw, "kind", "idx_logs_ts_kind", scope, sargs)
			if err != nil {
				return err
			}
			out.Traffic.ByKind = m
			return nil
		}
		rows, err := s.rdb.QueryContext(ctx, "SELECT kind, COUNT(*) FROM logs INDEXED BY idx_logs_ts_kind"+trafficBase+" GROUP BY kind", trafficArgs...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k string
			var n int64
			if err := rows.Scan(&k, &n); err != nil {
				return err
			}
			out.Traffic.ByKind[k] = n
		}
		return rows.Err()
	})

	// by_device: a deployment registers only a handful of devices, so this
	// GROUP BY stays cheap even when the window is large.
	run("by_device", func(ctx context.Context) error {
		if useRollup {
			m, err := s.rollupHourCounts(ctx, rw, "device", "idx_logs_ts_device", scope, sargs)
			if err != nil {
				return err
			}
			// Match the scan query: empty devices are excluded and the list is
			// capped at the top 100.
			delete(m, "")
			if len(m) > 100 {
				top := topCounts(m, 100)
				m = make(map[string]int64, len(top))
				for _, v := range top {
					m[v.Value] = v.Count
				}
			}
			out.ByDevice = m
			return nil
		}
		devWhere := trafficBase + " AND device != ''"
		devArgs := append([]interface{}{}, trafficArgs...)
		devRows, err := s.rdb.QueryContext(ctx,
			"SELECT device, COUNT(*) FROM logs INDEXED BY idx_logs_ts_device"+devWhere+
				" GROUP BY device ORDER BY 2 DESC LIMIT 100", devArgs...)
		if err != nil {
			return err
		}
		defer devRows.Close()
		out.ByDevice = map[string]int64{}
		for devRows.Next() {
			var d string
			var n int64
			if err := devRows.Scan(&d, &n); err != nil {
				return err
			}
			if d != "" {
				out.ByDevice[d] = n
			}
		}
		return devRows.Err()
	})

	// IP/app rankings: the primary payload of 流量分析 (explicit from/to
	// windows, rank=true). Bounded by their LIMIT 20 caps; the bare
	// 系统概况 call (cheap=true) omits them. Without an explicit window a
	// deep-dive (full=true, no from/to) bounds the rankings to the
	// trailing hour like the extras, so a bare ?full=1 call cannot scan
	// the whole history.
	rankCond := timeCond
	rankArgs := timeArgs
	if !hasWindow && !cheap {
		cutoff := time.Now().Unix() - 3600
		if rankCond == "" {
			rankCond = " AND ts >= ?"
			rankArgs = []interface{}{cutoff}
		} else {
			rankCond += " AND ts >= ?"
			rankArgs = append([]interface{}{}, rankArgs...)
			rankArgs = append(rankArgs, cutoff)
		}
	}
	if rank {
		ipWhere := " WHERE (src_ip != '' OR dst_ip != '')"
		ipArgs := []interface{}{}
		if scope != "" {
			ipWhere += " AND " + scope
			ipArgs = append(ipArgs, sargs...)
		}
		if rankCond != "" {
			ipWhere += rankCond
			ipArgs = append(ipArgs, rankArgs...)
		}
		run("ip_ranking", func(ctx context.Context) error {
			if useRollup {
				m, err := s.rollupIPCounts(ctx, rw, scope, sargs)
				if err != nil {
					return err
				}
				out.IPRanking = topPairs(m, 20)
				return nil
			}
			rows, err := s.rdb.QueryContext(ctx,
				"SELECT COALESCE(NULLIF(src_ip,''), dst_ip), COUNT(*), COALESCE(SUM(bytes_in + bytes_out),0) FROM logs"+ipWhere+
					" GROUP BY 1 ORDER BY 3 DESC LIMIT 20", ipArgs...)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var v IPRankValue
				if err := rows.Scan(&v.IP, &v.Records, &v.Bytes); err != nil {
					return err
				}
				if v.IP == "" {
					continue
				}
				out.IPRanking = append(out.IPRanking, v)
			}
			return rows.Err()
		})

		// App ranking by appid count, excluding unknown (-1). Served by
		// idx_logs_ts_appid over the window.
		appWhere := " WHERE appid >= 0"
		appArgs := []interface{}{}
		if scope != "" {
			appWhere += " AND " + scope
			appArgs = append(appArgs, sargs...)
		}
		if rankCond != "" {
			appWhere += rankCond
			appArgs = append(appArgs, rankArgs...)
		}
		run("app_ranking", func(ctx context.Context) error {
			if useRollup {
				m, err := s.rollupDimCounts(ctx, rw, rollupDimAppid, "CAST(appid AS TEXT)", "idx_logs_ts_appid", " AND appid >= 0", scope, sargs)
				if err != nil {
					return err
				}
				out.AppRanking = appRankingFromCounts(m)
				return nil
			}
			appRows, err := s.rdb.QueryContext(ctx,
				"SELECT appid, COUNT(*) FROM logs"+appWhere+" GROUP BY appid ORDER BY COUNT(*) DESC LIMIT 20", appArgs...)
			if err != nil {
				return err
			}
			defer appRows.Close()
			for appRows.Next() {
				var appid int
				var n int64
				if err := appRows.Scan(&appid, &n); err != nil {
					return err
				}
				name := AppNameOf(appid)
				if name == "" {
					name = strconv.Itoa(appid)
				}
				out.AppRanking = append(out.AppRanking, CountValue{
					Value: name,
					Count: n,
				})
			}
			return appRows.Err()
		})
	}

	// ---- overview extras ----
	// Top domain / source-IP lists are always computed so the 系统概况 1h
	// view can show them; they follow the effective window, which the
	// cheap path bounds to the trailing hour, so even the default call
	// stays an index-bounded set of queries (the (ts, domain) /
	// (ts, src_ip) composite indexes serve both). The recent-rows list
	// is still opt-in via ?full=1 (it materializes full rows, which the
	// auto-refresh does not need).
	{
		extraWhere := baseWhere
		extraArgs := append([]interface{}{}, baseArgs...)
		if extraWhere == "" {
			extraWhere = " WHERE ts >= ?"
			extraArgs = append(extraArgs, time.Now().Unix()-3600)
		}

		run("top_domains", func(ctx context.Context) error {
			if useRollup {
				m, err := s.rollupDimCounts(ctx, rw, rollupDimDomain, "domain", "idx_logs_ts_domain", " AND domain != ''", scope, sargs)
				if err != nil {
					return err
				}
				out.TopDomains = topCounts(m, 10)
				return nil
			}
			v, err := s.topValues(ctx, "domain", "idx_logs_ts_domain", 10, extraWhere, extraArgs)
			if err != nil {
				return err
			}
			out.TopDomains = v
			return nil
		})
		run("top_src_ip", func(ctx context.Context) error {
			if useRollup {
				m, err := s.rollupDimCounts(ctx, rw, rollupDimSrcIP, "src_ip", "idx_logs_ts_src", " AND src_ip != ''", scope, sargs)
				if err != nil {
					return err
				}
				out.TopSrcIP = topCounts(m, 10)
				return nil
			}
			v, err := s.topValues(ctx, "src_ip", "idx_logs_ts_src", 10, extraWhere, extraArgs)
			if err != nil {
				return err
			}
			out.TopSrcIP = v
			return nil
		})

		// Recent records within the window (last 10) — deep-dive only.
		if full {
			run("recent", func(ctx context.Context) error {
				recentRows, err := s.rdb.QueryContext(ctx,
					"SELECT "+logCols+" FROM logs"+extraWhere+
						" ORDER BY ts DESC, id DESC LIMIT 10", extraArgs...)
				if err != nil {
					return err
				}
				defer recentRows.Close()
				out.Recent = make([]Entry, 0, 10)
				for recentRows.Next() {
					e, err := scanEntry(recentRows.Scan)
					if err != nil {
						return err
					}
					out.Recent = append(out.Recent, e)
				}
				return recentRows.Err()
			})
		}
	}

	wg.Wait()
	if fail != nil {
		return nil, fail
	}
	return out, nil
}

// warmupTimeout bounds Warmup so a pathological planner choice aborts instead
// of running unbounded.
const warmupTimeout = 60 * time.Second

// Warmup primes the SQLite page cache so the first user request does not pay
// the cold-cache cost of scanning the large index/tree pages. It runs the
// aggregate queries the default dashboard paths execute (see warmupProbes).
//
// Two invariants keep warmup from ever wedging the service:
//
//  1. It runs on the dedicated read pool (query_only). A cold aggregate on a
//     large table can take minutes; holding the write connection would starve
//     ingest and every DB-backed HTTP handler. The read pool is independent.
//  2. It is bounded by warmupTimeout.
//
// Every probe must additionally be index-bounded; TestWarmupProbesAreIndexBounded
// enforces this.
func (s *Store) Warmup() error {
	now := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), warmupTimeout)
	defer cancel()
	for _, q := range warmupProbes(now.Add(-time.Hour).Unix(), now.Add(-24*time.Hour).Unix()) {
		if err := drainQuery(ctx, s.rdb, q); err != nil {
			return err
		}
	}
	return nil
}

// drainQuery runs q to completion, discarding the rows. Probes return varying
// column counts, so the scan destinations are sized from the result columns.
func drainQuery(ctx context.Context, db *sql.DB, q string) error {
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	dest := make([]any, len(cols))
	for i := range dest {
		var v any
		dest[i] = &v
	}
	for rows.Next() {
		if err := rows.Scan(dest...); err != nil {
			return err
		}
	}
	return rows.Err()
}

// warmupProbes returns the cache-priming statements. Each MUST be bounded to a
// small indexed range — a ts window or an equality seek — and never a bare
// scan; see Warmup. Kept as a helper so tests can EXPLAIN every probe's plan.
func warmupProbes(hour, day int64) []string {
	return []string{
		fmt.Sprintf("SELECT COUNT(*), COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0) FROM logs WHERE ts >= %d", hour),
		fmt.Sprintf("SELECT (ts/3600)*3600 AS h, COUNT(*) FROM logs WHERE ts >= %d GROUP BY h", day),
		"SELECT COUNT(*) FROM logs WHERE kind = ''",
		"SELECT COUNT(*) FROM logs WHERE src_ip = ''",
		"SELECT COUNT(*) FROM logs WHERE dst_ip = ''",
		"SELECT COUNT(*) FROM logs WHERE device = ''",
		warmupAppidProbe(hour),
	}
}

// warmupAppidProbe is the appid cache-warming probe. It MUST stay ts-bounded:
// the logs table has no single-column appid index, so a bare `WHERE appid = ?`
// degrades to a full table scan which — on the store's single pooled
// connection — starves ingest and the API (the live incident). The ts bound
// makes it seek idx_logs_ts_appid instead.
func warmupAppidProbe(hour int64) string {
	return "SELECT COUNT(*) FROM logs WHERE ts >= " + strconv.FormatInt(hour, 10) + " AND appid = 0"
}

// GetConfig loads config from kv with defaults; dbPath comes from the flag.
func (s *Store) GetConfig(dbPath string) (Config, error) {
	cfg := Config{
		HTTPAddr:      ":8080",
		RetentionDays: 30,
		DBPath:        dbPath,
	}
	ctx, cancel := s.readCtx()
	defer cancel()
	rows, err := s.rdb.QueryContext(ctx, "SELECT key, value FROM kv")
	if err != nil {
		return cfg, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return cfg, err
		}
		switch k {
		case "http_addr":
			cfg.HTTPAddr = v
		case "retention_days":
			fmt.Sscanf(v, "%d", &cfg.RetentionDays)
		case "tls":
			cfg.TLS = v == "1" || v == "true"
		case "tls_cert":
			cfg.TLSCert = v
		case "tls_key":
			cfg.TLSKey = v
		case "captcha":
			cfg.Captcha = v == "1" || v == "true"
		}
	}
	return cfg, rows.Err()
}

// SetConfig persists the service configuration. It is a full write: the
// admin 服务配置 form submits the complete config, so the TLS/captcha
// toggles and certificate fields are stored exactly as given (an empty
// certificate clears it). handleConfigPut back-fills http_addr/retention
// from the current row so a hand-written partial PUT cannot blank them.
func (s *Store) SetConfig(c Config) error {
	pairs := map[string]string{
		"http_addr":      c.HTTPAddr,
		"retention_days": strconv.Itoa(c.RetentionDays),
		"tls":            boolKV(c.TLS),
		"tls_cert":       c.TLSCert,
		"tls_key":        c.TLSKey,
		"captcha":        boolKV(c.Captcha),
	}
	for k, v := range pairs {
		if _, err := s.db.Exec(
			"INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
			k, v); err != nil {
			return err
		}
	}
	return nil
}

func boolKV(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// ApplyRetention deletes rows older than retentionDays; returns deleted count.
func (s *Store) ApplyRetention(retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().Unix() - int64(retentionDays)*86400
	var n int64
	if err := s.writeTx(func(tx *sql.Tx) error {
		res, err := tx.Exec("DELETE FROM logs WHERE ts < ?", cutoff)
		if err != nil {
			return err
		}
		m, err := res.RowsAffected()
		if err != nil {
			return err
		}
		n = m
		// Prune the derived rollups with the same cutoff. Both tables are
		// keyed by hour, so this drops whole expired buckets and keeps the
		// rollups from outliving the rows they were derived from.
		if _, err := tx.Exec("DELETE FROM agg_hour WHERE hour < ?", cutoff); err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM agg_dim WHERE hour < ?", cutoff); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return 0, err
	}
	return n, nil
}

/* ---------------- hourly rollups ---------------- */

// rollupChunk bounds one rollup transaction. RollupTick may consume a much
// larger budget per call, but it commits every chunk, so its write
// transactions stay short and never hold the write mutex for long.
const rollupChunk = 2000

// rollupRow is the narrow projection the rollups need from logs. Selecting
// only these columns keeps the backfill out of the wide parts of the table
// (counters / extra / raw), which is what makes replaying 29M rows cheap.
type rollupRow struct {
	id       int64
	ts       int64
	device   string
	kind     string
	domain   string
	srcIP    string
	dstIP    string
	appid    int
	bytesIn  int64
	bytesOut int64
}

// agg_dim dimension tags.
const (
	rollupDimDomain = "domain"
	rollupDimSrcIP  = "src_ip"
	rollupDimIP     = "ip"
	rollupDimAppid  = "appid"
)

// hourBucket returns the hour a ts belongs to. It is the single definition
// shared by the rollup writer and the rollup readers, and is the same
// (ts/3600)*3600 rounding the raw trend query uses.
func hourBucket(ts int64) int64 {
	return (ts / 3600) * 3600
}

// rollupLastID reports the highest logs.id already folded into the rollups.
func (s *Store) rollupLastID() (int64, error) {
	ctx, cancel := s.readCtx()
	defer cancel()
	var id int64
	if err := s.rdb.QueryRowContext(ctx, "SELECT last_id FROM rollup_state WHERE id = 1").Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

// RollupLag reports how many newly inserted rows are not yet folded in
// (0 = the rollups are current). The read path uses it to decide whether a
// rollup-backed answer would be exact, and the worker logs it while backfilling.
func (s *Store) RollupLag() (int64, error) {
	ctx, cancel := s.readCtx()
	defer cancel()
	// MAX(id) on an INTEGER PRIMARY KEY is a B-tree-maximum seek, not a scan.
	var maxID int64
	if err := s.rdb.QueryRowContext(ctx, "SELECT COALESCE(MAX(id),0) FROM logs").Scan(&maxID); err != nil {
		return 0, err
	}
	var lastID int64
	if err := s.rdb.QueryRowContext(ctx, "SELECT last_id FROM rollup_state WHERE id = 1").Scan(&lastID); err != nil {
		return 0, err
	}
	if maxID <= lastID {
		return 0, nil
	}
	return maxID - lastID, nil
}

// RollupTick folds at most budget newly inserted rows into the rollup tables
// and returns how many it folded (0 = fully caught up).
//
// It deliberately runs OUTSIDE the ingest path: a plain read of logs on the
// read-only pool plus short additive upserts on the write connection. The live
// incident that shaped this package was a read query starving the ingest
// writer, so the rollup never joins InsertBatch's transaction and can always
// be backfilled or replayed later. Because rollup_state.last_id advances in the
// same transaction as its upserts, an interrupted tick loses nothing and
// replays (the aggregates are additive).
func (s *Store) RollupTick(budget int) (int, error) {
	if budget <= 0 {
		budget = rollupChunk
	}
	lastID, err := s.rollupLastID()
	if err != nil {
		return 0, err
	}
	total := 0
	for total < budget {
		n := rollupChunk
		if rem := budget - total; rem < n {
			n = rem
		}
		rows, err := s.readRollupRows(lastID, n)
		if err != nil {
			return total, err
		}
		if len(rows) == 0 {
			break
		}
		if err := s.applyRollup(rows); err != nil {
			return total, err
		}
		lastID = rows[len(rows)-1].id
		total += len(rows)
	}
	return total, nil
}

// readRollupRows reads the next `limit` rows after id `after`, ordered by id so
// the rollup advances monotonically. ORDER BY id rides the primary key.
func (s *Store) readRollupRows(after int64, limit int) ([]rollupRow, error) {
	ctx, cancel := s.readCtx()
	defer cancel()
	rows, err := s.rdb.QueryContext(ctx,
		"SELECT id, ts, device, kind, domain, src_ip, dst_ip, appid, bytes_in, bytes_out FROM logs WHERE id > ? ORDER BY id LIMIT ?",
		after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]rollupRow, 0, limit)
	for rows.Next() {
		var r rollupRow
		if err := rows.Scan(&r.id, &r.ts, &r.device, &r.kind, &r.domain, &r.srcIP, &r.dstIP, &r.appid, &r.bytesIn, &r.bytesOut); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// applyRollup folds one chunk into agg_hour/agg_dim and advances last_id, all
// in a single transaction, so the recorded state can never drift from the
// aggregates.
func (s *Store) applyRollup(rows []rollupRow) error {
	type hourKey struct {
		hour   int64
		device string
		kind   string
	}
	type dimKey struct {
		dim    string
		device string
		value  string
		hour   int64
	}
	hours := make(map[hourKey][3]int64, len(rows))
	dims := make(map[dimKey][2]int64, 4*len(rows))
	for _, r := range rows {
		h := hourBucket(r.ts)
		hk := hourKey{h, r.device, r.kind}
		v := hours[hk]
		v[0]++
		v[1] += r.bytesIn
		v[2] += r.bytesOut
		hours[hk] = v

		bytes := r.bytesIn + r.bytesOut
		addDim := func(dim, value string) {
			if value == "" {
				return
			}
			dk := dimKey{dim, r.device, value, h}
			d := dims[dk]
			d[0]++
			d[1] += bytes
			dims[dk] = d
		}
		addDim(rollupDimDomain, r.domain)
		addDim(rollupDimSrcIP, r.srcIP)
		// The IP ranking groups by COALESCE(NULLIF(src_ip,''), dst_ip) and
		// skips rows where both are empty, so the rollup key is that
		// expression verbatim.
		if r.srcIP != "" {
			addDim(rollupDimIP, r.srcIP)
		} else {
			addDim(rollupDimIP, r.dstIP)
		}
		// The app ranking counts appid >= 0 only (unknown is -1).
		if r.appid >= 0 {
			addDim(rollupDimAppid, strconv.Itoa(r.appid))
		}
	}
	lastID := rows[len(rows)-1].id
	return s.writeTx(func(tx *sql.Tx) error {
		hs, err := tx.Prepare(`INSERT INTO agg_hour(hour, device, kind, n, bytes_in, bytes_out)
			VALUES(?,?,?,?,?,?)
			ON CONFLICT(hour, device, kind) DO UPDATE SET
			  n = n + excluded.n,
			  bytes_in = bytes_in + excluded.bytes_in,
			  bytes_out = bytes_out + excluded.bytes_out`)
		if err != nil {
			return err
		}
		defer hs.Close()
		for k, v := range hours {
			if _, err := hs.Exec(k.hour, k.device, k.kind, v[0], v[1], v[2]); err != nil {
				return err
			}
		}
		ds, err := tx.Prepare(`INSERT INTO agg_dim(dim, device, value, hour, n, bytes)
			VALUES(?,?,?,?,?,?)
			ON CONFLICT(dim, device, value, hour) DO UPDATE SET
			  n = n + excluded.n,
			  bytes = bytes + excluded.bytes`)
		if err != nil {
			return err
		}
		defer ds.Close()
		for k, v := range dims {
			if _, err := ds.Exec(k.dim, k.device, k.value, k.hour, v[0], v[1]); err != nil {
				return err
			}
		}
		_, err = tx.Exec("UPDATE rollup_state SET last_id = ?, updated_at = ? WHERE id = 1",
			lastID, time.Now().Unix())
		return err
	})
}

/* ---------------- devices ---------------- */

// ListDevices returns all devices ordered by name.
func (s *Store) ListDevices() ([]Device, error) {
	ctx, cancel := s.readCtx()
	defer cancel()
	rows, err := s.rdb.QueryContext(ctx, "SELECT id, name, port, enabled FROM devices ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var en int
		if err := rows.Scan(&d.ID, &d.Name, &d.Port, &en); err != nil {
			return nil, err
		}
		d.Enabled = en != 0
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListEnabledDevices returns only enabled devices.
func (s *Store) ListEnabledDevices() ([]Device, error) {
	ctx, cancel := s.readCtx()
	defer cancel()
	rows, err := s.rdb.QueryContext(ctx, "SELECT id, name, port, enabled FROM devices WHERE enabled=1 ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var en int
		if err := rows.Scan(&d.ID, &d.Name, &d.Port, &en); err != nil {
			return nil, err
		}
		d.Enabled = true
		out = append(out, d)
	}
	return out, rows.Err()
}

// UpsertDevice inserts or updates a device. Name must be unique, port 1-65535.
func (s *Store) UpsertDevice(d Device) (Device, error) {
	if strings.TrimSpace(d.Name) == "" {
		return d, fmt.Errorf("device name required")
	}
	if d.Port < 1 || d.Port > 65535 {
		return d, fmt.Errorf("port must be 1-65535")
	}
	en := 0
	if d.Enabled {
		en = 1
	}
	if d.ID > 0 {
		err := s.writeTx(func(tx *sql.Tx) error {
			var oldName string
			if err := tx.QueryRow("SELECT name FROM devices WHERE id=?", d.ID).Scan(&oldName); err != nil {
				return err
			}
			res, err := tx.Exec("UPDATE devices SET name=?, port=?, enabled=? WHERE id=?", d.Name, d.Port, en, d.ID)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return fmt.Errorf("device %d not found", d.ID)
			}
			if oldName != d.Name {
				_, err := tx.Exec("UPDATE logs SET device=? WHERE device=?", d.Name, oldName)
				return err
			}
			return nil
		})
		if err != nil {
			return d, err
		}
	} else {
		res, err := s.db.Exec("INSERT INTO devices(name, port, enabled) VALUES(?,?,?)", d.Name, d.Port, en)
		if err != nil {
			return d, err
		}
		id, _ := res.LastInsertId()
		d.ID = id
	}
	return d, nil
}
// DeleteDevice removes a device and returns the name that was deleted.
func (s *Store) DeleteDevice(id int64) (string, error) {
	var name string
	err := s.db.QueryRow("SELECT name FROM devices WHERE id=?", id).Scan(&name)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("device %d not found", id)
	}
	if err != nil {
		return "", err
	}
	if _, err := s.db.Exec("DELETE FROM devices WHERE id=?", id); err != nil {
		return "", err
	}
	return name, nil
}

// CountDevices returns device count (used to guard the last-device deletion).
func (s *Store) CountDevices() (int64, error) {
	var n int64
	err := s.db.QueryRow("SELECT COUNT(*) FROM devices").Scan(&n)
	return n, err
}

/* ---------------- users & sessions ---------------- */

const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

const pbkdf2Iter = 210000

// HashPassword derives a stored hash with PBKDF2-HMAC-SHA256.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2$sha256$%d$%s$%s",
		pbkdf2Iter,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// CheckPassword verifies pw against a HashPassword-produced hash.
func CheckPassword(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 5 || parts[0] != "pbkdf2" || parts[1] != "sha256" {
		return false
	}
	var iter int
	if _, err := fmt.Sscanf(parts[2], "%d", &iter); err != nil || iter <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// CreateUser inserts a user with a hashed password.
func (s *Store) CreateUser(u User, password string) (User, error) {
	u.Username = strings.TrimSpace(u.Username)
	if u.Username == "" {
		return u, fmt.Errorf("username required")
	}
	if password == "" {
		return u, fmt.Errorf("password required")
	}
	if u.Role != RoleAdmin && u.Role != RoleUser {
		return u, fmt.Errorf("role must be admin or user")
	}
	if strings.TrimSpace(u.Devices) == "" {
		u.Devices = "*"
	}
	hash, err := HashPassword(password)
	if err != nil {
		return u, err
	}
	res, err := s.db.Exec("INSERT INTO users(username, pass_hash, role, devices, created_at, tfa_required) VALUES(?,?,?,?,?,?)",
		u.Username, hash, u.Role, u.Devices, time.Now().Unix(), u.TFARequired)
	if err != nil {
		return u, err
	}
	u.ID, _ = res.LastInsertId()
	u.CreatedAt = time.Now().Unix()
	u.PassHash = ""
	u.TFASecret = ""
	u.TFAEnabled = false
	return u, nil
}

// UpdateUser updates role/devices and optionally the password.
func (s *Store) UpdateUser(id int64, role, devices, newPassword string) error {
	if role != "" && role != RoleAdmin && role != RoleUser {
		return fmt.Errorf("role must be admin or user")
	}
	if role != "" {
		if _, err := s.db.Exec("UPDATE users SET role=? WHERE id=?", role, id); err != nil {
			return err
		}
	}
	if devices != "" {
		if _, err := s.db.Exec("UPDATE users SET devices=? WHERE id=?", devices, id); err != nil {
			return err
		}
	}
	if newPassword != "" {
		hash, err := HashPassword(newPassword)
		if err != nil {
			return err
		}
		if _, err := s.db.Exec("UPDATE users SET pass_hash=? WHERE id=?", hash, id); err != nil {
			return err
		}
	}
	return nil
}

// SetUserTFARequired toggles the admin-forced two-factor requirement for a
// user (the user may still enroll voluntarily when it is off).
func (s *Store) SetUserTFARequired(id int64, required bool) error {
	v := 0
	if required {
		v = 1
	}
	_, err := s.db.Exec("UPDATE users SET tfa_required=? WHERE id=?", v, id)
	return err
}

// SetUserTFASecret stores the user's enrolled TOTP secret, or clears it when
// secret is empty (self-service disable, or an admin reset after the user
// lost their authenticator).
func (s *Store) SetUserTFASecret(id int64, secret string) error {
	_, err := s.db.Exec("UPDATE users SET tfa_secret=? WHERE id=?", secret, id)
	return err
}

// ListUsers returns all users without password hashes.
func (s *Store) ListUsers() ([]User, error) {
	ctx, cancel := s.readCtx()
	defer cancel()
	rows, err := s.rdb.QueryContext(ctx, "SELECT id, username, role, devices, created_at, tfa_required, (tfa_secret <> '') FROM users ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.Devices, &u.CreatedAt, &u.TFARequired, &u.TFAEnabled); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// GetUserByUsername returns a user (with hash) by name.
func (s *Store) GetUserByUsername(name string) (*User, error) {
	ctx, cancel := s.readCtx()
	defer cancel()
	row := s.rdb.QueryRowContext(ctx, "SELECT id, username, pass_hash, role, devices, created_at, tfa_required, tfa_secret FROM users WHERE username=?", name)
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.PassHash, &u.Role, &u.Devices, &u.CreatedAt, &u.TFARequired, &u.TFASecret)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.TFAEnabled = u.TFASecret != ""
	return &u, nil
}

// GetUser returns a user (without hash) by id.
func (s *Store) GetUser(id int64) (*User, error) {
	ctx, cancel := s.readCtx()
	defer cancel()
	row := s.rdb.QueryRowContext(ctx, "SELECT id, username, pass_hash, role, devices, created_at, tfa_required, tfa_secret FROM users WHERE id=?", id)
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.PassHash, &u.Role, &u.Devices, &u.CreatedAt, &u.TFARequired, &u.TFASecret)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.TFAEnabled = u.TFASecret != ""
	u.PassHash = ""
	return &u, nil
}

// DeleteUser removes a user; refuses to delete the last admin.
func (s *Store) DeleteUser(id int64) error {
	var role string
	if err := s.db.QueryRow("SELECT role FROM users WHERE id=?", id).Scan(&role); err != nil {
		return err
	}
	if role == RoleAdmin {
		var admins int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE role=?", RoleAdmin).Scan(&admins); err != nil {
			return err
		}
		if admins <= 1 {
			return fmt.Errorf("cannot delete the last admin account")
		}
	}
	_, err := s.db.Exec("DELETE FROM users WHERE id=?", id)
	return err
}

// CountUsers returns the total user count.
func (s *Store) CountUsers() (int64, error) {
	var n int64
	ctx, cancel := s.readCtx()
	defer cancel()
	err := s.rdb.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&n)
	return n, err
}

// CreateSession issues a random token for a user.
func (s *Store) CreateSession(userID int64, ttl time.Duration) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	exp := time.Now().Add(ttl).Unix()
	if _, err := s.db.Exec("INSERT INTO sessions(token, user_id, expires) VALUES(?,?,?)", tok, userID, exp); err != nil {
		return "", err
	}
	return tok, nil
}

// GetUserByToken resolves a session token to its user; expired tokens are
// deleted and rejected.
func (s *Store) GetUserByToken(token string) (*User, error) {
	ctx, cancel := s.readCtx()
	defer cancel()
	row := s.rdb.QueryRowContext(ctx,
		"SELECT u.id, u.username, u.pass_hash, u.role, u.devices, u.created_at, u.tfa_required, u.tfa_secret "+
			"FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token=?", token)
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.PassHash, &u.Role, &u.Devices, &u.CreatedAt, &u.TFARequired, &u.TFASecret)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var expires int64
	if err := s.rdb.QueryRowContext(ctx, "SELECT expires FROM sessions WHERE token=?", token).Scan(&expires); err != nil {
		return nil, err
	}
	if expires < time.Now().Unix() {
		s.DeleteSession(token)
		return nil, nil
	}
	u.TFAEnabled = u.TFASecret != ""
	u.PassHash = ""
	return &u, nil
}

// DeleteSession invalidates a token.
func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE token=?", token)
	return err
}

// DeleteSessionsExcept revokes every session of userID except keepToken
// (used after a password change so the caller stays logged in).
func (s *Store) DeleteSessionsExcept(userID int64, keepToken string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE user_id=? AND token<>?", userID, keepToken)
	return err
}

// CleanExpiredSessions deletes expired tokens (called periodically).
func (s *Store) CleanExpiredSessions() error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE expires < ?", time.Now().Unix())
	return err
}