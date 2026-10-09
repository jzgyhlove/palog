// Package store persists normalized log records in SQLite and serves the
// queries required by the REST API (see docs/API.md). It also holds the
// device registry (one UDP port per device), the user registry and the
// auth session table.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"crypto/pbkdf2" // stdlib since Go 1.24

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
}

// Default device name used to stamp rows collected before the device table
// existed (single-socket deployments).
const DefaultDevice = "panabit"

type Store struct {
	db     *sql.DB
	dbPath string
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
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires);`

// Open opens (and migrates) the database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// modernc sqlite: single writer; WAL keeps readers unblocked.
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA busy_timeout=5000;",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("pragma: %w", err)
		}
	}
	s := &Store{db: db, dbPath: path}
	// legacy DBs (pre multi-device) lack logs.device; add it before schema
	// so that idx_logs_device can be created.
	if err := s.migrateDeviceColumn(); err != nil {
		db.Close()
		return nil, fmt.Errorf("device column: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := s.migrateLegacy(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate legacy: %w", err)
	}
	return s, nil
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
	_, err = s.db.Exec("ALTER TABLE logs ADD COLUMN device TEXT NOT NULL DEFAULT ''")
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
	if _, err := s.db.Exec(
		"INSERT INTO devices(name, port, enabled) VALUES(?,?,1)", DefaultDevice, port); err != nil {
		return err
	}
	_, err = s.db.Exec("UPDATE logs SET device=? WHERE device=''", DefaultDevice)
	return err
}

func parseUDPPort(addr string) (int, error) {
	addr = strings.TrimSpace(addr)
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		addr = addr[i+1:]
	}
	return strconv.Atoi(addr)
}

func (s *Store) Close() error { return s.db.Close() }

// InsertBatch writes entries in one transaction.
func (s *Store) InsertBatch(entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO logs
	  (device, recv_ts, kind, ts, ts_end, src_ip, src_port, dst_ip, dst_port, proto,
	   mac, iface, iface2, appid, domain, host, path, method, user,
	   bytes_in, bytes_out, counters, flags, rec_type, extra, raw)
	  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		counters := ""
		if len(e.Counters) > 0 {
			b, err := json.Marshal(e.Counters)
			if err != nil {
				tx.Rollback()
				return err
			}
			counters = string(b)
		}
		extra := ""
		if len(e.Extra) > 0 {
			b, err := json.Marshal(e.Extra)
			if err != nil {
				tx.Rollback()
				return err
			}
			extra = string(b)
		}
		if _, err := stmt.Exec(e.Device, e.RecvTS, e.Kind, e.TS, e.TSEnd,
			e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.Proto,
			e.MAC, e.Iface, e.Iface2, e.Appid, e.Domain, e.Host, e.Path, e.Method, e.User,
			e.BytesIn, e.BytesOut, counters, e.Flags, e.RecType, extra, e.Raw); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
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
	where, args := buildWhere(q)

	var total int64
	if err := s.db.QueryRow("SELECT COUNT(*) FROM logs"+where, args...).Scan(&total); err != nil {
		return 0, nil, err
	}
	order := "DESC"
	if strings.EqualFold(q.Order, "asc") {
		order = "ASC"
	}
	sqlStr := "SELECT " + logCols + " FROM logs" + where +
		" ORDER BY ts " + order + ", id " + order + " LIMIT ? OFFSET ?"
	rows, err := s.db.Query(sqlStr, append(args, q.Limit, q.Offset)...)
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
	row := s.db.QueryRow("SELECT "+logCols+" FROM logs WHERE id = ?", id)
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

// Stats aggregates dashboard data. devices limits scope (nil = all).
func (s *Store) Stats(c Counters, uptime time.Duration, devices []string) (*Stats, error) {
	st := &Stats{
		Packets:     c.Packets,
		Records:     c.Records,
		ParseErrors: c.ParseErrors,
		ByKind:      map[string]int64{},
		ByDevice:    map[string]int64{},
	}
	if uptime.Seconds() > 0 {
		st.PPS = float64(c.Packets) / uptime.Seconds()
	}
	scope, sargs := scopeCond(devices)
	where := ""
	args := []interface{}{}
	if scope != "" {
		where = " WHERE " + scope
		args = sargs
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM logs"+where, args...).Scan(&st.Total); err != nil {
		return nil, err
	}
	// LastHour: append a ts guard to the scope filter. When scope is empty
	// `where` is empty, so build from a bare ts clause instead of concatenating.
	lastWhere := " WHERE ts >= ?"
	lastArgs := []interface{}{time.Now().Unix() - 3600}
	if where != "" {
		lastWhere = where + " AND ts >= ?"
		lastArgs = append(append([]interface{}{}, sargs...), time.Now().Unix()-3600)
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM logs"+lastWhere, lastArgs...).Scan(&st.LastHour); err != nil {
		return nil, err
	}

	groupWhere := ""
	gArgs := []interface{}{}
	if scope != "" {
		groupWhere = " WHERE " + scope
		gArgs = append(gArgs, sargs...)
	}
	// ByKind: same table filter groupWhere (empty = all rows).
	rows, err := s.db.Query("SELECT kind, COUNT(*) FROM logs"+groupWhere+" GROUP BY kind", gArgs...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			rows.Close()
			return nil, err
		}
		st.ByKind[k] = n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// ByDevice: same filter, plus excluding the empty device sentinel.
	// groupWhere may be empty (no scope), so build the clause conditionally.
	devWhere := " WHERE device != ''"
	devArgs := []interface{}{}
	if groupWhere != "" {
		devWhere = groupWhere + " AND device != ''"
		devArgs = gArgs
	}
	rows, err = s.db.Query("SELECT device, COUNT(*) FROM logs"+devWhere+" GROUP BY device ORDER BY 2 DESC", devArgs...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var d string
		var n int64
		if err := rows.Scan(&d, &n); err != nil {
			rows.Close()
			return nil, err
		}
		st.ByDevice[d] = n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if st.TopDomains, err = s.topValues("domain", 10, scope, sargs); err != nil {
		return nil, err
	}
	if st.TopSrcIP, err = s.topValues("src_ip", 10, scope, sargs); err != nil {
		return nil, err
	}

	if st.Devices, err = s.ListDevices(); err != nil {
		return nil, err
	}

	// 24 contiguous hourly buckets ending at the current hour (UTC labels).
	now := time.Now().UTC()
	curHour := now.Truncate(time.Hour)
	hWhere := " WHERE ts >= ?"
	hArgs := []interface{}{curHour.Add(-23 * time.Hour).Unix()}
	if scope != "" {
		hWhere = " WHERE " + scope + " AND ts >= ?"
		hArgs = append(append([]interface{}{}, sargs...), curHour.Add(-23*time.Hour).Unix())
	}
	rows, err = s.db.Query("SELECT (ts/3600)*3600 AS h, COUNT(*) FROM logs"+hWhere+" GROUP BY h", hArgs...)
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

	_, recent, err := s.Query(LogQuery{Limit: 10, Order: "desc", Devices: devices})
	if err != nil {
		return nil, err
	}
	st.Recent = recent
	return st, nil
}

func (s *Store) topValues(col string, n int, scope string, sargs []interface{}) ([]CountValue, error) {
	// col is an internal constant, never user input.
	where := " WHERE " + col + " != ''"
	args := []interface{}{}
	if scope != "" {
		where += " AND " + scope
		args = append(args, sargs...)
	}
	args = append(args, n)
	rows, err := s.db.Query(
		"SELECT "+col+", COUNT(*) AS c FROM logs"+where+" GROUP BY "+col+" ORDER BY c DESC LIMIT ?", args...)
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

// GetConfig loads config from kv with defaults; dbPath comes from the flag.
func (s *Store) GetConfig(dbPath string) (Config, error) {
	cfg := Config{
		HTTPAddr:      ":8080",
		RetentionDays: 30,
		DBPath:        dbPath,
	}
	rows, err := s.db.Query("SELECT key, value FROM kv")
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
		}
	}
	return cfg, rows.Err()
}

// SetConfig persists the given fields (empty string / zero = leave unchanged).
func (s *Store) SetConfig(c Config) error {
	pairs := map[string]string{}
	if c.HTTPAddr != "" {
		pairs["http_addr"] = c.HTTPAddr
	}
	if c.RetentionDays > 0 {
		pairs["retention_days"] = fmt.Sprintf("%d", c.RetentionDays)
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

// ApplyRetention deletes rows older than retentionDays; returns deleted count.
func (s *Store) ApplyRetention(retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().Unix() - int64(retentionDays)*86400
	res, err := s.db.Exec("DELETE FROM logs WHERE ts < ?", cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

/* ---------------- devices ---------------- */

// ListDevices returns all devices ordered by name.
func (s *Store) ListDevices() ([]Device, error) {
	rows, err := s.db.Query("SELECT id, name, port, enabled FROM devices ORDER BY name")
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
	rows, err := s.db.Query("SELECT id, name, port, enabled FROM devices WHERE enabled=1 ORDER BY name")
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
		res, err := s.db.Exec("UPDATE devices SET name=?, port=?, enabled=? WHERE id=?", d.Name, d.Port, en, d.ID)
		if err != nil {
			return d, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return d, fmt.Errorf("device %d not found", d.ID)
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
	res, err := s.db.Exec("INSERT INTO users(username, pass_hash, role, devices, created_at) VALUES(?,?,?,?,?)",
		u.Username, hash, u.Role, u.Devices, time.Now().Unix())
	if err != nil {
		return u, err
	}
	u.ID, _ = res.LastInsertId()
	u.CreatedAt = time.Now().Unix()
	u.PassHash = ""
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

// ListUsers returns all users without password hashes.
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query("SELECT id, username, role, devices, created_at FROM users ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.Devices, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// GetUserByUsername returns a user (with hash) by name.
func (s *Store) GetUserByUsername(name string) (*User, error) {
	row := s.db.QueryRow("SELECT id, username, pass_hash, role, devices, created_at FROM users WHERE username=?", name)
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.PassHash, &u.Role, &u.Devices, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// GetUser returns a user (without hash) by id.
func (s *Store) GetUser(id int64) (*User, error) {
	row := s.db.QueryRow("SELECT id, username, pass_hash, role, devices, created_at FROM users WHERE id=?", id)
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.PassHash, &u.Role, &u.Devices, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
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
	err := s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
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
	row := s.db.QueryRow(
		"SELECT u.id, u.username, u.pass_hash, u.role, u.devices, u.created_at "+
			"FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token=?", token)
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.PassHash, &u.Role, &u.Devices, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var expires int64
	if err := s.db.QueryRow("SELECT expires FROM sessions WHERE token=?", token).Scan(&expires); err != nil {
		return nil, err
	}
	if expires < time.Now().Unix() {
		s.DeleteSession(token)
		return nil, nil
	}
	u.PassHash = ""
	return &u, nil
}

// DeleteSession invalidates a token.
func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE token=?", token)
	return err
}

// CleanExpiredSessions deletes expired tokens (called periodically).
func (s *Store) CleanExpiredSessions() error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE expires < ?", time.Now().Unix())
	return err
}