// Package store persists normalized log records in SQLite and serves the
// queries required by the REST API (see docs/API.md).
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Entry is one normalized log row (both text logs and binary records).
type Entry struct {
	ID        int64              `json:"id"`
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
	Kind   string
	Q      string
	SrcIP  string
	DstIP  string
	Domain string
	From   int64 // unix seconds, 0 = unset
	To     int64
	Limit  int
	Offset int
	Order  string // asc | desc
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
	TopDomains  []CountValue     `json:"top_domains"`
	TopSrcIP    []CountValue     `json:"top_src_ip"`
	Hourly      []HourCount      `json:"hourly"`
	Recent      []Entry          `json:"recent"`
}

type CountValue struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

type HourCount struct {
	Hour  string `json:"hour"`
	Count int64  `json:"count"`
}

// Config is the kv-backed service configuration.
type Config struct {
	ListenUDP     string `json:"listen_udp"`
	HTTPAddr      string `json:"http_addr"`
	RetentionDays int    `json:"retention_days"`
	DBPath        string `json:"db_path"`
}

type Store struct {
	db     *sql.DB
	dbPath string
}

const schema = `
CREATE TABLE IF NOT EXISTS logs (
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
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);
CREATE INDEX IF NOT EXISTS idx_logs_kind ON logs(kind);
CREATE INDEX IF NOT EXISTS idx_logs_src ON logs(src_ip);
CREATE INDEX IF NOT EXISTS idx_logs_dst ON logs(dst_ip);
CREATE INDEX IF NOT EXISTS idx_logs_domain ON logs(domain);
CREATE TABLE IF NOT EXISTS kv (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);`

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
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db, dbPath: path}, nil
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
	  (recv_ts, kind, ts, ts_end, src_ip, src_port, dst_ip, dst_port, proto,
	   mac, iface, iface2, appid, domain, host, path, method, user,
	   bytes_in, bytes_out, counters, flags, rec_type, extra, raw)
	  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
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
		if _, err := stmt.Exec(e.RecvTS, e.Kind, e.TS, e.TSEnd,
			e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.Proto,
			e.MAC, e.Iface, e.Iface2, e.Appid, e.Domain, e.Host, e.Path, e.Method, e.User,
			e.BytesIn, e.BytesOut, counters, e.Flags, e.RecType, extra, e.Raw); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

const logCols = `id, recv_ts, kind, ts, ts_end, src_ip, src_port, dst_ip, dst_port,
  proto, mac, iface, iface2, appid, domain, host, path, method, user,
  bytes_in, bytes_out, counters, flags, rec_type, extra, raw`

func scanEntry(scan func(dest ...interface{}) error) (Entry, error) {
	var e Entry
	var counters, extra string
	err := scan(&e.ID, &e.RecvTS, &e.Kind, &e.TS, &e.TSEnd,
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

func buildWhere(q LogQuery) (string, []interface{}) {
	var conds []string
	var args []interface{}
	if q.Kind != "" {
		conds = append(conds, "kind = ?")
		args = append(args, q.Kind)
	}
	if q.SrcIP != "" {
		conds = append(conds, "src_ip = ?")
		args = append(args, q.SrcIP)
	}
	if q.DstIP != "" {
		conds = append(conds, "dst_ip = ?")
		args = append(args, q.DstIP)
	}
	if q.Domain != "" {
		conds = append(conds, "domain = ?")
		args = append(args, q.Domain)
	}
	if q.Q != "" {
		like := "%" + escapeLike(q.Q) + "%"
		conds = append(conds, "(src_ip LIKE ? ESCAPE '\\' OR dst_ip LIKE ? ESCAPE '\\' OR domain LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\' OR user LIKE ? ESCAPE '\\')")
		for i := 0; i < 6; i++ {
			args = append(args, like)
		}
	}
	if q.From > 0 {
		conds = append(conds, "ts >= ?")
		args = append(args, q.From)
	}
	if q.To > 0 {
		conds = append(conds, "ts <= ?")
		args = append(args, q.To)
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

// Stats aggregates dashboard data. uptime is the process uptime.
func (s *Store) Stats(c Counters, uptime time.Duration) (*Stats, error) {
	st := &Stats{
		Packets:     c.Packets,
		Records:     c.Records,
		ParseErrors: c.ParseErrors,
		ByKind:      map[string]int64{},
	}
	if uptime.Seconds() > 0 {
		st.PPS = float64(c.Packets) / uptime.Seconds()
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM logs").Scan(&st.Total); err != nil {
		return nil, err
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM logs WHERE ts >= ?", time.Now().Unix()-3600).Scan(&st.LastHour); err != nil {
		return nil, err
	}
	rows, err := s.db.Query("SELECT kind, COUNT(*) FROM logs GROUP BY kind")
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

	if st.TopDomains, err = s.topValues("domain", 10); err != nil {
		return nil, err
	}
	if st.TopSrcIP, err = s.topValues("src_ip", 10); err != nil {
		return nil, err
	}

	// 24 contiguous hourly buckets ending at the current hour (UTC labels).
	now := time.Now().UTC()
	curHour := now.Truncate(time.Hour)
	rows, err = s.db.Query(
		"SELECT (ts/3600)*3600 AS h, COUNT(*) FROM logs WHERE ts >= ? GROUP BY h",
		curHour.Add(-23*time.Hour).Unix())
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

	_, recent, err := s.Query(LogQuery{Limit: 10, Order: "desc"})
	if err != nil {
		return nil, err
	}
	st.Recent = recent
	return st, nil
}

func (s *Store) topValues(col string, n int) ([]CountValue, error) {
	// col is an internal constant, never user input.
	rows, err := s.db.Query(
		"SELECT "+col+", COUNT(*) AS c FROM logs WHERE "+col+" != '' GROUP BY "+col+" ORDER BY c DESC LIMIT ?", n)
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
		ListenUDP:     ":40200",
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
		case "listen_udp":
			cfg.ListenUDP = v
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
	if c.ListenUDP != "" {
		pairs["listen_udp"] = c.ListenUDP
	}
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
