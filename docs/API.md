# palog REST API 契约(后端与 Web UI 的唯一对接合同)

Go 单二进制:HTTP 服务同时托管 `/api/*` 与 `go:embed` 的静态 UI(`web/` 目录)。
所有 API 返回 JSON,`Content-Type: application/json; charset=utf-8`。
错误统一:`{"error": "message"}`,HTTP 4xx/5xx。

## 1. 数据模型(SQLite,单库文件,默认 `./palog.db`)

### 表 `logs`(统一日志表,文本与二进制记录均归一化写入)

| 列 | 类型 | 说明 |
|---|---|---|
| id | INTEGER PK AUTOINCREMENT | |
| recv_ts | INTEGER | 服务端接收时间(Unix 秒) |
| kind | TEXT | `dnsquery` \| `http` \| `session`(二进制会话记录) |
| ts | INTEGER | 记录时间:文本=epoch 字段;二进制=ts1 |
| ts_end | INTEGER | 二进制 ts2,文本为 0 |
| src_ip | TEXT | 源 IP |
| src_port | INTEGER | |
| dst_ip | TEXT | |
| dst_port | INTEGER | |
| proto | INTEGER | 6/17(二进制),文本 http=6, dns=17 |
| mac | TEXT | |
| iface | TEXT | 二进制 iface,文本空 |
| iface2 | TEXT | 二进制 TLV 0x1e,可空 |
| appid | INTEGER | 二进制 appid / HTTP4 第 8 字段,-1 表示无 |
| domain | TEXT | dns 域名 / TLV 0x03,可空 |
| host | TEXT | HTTP host,可空 |
| path | TEXT | HTTP path,可空 |
| method | TEXT | HTTP method,可空 |
| user | TEXT | HTTP user,可空 |
| bytes_in | INTEGER | 二进制,文本 0 |
| bytes_out | INTEGER | 二进制,文本 0 |
| counters | TEXT | 二进制 TLV 0x05 的 JSON 数组字符串,可空 |
| flags | TEXT | TLV 0x08/0x14 hex,可空 |
| rec_type | INTEGER | 二进制记录头 type,文本 0 |
| extra | TEXT | 未知 TLV 的 JSON 对象 {typeHex: valueHex},可空 |
| raw | TEXT | 原始行 / 二进制记录 hex(排障用) |

索引:`(ts)`,`(kind)`,`(src_ip)`,`(dst_ip)`,`(domain)`。

### 表 `kv`(配置/元数据,key TEXT PK, value TEXT)

键:`listen_udp`(如 `:40200`)、`http_addr`(如 `:8080`)、`retention_days`(默认 30)。

### 表 `stats_daily`(可选,若实现则 GET /api/stats 用它加速;否则实时聚合)

## 2. 端点

### GET /api/health
`{"ok": true, "uptime_sec": 123, "packets": 100, "records": 1450, "parse_errors": 0}`

### GET /api/stats
仪表盘数据:
```json
{
  "total": 15000,
  "last_hour": 800,
  "pps": 2.8,
  "packets": 1024,
  "parse_errors": 0,
  "by_kind": {"dnsquery": 6000, "http": 7000, "session": 2000},
  "top_domains": [{"value": "edr.syslog.top", "count": 170}],
  "top_src_ip": [{"value": "10.10.10.222", "count": 300}],
  "hourly": [{"hour": "2026-10-08T10:00:00Z", "count": 400}],
  "recent": [ /* 最近 10 条,同 /api/logs 的 item 形状 */ ]
}
```

### GET /api/logs
Query 参数:`kind`、`q`(跨 src_ip/dst_ip/domain/host/path/user 模糊)、`src_ip`、`dst_ip`、`domain`、`from`(Unix 秒或 RFC3339)、`to`、`limit`(默认 100,最大 1000)、`offset`、`order`(`asc`|`desc`,默认 desc)。
响应:
```json
{"total": 12345, "limit": 100, "offset": 0, "items": [ { ...log item... } ]}
```
log item 形状(与表列同名):
```json
{"id":1,"recv_ts":0,"kind":"session","ts":0,"ts_end":0,
 "src_ip":"","src_port":0,"dst_ip":"","dst_port":0,"proto":6,
 "mac":"","iface":"","iface2":"","appid":-1,"domain":"","host":"",
 "path":"","method":"","user":"","bytes_in":0,"bytes_out":0,
 "counters":null,"flags":null,"rec_type":0,"extra":null,"raw":""}
```

### GET /api/logs/:id
单条,同 item 形状;404 → `{"error":"not found"}`。

### GET /api/config
`{"listen_udp":":40200","http_addr":":8080","retention_days":30,"db_path":"./palog.db"}`

### PUT /api/config
Body 同 GET 形状(可部分更新)。`listen_udp`/`retention_days` 热生效;`http_addr` 需重启(返回 `"restart_required":true` 提示字段)。
响应:更新后的完整 config。

### POST /api/maintenance/retention
立即执行一次按 `retention_days` 清理。响应:`{"deleted": 123}`。

## 3. 静态 UI

- `GET /` → `web/index.html`;`/app.js`、`/style.css` 等从 `web/` embed 提供。
- 前端纯原生 JS(无构建步骤、无 npm),单页三视图:仪表盘 / 日志查询 / 系统管理(用 tab 切换即可,允许3 个 html 文件)。
- 前端只依赖 §2 端点。

## 4. 后端结构约定(后端 agent 产出)

```
palog/
  go.mod                     module palog
  cmd/server/main.go         入口:flag 读 -db -udp -http,启动 UDP + HTTP
  internal/parse/            文本 + 二进制解析(单测对 testdata/golden.json 逐字段比对)
  internal/store/            SQLite(modernc.org/sqlite,纯 Go,免 CGO)
  internal/receiver/         UDP 收包 → parse → store 批量写
  internal/api/              REST 处理器
  web/                       前端静态文件(由前端 agent 产出,后端 go:embed)
  testdata/golden.json       已存在
  docs/PROTOCOL.md docs/API.md  已存在
```

解析单测要求:对 golden.json 中全部 103 包/1503 条记录逐字段比对,0 差异;文本 145行全解析。
`go vet ./...` 干净;`GOOS=linux GOARCH=amd64 go build ./cmd/server` 成功。
