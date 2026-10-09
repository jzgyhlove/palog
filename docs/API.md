# palog REST API 契约(后端与 Web UI 的唯一对接合同)

Go 单二进制:HTTP 服务同时托管 `/api/*` 与 `go:embed` 的静态 UI(`web/` 目录)。
所有 API 返回 JSON,`Content-Type: application/json; charset=utf-8`。
错误统一:`{"error": "message"}`,HTTP 4xx/5xx。

除 `POST /api/login`、`GET /api/health` 外,所有端点均需鉴权:
`Authorization: Bearer <token>`(token 由登录获得,有效期 12 小时)。
未带/无效 token → `401 {"error":"missing token"|"invalid or expired token"}`。
普通用户被授权部分端点过滤其可访问设备;越权访问管理端点 → `403`。

## 1. 数据模型(SQLite,单库文件,默认 `./palog.db`)

### 表 `devices`(多设备:每一台设备 = 一个命名 UDP 端口)

| 列 | 类型 | 说明 |
|---|---|---|
| id | INTEGER PK AUTOINCREMENT | |
| name | TEXT UNIQUE | 设备名(如 `fw-1`、`panabit`),端口起名后可按名筛选 |
| port | INTEGER | 该设备独立 UDP 监听端口 |
| enabled | INTEGER | 1 监听 / 0 停止(改端口/禁用由 receiver 每秒 reconcile) |

旧版单端口库迁移:仅有历史日志数据的库自动创建默认设备 `panabit`(端口取 kv `listen_udp`,默认 40200),历史行 `device` 置为 `panabit`。

### 表 `users`(多用户分权限)

| 列 | 类型 | 说明 |
|---|---|---|
| id | INTEGER PK AUTOINCREMENT | |
| username | TEXT UNIQUE | |
| pass_hash | TEXT | PBKDF2-SHA256(210k 迭代),格式 `pbkdf2$sha256$<iter>$<saltB64>$<keyB64>` |
| role | TEXT | `admin` \| `user` |
| devices | TEXT | 可查设备名,`*` = 全部;或逗号分隔如 `fw-1,fw-2` |
| created_at | INTEGER | |

`GET /api/users` 永不返回 `pass_hash`。

### 表 `sessions`

| 列 | 类型 | 说明 |
|---|---|---|
| token | TEXT PK | 登录令牌(随机 32+ 字节) |
| user_id | INTEGER | |
| expires | INTEGER | Unix 秒,每日清理 |

### 表 `logs`(统一日志表,文本与二进制记录均归一化写入,新增 `device` 列)

| 列 | 类型 | 说明 |
|---|---|---|
| id | INTEGER PK AUTOINCREMENT | |
| **device** | TEXT | 来源设备名(接收时打标,查询按此收敛权限) |
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

索引:`(ts)`,`(kind)`,`(src_ip)`,`(dst_ip)`,`(domain)`,`(device)`。

### 表 `kv`(配置/元数据,key TEXT PK, value TEXT)

键:`http_addr`(如 `:8080`)、`retention_days`(默认 30)。
UDP 监听已由 `devices` 表驱动,**`listen_udp` 键仅作旧库迁移来源**。

## 2. 端点

### 公开(无需鉴权)

#### POST /api/login
Body:`{"username":"admin","password":"..."}`。
成功:`{"token":"...","expires_in":43200}`;失败 → `401 {"error":"invalid credentials"}`。
`username` 不存在或密码错误均返回同一 401(防用户枚举)。

#### GET /api/health
`{"ok":true,"uptime_sec":123,"packets":100,"records":1450,"parse_errors":0,"dropped":0,"listeners":[{"device":"fw-1","port":40200,"addr":"[::]:40200","active":true}]}`
`listeners` 为当前实际监听的设备列表(供多设备运维检查)。

### 鉴权端点

#### POST /api/logout
使当前 token 失效。`200 {"ok":true}`。

#### GET /api/me
当前用户:`{"id":1,"username":"admin","role":"admin","devices":"*"}`。

#### PUT /api/me/password
自助修改当前用户密码。Body:`{"old_password":"...","new_password":"..."}`。
- `old_password` 错误 → `401 {"error":"current password is incorrect"}`
- `new_password` 少于 6 位或与旧密码相同 → `400`
- 成功:`200 {"ok":true}`,并吊销该用户除当前 token 外的**所有其他会话**(本会话保持有效)
- 改密后旧密码立即失效,其他设备/浏览器的历史 token 全部作废

#### GET /api/stats
仪表盘数据。`?device=` 过滤单设备(普通用户仅能查权限内设备,越权 → 403):
```json
{
  "total": 15000, "last_hour": 800, "pps": 2.8,
  "packets": 1024, "parse_errors": 0,
  "by_kind": {"dnsquery": 6000, "http": 7000, "session": 2000},
  "by_device": {"fw-1": 9000, "fw-2": 6000},
  "top_domains": [{"value": "edr.syslog.top", "count": 170}],
  "top_src_ip": [{"value": "10.10.10.222", "count": 300}],
  "hourly": [{"hour": "2026-10-08T10:00:00Z", "count": 400}],
  "recent": [ /* 最近 10 条,同 /api/logs 的 item 形状 */ ],
  "devices": [ /* 同 GET /api/devices 条目 */ ]
}
```

#### GET /api/logs
Query 参数:`device`、`kind`、`q`(跨 src_ip/dst_ip/domain/host/path/user 模糊)、`src_ip`、`dst_ip`、`domain`、`from`(Unix 秒或 RFC3339)、`to`、`limit`(默认 100,最大 1000)、`offset`、`order`(`asc`|`desc`,默认 desc)。
普通用户查询强制收敛到其 `devices` 白名单;显式传越权 `device` → `403`。
响应:
```json
{"total": 12345, "limit": 100, "offset": 0, "items": [ { ...log item... } ]}
```
log item 形状(与表列同名,含 `device`):
```json
{"id":1,"device":"fw-1","recv_ts":0,"kind":"session","ts":0,"ts_end":0,
 "src_ip":"","src_port":0,"dst_ip":"","dst_port":0,"proto":6,
 "mac":"","iface":"","iface2":"","appid":-1,"domain":"","host":"",
 "path":"","method":"","user":"","bytes_in":0,"bytes_out":0,
 "counters":null,"flags":null,"rec_type":0,"extra":null,"raw":""}
```

#### GET /api/logs/:id
单条,同 item 形状;404 → `{"error":"not found"}`。
越权访问权限外设备的记录 → `404`(不泄露存在性)。

#### GET /api/devices
设备列表:
- admin:全量 `{"devices":[{"id":1,"name":"fw-1","port":40200,"enabled":true}]}`
- 普通用户:仅其权限内设备含 `port`;列表仍展示全部设备名但权限外设备省略 `port` 字段(保密端口拓扑)。

### 管理端点(仅 `admin`,普通用户 → `403`)

#### PUT /api/devices
新增或更新设备。Body:`{"id":0,"name":"fw-3","port":40300,"enabled":true}`(`id=0` 新增;带 id 更新同名设备)。
重名 → `400`;成功返回完整设备对象 `{"device":{...}}`。

#### DELETE /api/devices/:id
删除设备并停止其监听。不存在 → `400`。成功 `{"ok":true}`。

#### GET /api/users
`{"users":[{"id":1,"username":"admin","role":"admin","devices":"*","created_at":...}]}`,无 `pass_hash`。

#### PUT /api/users
新增用户。Body:`{"username":"user2","password":"...","role":"user","devices":"fw-1,fw-2"}`。
`role` 限 `admin|user`;`devices` 用 `*` 或逗号列表。重名 → `400`。

#### PUT /api/users/:id
更新角色/设备范围(可传 `role`、`devices`,可选 `password` 改密)。

#### DELETE /api/users/:id
删除用户。不能删除自己的账号(最后一个 admin 保护由 store 层保证)→ `400`。

#### GET /api/config
`{"http_addr":":8080","retention_days":30,"db_path":"./palog.db"}`
(注意:已无 `listen_udp`,UDP 由 devices 表驱动。)

#### PUT /api/config
Body 同 GET 形状(可部分更新)。`retention_days` 热生效;`http_addr` 需重启(返回 `"restart_required":true` 提示)。
响应:更新后的完整 config。

#### POST /api/maintenance/retention
立即执行一次按 `retention_days` 清理。响应:`{"deleted": 123}`。

## 3. 静态 UI

- `GET /` → `web/index.html`;`/app.js`、`/style.css` 等从 `web/` embed 提供。
- 前端纯原生 JS(无构建步骤、无 npm),单页三视图:仪表盘 / 日志查询 / 系统管理(运行状态、设备管理、用户管理、服务配置子视图)。
- 未登录时展示登录 overlay(`POST /api/login`);`401` 任意响应自动回到登录态。
- 前端只依赖 §2 端点。管理端 UI 元素带 `admin-only` class,按 `GET /api/me` 的角色显隐。

## 4. 后端结构约定

```
palog/
  go.mod                     module palog
  cmd/server/main.go         入口:flag 读 -db -http -admin-pw;启动 receiver(由 devices 表驱动)+ HTTP;
                             无用户时自动创建 admin(-admin-pw 指定或随机 16 位打印到日志)
  internal/parse/            文本 + 二进制解析(单测对 testdata/golden.json 逐字段比对)
  internal/store/            SQLite(modernc.org/sqlite,纯 Go,免 CGO)+ 设备/用户/会话/迁移
  internal/receiver/         每设备独立 UDP conn → parse → store 批量写(1s reconcile)
  internal/api/              REST 处理器(鉴权中间件 + 范围收敛)
  web/                       前端静态文件(go:embed)
  testdata/golden.json       已存在
  docs/PROTOCOL.md docs/API.md  已存在
  deploy/                    deploy.ps1 + palog.service + e2e_check.sh
```

- 旧库升级:自动为 `logs` 补 `device` 列(有历史数据则建默认 `panabit` 设备并回填)。
- 解析单测要求:对 golden.json 中全部 103 包/1503 条记录逐字段比对,0 差异;文本 145 行全解析。
- `go vet ./...` 干净;`GOOS=linux GOARCH=amd64 go build ./cmd/server` 成功。