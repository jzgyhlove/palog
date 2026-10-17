# palog — Panabit 日志审计系统

Go 单二进制实现的网络日志审计平台:接收 Panabit发送的日志,解析后写入 SQLite,并提供多用户 Web 控制台进行查询、统计与审计。

无需外部数据库、无需 Node/Python 运行时,一个二进制 + 一个数据库文件即可运行。

## 功能特性

- **多设备接入**:每台 Panabit 对应一个命名 UDP 端口(如 `panabit` → `40200`),日志自动按设备打标存储
- **协议解析**:支持 Panabit 文本日志(`dnsquery3` / `HTTP4` / `qqlogin3`)与 PNB 二进制 TLV 记录包(会话、流量统计),由真实抓包逆向验证
- **多用户 RBAC**:`admin` / `user` 两种角色,普通用户按设备授权;用户可自助修改密码
- **查询与统计**:仪表盘实时速率、日志类型分布、Top 域名/源 IP、24 小时趋势;日志查询支持全文搜索、设备/类型/时间/排序过滤与分页;系统概况与流量分析的长窗口(7/30 天)由按小时预聚合表加速
- **数据保留**:按天自动清理过期日志与过期会话令牌
- **HTTPS 与访问防护**:内置 HTTPS——粘贴 PEM 证书链与私钥即可直接对外,无需反向代理;可选登录算术验证码防暴力破解;支持两步验证(2FA,基于 Google Authenticator 的 TOTP),用户可自助启用,管理员可对指定用户强制启用并一键重置
- **安全**:密码 PBKDF2-SHA256 加盐存储;Bearer token 会话(12 小时);全程无明文凭据外泄
- **零部署摩擦**:Web UI 通过 `go:embed` 打进二进制,无前端构建步骤

## 架构

```
Panabit ──UDP──▶ palog  ├── UDP 监听器(receiver.reconcile 每秒同步设备表)
                        ├── 解析器(parse: 文本行 + PNB 二进制 TLV)
                        ├── 批处理写入(receiver.writerLoop → store.InsertBatch)
                        ├── SQLite(单文件 ./palog.db)
                        └── HTTP 服务(api: REST + go:embed 静态 UI)
```

数据流:`UDP 包 → 解析 → 归一化 Entry → 批事务落库 → 查询/统计接口 → Web 控制台`

**写入与查询隔离**:SQLite 连接池固定为单写连接(`SetMaxOpenConns(1)`),接收端以「每 100 条 / 200ms」批量提交事务以避免写竞争;启动时的 page-cache 预热(`store.Warmup`)在**独立只读连接**上运行、受 60s 超时约束,且每条预热语句都必须是走索引的 `SEARCH`(由 `TestWarmupProbesAreIndexBounded` 用 `EXPLAIN QUERY PLAN` 守住),保证预热既不会占用写连接、也不会退化为全表扫描而拖慢接收与接口。

**长窗口预聚合(rollup)**:「系统概况 / 流量分析」的聚合另有一层按小时的派生表——`agg_hour` 记 `小时 + 设备 + 日志类型` 的条数与上下行字节,`agg_dim` 记 `小时` 上的域名 / 源 IP / IP 排名键 / 应用 ID 计数,`rollup_state` 记录折叠进度。后台 worker 每秒按 `logs.id` 单调推进,首次启动自动回填全部历史;`logs` 表及其全部索引不受影响,仍是唯一事实来源,预聚合丢失或落后都可按 id 重放重建(聚合可加,故重放幂等)。读取时**整点小时**取自预聚合表、窗口首尾**不完整的小时**取自 `logs`,两者在 Go 侧合并;仅当预聚合被证明完整时才启用(见 `store.rollupReady`:下界与折叠前沿校验),否则整个面板回退到原始查询,因此启用它不会改变任何一个数字。数据保留清理会同步删除过期的小时桶。

## 支持解析的日志格式

| 格式 | 类型 | 字段 |
|---|---|---|
| `dnsquery3` | 文本 | `dnsquery3 <epoch> <MAC> <clientIP> <clientPort> <dnsServerIP> 53 <domain>` |
| `HTTP4` | 文本 | `HTTP4 <epoch> <MAC> <clientIP> <clientPort> <dstIP> <dstPort> <appid> <method> <host> <path> <user>` |
| `qqlogin3` | 文本 | `qqlogin3 <epoch> <MAC> <srcIP> <srcPort> <dstIP> <dstPort> <QQ号>` |
| PNB 二进制 | 二进制 | `PNB\0` 头的 TLV 记录包(会话/流量,见 `docs/PROTOCOL.md`) |

文本日志以 `<PNB{port}>` 为前缀;每个 UDP payload 只含一种格式。未识别数据计入「解析错误」指标,便于观测。

## 快速开始

### 1. 编译

```bash
# 本机(任意平台)
go build -o palog ./cmd/server

# Linux amd64(部署到服务器)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o palog-linux-amd64 -buildvcs=false ./cmd/server
```

要求 Go ≥ 1.27(使用 Go 1.22+ 的 `http.ServeMux` 方法路由与 `go:embed`)。依赖仅有纯 Go 的 `modernc.org/sqlite`,无需 CGO。

### 2. 运行

```bash
./palog -db ./palog.db -http 0.0.0.0:8080
```

参数:

| 参数 | 默认 | 说明 |
|---|---|---|
| `-db` | `./palog.db` | SQLite 数据库路径 |
| `-http` | 空(读库内配置) | HTTP 监听地址,覆盖 kv 配置 `http_addr`(默认 `:8080`) |
| `-admin-pw` | 自动生成 | 首次启动(无用户时)创建 admin 的初始密码 |

**首次启动**:当用户表为空时自动创建 `admin` 账号。若未指定 `-admin-pw`,程序会生成一个随机 16 位密码并**只打印一次**到日志,请登录后立即在「用户管理」中修改。

### 3. 配置 Panabit 发送日志

在 Panabit 上配置日志外发(对应每台设备的 UDP 目标端口),然后在 Web 控制台「系统管理 → 设备管理」中添加设备:

- 设备名称:任意可读名(如 `panabit`)
- **UDP 端口**:必须与该台 Panabit 的外发目标端口一致(设备表按端口监听)
- 状态:启用

设备表变更由 receiver 每秒 reconcile,无需重启服务。每台设备可通过一个独立端口接入;历史单端口库会自动迁移出默认 `panabit` 设备。

## 生产部署(systemd)

### 方式 A:使用部署脚本(Windows 本机 → Linux 服务器)

1. 交叉编译出 `palog-linux-amd64`
2. 安装 PuTTY(plink/pscp),确认目标服务器 hostkey
3. 执行脚本,逐项完成上传、安装到 `/opt/palog`、写入 systemd 服务、启动并自检:

```powershell
$env:PALOG_SSH_PW  = '服务器ssh密码'
$env:PALOG_ADMIN_PW = '自定义初始admin密码'   # 可选,缺省随机生成
powershell -File deploy\deploy.ps1
```

脚本完成输出 `web: http://<server>:8080/` 与初始 `admin / <密码>`。

### 方式 B:手工部署

```bash
# 1) 上传二进制并安装
sudo install -m 755 palog-linux-amd64 /opt/palog/palog
sudo mkdir -p /opt/palog /etc/palog

# 2) 初始 admin 密码(可选,仅首次无用户时生效)
echo 'PALOG_ADMIN_PW=你的强密码' | sudo tee /etc/palog/admin.env
sudo chmod 600 /etc/palog/admin.env

# 3) 安装 systemd 服务
sudo install -m 644 deploy/palog.service /etc/systemd/system/palog.service
sudo systemctl daemon-reload
sudo systemctl enable --now palog

# 4) 验证
curl -s http://127.0.0.1:8080/api/health
```

`deploy/palog.service`(可按需调整 User/路径):

```ini
[Unit]
Description=panabit log audit service (palog)
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/palog
EnvironmentFile=-/etc/palog/admin.env
ExecStart=/opt/palog/palog -db /opt/palog/palog.db -http 0.0.0.0:8080 -admin-pw ${PALOG_ADMIN_PW}
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

## Web 控制台

| 页面 | 能力 |
|---|---|
| 仪表盘 | 实时速率、累计包/记录/解析错误、日志类型分布、Top 域名、Top 源 IP、设备分布、24 小时趋势、最近记录 |
| 日志查询 | 关键词全文搜索、设备/类型/时间范围/排序过滤、分页;点击行查看详情与原始报文 |
| 系统概况 → 流量概况 | 总记录数、最近 1 小时记录、上下行流量汇总、按日志类型分布 |
| 系统概况 → 安全概况 | 解析错误总数、最近 1 小时记录数、事件概览 |
| 日志审计 → 会话日志 | 二进制 PNB 会话 + HTTP 会话分页列表 |
| 日志审计 → URL日志 | HTTP 日志分页列表（方法/Host/路径/应用 ID/用户） |
| 日志审计 → DNS日志 | DNS 查询日志分页列表（域名/源/目的/用户） |
| 日志审计 → 虚拟身份 | QQ 登录 / 用户身份日志分页列表 |
| 流量分析 → 流量排名-IP排名 | Top 20 IP 按总流量（流入+流出）排序 |
| 流量分析 → 应用排名 | Top 20 应用 ID 按记录数排序 |
| 系统管理 → 运行状态 | 服务健康、各指标、当前监听设备 |
| 系统管理 → 设备管理 | 增改删设备(名称/端口/启用) |
| 系统管理 → 用户管理 | 创建/编辑/删除用户,分配角色与可访问设备;可勾选「强制两步验证」并要求其绑定、可一键「重置 2FA」;admin 不受设备限制 |
| 系统管理 → 服务配置 | HTTP/HTTPS 协议、TLS 证书链与私钥(PEM)、登录算术验证码开关、数据保留天数、立即执行保留清理;协议或证书变更需重启生效 |
| 两步验证 | 顶部「两步验证」:自助启用/关闭 Google Authenticator(TOTP),扫码或手动录入密钥,关闭需当前密码 |
| 修改密码 | 顶部「修改密码」:验证当前密码后设置新密码,并吊销其他会话(本会话保持) |

## 安全配置(HTTPS / 验证码 / 两步验证)

三项能力均在 Web 控制台配置,无需改命令行参数。

### HTTPS(TLS)

「系统管理 → 服务配置」把「协议」选为 **HTTPS**,粘贴 **TLS 证书链(PEM)** 与 **私钥(PEM)**,保存后**重启服务**生效(保存返回 `restart_required:true`)。证书应为完整链(站点证书 + 中间 CA),私钥需与证书匹配。启用后二进制直接监听 TLS,无需 Nginx 等反代;监听地址由 `http_addr` 决定(如 `0.0.0.0:8443`)。

### 登录验证码

同页勾选「启用登录验证码」并保存(热生效,无需重启)。开启后登录页出现算术题(如 `4 + 5 = ?`):前端先取 `GET /api/captcha`(`{enabled,id,question}`),再连同 `captcha_id` / `captcha_answer` 提交。验证码 3 分钟内有效、一次性使用,答错或过期返回 `400 验证码错误或已过期`。用于削弱暴力破解与撞库。

### 两步验证(2FA / TOTP)

- **用户自助**:顶部「两步验证」→ 用 Google Authenticator(或任意 TOTP 应用)扫描二维码,或手动录入密钥,再输入 6 位动态码完成绑定;关闭需再次输入当前密码。
- **管理员强制**:「用户管理」中勾选某用户的「强制两步验证」并保存。该用户下次登录返回 `tfa_setup_required:true`,前端引导其立即绑定(未绑定前仍可登录,但会被要求完成绑定)。
- **登录校验**:已绑定账号须在密码之外再提供 `totp`(6 位动态码);缺失或错误返回 `401 {"totp_required":true}`,前端就地展开动态码输入框。
- **重置**:在「用户管理」行点「重置 2FA」(`PUT /api/users/{id}` body `{"reset_tfa":true}`)会清除该用户的 TOTP 密钥,下次登录需重新绑定——用于手机丢失/换机。

> 建议先启用 HTTPS(否则验证码答案与 2FA 动态码经明文信道传输),再按需开启验证码与 2FA。

## API 摘要

所有端点(除 `POST /api/login`、`GET /api/captcha`、`GET /api/health`)要求 `Authorization: Bearer <token>`;错误统一 `{"error":"message"}`。权限不足返回 `403`。

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| POST | `/api/login` | 公开 | 登录 `{username, password}`;开启验证码时需 `captcha_id`/`captcha_answer`,已绑定 2FA 的账号需 `totp`。返回 `{token, user, tfa_setup_required}` |
| GET | `/api/captcha` | 公开 | 登录算术验证码 `{enabled, id, question}`(未开启时 `enabled:false`) |
| GET | `/api/health` | 公开 | 健康、版本与计数(含 `version`、`listeners`) |
| GET | `/api/me` | 登录 | 当前用户信息(含 `tfa_required`/`tfa_enabled`) |
| PUT | `/api/me/password` | 登录 | 自助改密 `{old_password, new_password}` |
| POST | `/api/me/tfa/setup` | 登录 | 生成 TOTP 密钥与二维码 `{secret, otpauth, qr}` |
| POST | `/api/me/tfa/enable` | 登录 | 校验并启用 `{secret, code}` |
| POST | `/api/me/tfa/disable` | 登录 | 关闭两步验证(需当前密码)`{password}` |
| POST | `/api/logout` | 登录 | 注销当前会话 |
| GET | `/api/stats` | 登录 | 统计(按用户设备范围过滤) |
| GET | `/api/official-stats` | 登录 | 系统概况/安全概况/流量排名/应用排名(按用户设备范围过滤) |
| GET | `/api/logs` `/api/logs/{id}` | 登录 | 日志查询/详情 |
| GET | `/api/devices` | 登录 | 设备列表(按范围) |
| PUT/DELETE | `/api/devices` `/api/devices/{id}` | admin | 设备管理 |
| GET/PUT/DELETE | `/api/users` `/api/users/{id}` | admin | 用户管理;`PUT` 支持 `tfa_required` 与 `reset_tfa` |
| GET/PUT | `/api/config` | admin | 服务配置(含 `tls`/`tls_cert`/`tls_key`/`captcha`);协议或证书变更返回 `restart_required:true` |
| POST | `/api/maintenance/retention` | admin | 立即执行保留清理 |

完整契约与数据模型见 [`docs/API.md`](docs/API.md),PNB 协议逆向细节见 [`docs/PROTOCOL.md`](docs/PROTOCOL.md)。

## 测试与验证

```bash
go test ./...          # 单元/集成测试(解析 golden 数据、API、receiver、store)
go vet ./...
```

E2E 冒烟脚本(在服务器上以 ubuntu 运行,需初始 admin 密码):

```bash
bash deploy/e2e_check.sh <admin密码>
```

覆盖:登录 → 设备增删 → 权限隔离(普通用户越权 403) → 构造测试包入库 → 带设备标签查询验证。解析正确性由真实抓包 golden 数据回归保证(`internal/parse/parse_test.go`,103 个二进制包 / 1503 条记录全量比对)。

## 目录结构

```
.
├── VERSION                   # 当前发布版本号(内嵌进二进制,见 GET /api/health)
├── CHANGELOG.md              # 更新日志
├── cmd/server/main.go        # 入口:配置、admin 引导、receiver + HTTP、保留清理
├── internal/
│   ├── parse/                # PNB 日志解析(文本行 + 二进制 TLV)、golden 回归测试
│   ├── receiver/             # UDP 监听、设备 reconcile、批量落库
│   ├── api/                  # REST API + 鉴权中间件(RBAC/设备范围)
│   └── store/                # SQLite 存储(devices/users/sessions/logs/kv + 按小时预聚合 agg_hour/agg_dim/rollup_state)
├── web/                      # 前端(vanilla JS,go:embed 内嵌)
├── tools/diag_pcap/          # pcap 抓包诊断工具(解析成功率/错误分类)
├── deploy/                   # 部署脚本、systemd 单元、E2E 冒烟脚本
└── docs/                     # API 契约、PNB 协议规范
```

## 常见问题

- **解析错误在增长?** 在服务器抓包后用 `tools/diag_pcap` 诊断,区分「未识别格式」「截断包」:

  ```bash
  tcpdump -i any -s0 -w /tmp/cap.pcap 'udp port 40200'
  go run ./tools/diag_pcap /tmp/cap.pcap
  ```

  新格式解析规则可直接添加到 `internal/parse/parse.go` 并补回归测试。

- **如何查看当前监听端口?** `curl -s http://127.0.0.1:8080/api/health` 返回 `listeners` 列表。

- **忘记 admin 密码?** 无命令行重置;直接删除 `users` 表对应行后重启服务,将重新引导生成初始 admin(注意:会继续保留历史日志)。

- **如何开启 HTTPS?** 「系统管理 → 服务配置」把协议改为 HTTPS,粘贴 PEM 证书链(站点证书 + 中间 CA)与匹配私钥,保存后重启服务生效;启用后二进制直接监听 TLS,无需 Nginx 等反代。

- **如何开关登录验证码?** 「系统管理 → 服务配置」勾选/取消「启用登录验证码」并保存,即时生效,无需重启。

- **用户丢了两步验证设备 / 管理员被锁?** 任一 admin 在「用户管理」对该用户点「重置 2FA」(`PUT /api/users/{id}` 传 `{"reset_tfa":true}`),即可清空其 TOTP 密钥,下次登录重新绑定。

## License

MIT(见仓库 LICENSE,如未附带请以仓库为准)。