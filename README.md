# palog — Panabit 日志审计系统

Go 单二进制实现的网络日志审计平台:接收 Panabit发送的日志,解析后写入 SQLite,并提供多用户 Web 控制台进行查询、统计与审计。

无需外部数据库、无需 Node/Python 运行时,一个二进制 + 一个数据库文件即可运行。

## 功能特性

- **多设备接入**:每台 Panabit 对应一个命名 UDP 端口(如 `panabit` → `40200`),日志自动按设备打标存储
- **协议解析**:支持 Panabit 文本日志(`dnsquery3` / `HTTP4` / `qqlogin3`)与 PNB 二进制 TLV 记录包(会话、流量统计),由真实抓包逆向验证
- **多用户 RBAC**:`admin` / `user` 两种角色,普通用户按设备授权;用户可自助修改密码
- **查询与统计**:仪表盘实时速率、日志类型分布、Top 域名/源 IP、24 小时趋势;日志查询支持全文搜索、设备/类型/时间/排序过滤与分页
- **数据保留**:按天自动清理过期日志与过期会话令牌
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
| 系统管理 → 运行状态 | 服务健康、各指标、当前监听设备 |
| 系统管理 → 设备管理 | 增改删设备(名称/端口/启用) |
| 系统管理 → 用户管理 | 创建/编辑/删除用户,分配角色与可访问设备;admin 不受设备限制 |
| 系统管理 → 服务配置 | HTTP 地址、数据保留天数、立即执行保留清理 |
| 修改密码 | 顶部「修改密码」:验证当前密码后设置新密码,并吊销其他会话(本会话保持) |

## API 摘要

所有端点(除 `POST /api/login`、`GET /api/health`)要求 `Authorization: Bearer <token>`;错误统一 `{"error":"message"}`。权限不足返回 `403`。

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| POST | `/api/login` | 公开 | 登录,返回 `{token, user}` |
| GET | `/api/health` | 公开 | 健康与计数 |
| GET | `/api/me` | 登录 | 当前用户信息 |
| PUT | `/api/me/password` | 登录 | 自助改密 `{old_password, new_password}` |
| POST | `/api/logout` | 登录 | 注销当前会话 |
| GET | `/api/stats` | 登录 | 统计(按用户设备范围过滤) |
| GET | `/api/logs` `/api/logs/{id}` | 登录 | 日志查询/详情 |
| GET | `/api/devices` | 登录 | 设备列表(按范围) |
| PUT/DELETE | `/api/devices` `/api/devices/{id}` | admin | 设备管理 |
| GET/PUT/DELETE | `/api/users` `/api/users/{id}` | admin | 用户管理 |
| GET/PUT | `/api/config` | admin | 服务配置 |
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
├── cmd/server/main.go        # 入口:配置、admin 引导、receiver + HTTP、保留清理
├── internal/
│   ├── parse/                # PNB 日志解析(文本行 + 二进制 TLV)、golden 回归测试
│   ├── receiver/             # UDP 监听、设备 reconcile、批量落库
│   ├── api/                  # REST API + 鉴权中间件(RBAC/设备范围)
│   └── store/                # SQLite 存储(devices/users/sessions/logs/kv)
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

## License

MIT(见仓库 LICENSE,如未附带请以仓库为准)。