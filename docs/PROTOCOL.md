# Panabit PNB 日志协议规范(逆向自 172.16.16.200 实抓包)

来源:`/tmp/panabit_cap*.pcap`(10.10.10.58 抓取,90 秒,248 UDP 包)。
验证:Python 参考解码器对 103 个二进制包全量解码 1503 条记录,0 错误;
与文本日志交叉验证(HTTP 会话 IP/端口、edr.syslog.top 域名)一致。

传输层:UDP,目标端口号出现在文本日志前缀中(如 `<PNB40200>` = 端口 40200)。
每个 UDP payload 只含一种:**文本行日志** 或 **PNB 二进制记录包**,不混装。

---

## 1. 文本日志(每行一条,`\n` 结尾)

前缀:`<PNB{port}>`(port = 本地接收端口)。

### 1.1 dnsquery3(DNS 查询)

```
<PNB40200>dnsquery3 <epoch> <MAC> <clientIP> <clientPort> <dnsServerIP> 53 <domain>
```

例:
```
<PNB40200>dnsquery3 1791462429 00-e2-69-13-cd-4e 10.10.10.222 53210 223.5.5.5 53 edr.syslog.top
```

字段:`epoch` 秒级 Unix 时间;`MAC` 连字符分隔;client 为发起方;末段为查询域名。

### 1.2 HTTP4(HTTP 会话)

```
<PNB40200>HTTP4 <epoch> <MAC> <clientIP> <clientPort> <dstIP> <dstPort> <appid> <method> <host> <path> <user>
```

例:
```
<PNB40200>HTTP4 1791462429 00-e2-69-13-cd-4e 10.10.10.222 51216 95.211.79.57 80 714 GET ehtracker.org /announce?info_hash=... _NULL_USER_
```

字段:`appid` Panabit 应用识别 ID;`user` 未认证时为 `_NULL_USER_`。
path/query 可能含空格分隔以外的可打印字符;解析时按空白切分,**host 取第 10 段、path 取第 11 段起至倒数第 2 段、user 为最后 1 段**(path 不含空格,实际流量中未见空格)。

---

## 2. 二进制记录包(PNB binary)

### 2.1 包头(20 字节)

| 偏移 | 长度 | 内容 |
|---|---|---|
| 0 | 4 | 魔数 `50 4E 42 00` = `"PNB\0"` |
| 4 | 1 | 版本(实测 `08`) |
| 5 | 4 | 序号,**大端** u32,逐包递增 |
| 9 | 3 | 未知(实测 `4c 0a 00` 类) |
| 12 | 4 | 包时间,u32 LE Unix 秒 |
| 16 | 4 | 未知(实测 `3c 00 xx 04`) |

### 2.2 记录流

包头后为**顺序拼接的多条记录**(实测每包 13~16 条,平均 14.6)。
无记录数字段 —— 解析到包尾为止;容错解码见 §4。

#### 记录布局

```
[u8  type][u8 proto][u16le appid]     4B  记录头
[u32le ts1][u32le ts2][u32le bytesIn][u32le bytesOut]   16B
[iface 以 \0 结尾的 ASCII]            变长,≤16,实测 "eth1"/"eth2"
[u8 x][mac 6B]                        7B  x 字节语义未知(各记录不同,原样保留)
[TLV 流,至 0x00 终止字节]             变长
[0~7B 间隙填充(对齐到 4 字节)]       下一记录头总是 4 字节对齐
```

- `type`:高 4 位似为记录类别;实测值 0x48/0x4c/0x50/0x54/0x58/0x5c/0x60/0x64/0x68/0x6c/0x70/0x74/0x78(均为 4 的倍数)。
- `proto`:6 = TCP,17 = UDP。
- `appid`:Panabit 应用识别 ID(与文本日志 HTTP4 的 appid 同域,实测 1/23/559/714/2269…)。
- `ts1` = 会话开始时间(**可能早于抓包时间数小时**,判头时时间窗须放宽至包时间 −3 天 ~ +1 小时);`ts2` = 会话结束/最后活动时间。
- `bytesIn/bytesOut`:会话字节数(首见记录可能为 0,后续同会话记录更新)。
- `x` 字节:语义未知(MAC 前一字节),原样存储。

#### TLV 格式

`[u8 type][u8 length][length 字节 value]`,length 为 value 字节数(不含头)。

| type | length | 含义 | value 布局 |
|---|---|---|---|
| 0x01 | 12 | 四元组 | `srcIP(4) dstIP(4) sport(u16 BE) dport(u16 BE)`,src/dst 为会话首包方向 |
| 0x03 | 变长 | 域名(SNI/DNS/Host) | ASCII + `\0` 结尾,length 含 `\0` |
| 0x05 | 16 | 计数器 | 4×u32 LE,疑似 [pktA, pktB, pktC, pktD](C/D 实测多为 0/1) |
| 0x07 | 2 | 未知 | 实测恒 `c8 00`(=200?) |
| 0x08 | 2 | 标志 | `01 00` / `02 00`(方向或开关标记) |
| 0x13 | 13 | 未知(罕见) | 原样 hex |
| 0x14 | 2 | 标志 | `01 00` / `00 01` / `02 00` |
| 0x1e | 变长 | 对端接口名 | ASCII + `\0`(如 "eth1") |
| 0x20 | 1 | 未知(罕见) | 原样 hex |

未知 type:保留 type+hex,不报错。

#### 记录终止与同步

- TLV 流遇 `type = 0x00` 字节即记录结束(该字节消费后,其后有 0~7 字节**间隙填充**;
  间隙多为 `00`,偶见 `04 00 00` 等 —— 语义未知,忽略)。
- 下一条记录头必然 **4 字节对齐**,且满足:type ∈ [0x40,0x7c] 且为 4 的倍数、
  proto ∈ {6,17}、ts1 ∈ [包时间−259200, 包时间+3600]。
- 容错:终止字节缺失时,在当前位置后 ≤8 字节内扫描满足上述条件的位置重新同步。

### 2.3 与文本日志的对应

二进制记录 ≈ 文本日志的会话级版本:同一会话(同 IP 四元组 + 时间窗)在
文本中按事件输出(dnsquery3/HTTP4),在二进制中按会话汇总输出(appid + 域名 + 字节/包数)。

---

## 3. 流量基线(90 秒抓包)

- 速率 ≈ 2.8 包/s;仅 3 种文本行(dnsquery3 / HTTP4)+ 二进制包。
- 二进制:type/proto 主要 0x48/6(596)、0x60/6(303)、0x4c/6(220)、0x64/6(106)、0x48/17(113)…
- 含域名记录 550 条(其中 edr.syslog.top 170 条)。
- NAT/上下线/流量日志需在 Panabit「日志对接」勾选后才会出现(当前未开)。

## 4. 解码算法(Python 参考实现已验证)

```python
off = 20  # 跳过包头
while off < len(buf):
    assert is_hdr(buf, off)          # §2.2 同步条件
    read 记录头 + 16B 定长域 + iface(\0) + x + mac
    while True:
        t = buf[off]
        if t == 0: off += 1; break              # 终止字节
        if is_hdr(buf, off): break              # 缺终止字节的兜底
        ln = buf[off+1]; 按 §2.2 TLV 表解析; off += 2 + ln
    跳过 ≤7 字节间隙至下一个 is_hdr 位置
```

golden 数据:`testdata/golden.json`(1503 条记录 + 145 条文本行,由参考实现导出),
Go 解析器单测须与其逐字段比对。
