#!/usr/bin/env python3
# 向 palog 指定设备端口发送一行测试日志(格式: <PNB端口> ts kind ...)
import socket, sys, time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 40201
host = '127.0.0.1'

# dnsquery3 <seq> <mac> <srcip> <srcport> <dstip> <dstport=53> <domain>
# 时间戳用当前时间,保证落在日志查询默认的"最近 1 小时"时间窗内
ts = int(time.time())
pkt = '<PNB%d>dnsquery3 %d 00:11:22:33:44:55 10.9.9.9 3355 223.5.5.5 53 e2e.test.cn' % (port, ts)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(pkt.encode(), (host, port))
print('sent %d bytes to %s:%d (ts=%d)' % (len(pkt), host, port, ts))