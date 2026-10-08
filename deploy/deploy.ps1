# palog 部署脚本(Windows 本机执行,PowerShell 5.1)
# 用法: powershell -File deploy\deploy.ps1
# 前置: 已完成 GOOS=linux GOARCH=amd64 编译产出 palog-linux-amd64
$ErrorActionPreference = "Stop"
$plink = "C:\Program Files\PuTTY\plink.exe"
$pscp  = "C:\Program Files\PuTTY\pscp.exe"
$hk = "SHA256:7BjbBb85sfKyLCjcod+ifW5TejYnUjGVIf7d27qxe4Y"
# 密码不写死: 从环境变量取, 未设置则交互提示
$pw = if ($env:PALOG_SSH_PW) { $env:PALOG_SSH_PW } else { Read-Host "ubuntu@10.10.10.58 password" -AsSecureString | ConvertFrom-SecureString -AsPlainText }
$hostport = "ubuntu@10.10.10.58"
$bin = Join-Path $PSScriptRoot "..\palog-linux-amd64"
if (-not (Test-Path $bin)) { throw "binary not found: $bin  (先编译: `$env:GOOS='linux'; `$env:GOARCH='amd64'; go build -o palog-linux-amd64 ./cmd/server)" }

function Rsh([string]$cmd) {
  & $plink -batch -ssh -hostkey $hk -pw $pw $hostport $cmd 2>&1
  if ($LASTEXITCODE -ne 0) { Write-Warning "remote exit=$LASTEXITCODE :: $cmd" }
}

Write-Host "[1/4] upload binary + unit"
& $pscp -batch -hostkey $hk -pw $pw $bin "${hostport}:/tmp/palog" | Out-Null
& $pscp -batch -hostkey $hk -pw $pw (Join-Path $PSScriptRoot "palog.service") "${hostport}:/tmp/palog.service" | Out-Null

Write-Host "[2/4] install to /opt/palog"
Rsh "echo '$pw' | sudo -S -p '' mkdir -p /opt/palog && echo '$pw' | sudo -S -p '' install -m 755 /tmp/palog /opt/palog/palog && echo '$pw' | sudo -S -p '' install -m 644 /tmp/palog.service /etc/systemd/system/palog.service"

Write-Host "[3/4] enable + restart"
Rsh "echo '$pw' | sudo -S -p '' systemctl daemon-reload && echo '$pw' | sudo -S -p '' systemctl enable palog && echo '$pw' | sudo -S -p '' systemctl restart palog"

Write-Host "[4/4] verify"
Start-Sleep -Seconds 2
Rsh "systemctl is-active palog; curl -s http://127.0.0.1:8080/api/health; echo; ss -lnu | grep 40200 || true"
Write-Host "done. web: http://10.10.10.58:8080/"
