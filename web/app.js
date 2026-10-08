/* palog 日志审计控制台 — vanilla JS,无构建步骤 */
'use strict';

/* ---------------- helpers ---------------- */
const $ = (id) => document.getElementById(id);

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function fmtTime(ts) {
  if (!ts) return '<span class="faint">-</span>';
  const d = new Date(ts * 1000);
  const p = (n) => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) +
    ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}

function relTime(ts) {
  const diff = Math.floor(Date.now() / 1000) - ts;
  if (diff < 0) return '';
  if (diff < 60) return diff + ' 秒前';
  if (diff < 3600) return Math.floor(diff / 60) + ' 分钟前';
  if (diff < 86400) return Math.floor(diff / 3600) + ' 小时前';
  return Math.floor(diff / 86400) + ' 天前';
}

function kindBadge(kind) {
  const map = { dnsquery: ['dns', 'DNS'], http: ['http', 'HTTP'], session: ['sess', '会话'] };
  const m = map[kind] || ['', kind];
  return '<span class="badge ' + m[0] + '">' + esc(m[1]) + '</span>';
}

function protoBadge(p) {
  if (p === 6) return '<span class="badge proto">TCP</span>';
  if (p === 17) return '<span class="badge proto">UDP</span>';
  return '<span class="faint">-</span>';
}

function ipPort(ip, port) {
  if (!ip) return '<span class="faint">-</span>';
  let out = esc(ip);
  if (port) out += ':' + esc(port);
  return out;
}

function fmtBytes(b) {
  if (!b) return '0';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = b;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return v.toFixed(i === 0 ? 0 : 1) + ' ' + u[i];
}

/* toasts */
function toast(msg, isErr) {
  const el = document.createElement('div');
  el.className = 'toast' + (isErr ? ' err' : '');
  el.textContent = msg;
  $('toasts').appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .3s'; }, 3600);
  setTimeout(() => el.remove(), 4000);
}

/* api helper */
async function api(path, options) {
  const res = await fetch(path, options);
  let data = null;
  try { data = await res.json(); } catch (e) { /* non-json */ }
  if (!res.ok) {
    const msg = data && data.error ? data.error : ('HTTP ' + res.status);
    throw new Error(msg);
  }
  return data;
}

/* datetime-local <-> unix */
function toDTLocal(ts) {
  if (!ts) return '';
  const d = new Date(ts * 1000);
  const p = (n) => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) +
    'T' + p(d.getHours()) + ':' + p(d.getMinutes());
}
function fromDTLocal(v) {
  if (!v) return 0;
  const t = new Date(v).getTime();
  return isNaN(t) ? 0 : Math.floor(t / 1000);
}

/* ---------------- tab navigation ---------------- */
function switchView(name) {
  document.querySelectorAll('nav.tabs button').forEach(b =>
    b.classList.toggle('active', b.dataset.view === name));
  document.querySelectorAll('.view').forEach(v => {
    v.classList.toggle('active', v.id === 'view-' + name);
  });
  if (name === 'sys') refreshSys();
}
document.querySelectorAll('nav.tabs button').forEach(b =>
  b.addEventListener('click', () => switchView(b.dataset.view)));

/* ---------------- live header ---------------- */
let liveTimer = null;
async function refreshLive() {
  try {
    const h = await api('/api/health');
    $('live-stats').textContent = h.packets + ' 包 / ' + h.records + ' 记录 / 错 ' + h.parse_errors;
    $('live-dot').classList.toggle('paused', !h.ok);
  } catch (e) {
    $('live-stats').textContent = '服务离线';
    $('live-dot').classList.add('paused');
  }
}

/* ---------------- drawer (detail) ---------------- */
let drawerId = 0;
function openDrawer(id) {
  drawerId = id;
  api('/api/logs/' + id).then(renderDrawer).catch(err => toast('加载详情失败: ' + err.message, true));
}
async function renderDrawer(item) {
  const m = { dnsquery: 'dns', http: 'http', session: 'sess' };
  const b = m[item.kind] || '';
  $('d-kind').className = 'badge ' + b;
  $('d-kind').textContent = item.kind;

  const rows = [
    ['ID', item.id], ['类型', item.kind], ['接收时间', item.recv_ts ? fmtTime(item.recv_ts) : '-'],
    ['记录时间', item.ts ? fmtTime(item.ts) : '-'], ['结束时间', item.ts_end ? fmtTime(item.ts_end) : '-'],
    ['源地址', item.src_ip ? item.src_ip + (item.src_port ? ':' + item.src_port : '') : ''],
    ['目的地址', item.dst_ip ? item.dst_ip + (item.dst_port ? ':' + item.dst_port : '') : ''],
    ['协议', item.proto === 6 ? 'TCP(6)' : item.proto === 17 ? 'UDP(17)' : (item.proto || '')],
    ['MAC', item.mac], ['接口', item.iface], ['对端接口', item.iface2],
    ['应用 ID', item.appid >= 0 ? item.appid : ''],
    ['域名', item.domain], ['Host', item.host], ['路径', item.path],
    ['方法', item.method], ['用户', item.user],
    ['流入字节', item.bytes_in], ['流出字节', item.bytes_out],
    ['计数器', item.counters ? JSON.stringify(item.counters) : ''],
    ['标志位', item.flags], ['记录类型', item.rec_type ? '0x' + item.rec_type.toString(16) : ''],
    ['未知 TLV', item.extra && Object.keys(item.extra).length ? JSON.stringify(item.extra) : ''],
  ];
  const html = rows.map(([k, v]) =>
    '<dt>' + esc(k) + '</dt><dd' + (v ? '' : ' class="empty"') + '>' + esc(v) + '</dd>').join('');
  $('d-fields').innerHTML = html;
  $('d-raw').textContent = item.raw || '(无原始内容)';

  $('drawer').classList.add('open');
  $('drawer-bg').classList.add('open');
  $('d-close').focus();
}
function closeDrawer() {
  $('drawer').classList.remove('open');
  $('drawer-bg').classList.remove('open');
}
$('d-close').addEventListener('click', closeDrawer);
$('drawer-bg').addEventListener('click', closeDrawer);
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeDrawer();
});

/* ---------------- dashboard ---------------- */
function barList(el, items) {
  if (!items || items.length === 0) {
    el.innerHTML = '<div class="h-empty">暂无数据</div>';
    return;
  }
  const max = items[0].count || 1;
  el.innerHTML = items.map(it =>
    '<div class="bar-row">' +
    '<span class="key" title="' + esc(it.value) + '">' + esc(it.value) + '</span>' +
    '<div class="track"><div class="fill" style="width:' + Math.max(2, Math.round(it.count / max * 100)) + '%"></div></div>' +
    '<span class="cnt">' + it.count + '</span></div>'
  ).join('');
}

function renderHourly(hourly) {
  const el = $('s-hourly');
  const data = hourly || [];
  const max = Math.max(1, ...data.map(d => d.count));
  if (data.length === 0) { el.innerHTML = '<div class="h-empty">暂无数据</div>'; return; }
  const barOf = (d) => {
    const h = Math.max(1, Math.round(d.count / max * 100));
    const tipTime = new Date(d.hour);
    const label = tipTime.toLocaleDateString('zh-CN', { month: 'numeric', day: 'numeric' }) + ' ' +
      String(tipTime.getHours()).padStart(2, '0') + ':00';
    return '<div class="h-col" title="' + esc(label) + ' · ' + d.count + ' 条">' +
      '<div class="tip">' + esc(label) + ' · ' + d.count + ' 条</div>' +
      '<div class="h-bar" style="height:' + h + '%"></div></div>';
  };
  el.innerHTML = '<div class="hourly">' + data.map(barOf).join('') + '</div>';
}

function kindShare(byKind) {
  const names = { dnsquery: 'DNS 查询', http: 'HTTP 会话', session: '协议会话' };
  const entries = Object.entries(byKind || {}).map(([k, v]) =>
    [names[k] || k, v]).sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((s, e) => s + e[1], 0) || 1;
  const el = $('s-kinds');
  if (entries.length === 0) { el.innerHTML = '<div class="h-empty">暂无数据</div>'; return; }
  el.innerHTML = entries.map(([k, v]) => {
    const pct = Math.round(v / total * 100);
    return '<div class="bar-row">' +
      '<span class="key" style="font-family:var(--sans)">' + esc(k) + '</span>' +
      '<div class="track"><div class="fill" style="width:' + pct + '%"></div></div>' +
      '<span class="cnt">' + pct + '%</span></div>';
  }).join('');
}

function recentRow(item) {
  const target = item.kind === 'dnsquery' ? item.domain : item.host;
  const path = item.kind === 'http' ? item.path : '';
  const id = item.id;
  return '<tr class="row-link" tabindex="0" data-id="' + id + '">' +
    '<td class="mono dim" title="' + esc(fmtTime(item.ts)) + '">' + esc(fmtTime(item.ts)) + ' <span class="faint">' + esc(relTime(item.ts)) + '</span></td>' +
    '<td>' + kindBadge(item.kind) + '</td>' +
    '<td class="mono">' + ipPort(item.src_ip, item.src_port) + '</td>' +
    '<td class="mono">' + ipPort(item.dst_ip, item.dst_port) + '</td>' +
    '<td class="mono trunc">' + esc(target || '') + '</td>' +
    '<td class="mono trunc">' + esc(path || '') + '</td>' +
    '<td>' + (item.appid >= 0 ? '<span class="badge appid">' + item.appid + '</span>' : '<span class="faint">-</span>') + '</td>' +
    '<td class="mono dim">' + fmtBytes(item.bytes_in) + ' / ' + fmtBytes(item.bytes_out) + '</td>' +
    '</tr>';
}

async function refreshDash() {
  try {
    const s = await api('/api/stats');
    $('s-total').textContent = fmtNum(s.total);
    $('s-hour').textContent = fmtNum(s.last_hour);
    $('s-pps').innerHTML = s.pps.toFixed(2) + ' <small>包/秒</small>';
    $('s-pkts').innerHTML = fmtNum(s.packets) + ' / ' + fmtNum(s.records);
    $('s-errs').textContent = fmtNum(s.parse_errors);
    $('s-total').textContent = fmtNum(s.total);
    kindShare(s.by_kind);
    barList($('s-domains'), s.top_domains);
    barList($('s-srcip'), s.top_src_ip);
    renderHourly(s.hourly);
    const tb = $('s-recent');
    if (s.recent && s.recent.length) {
      tb.innerHTML = s.recent.map(recentRow).join('');
      $('s-recent-empty').style.display = 'none';
    } else {
      tb.innerHTML = '';
      $('s-recent-empty').style.display = 'block';
    }
  } catch (err) {
    toast('仪表盘加载失败: ' + err.message, true);
  }
}

function fmtNum(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e4) return (n / 1e3).toFixed(1) + 'k';
  return String(n);
}

/* recent table row click (event delegation) */
document.addEventListener('click', (e) => {
  const tr = e.target.closest('tr[data-id]');
  if (tr) openDrawer(Number(tr.dataset.id));
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    const tr = e.target.closest && e.target.closest('tr[data-id]');
    if (tr) openDrawer(Number(tr.dataset.id));
  }
});

/* ---------------- log query ---------------- */
const queryState = { limit: 100, offset: 0 };

function buildQueryParams() {
  const p = new URLSearchParams();
  const k = $('f-kind').value; if (k) p.set('kind', k);
  const q = $('f-q').value.trim(); if (q) p.set('q', q);
  const s = $('f-src').value.trim(); if (s) p.set('src_ip', s);
  const d = $('f-dst').value.trim(); if (d) p.set('dst_ip', d);
  const dom = $('f-domain').value.trim(); if (dom) p.set('domain', dom);
  const from = fromDTLocal($('f-from').value); if (from) p.set('from', from);
  const to = fromDTLocal($('f-to').value); if (to) p.set('to', to);
  p.set('order', $('f-order').value);
  p.set('limit', queryState.limit);
  p.set('offset', queryState.offset);
  return p;
}

function logRow(item, idx) {
  const target = item.kind === 'dnsquery' ? item.domain
    : item.kind === 'http' ? item.host
      : (item.domain || item.host || '');
  const path = item.kind === 'http' ? item.path : '';
  const id = item.id;
  return '<tr class="row-link" tabindex="0" data-id="' + id + '">' +
    '<td class="mono dim nowrap">' + esc(fmtTime(item.ts)) + '</td>' +
    '<td>' + kindBadge(item.kind) + '</td>' +
    '<td class="mono">' + ipPort(item.src_ip, item.src_port) + '</td>' +
    '<td class="mono">' + ipPort(item.dst_ip, item.dst_port) + '</td>' +
    '<td>' + protoBadge(item.proto) + '</td>' +
    '<td class="mono trunc">' + esc(target || '') + '</td>' +
    '<td class="mono trunc wide">' + esc(path || '') + '</td>' +
    '<td>' + (item.appid >= 0 ? '<span class="badge appid">' + item.appid + '</span>' : '<span class="faint">-</span>') + '</td>' +
    '<td class="mono dim">' + fmtBytes(item.bytes_in) + ' / ' + fmtBytes(item.bytes_out) + '</td>' +
    '</tr>';
}

async function runQuery() {
  const tb = $('l-body');
  tb.innerHTML = '<tr><td colspan="9"><div class="empty"><span class="spin" style="vertical-align:-2px;margin-right:8px;"></span>查询中…</div></td></tr>';
  $('l-loading').style.display = 'inline-block';
  $('l-prev').disabled = true;
  $('l-next').disabled = true;
  try {
    const r = await api('/api/logs?' + buildQueryParams().toString());
    const items = r.items || [];
    $('l-total').textContent = r.total;
    $('l-page').textContent = Math.floor(r.offset / r.limit) + 1;
    $('l-empty').style.display = items.length ? 'none' : 'block';
    tb.innerHTML = items.map(logRow).join('');
    $('l-prev').disabled = queryState.offset <= 0;
    $('l-next').disabled = queryState.offset + items.length >= r.total;
  } catch (err) {
    tb.innerHTML = '';
    $('l-empty').style.display = 'block';
    $('l-empty').textContent = '查询失败: ' + err.message;
    toast('查询失败: ' + err.message, true);
  } finally {
    $('l-loading').style.display = 'none';
  }
}

/* debounce q */
let qTimer = null;
$('f-q').addEventListener('input', () => {
  clearTimeout(qTimer);
  qTimer = setTimeout(() => { queryState.offset = 0; runQuery(); }, 300);
});
$('f-search').addEventListener('click', () => { queryState.offset = 0; runQuery(); });
$('f-kind').addEventListener('change', () => { queryState.offset = 0; runQuery(); });
$('f-order').addEventListener('change', () => { queryState.offset = 0; runQuery(); });
['f-src', 'f-dst', 'f-domain', 'f-from', 'f-to'].forEach(id =>
  $(id).addEventListener('change', () => { queryState.offset = 0; runQuery(); }));
$('l-prev').addEventListener('click', () => {
  queryState.offset = Math.max(0, queryState.offset - queryState.limit);
  runQuery();
});
$('l-next').addEventListener('click', () => {
  queryState.offset += queryState.limit;
  runQuery();
});
$('f-reset').addEventListener('click', () => {
  ['f-kind', 'f-q', 'f-src', 'f-dst', 'f-domain', 'f-from', 'f-to', 'f-order'].forEach(id => {
    if (id === 'f-kind' || id === 'f-order') $(id).value = id === 'f-kind' ? '' : 'desc';
    else if (id === 'f-from' || id === 'f-to') $(id).value = '';
    else $(id).value = '';
  });
  queryState.offset = 0;
  runQuery();
});

/* ---------------- system management ---------------- */
let cfgCache = null;

async function refreshSys() {
  try {
    const cfg = await api('/api/config');
    cfgCache = cfg;
    $('c-udp').value = cfg.listen_udp || '';
    $('c-http').value = cfg.http_addr || '';
    $('c-keep').value = cfg.retention_days != null ? cfg.retention_days : '';
    $('c-db').textContent = cfg.db_path || '-';
    $('c-note').textContent = cfg.listen_udp ? '' : '';
  } catch (e) {
    toast('读取配置失败: ' + e.message, true);
  }
  try {
    const h = await api('/api/health');
    const cells = [
      [secToDur(h.uptime_sec || 0), '运行时长(Uptime)'],
      [h.packets, '已收 UDP 包'],
      [h.records, '已存记录'],
      [h.parse_errors, '解析错误'],
    ];
    $('h-cells').innerHTML = cells.map(([v, l]) =>
      '<div class="cell"><b>' + esc(typeof v === 'string' ? v : fmtNum(v)) + '</b><span>' + esc(l) + '</span></div>').join('');
    $('h-addr').textContent = h.listen_udp || '-';
    $('h-live').textContent = h.ok ? '服务运行中' : '服务异常';
  } catch (e) {
    $('h-live').textContent = '无法连接服务';
    toast('读取运行状态失败: ' + e.message, true);
  }
}

function secToDur(sec) {
  const d = Math.floor(sec / 86400), hh = Math.floor((sec % 86400) / 3600),
    mm = Math.floor((sec % 3600) / 60);
  return (d ? d + ' 天 ' : '') + hh + ' 时 ' + mm + ' 分';
}

$('c-save').addEventListener('click', async () => {
  const body = {};
  const udp = $('c-udp').value.trim();
  const http = $('c-http').value.trim();
  const keep = parseInt($('c-keep').value, 10);
  if (udp && udp !== cfgCache.listen_udp) body.listen_udp = udp;
  if (http && http !== cfgCache.http_addr) body.http_addr = http;
  if (keep && keep !== cfgCache.retention_days) body.retention_days = keep;
  if (Object.keys(body).length === 0) { toast('没有要保存的变更'); return; }
  try {
    const r = await api('/api/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    cfgCache = r.config;
    $('c-udp').value = r.config.listen_udp;
    $('c-http').value = r.config.http_addr;
    $('c-keep').value = r.config.retention_days;
    if (r.restart_required) {
      toast('已保存。HTTP 监听地址变更需重启服务才能生效。');
    } else {
      toast('配置已保存并生效');
    }
  } catch (e) {
    toast('保存失败: ' + e.message, true);
  }
});

$('c-retention').addEventListener('click', async () => {
  $('c-retention').disabled = true;
  try {
    const r = await api('/api/maintenance/retention', { method: 'POST' });
    toast('清理完成，删除 ' + r.deleted + ' 条记录');
  } catch (e) {
    toast('清理失败: ' + e.message, true);
  } finally {
    $('c-retention').disabled = false;
  }
});

/* ---------------- init & timers ---------------- */
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) { refreshLive(); refreshDash(); }
});

refreshLive();
refreshDash();
runQuery();
// auto refresh: dashboard 10s, live 5s, system view when visible
setInterval(() => { if (!document.hidden) refreshLive(); }, 5000);
setInterval(() => { if (!document.hidden && $('view-dash').classList.contains('active')) refreshDash(); }, 10000);