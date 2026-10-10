/* palog 日志审计控制台 — vanilla JS,无构建步骤
 * 多设备(端口命名) + 多用户(按设备授权) + Bearer token 鉴权
 */
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
  const map = {
    dnsquery: ['dns', 'DNS'],
    http: ['http', 'HTTP'],
    session: ['sess', '会话'],
    qqlogin: ['qq', 'QQ登录']
  };
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

function fmtNum(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e4) return (n / 1e3).toFixed(1) + 'k';
  return String(n);
}

function devBadge(name) {
  if (!name) return '<span class="faint">-</span>';
  return '<span class="badge dev">' + esc(name) + '</span>';
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

/* ---------------- auth ---------------- */
const TOKEN_KEY = 'palog_token';
let ME = null; // {id,username,role,devices}

function getToken() { return localStorage.getItem(TOKEN_KEY) || ''; }
function setToken(t) { t ? localStorage.setItem(TOKEN_KEY, t) : localStorage.removeItem(TOKEN_KEY); }

async function api(path, options) {
  options = options || {};
  const headers = Object.assign({}, options.headers || {});
  const tok = getToken();
  if (tok) headers['Authorization'] = 'Bearer ' + tok;
  const res = await fetch(path, Object.assign({}, options, { headers }));
  let data = null;
  try { data = await res.json(); } catch (e) { /* non-json */ }
  if (res.status === 401 && !path.startsWith('/api/login')) {
    showLogin('会话已过期，请重新登录');
    throw new Error('unauthorized');
  }
  if (!res.ok) {
    const msg = data && data.error ? data.error : ('HTTP ' + res.status);
    throw new Error(msg);
  }
  return data;
}

function showLogin(msg) {
  setToken('');
  ME = null;
  $('login-err').textContent = msg || '';
  $('login-bg').classList.add('open');
  setTimeout(() => $('li-user').focus(), 60);
}

async function setupAuth() {
  if (!getToken()) { showLogin(''); return; }
  try {
    ME = await api('/api/me');
    applyMe();
  } catch (e) {
    showLogin('无法验证登录状态');
  }
}

function applyMe() {
  $('login-bg').classList.remove('open');
  const who = $('whoami');
  who.textContent = ME.username + ' · ' + (ME.role === 'admin' ? '管理员' : '用户');
  who.title = '可访问设备: ' + (ME.devices || '*');
  // admin-only controls
  document.querySelectorAll('.admin-only').forEach(el => el.style.display =
    ME.role === 'admin' ? '' : 'none');
  if (ME.role !== 'admin' && $('sys-devices') && $('sys-devices').classList.contains('active')) {
    switchSub('stat');
  }
  // announce to global listeners
  document.dispatchEvent(new CustomEvent('palog:me', { detail: ME }));
}

$('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('li-btn');
  btn.disabled = true;
  $('login-err').textContent = '';
  try {
    const r = await api('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: $('li-user').value.trim(), password: $('li-pass').value }),
    });
    setToken(r.token);
    ME = r.user;
    applyMe();
    $('li-pass').value = '';
    refreshLive(); refreshDash(); refreshDevices(); refreshUsers();
    toast('欢迎，' + ME.username);
  } catch (err) {
    $('login-err').textContent = err.message;
  } finally {
    btn.disabled = false;
  }
});

$('btn-logout').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST' }); } catch (e) { /* ignore */ }
  setToken('');
  ME = null;
  showLogin('已退出登录');
});

/* ---------------- change password ---------------- */
const pwdBg = $('pwd-bg');

function openPwd() {
  $('pwd-err').textContent = '';
  $('pwd-form').reset();
  pwdBg.classList.add('open');
  setTimeout(() => $('pw-old').focus(), 60);
}
function closePwd() {
  pwdBg.classList.remove('open');
}

$('btn-chgpwd').addEventListener('click', openPwd);
$('pw-cancel').addEventListener('click', closePwd);
pwdBg.addEventListener('click', (e) => { if (e.target === pwdBg) closePwd(); });
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && pwdBg.classList.contains('open')) closePwd();
});

$('pwd-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('pw-btn');
  const err = $('pwd-err');
  err.textContent = '';
  const oldPw = $('pw-old').value;
  const newPw = $('pw-new').value;
  if (newPw !== $('pw-new2').value) {
    err.textContent = '两次输入的新密码不一致';
    return;
  }
  if (newPw.length < 6) {
    err.textContent = '新密码至少 6 位';
    return;
  }
  btn.disabled = true;
  try {
    await api('/api/me/password', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ old_password: oldPw, new_password: newPw }),
    });
    closePwd();
    toast('密码修改成功');
  } catch (err2) {
    err.textContent = err2.message;
  } finally {
    btn.disabled = false;
  }
});

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

/* 日志查询默认时间窗:最近 1 小时(至 = 现在,向上取整到分钟以覆盖当前分钟) */
function defaultLogWindow() {
  const now = Math.floor(Date.now() / 1000);
  const to = Math.ceil(now / 60) * 60;
  $('f-from').value = toDTLocal(now - 3600);
  $('f-to').value = toDTLocal(to);
}

/* ---------------- device filter ---------------- */
let DEVICES = []; // visible devices (server already scoped by role)

async function refreshDevices() {
  try {
    const r = await api('/api/devices');
    DEVICES = (r.devices || []);
    const opts = (['<option value="">全部设备</option>']).concat(
      DEVICES.map(d => '<option value="' + esc(d.name) + '">' + esc(d.name) + (d.enabled ? '' : ' (已禁用)') + '</option>')
    ).join('');
    $('f-device').innerHTML = opts;
    $('d-device').innerHTML = opts;
  } catch (e) { /* 401 handled globally */ }
}

/* ---------------- tab navigation ---------------- */
function switchView(name) {
  document.querySelectorAll('nav.tabs button').forEach(b =>
    b.classList.toggle('active', b.dataset.view === name));
  document.querySelectorAll('.view').forEach(v => {
    v.classList.toggle('active', v.id === 'view-' + name);
  });
  if (name === 'logs') {
    // 打开日志查询页时:若未显式设置过时间窗,默认最近 1 小时并自动加载
    if (!queryState.timeSet) {
      defaultLogWindow();
      queryState.timeSet = true;
    }
    runQuery();
  }
  if (name === 'sys') refreshSys();
}
document.querySelectorAll('nav.tabs button').forEach(b =>
  b.addEventListener('click', () => switchView(b.dataset.view)));

/* system subtabs */
function switchSub(name) {
  document.querySelectorAll('#sys-tabs button').forEach(b =>
    b.classList.toggle('active', b.dataset.sub === name));
  document.querySelectorAll('.subview').forEach(v => {
    v.classList.toggle('active', v.id === 'sys-' + name);
  });
  if (name === 'devices') refreshDevTable();
  if (name === 'users') refreshUsersTable();
  if (name === 'config') refreshConfig();
  if (name === 'stat') refreshSys();
}
document.querySelectorAll('#sys-tabs button').forEach(b =>
  b.addEventListener('click', () => switchSub(b.dataset.sub)));

/* ---------------- live header ---------------- */
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
  api('/api/logs/' + id).then(renderDrawer).catch(err => {
    if (err.message !== 'unauthorized') toast('加载详情失败: ' + err.message, true);
  });
}
async function renderDrawer(item) {
  const m = { dnsquery: 'dns', http: 'http', session: 'sess', qqlogin: 'qq' };
  const b = m[item.kind] || '';
  $('d-kind').className = 'badge ' + b;
  $('d-kind').textContent = item.kind;

  const rows = [
    ['ID', item.id], ['设备', item.device], ['类型', item.kind],
    ['接收时间', item.recv_ts ? fmtTime(item.recv_ts) : '-'],
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
  const names = { dnsquery: 'DNS 查询', http: 'HTTP 会话', session: '协议会话', qqlogin: 'QQ 登录' };
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

function devShare(byDevice) {
  const entries = Object.entries(byDevice || {}).sort((a, b) => b[1] - a[1]);
  const el = $('s-devices');
  if (entries.length === 0) { el.innerHTML = '<div class="h-empty">暂无数据或无跨设备数据</div>'; return; }
  const total = entries.reduce((s, e) => s + e[1], 0) || 1;
  el.innerHTML = entries.map(([k, v]) => {
    const pct = Math.round(v / total * 100);
    return '<div class="bar-row">' +
      '<span class="key" style="font-family:var(--sans)">' + esc(k) + '</span>' +
      '<div class="track"><div class="fill" style="width:' + pct + '%"></div></div>' +
      '<span class="cnt">' + fmtNum(v) + ' (' + pct + '%)</span></div>';
  }).join('');
}

function recentRow(item) {
  const target = item.kind === 'dnsquery' ? item.domain : item.kind === 'qqlogin' ? item.user : item.host;
  const path = item.kind === 'http' ? item.path : '';
  const id = item.id;
  return '<tr class="row-link" tabindex="0" data-id="' + id + '">' +
    '<td class="mono dim" title="' + esc(fmtTime(item.ts)) + '">' + esc(fmtTime(item.ts)) + ' <span class="faint">' + esc(relTime(item.ts)) + '</span></td>' +
    '<td>' + devBadge(item.device) + '</td>' +
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
    const dev = $('d-device').value;
    const params = new URLSearchParams();
    if (dev) params.set('device', dev);
    const qs = params.toString();
    const s = await api('/api/stats' + (qs ? '?' + qs : ''));
    $('s-total').textContent = fmtNum(s.total);
    $('s-hour').textContent = fmtNum(s.last_hour);
    $('s-pps').innerHTML = s.pps.toFixed(2) + ' <small>包/秒</small>';
    $('s-pkts').innerHTML = fmtNum(s.packets) + ' / ' + fmtNum(s.records);
    $('s-errs').textContent = fmtNum(s.parse_errors);
    kindShare(s.by_kind);
    barList($('s-domains'), s.top_domains);
    barList($('s-srcip'), s.top_src_ip);
    devShare(s.by_device);
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
    if (err.message !== 'unauthorized') toast('仪表盘加载失败: ' + err.message, true);
  }
}

$('d-device').addEventListener('change', refreshDash);

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
const queryState = { limit: 100, offset: 0, timeSet: false };

function buildQueryParams() {
  const p = new URLSearchParams();
  const dev = $('f-device').value; if (dev) p.set('device', dev);
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
      : item.kind === 'qqlogin' ? item.user
        : (item.domain || item.host || '');
  const path = item.kind === 'http' ? item.path : '';
  const id = item.id;
  return '<tr class="row-link" tabindex="0" data-id="' + id + '">' +
    '<td class="mono dim nowrap">' + esc(fmtTime(item.ts)) + '</td>' +
    '<td>' + devBadge(item.device) + '</td>' +
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
  tb.innerHTML = '<tr><td colspan="10"><div class="empty"><span class="spin" style="vertical-align:-2px;margin-right:8px;"></span>查询中…</div></td></tr>';
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
    if (err.message === 'unauthorized') return;
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
$('f-device').addEventListener('change', () => { queryState.offset = 0; runQuery(); });
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
  ['f-device', 'f-kind', 'f-q', 'f-src', 'f-dst', 'f-domain', 'f-order'].forEach(id => {
    if (id === 'f-kind' || id === 'f-order') $(id).value = id === 'f-kind' ? '' : 'desc';
    else $(id).value = '';
  });
  // 时间窗重置回默认最近 1 小时(而非清空 → 避免触发全表查询)
  defaultLogWindow();
  queryState.offset = 0;
  runQuery();
});

/* ---------------- 系统管理: 运行状态 ---------------- */
async function refreshSys() {
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
    const listeners = (h.listeners || []).map(l =>
      '<span class="badge dev" style="margin-right:4px;">' + esc(l.device) +
      ' :' + esc(l.port) + (l.active ? '' : ' (关)') + '</span>').join('');
    $('h-listeners').innerHTML = listeners || '无';
    $('h-live').textContent = h.ok ? '服务运行中' : '服务异常';
  } catch (e) {
    if (e.message !== 'unauthorized') { $('h-live').textContent = '无法连接服务'; }
  }
}

function secToDur(sec) {
  const d = Math.floor(sec / 86400), hh = Math.floor((sec % 86400) / 3600),
    mm = Math.floor((sec % 3600) / 60);
  return (d ? d + ' 天 ' : '') + hh + ' 时 ' + mm + ' 分';
}

/* ---------------- 系统管理: 设备管理 (admin) ---------------- */
let editingDeviceId = 0;

async function refreshDevTable() {
  try {
    const r = await api('/api/devices');
    const items = r.devices || [];
    $('dv-hint').textContent = '共 ' + items.length + ' 个设备';
    const tb = $('dv-body');
    tb.innerHTML = items.map(d =>
      '<tr>' +
      '<td class="faint">' + d.id + '</td>' +
      '<td>' + devBadge(d.name) + '</td>' +
      '<td class="mono">' + d.port + '</td>' +
      '<td>' + (d.enabled ? '<span class="ok-txt">启用</span>' : '<span class="faint">已禁用</span>') + '</td>' +
      '<td>' +
      '<button class="btn sm" data-edit="' + d.id + '">编辑</button> ' +
      '<button class="btn sm danger" data-del="' + d.id + '">删除</button>' +
      '</td></tr>'
    ).join('');
  } catch (e) { /* 401 global */ }
}

$('dv-add').addEventListener('click', async () => {
  const name = $('dv-name').value.trim();
  const port = parseInt($('dv-port').value, 10);
  if (!name) { toast('请填写设备名称', true); return; }
  if (!port || port < 1 || port > 65535) { toast('端口须为 1-65535', true); return; }
  try {
    await api('/api/devices', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: editingDeviceId, name, port, enabled: $('dv-enabled').checked }),
    });
    toast(editingDeviceId ? '设备已更新，监听将在 1 秒内迁移' : '设备已添加，监听已启动');
    editingDeviceId = 0;
    $('dv-add').textContent = '添加 / 更新设备';
    $('dv-name').value = ''; $('dv-port').value = '';
    refreshDevTable(); refreshDevices();
  } catch (e) {
    if (e.message !== 'unauthorized') toast('保存失败: ' + e.message, true);
  }
});

$('dv-body').addEventListener('click', async (e) => {
  const editBtn = e.target.closest('button[data-edit]');
  if (editBtn) {
    try {
      const r = await api('/api/devices');
      const d = (r.devices || []).find(x => x.id === Number(editBtn.dataset.edit));
      if (!d) return;
      editingDeviceId = d.id;
      $('dv-name').value = d.name;
      $('dv-port').value = d.port;
      $('dv-enabled').checked = d.enabled;
      $('dv-add').textContent = '保存修改(' + d.name + ')';
      toast('正在编辑「' + d.name + '」');
      return;
    } catch (err) { return; }
  }
  const delBtn = e.target.closest('button[data-del]');
  if (delBtn) {
    const id = Number(delBtn.dataset.del);
    if (!confirm('确定删除该设备及其监听端口吗？历史日志会保留，但需重新配置。')) return;
    try {
      const r = await api('/api/devices/' + id, { method: 'DELETE' });
      toast('设备已删除');
      refreshDevTable(); refreshDevices();
    } catch (err) {
      if (err.message !== 'unauthorized') toast('删除失败: ' + err.message, true);
    }
  }
});

/* ---------------- 系统管理: 用户管理 (admin) ---------------- */
const ROLE_NAME = { admin: '管理员', user: '普通用户' };

async function refreshUsersTable() {
  try {
    const r = await api('/api/users');
    const items = r.users || [];
    const tb = $('us-body');
    tb.innerHTML = items.map(u =>
      '<tr>' +
      '<td class="faint">' + u.id + '</td>' +
      '<td>' + esc(u.username) + (u.id === ME.id ? ' <span class="faint">(当前)</span>' : '') + '</td>' +
      '<td>' + (u.role === 'admin' ? '<span class="badge dev">管理员</span>' : '<span class="badge proto">用户</span>') + '</td>' +
      '<td class="mono dim">' + esc(u.devices || '') + '</td>' +
      '<td class="faint">' + fmtTime(u.created_at) + '</td>' +
      '<td>' +
      '<button class="btn sm" data-u-edit="' + u.id + '">编辑</button> ' +
      (u.id !== ME.id ? '<button class="btn sm danger" data-u-del="' + u.id + '">删除</button>' : '') +
      '</td></tr>'
    ).join('');
  } catch (e) { /* 401 */ }
}

let editingUserId = 0;

function fillUserForm(u) {
  editingUserId = u.id;
  $('us-name').value = u.username;
  $('us-name').disabled = true;
  $('us-pass').value = '';
  $('us-pass').placeholder = '留空则不修改密码';
  $('us-role').value = u.role;
  $('us-devices').value = u.role === 'admin' ? '*' : (u.devices || '');
  $('us-add').textContent = '保存修改(' + u.username + ')';
}

$('us-add').addEventListener('click', async () => {
  const name = $('us-name').value.trim();
  const role = $('us-role').value;
  if (!name) { toast('请填写用户名', true); return; }
  const payload = { username: name, role };
  if (role === 'admin') {
    payload.devices = '*';
  } else {
    const devs = $('us-devices').value.trim();
    payload.devices = devs ? devs.replace(/，/g, ',').split(',').map(s => s.trim()).filter(Boolean).join(',') : '';
  }
  try {
    if (editingUserId) {
      const devs = $('us-devices').value.trim();
      await api('/api/users/' + editingUserId, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role, devices: role === 'admin' ? '*' : devs, password: $('us-pass').value }),
      });
      toast('用户已更新');
    } else {
      payload.password = $('us-pass').value;
      await api('/api/users', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      toast('用户已创建');
    }
    editingUserId = 0;
    $('us-name').disabled = false;
    $('us-pass').value = '';
    $('us-pass').placeholder = '密码(仅创建时填写)';
    $('us-add').textContent = '创建用户';
    refreshUsersTable();
  } catch (e) {
    if (e.message !== 'unauthorized') toast('保存失败: ' + e.message, true);
  }
});

$('us-body').addEventListener('click', async (e) => {
  const editBtn = e.target.closest('button[data-u-edit]');
  if (editBtn) {
    try {
      const r = await api('/api/users');
      const u = (r.users || []).find(x => x.id === Number(editBtn.dataset.uEdit));
      if (u) fillUserForm(u);
    } catch (err) { /* ignore */ }
    return;
  }
  const delBtn = e.target.closest('button[data-u-del]');
  if (delBtn) {
    const id = Number(delBtn.dataset.uDel);
    if (!confirm('确定删除该用户？')) return;
    try {
      await api('/api/users/' + id, { method: 'DELETE' });
      toast('用户已删除');
      refreshUsersTable();
    } catch (err) {
      if (err.message !== 'unauthorized') toast('删除失败: ' + err.message, true);
    }
  }
});

/* ---------------- 系统管理: 服务配置 (admin) ---------------- */
let cfgCache = null;

async function refreshConfig() {
  try {
    const cfg = await api('/api/config');
    cfgCache = cfg;
    $('c-http').value = cfg.http_addr || '';
    $('c-keep').value = cfg.retention_days != null ? cfg.retention_days : '';
    $('c-db').textContent = cfg.db_path || '-';
  } catch (e) { /* 401 */ }
}

$('c-save').addEventListener('click', async () => {
  const body = {};
  const http = $('c-http').value.trim();
  const keep = parseInt($('c-keep').value, 10);
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
    $('c-http').value = r.config.http_addr;
    $('c-keep').value = r.config.retention_days;
    toast(r.restart_required ? '已保存。HTTP 监听地址变更需重启服务才能生效。' : '配置已保存并生效');
  } catch (e) {
    if (e.message !== 'unauthorized') toast('保存失败: ' + e.message, true);
  }
});

$('c-retention').addEventListener('click', async () => {
  $('c-retention').disabled = true;
  try {
    const r = await api('/api/maintenance/retention', { method: 'POST' });
    toast('清理完成，删除 ' + r.deleted + ' 条记录');
  } catch (e) {
    if (e.message !== 'unauthorized') toast('清理失败: ' + e.message, true);
  } finally {
    $('c-retention').disabled = false;
  }
});

/* ---------------- init & timers ---------------- */
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && ME) { refreshLive(); refreshDash(); }
});

// auth gates everything
setupAuth().then(() => {
  refreshLive();
  refreshDash();
  refreshDevices();
  // 日志查询默认最近 1 小时,避免启动即全表查询
  defaultLogWindow();
  queryState.timeSet = true;
  runQuery();
});

// auto refresh: dashboard 10s, live 5s, system view when visible
setInterval(() => { if (!document.hidden && ME) refreshLive(); }, 5000);
setInterval(() => { if (!document.hidden && ME && $('view-dash').classList.contains('active')) refreshDash(); }, 10000);