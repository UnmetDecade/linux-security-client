'use strict';

/* lsec Web UI - no frameworks, no external requests. All data comes from the
   local daemon API; nothing is mocked or fabricated. */

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const SEVERITY_LABEL = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' };
const STATUS_LABEL = {
  queued: '排队中', cancel_requested: '正在取消', cancelled: '已取消',
  succeeded: '已完成', failed: '失败', partial: '部分完成',
  new: '新事件', acknowledged: '已确认', investigating: '调查中', resolved: '已解决', ignored: '已忽略',
  quarantined: '已隔离', restored: '已恢复', deleted: '已删除', missing: '文件缺失',
  ok: '正常', degraded: '降级', unavailable: '不可用', unknown: '未知', incompatible: '不兼容',
  available: '可用',
  check_failed: '检查失败', permission_denied: '权限不足',
  not_installed: '未安装', stopped: '未启动', running: '运行中',
  pass: '通过', finding: '发现风险', error: '未能执行', skipped: '已跳过',
  current: '当前有效', stale: '已过期', not_run: '尚未运行', ready: '就绪',
  monitored: '监控中', disabled: '未启用', initializing: '初始化中',
  compatible: '环境兼容', unsupported: '内核不支持', requires_privileges: '权限不足',
  requires_setup: '需要额外配置',
};
const RISK_LABEL = { critical: '严重', high: '高危', medium: '中危', low: '低危', none: '无风险', unknown: '未知' };
const FALCO_CAPABILITY_LABEL = {
  compatible: '环境兼容（运行状态未验证）', unsupported: '内核/eBPF 不支持',
  requires_privileges: '缺少所需权限', requires_setup: '需要额外配置', unknown: '无法判断',
};
const PAGE_META = {
  dashboard: ['安全概览', '本机防护真实状态、组件健康与最近风险'],
  scan: ['病毒查杀', '快速 / 全盘 / 自定义扫描，查看真实进度与检测结果'],
  yara: ['YARA 规则检测', '签名规则包的安装、校验、版本激活与规则命中结果'],
  host: ['主机防护', '账户、权限、SSH、端口与内核基线的真实检查结果'],
  containers: ['容器防护', '只读容器清单、危险配置检查与运行时事件接入'],
  audit: ['安全体检', '只读主机基线体检、Lynis 结果与运行环境自检'],
  events: ['安全事件', '统一事件中心：过滤、证据、状态流转与导出'],
  quarantine: ['隔离区', '隔离文件的证据、恢复与删除'],
  components: ['组件管理', 'ClamAV 等安全组件的真实安装与运行状态'],
  policy: ['防护策略', '处置模式、定时扫描与自动化边界'],
  settings: ['设置与日志', '守护进程信息、审计记录与运行日志'],
};
const state = {
  role: null,
  csrf: sessionStorage.getItem('lsec_csrf') || '',
  page: 'dashboard',
  timer: null,
  status: null,
  modalOnClose: null,
};

class ApiError extends Error {
  constructor(message, code, status, details) {
    super(message);
    this.code = code || 'internal_error';
    this.status = status || 0;
    this.details = details;
  }
}

/* --------------------------------------------------------------- helpers */
function esc(value) {
  return String(value === null || value === undefined ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function fmtTime(value) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return esc(value);
  return date.toLocaleString('zh-CN', { hour12: false });
}
function fmtBytes(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return '-';
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n;
  let u = -1;
  do { v /= 1024; u += 1; } while (v >= 1024 && u < units.length - 1);
  return `${v.toFixed(1)} ${units[u]}`;
}
function toast(message, isError = false) {
  const node = $('#toast');
  node.textContent = message;
  node.classList.toggle('error', isError);
  node.classList.remove('hidden');
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => node.classList.add('hidden'), 4200);
}
function setPill(text, kind = 'neutral') {
  const pill = $('#overall-pill');
  pill.textContent = text;
  pill.className = `pill ${kind}`;
}
function badge(kind, text) {
  return `<span class="badge ${esc(kind)}">${esc(text)}</span>`;
}
function severityBadge(severity) {
  return badge(severity, SEVERITY_LABEL[severity] || severity);
}
function statusBadge(status) {
  const kind = { succeeded: 'ok', failed: 'danger', partial: 'warn', cancelled: 'neutral',
    running: 'info', queued: 'neutral', cancel_requested: 'warn', new: 'info',
    acknowledged: 'warn', investigating: 'warn', resolved: 'ok', ignored: 'neutral',
    quarantined: 'warn', restored: 'ok', deleted: 'neutral', missing: 'danger',
    pass: 'ok', finding: 'warn', error: 'danger', skipped: 'neutral',
    current: 'ok', stale: 'warn', not_run: 'neutral', ready: 'ok',
    monitored: 'ok', disabled: 'neutral', initializing: 'info', degraded: 'warn',
    unavailable: 'danger', permission_denied: 'danger',
    compatible: 'ok', unsupported: 'danger', requires_privileges: 'danger',
    requires_setup: 'warn' }[status] || 'neutral';
  return badge(kind, STATUS_LABEL[status] || status);
}
function riskBadge(risk) {
  const kind = { critical: 'danger', high: 'danger', medium: 'warn', low: 'info', none: 'ok', unknown: 'neutral' }[risk] || 'neutral';
  return badge(kind, RISK_LABEL[risk] || risk || '未知');
}
function fmtUptime(seconds) {
  const n = Number(seconds);
  if (!Number.isFinite(n)) return '-';
  const hours = Math.floor(n / 3600);
  if (hours < 1) return `${Math.floor(n / 60)} 分钟`;
  if (hours < 48) return `${hours} 小时`;
  return `${Math.floor(hours / 24)} 天 ${hours % 24} 小时`;
}
function containerUptime(item) {
  if (!item || !item.started_at) return '-';
  const started = new Date(item.started_at);
  if (Number.isNaN(started.getTime())) return '-';
  return fmtUptime(Math.max(0, (Date.now() - started.getTime()) / 1000));
}
function healthBadge(health) {
  const kind = { ok: 'ok', degraded: 'warn', unavailable: 'danger', incompatible: 'danger',
    check_failed: 'danger', permission_denied: 'danger', unknown: 'neutral' }[health] || 'neutral';
  return badge(kind, STATUS_LABEL[health] || health);
}
function overallKind(overall) {
  return { healthy: 'ok', at_risk: 'danger', protection_incomplete: 'warn' }[overall] || 'neutral';
}
function empty(text) { return `<div class="empty">${esc(text)}</div>`; }

/* ------------------------------------------------------------------- API */
async function api(path, options = {}) {
  const method = options.method || 'GET';
  const headers = { Accept: 'application/json' };
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && state.csrf) headers['X-LSEC-CSRF'] = state.csrf;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeout || 30000);
  let response;
  try {
    response = await fetch(`/api/v1${path}`, {
      method,
      headers,
      credentials: 'same-origin',
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timer);
    throw new ApiError('无法连接守护进程，请检查服务状态', 'network_error', 0);
  }
  clearTimeout(timer);
  let payload = null;
  try { payload = await response.json(); } catch (err) { payload = null; }
  if (response.status === 401 && path !== '/auth/login') {
    showLogin('登录已过期，请重新登录');
    throw new ApiError(payload?.error?.message || '未登录', 'unauthorized', 401);
  }
  if (!response.ok || !payload || payload.ok === false) {
    const error = payload?.error || {};
    throw new ApiError(error.message || `请求失败（HTTP ${response.status}）`, error.code, response.status, error.details);
  }
  return payload;
}

/* ----------------------------------------------------------------- modal */
function openModal(title, bodyHtml, footerHtml = '', options = {}) {
  $('#modal-title').textContent = title;
  $('#modal-body').innerHTML = bodyHtml;
  $('#modal-foot').innerHTML = footerHtml;
  $('#modal .modal-card').classList.toggle('wide', Boolean(options.wide));
  $('#modal').classList.remove('hidden');
  state.modalOnClose = options.onClose || null;
}
function closeModal(result) {
  $('#modal').classList.add('hidden');
  const callback = state.modalOnClose;
  state.modalOnClose = null;
  if (typeof callback === 'function') callback(result);
}
function confirmDialog(title, messageHtml, options = {}) {
  return new Promise((resolve) => {
    openModal(
      title,
      messageHtml,
      `<button class="btn" id="modal-cancel">取消</button>
       <button class="btn ${options.danger ? 'danger' : 'primary'}" id="modal-ok">${esc(options.confirmText || '确认')}</button>`,
      { onClose: (result) => resolve(result === true) }
    );
    $('#modal-cancel').onclick = () => closeModal(false);
    $('#modal-ok').onclick = () => closeModal(true);
  });
}

function renderError(error) {
  $('#content').innerHTML = `<div class="notice danger">加载失败：${esc(error.message)}</div>`;
  setPill('数据不可用', 'danger');
}

/* ------------------------------------------------------------------ auth */
function showLogin(message = '') {
  clearInterval(state.timer);
  state.timer = null;
  state.csrf = '';
  sessionStorage.removeItem('lsec_csrf');
  sessionStorage.removeItem('lsec_role');
  $('#app').classList.add('hidden');
  $('#login').classList.remove('hidden');
  const error = $('#login-error');
  if (message) {
    error.textContent = message;
    error.classList.remove('hidden');
  } else {
    error.classList.add('hidden');
  }
  setTimeout(() => $('#token').focus(), 30);
}

function showApp() {
  $('#login').classList.add('hidden');
  $('#app').classList.remove('hidden');
  const role = state.role || sessionStorage.getItem('lsec_role') || 'viewer';
  $('#role-badge').textContent = role === 'admin' ? '管理员' : '只读';
  document.body.dataset.role = role;
}

async function doLogin(event) {
  event.preventDefault();
  const button = $('#login-form button[type=submit]');
  const errorNode = $('#login-error');
  const token = $('#token').value.trim();
  if (!token) return;
  button.disabled = true;
  button.textContent = '登录中…';
  errorNode.classList.add('hidden');
  try {
    const payload = await api('/auth/login', { method: 'POST', body: { token } });
    state.csrf = payload.csrf_token;
    state.role = payload.role;
    sessionStorage.setItem('lsec_csrf', state.csrf);
    sessionStorage.setItem('lsec_role', state.role);
    $('#token').value = '';
    showApp();
    navigate(location.hash.replace('#', '') || 'dashboard');
  } catch (err) {
    errorNode.textContent = err.message;
    errorNode.classList.remove('hidden');
  } finally {
    button.disabled = false;
    button.textContent = '登录';
  }
}

async function doLogout() {
  try { await api('/auth/logout', { method: 'POST', body: {} }); } catch (err) { /* ignore */ }
  showLogin('已退出登录');
}

/* ------------------------------------------------------------- navigation */
function navigate(page) {
  if (!PAGE_META[page]) page = 'dashboard';
  state.page = page;
  if (location.hash !== `#${page}`) location.hash = page;
  clearInterval(state.timer);
  state.timer = null;
  $$('.nav-item').forEach((button) => button.classList.toggle('active', button.dataset.page === page));
  $('#page-title').textContent = PAGE_META[page][0];
  $('#page-sub').textContent = PAGE_META[page][1];
  $('#content').innerHTML = '<div class="empty">加载中…</div>';
  setPill('读取中', 'neutral');
  renderPage();
}

async function renderPage() {
  try {
    const renderer = RENDERERS[state.page] || RENDERERS.dashboard;
    await renderer();
  } catch (err) {
    if (err.status !== 401) renderError(err);
  }
}

/* ------------------------------------------------------------- dashboard */
async function renderDashboard() {
  const [{ status }, { events }] = await Promise.all([
    api('/status'),
    api('/events?limit=6'),
  ]);
  state.status = status;
  setPill(status.overall_label, overallKind(status.overall));
  const p = status.protection;
  const realtimeText = p.real_time.state === 'active' ? '已启用' : p.real_time.state === 'unsupported' ? '不支持' : '未启用';
  const dbText = { current: '正常', outdated: '需要更新', missing: '缺失', unknown: '未知' }[p.virus_database.state] || p.virus_database.state;
  const dbSub = p.virus_database.updated_at ? `更新于 ${fmtTime(p.virus_database.updated_at)}` : p.virus_database.age_hours !== null ? `约 ${p.virus_database.age_hours} 小时前` : '没有病毒库信息';
  const onDemandText = { ready: '可用', degraded: '降级', stopped: '已停止', unavailable: '不可用' }[p.on_demand.state] || p.on_demand.state;
  const last = status.last_scan;
  const highOpen = (status.events.high || 0) + (status.events.critical || 0);
  const isAdmin = state.role === 'admin';

  const reasons = (status.reasons || []).map((reason) => `<li>${esc(reason)}</li>`).join('');
  const componentRows = (status.components.items || []).map((component) => `
    <tr>
      <td><strong>${esc(component.display_name)}</strong><div class="mono">${esc(component.component_id)}</div></td>
      <td>${component.installed ? '已安装' : '未安装'}</td>
      <td>${healthBadge(component.health_status)}</td>
      <td class="mono">${esc(component.version || '-')}</td>
      <td class="muted">${esc(component.error_message || '-')}</td>
    </tr>`).join('');

  const eventRows = events.map((event) => `
    <tr class="clickable" data-event-id="${esc(event.event_id)}">
      <td>${severityBadge(event.severity)}</td>
      <td>${statusBadge(event.status)}</td>
      <td><span class="truncate">${esc(event.title)}</span></td>
      <td class="muted">${esc(fmtTime(event.last_seen_at))}</td>
    </tr>`).join('');

  $('#content').innerHTML = `
    <section class="hero state-${esc(status.overall)}">
      <div class="hero-top">
        <div>
          <h2>${esc(status.overall_label)}</h2>
          <p>${esc(status.summary)}</p>
        </div>
        <div class="row-actions">
          ${isAdmin ? '<button class="btn primary" id="dash-quick-scan">快速扫描</button>' : ''}
          <button class="btn" data-goto="scan">前往病毒查杀</button>
        </div>
      </div>
      ${reasons ? `<div class="hero-reasons"><strong>需要关注</strong><ul>${reasons}</ul></div>` : ''}
    </section>

    <div class="grid-4">
      <div class="stat">
        <div class="label">实时防护</div>
        <div class="value">${esc(realtimeText)}</div>
        <div class="sub">${esc(p.real_time.reason || '')}</div>
      </div>
      <div class="stat">
        <div class="label">病毒库</div>
        <div class="value">${esc(dbText)}</div>
        <div class="sub">${esc(dbSub)}</div>
      </div>
      <div class="stat">
        <div class="label">按需扫描</div>
        <div class="value">${esc(onDemandText)}</div>
        <div class="sub">${esc(p.on_demand.reason)}</div>
      </div>
      <div class="stat">
        <div class="label">未处理高危事件</div>
        <div class="value">${highOpen}</div>
        <div class="sub">全部未处理 ${status.events.total_open} 条</div>
      </div>
    </div>

    <div class="grid-3">
      <div class="card">
        <div class="card-head"><h2>最近扫描</h2><button class="btn small ghost" data-goto="scan">查看</button></div>
        ${last ? `
          <div class="detail-grid">
            <dt>任务类型</dt><dd>${esc(last.task_type)}</dd>
            <dt>状态</dt><dd>${statusBadge(last.status)}</dd>
            <dt>完成时间</dt><dd>${esc(fmtTime(last.finished_at))}</dd>
            <dt>扫描文件</dt><dd>${last.files_scanned}</dd>
            <dt>检测 / 错误</dt><dd>${last.detections_count} / ${last.errors_count}</dd>
          </div>` : '<div class="empty">还没有扫描记录</div>'}
      </div>
      <div class="card">
        <div class="card-head"><h2>主机与容器</h2><button class="btn small ghost" data-goto="host">主机详情</button></div>
        <div class="detail-grid">
          <dt>主机基线</dt><dd>${statusBadge(status.host_baseline.state)} ${esc(status.host_baseline.note)}</dd>
          <dt>容器监控</dt><dd>${statusBadge(status.containers.state)} ${esc(status.containers.note)}</dd>
          <dt>容器风险</dt><dd>${Number(status.containers.risky || 0)} 个风险容器 · ${Number(status.containers.findings || 0)} 项发现</dd>
          <dt>YARA 规则</dt><dd>${statusBadge(status.yara.state)} ${esc(status.yara.note)}</dd>
        </div>
        <div class="form-actions"><button class="btn small" data-goto="containers">容器防护</button><button class="btn small" data-goto="yara">规则检测</button></div>
        <p class="hint" style="margin-top:6px">未实现或不可用的能力会明确标注，不会显示为已防护。</p>
      </div>
      <div class="card">
        <div class="card-head"><h2>隔离区</h2><button class="btn small ghost" data-goto="quarantine">打开</button></div>
        <div class="detail-grid">
          <dt>处置模式</dt><dd>${esc(status.quarantine.mode)}</dd>
          <dt>自动隔离</dt><dd>${status.quarantine.auto_quarantine_enabled ? '已启用' : '未启用'}</dd>
        </div>
        <p class="hint" style="margin-top:12px">隔离、恢复、删除都需要二次确认并写入审计记录。</p>
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h2>组件状态</h2><button class="btn small ghost" data-goto="components">组件管理</button></div>
      <div class="table-wrap"><table>
        <thead><tr><th>组件</th><th>安装</th><th>健康</th><th>版本</th><th>说明</th></tr></thead>
        <tbody>${componentRows || '<tr><td colspan="5">暂无组件数据</td></tr>'}</tbody>
      </table></div>
    </div>

    <div class="card">
      <div class="card-head"><h2>最近事件</h2><button class="btn small ghost" data-goto="events">事件中心</button></div>
      <div class="table-wrap"><table>
        <thead><tr><th>级别</th><th>状态</th><th>标题</th><th>最近发生</th></tr></thead>
        <tbody>${eventRows || '<tr><td colspan="4">当前没有事件</td></tr>'}</tbody>
      </table></div>
    </div>`;

  $$('[data-goto]').forEach((button) => { button.onclick = () => navigate(button.dataset.goto); });
  $$('[data-event-id]').forEach((row) => {
    row.onclick = () => showEventModal(row.dataset.eventId);
  });
  const quick = $('#dash-quick-scan');
  if (quick) {
    quick.onclick = async () => {
      const ok = await confirmDialog('开始快速扫描', '<p>将扫描配置的快速扫描目录。扫描任务由守护进程执行，可在“病毒查杀”中查看进度。</p>', { confirmText: '开始扫描' });
      if (!ok) return;
      try {
        const payload = await api('/scans', { method: 'POST', body: { type: 'quick', engines: ['clamav'] } });
        toast('扫描任务已创建');
        navigate('scan');
      } catch (err) { toast(err.message, true); }
    };
  }
  clearInterval(state.timer);
  state.timer = setInterval(() => {
    if (state.page === 'dashboard' && $('#modal').classList.contains('hidden')) {
      renderDashboard().catch((err) => { if (err.status !== 401) console.warn(err); });
    }
  }, 20000);
}

/* ------------------------------------------------------------------ yara */
async function renderYara() {
  const [{ yara }, { packs, inbox_dir: inbox }] = await Promise.all([
    api('/yara'),
    api('/yara/packs'),
  ]);
  const component = yara.component || {};
  const rules = yara.rules || {};
  const signature = rules.signature || {};
  const isAdmin = state.role === 'admin';
  const ready = Boolean(yara.scan_ready);
  setPill(ready ? '规则扫描就绪' : '规则扫描未就绪', ready ? 'ok' : 'warn');

  const versionRows = [];
  packs.forEach((pack) => {
    pack.versions.forEach((version) => {
      versionRows.push(`
        <tr>
          <td class="mono">${esc(pack.pack_id)}</td>
          <td>${esc(version.name || '-')}</td>
          <td class="mono">${esc(version.version)}</td>
          <td>${Number(version.rules_count || 0)}</td>
          <td>${version.signature_verified ? badge('ok', '已验证') : badge('warn', '未验证')}</td>
          <td>${version.active ? badge('ok', '当前激活') : badge('neutral', '未激活')}</td>
          <td class="muted">${esc(fmtTime(version.installed_at))}</td>
          <td>
            <div class="row-actions">
              ${isAdmin && !version.active ? `<button class="btn small" data-yara-activate="${esc(pack.pack_id)}" data-version="${esc(version.version)}">激活</button>` : ''}
              ${isAdmin && !version.active ? `<button class="btn small danger" data-yara-delete="${esc(pack.pack_id)}" data-version="${esc(version.version)}">删除</button>` : ''}
            </div>
          </td>
        </tr>`);
    });
  });

  $('#content').innerHTML = `
    <div class="card">
      <div class="card-head">
        <div><h2>YARA 规则包状态</h2><p>状态来自守护进程真实探测；安装不等于正在检测，只有已激活的规则包才会用于扫描。</p></div>
        <button class="btn small" id="yara-refresh">刷新</button>
      </div>
      <div class="notice ${ready ? 'info' : 'warn'}">
        ${ready
          ? `已激活 ${Number(rules.active_count || 0)} 个规则包，规则扫描可用。规则命中表示规则匹配，不等同于已确认恶意软件。`
          : esc(component.error_message || '规则扫描未就绪。请安装并激活经过校验的规则包。')}
      </div>
      <div class="detail-grid">
        <dt>安装 / 健康</dt><dd>${component.installed ? '已安装' : '未安装'} · ${statusBadge(component.health_status || 'unknown')}</dd>
        <dt>版本</dt><dd class="mono">${esc(component.version || '-')}</dd>
        <dt>扫描就绪</dt><dd>${ready ? badge('ok', '是') : badge('warn', '否')}</dd>
        <dt>规则包 / 已激活</dt><dd>${Number(rules.packs_count || 0)} / ${Number(rules.active_count || 0)}</dd>
        <dt>签名强制</dt><dd>${signature.required ? '是' : '否'}</dd>
        <dt>可信公钥</dt><dd>${signature.public_key_present ? badge('ok', '已配置') : badge('warn', '缺失')} <span class="mono">${esc(signature.public_key || '-')}</span></dd>
        <dt>规则根目录</dt><dd class="mono">${esc(rules.rules_dir || '-')}</dd>
        <dt>投递目录</dt><dd class="mono">${esc(inbox || rules.inbox_dir || '-')}</dd>
      </div>
      ${rules.state_error ? `<div class="notice danger">规则状态读取异常：${esc(rules.state_error)}</div>` : ''}
      <p class="hint" style="margin-top:12px">守护进程不会自动下载规则，也不会自动隔离或删除命中文件。规则包必须位于投递目录内，且通过 manifest、SHA-256、签名和 yarac 编译校验后才能安装。</p>
    </div>

    ${isAdmin ? `
    <div class="card">
      <div class="card-head"><h2>安装规则包</h2><p>先将签名规则包（.zip 或目录）放入投递目录，再填写其绝对路径。</p></div>
      <div class="form-grid">
        <div class="form-row full">
          <label class="f-label" for="yara-pack-path">规则包绝对路径</label>
          <input type="text" id="yara-pack-path" placeholder="${esc(inbox || '/data/yara/inbox')}/my-rules-1.0.0.zip">
        </div>
        <div class="form-row">
          <label class="checkline"><input type="checkbox" id="yara-activate" checked> 安装成功后立即激活</label>
        </div>
      </div>
      <div class="form-actions"><button class="btn primary" id="yara-install">校验并安装</button></div>
    </div>` : '<div class="notice info">只读账号可查看规则包状态，安装、激活和删除需要管理员令牌。</div>'}

    <div class="card">
      <div class="card-head"><h2>规则包版本</h2><span class="hint">历史版本保留，可切换回滚</span></div>
      <div class="table-wrap"><table>
        <thead><tr><th>规则包</th><th>名称</th><th>版本</th><th>规则数</th><th>签名</th><th>状态</th><th>安装时间</th><th></th></tr></thead>
        <tbody>${versionRows.join('') || '<tr><td colspan="8">尚未安装规则包</td></tr>'}</tbody>
      </table></div>
    </div>`;

  $('#yara-refresh').onclick = () => renderYara().catch((err) => toast(err.message, true));

  $$('[data-yara-activate]').forEach((button) => {
    button.onclick = async () => {
      const packId = button.dataset.yaraActivate;
      const version = button.dataset.version;
      const ok = await confirmDialog(
        '激活规则包版本',
        `<p>将把 <span class="mono">${esc(packId)}@${esc(version)}</span> 设为当前激活版本。下一次扫描使用该版本；旧版本保留以便回滚。</p>`,
        { confirmText: '激活' },
      );
      if (!ok) return;
      try {
        await api(`/yara/packs/${encodeURIComponent(packId)}/${encodeURIComponent(version)}/activate`, {
          method: 'POST', body: { confirm: true },
        });
        toast('规则包版本已激活');
        await renderYara();
      } catch (err) { toast(err.message, true); }
    };
  });

  $$('[data-yara-delete]').forEach((button) => {
    button.onclick = async () => {
      const packId = button.dataset.yaraDelete;
      const version = button.dataset.version;
      const ok = await confirmDialog(
        '删除规则包版本',
        `<p>将从磁盘删除 <span class="mono">${esc(packId)}@${esc(version)}</span>。当前激活版本不能删除。此操作会写入审计记录。</p>`,
        { confirmText: '删除', danger: true },
      );
      if (!ok) return;
      try {
        await api(`/yara/packs/${encodeURIComponent(packId)}/${encodeURIComponent(version)}`, {
          method: 'DELETE', body: { confirm: true },
        });
        toast('规则包版本已删除');
        await renderYara();
      } catch (err) { toast(err.message, true); }
    };
  });

  const install = $('#yara-install');
  if (install) {
    install.onclick = async () => {
      const path = $('#yara-pack-path').value.trim();
      if (!path) { toast('请填写规则包绝对路径', true); return; }
      const activate = $('#yara-activate').checked;
      const ok = await confirmDialog(
        '安装 YARA 规则包',
        `<p>将校验 <span class="mono">${esc(path)}</span> 的 manifest、文件 SHA-256、OpenSSL 签名和 yarac 编译结果。任一校验失败都会拒绝安装。</p><p>${activate ? '安装成功后将立即激活。' : '安装后不会自动激活。'}</p>`,
        { confirmText: '校验并安装' },
      );
      if (!ok) return;
      install.disabled = true;
      try {
        const payload = await api('/yara/packs', {
          method: 'POST',
          body: { path, activate, confirm: true },
          timeout: 300000,
        });
        toast(`已安装 ${payload.pack.pack_id}@${payload.pack.version}`);
        await renderYara();
      } catch (err) {
        toast(err.message, true);
        install.disabled = false;
      }
    };
  }
}

/* ------------------------------------------------------------------ scan */
let scanForm = { type: 'quick', engines: {} };

const ENGINE_LABEL = { clamav: 'ClamAV', yara: 'YARA' };

async function renderScan() {
  const [capabilitiesPayload, tasksPayload] = await Promise.all([
    api('/capabilities'),
    api('/scans?limit=20'),
  ]);
  const caps = capabilitiesPayload.capabilities;
  const scanCap = caps.malware_scan;
  const engines = scanCap.engines || {};
  const engineInfo = (id) => engines[id] || {
    state: id === 'clamav' ? scanCap.state : 'unavailable',
    reason: scanCap.reason,
  };
  const clamav = engineInfo('clamav');
  const yara = engineInfo('yara');
  const clamavReady = clamav.state === 'available';
  const yaraReady = yara.state === 'available';
  const anyReady = clamavReady || yaraReady;
  const selected = (id, ready) => (Object.prototype.hasOwnProperty.call(scanForm.engines, id) ? scanForm.engines[id] : ready);
  const isAdmin = state.role === 'admin';
  setPill(anyReady ? '扫描引擎可用' : '扫描引擎不可用', anyReady ? 'ok' : 'danger');
  const engineLine = (id, info, ready) => `
    <label class="checkline">
      <input type="checkbox" class="scan-engine" value="${id}" ${selected(id, ready) && ready ? 'checked' : ''} ${ready ? '' : 'disabled'}>
      ${ENGINE_LABEL[id]} ${statusBadge(info.state)}
      <span class="hint">${esc(info.reason || '')}</span>
    </label>`;

  $('#content').innerHTML = `
    <div class="card">
      <div class="card-head">
        <div><h2>新建扫描任务</h2><p>扫描引擎可选 ClamAV 与 YARA；进度和结果来自真实任务状态。</p></div>
      </div>
      ${!anyReady ? `<div class="notice warn">没有可用的扫描引擎：${esc(scanCap.reason || yara.reason || '')}。可先到“组件管理”或“规则检测”检查状态。</div>` : ''}
      ${!yaraReady ? `<div class="notice info">YARA 规则扫描不可用：${esc(yara.reason || '')}。可在“规则检测”中安装并激活经过校验的规则包。</div>` : ''}
      <div class="form-grid">
        <div class="form-row full">
          <label class="f-label">扫描类型</label>
          <div class="seg" id="scan-type">
            <button type="button" data-type="quick" class="${scanForm.type === 'quick' ? 'active' : ''}">快速扫描</button>
            <button type="button" data-type="full" class="${scanForm.type === 'full' ? 'active' : ''}">全盘扫描</button>
            <button type="button" data-type="custom" class="${scanForm.type === 'custom' ? 'active' : ''}">自定义路径</button>
          </div>
        </div>
        <div class="form-row full ${scanForm.type === 'custom' ? '' : 'hidden'}" id="custom-paths">
          <label class="f-label" for="scan-paths">扫描路径（每行一个，必须位于允许的扫描范围内）</label>
          <textarea id="scan-paths" placeholder="/scan/downloads&#10;/scan/home/user"></textarea>
        </div>
        <div class="form-row full">
          <label class="f-label">扫描引擎（至少选择一个可用引擎）</label>
          ${engineLine('clamav', clamav, clamavReady)}
          ${engineLine('yara', yara, yaraReady)}
        </div>
        <div class="form-row">
          <label class="f-label">说明</label>
          <p class="hint">全盘扫描以容器可见的 <code>/</code> 为根；容器默认不启用实时防护。扫描不会自动删除或隔离文件。YARA 命中表示规则匹配，不等同于已确认恶意软件。</p>
        </div>
      </div>
      <div class="form-actions">
        <button class="btn primary" id="scan-start" ${!isAdmin || !anyReady ? 'disabled' : ''}>开始扫描</button>
        ${!isAdmin ? '<span class="hint">只读账号不能创建扫描任务。</span>' : ''}
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h2>扫描任务</h2><span class="hint" id="scan-refresh-hint">每 4 秒刷新</span></div>
      <div id="scan-tasks">${empty('加载中…')}</div>
    </div>`;

  $$('#scan-type button').forEach((button) => {
    button.onclick = () => {
      scanForm.type = button.dataset.type;
      $$('#scan-type button').forEach((b) => b.classList.toggle('active', b === button));
      $('#custom-paths').classList.toggle('hidden', scanForm.type !== 'custom');
    };
  });
  $$('.scan-engine').forEach((checkbox) => {
    checkbox.onchange = () => { scanForm.engines[checkbox.value] = checkbox.checked; };
  });

  const start = $('#scan-start');
  if (start && isAdmin && anyReady) {
    start.onclick = async () => {
      const chosen = $$('.scan-engine').filter((item) => item.checked && !item.disabled).map((item) => item.value);
      if (!chosen.length) { toast('请至少选择一个可用的扫描引擎', true); return; }
      const body = { type: scanForm.type, engines: chosen };
      if (scanForm.type === 'custom') {
        const paths = $('#scan-paths').value.split('\n').map((line) => line.trim()).filter(Boolean);
        if (!paths.length) { toast('请填写至少一个扫描路径', true); return; }
        body.paths = paths;
      }
      const label = { quick: '快速扫描', full: '全盘扫描', custom: '自定义扫描' }[body.type];
      const ok = await confirmDialog(`开始${label}`, `<p>将使用 ${chosen.map((id) => ENGINE_LABEL[id]).join(' + ')} 执行；任务在守护进程后台运行，可随时取消。扫描期间可能占用磁盘与 CPU。</p>`, { confirmText: '开始' });
      if (!ok) return;
      try {
        await api('/scans', { method: 'POST', body });
        toast('扫描任务已创建');
        await refreshScanTasks();
      } catch (err) { toast(err.message, true); }
    };
  }

  await refreshScanTasks();
  state.timer = setInterval(() => {
    if (state.page === 'scan' && $('#modal').classList.contains('hidden')) {
      refreshScanTasks().catch((err) => { if (err.status !== 401) console.warn(err); });
    }
  }, 4000);
}

async function refreshScanTasks() {
  const { tasks } = await api('/scans?limit=20');
  const active = tasks.find((task) => ['running', 'cancel_requested'].includes(task.status));
  const activeHtml = active ? renderActiveTask(active) : '';
  const rows = tasks.map((task) => `
    <tr>
      <td><span class="mono">${esc(task.task_id.slice(0, 8))}</span></td>
      <td>${esc(task.task_type)}</td>
      <td>${statusBadge(task.status)}</td>
      <td>${task.progress === null || task.progress === undefined ? '<span class="muted">未知</span>' : `${Number(task.progress).toFixed(1)}%`}</td>
      <td>${task.files_scanned}</td>
      <td>${task.detections_count}</td>
      <td>${task.errors_count}</td>
      <td class="muted">${esc(fmtTime(task.created_at))}</td>
      <td><div class="row-actions">
        <button class="btn small" data-task-show="${esc(task.task_id)}">详情</button>
        ${state.role === 'admin' && ['queued', 'running', 'cancel_requested'].includes(task.status)
          ? `<button class="btn small danger" data-task-cancel="${esc(task.task_id)}">取消</button>` : ''}
      </div></td>
    </tr>`).join('');
  const target = $('#scan-tasks');
  if (!target) return;
  target.innerHTML = `${activeHtml}
    <div class="table-wrap"><table>
      <thead><tr><th>任务</th><th>类型</th><th>状态</th><th>进度</th><th>文件</th><th>检测</th><th>错误</th><th>创建时间</th><th></th></tr></thead>
      <tbody>${rows || '<tr><td colspan="9">还没有扫描任务</td></tr>'}</tbody>
    </table></div>`;
  $$('[data-task-show]').forEach((button) => { button.onclick = () => showTaskModal(button.dataset.taskShow); });
  $$('[data-task-cancel]').forEach((button) => {
    button.onclick = async () => {
      const ok = await confirmDialog('取消扫描任务', '<p>取消请求会传递到后台任务；当前文件扫描完成后停止。已产生的检测事件会保留。</p>', { confirmText: '取消任务', danger: true });
      if (!ok) return;
      try { await api(`/scans/${button.dataset.taskCancel}/cancel`, { method: 'POST', body: {} }); toast('已发送取消请求'); await refreshScanTasks(); }
      catch (err) { toast(err.message, true); }
    };
  });
}

function renderActiveTask(task) {
  const progress = task.progress;
  return `
    <div style="margin-bottom:16px">
      <div class="progress-track"><div class="progress-fill" style="width:${progress === null ? 0 : Math.min(100, progress)}%"></div></div>
      <div class="progress-label">
        <span>${progress === null ? '进度未知（正在枚举文件或任务刚开始）' : `${progress.toFixed(1)}%`} · 已扫描 ${task.files_scanned} 个文件 · 检测 ${task.detections_count} · 错误 ${task.errors_count}</span>
        <span>${statusBadge(task.status)}</span>
      </div>
    </div>`;
}

async function showTaskModal(taskId) {
  let task;
  try {
    task = (await api(`/scans/${taskId}`)).task;
  } catch (err) { toast(err.message, true); return; }
  const summary = task.result_summary || {};
  const detections = summary.detections_sample || [];
  const errors = task.error_details || [];
  const detectionRows = detections.map((detection) => `
    <tr>
      <td class="mono">${esc(detection.path)}</td>
      <td>${esc(detection.detection_name)}</td>
      <td>${severityBadge(detection.severity)}</td>
      <td>${state.role === 'admin' ? `<button class="btn small danger" data-quarantine="${esc(detection.path)}" data-event="${esc(detection.event_id)}" data-name="${esc(detection.detection_name)}">隔离</button>` : ''}</td>
    </tr>`).join('');
  const errorRows = errors.slice(0, 20).map((error) => `
    <li><span class="mono">${esc(error.path || '')}</span> ${esc(error.error || '')}</li>`).join('');
  openModal(`扫描任务 ${task.task_id.slice(0, 8)}`, `
    <dl class="detail-grid">
      <dt>任务 ID</dt><dd class="mono">${esc(task.task_id)}</dd>
      <dt>类型 / 引擎</dt><dd>${esc(task.task_type)} / ${esc((task.selected_engines || []).join(', '))}</dd>
      <dt>状态</dt><dd>${statusBadge(task.status)}</dd>
      <dt>目标</dt><dd class="mono">${esc((task.target_paths || []).join(', '))}</dd>
      <dt>创建 / 开始 / 结束</dt><dd>${esc(fmtTime(task.created_at))} / ${esc(fmtTime(task.started_at))} / ${esc(fmtTime(task.finished_at))}</dd>
      <dt>文件 / 检测 / 错误</dt><dd>${task.files_scanned} / ${task.detections_count} / ${task.errors_count}</dd>
      <dt>证据报告</dt><dd class="mono">${esc(summary.evidence_path || '-')}</dd>
    </dl>
    <h3 style="font-size:14px;margin:20px 0 8px">检测结果</h3>
    ${detectionRows ? `<div class="table-wrap"><table><thead><tr><th>路径</th><th>检测名</th><th>级别</th><th></th></tr></thead><tbody>${detectionRows}</tbody></table></div>` : '<div class="empty">没有检测到恶意文件</div>'}
    <h3 style="font-size:14px;margin:20px 0 8px">错误（最多显示 20 条）</h3>
    ${errorRows ? `<ul class="list-clean">${errorRows}</ul>` : '<p class="muted">没有错误</p>'}
  `, `<button class="btn" id="modal-cancel">关闭</button>`, { wide: true });
  $('#modal-cancel').onclick = () => closeModal();
  $$('[data-quarantine]').forEach((button) => {
    button.onclick = () => {
      closeModal();
      quarantinePath(button.dataset.quarantine, button.dataset.event, button.dataset.name);
    };
  });
}

/* ----------------------------------------------------------------- events */
let eventFilters = { severity: '', status: '', source: '', category: '', q: '' };

async function renderEvents() {
  const isAdmin = state.role === 'admin';
  setPill('统一事件中心', 'info');
  $('#content').innerHTML = `
    <div class="card">
      <div class="card-head"><h2>事件列表</h2><div class="row-actions">
        <button class="btn small" id="events-refresh">刷新</button>
        <button class="btn small" id="export-json">导出 JSON</button>
        <button class="btn small" id="export-csv">导出 CSV</button>
      </div></div>
      <div class="filters">
        <div class="form-row"><label class="f-label">级别</label>
          <select id="f-severity"><option value="">全部</option>${Object.entries(SEVERITY_LABEL).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}</select>
        </div>
        <div class="form-row"><label class="f-label">状态</label>
          <select id="f-status"><option value="">全部</option>
            <option value="new">新事件</option><option value="acknowledged">已确认</option>
            <option value="investigating">调查中</option><option value="resolved">已解决</option><option value="ignored">已忽略</option>
          </select>
        </div>
        <div class="form-row"><label class="f-label">来源</label>
          <select id="f-source"><option value="">全部</option>
            <option value="clamav">ClamAV</option><option value="falco">Falco</option><option value="wazuh">Wazuh</option>
            <option value="yara">YARA</option><option value="lynis">Lynis</option><option value="docker">Docker 容器</option>
            <option value="system">系统</option>
          </select>
        </div>
        <div class="form-row"><label class="f-label">类别</label>
          <select id="f-category"><option value="">全部</option>
            <option value="malware">恶意软件</option><option value="intrusion">入侵</option><option value="runtime">运行时</option>
            <option value="integrity">完整性</option><option value="vulnerability">漏洞</option><option value="configuration">配置</option>
          </select>
        </div>
        <div class="form-row grow"><label class="f-label">搜索</label>
          <input type="text" id="f-q" placeholder="标题、说明或路径">
        </div>
        <button class="btn primary" id="f-apply">筛选</button>
      </div>
      <div id="events-table">${empty('加载中…')}</div>
    </div>`;
  $('#f-severity').value = eventFilters.severity;
  $('#f-status').value = eventFilters.status;
  $('#f-source').value = eventFilters.source;
  $('#f-category').value = eventFilters.category;
  $('#f-q').value = eventFilters.q;
  $('#f-apply').onclick = () => {
    eventFilters = {
      severity: $('#f-severity').value,
      status: $('#f-status').value,
      source: $('#f-source').value,
      category: $('#f-category').value,
      q: $('#f-q').value.trim(),
    };
    refreshEvents().catch((err) => toast(err.message, true));
  };
  $('#events-refresh').onclick = () => refreshEvents().catch((err) => toast(err.message, true));
  $('#export-json').onclick = () => downloadExport('json');
  $('#export-csv').onclick = () => downloadExport('csv');
  $('#f-q').addEventListener('keydown', (event) => { if (event.key === 'Enter') $('#f-apply').click(); });
  await refreshEvents();
}

function eventQuery() {
  const params = new URLSearchParams();
  Object.entries(eventFilters).forEach(([key, value]) => { if (value) params.set(key, value); });
  return params.toString();
}

async function refreshEvents() {
  const payload = await api(`/events?${eventQuery()}&limit=100`);
  const isAdmin = state.role === 'admin';
  const rows = payload.events.map((event) => {
    const target = event.target || {};
    const targetText = target.path || target.name
      || (target.container_id ? String(target.container_id).slice(0, 12) : '-');
    return `
    <tr>
      <td>${severityBadge(event.severity)}</td>
      <td>${statusBadge(event.status)}</td>
      <td>${esc(event.source)}</td>
      <td><button class="link-btn" data-event-open="${esc(event.event_id)}" style="color:var(--accent);font-size:13px;font-weight:600">${esc(event.title)}</button></td>
      <td class="mono truncate">${esc(targetText)}</td>
      <td>${event.occurrences}</td>
      <td class="muted">${esc(fmtTime(event.last_seen_at))}</td>
      <td>${isAdmin && target.path && event.category === 'malware'
        ? `<button class="btn small danger" data-quarantine="${esc(target.path)}" data-event="${esc(event.event_id)}" data-name="${esc((event.evidence || {}).detection_name || '')}">隔离</button>` : ''}</td>
    </tr>`;
  }).join('');
  $('#events-table').innerHTML = `
    <div class="table-wrap"><table>
      <thead><tr><th>级别</th><th>状态</th><th>来源</th><th>标题</th><th>目标</th><th>次数</th><th>最近发生</th><th></th></tr></thead>
      <tbody>${rows || '<tr><td colspan="8">没有匹配的事件</td></tr>'}</tbody>
    </table></div>
    <p class="hint" style="margin-top:10px">共 ${payload.total} 条，显示 ${payload.events.length} 条</p>`;
  $$('[data-event-open]').forEach((button) => { button.onclick = () => showEventModal(button.dataset.eventOpen); });
  $$('[data-quarantine]').forEach((button) => {
    button.onclick = () => quarantinePath(button.dataset.quarantine, button.dataset.event, button.dataset.name);
  });
}

async function downloadExport(format) {
  try {
    const response = await fetch(`/api/v1/events/export?${eventQuery()}&format=${format}`, { credentials: 'same-origin' });
    if (!response.ok) throw new Error(`导出失败（HTTP ${response.status}）`);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `lsec-events-${new Date().toISOString().slice(0, 10)}.${format}`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    toast(`已导出 ${format.toUpperCase()}`);
  } catch (err) { toast(err.message, true); }
}

async function showEventModal(eventId) {
  let event;
  try { event = (await api(`/events/${eventId}`)).event; }
  catch (err) { toast(err.message, true); return; }
  const evidence = event.evidence || {};
  const target = event.target || {};
  const details = evidence.details || {};
  const actions = (event.recommended_actions || []).map((action) => `<li>${esc(action)}</li>`).join('');
  const isAdmin = state.role === 'admin';
  const transitionButtons = isAdmin ? `
    <div class="form-row full" style="margin-top:14px">
      <label class="f-label" for="event-note">备注（可选）</label>
      <textarea id="event-note" placeholder="记录处置说明…"></textarea>
    </div>
    <div class="form-actions">
      ${event.status === 'new' ? '<button class="btn" data-event-status="acknowledged">确认</button><button class="btn" data-event-status="investigating">开始调查</button>' : ''}
      ${['new', 'acknowledged', 'investigating'].includes(event.status) ? '<button class="btn primary" data-event-status="resolved">标记已解决</button><button class="btn" data-event-status="ignored">忽略</button>' : ''}
      ${['resolved', 'ignored'].includes(event.status) ? '<button class="btn" data-event-status="new">重新打开</button>' : ''}
    </div>` : '<p class="hint">只读账号不能修改事件状态。</p>';
  openModal('事件详情', `
    <dl class="detail-grid">
      <dt>标题</dt><dd><strong>${esc(event.title)}</strong></dd>
      <dt>事件 ID</dt><dd class="mono">${esc(event.event_id)}</dd>
      <dt>级别 / 来源</dt><dd>${severityBadge(event.severity)} ${esc(event.source)} / ${esc(event.category)}</dd>
      <dt>状态</dt><dd>${statusBadge(event.status)}</dd>
      <dt>首次 / 最近</dt><dd>${esc(fmtTime(event.first_seen_at))} / ${esc(fmtTime(event.last_seen_at))}</dd>
      <dt>发生次数</dt><dd>${event.occurrences}</dd>
      <dt>目标</dt><dd class="mono">${esc(target.type || '')} ${esc(target.path || target.name || '')}</dd>
      <dt>容器 ID</dt><dd class="mono">${esc(target.container_id || '-')}</dd>
      <dt>检测名</dt><dd>${esc(evidence.detection_name || '-')}</dd>
      <dt>SHA256</dt><dd class="mono">${esc(evidence.sha256 || '-')}</dd>
      <dt>任务</dt><dd class="mono">${esc(details.task_id || '-')}</dd>
      <dt>说明</dt><dd>${esc(event.description)}</dd>
    </dl>
    ${actions ? `<h3 style="font-size:14px;margin:18px 0 6px">建议</h3><ul class="list-clean">${actions}</ul>` : ''}
    ${evidence.sha256 && isAdmin && target.path ? `<div class="form-actions"><button class="btn danger" id="event-quarantine">隔离该文件</button></div>` : ''}
    ${transitionButtons}
  `, `<button class="btn" id="modal-cancel">关闭</button>`, { wide: true });
  $('#modal-cancel').onclick = () => closeModal();
  const quarantineButton = $('#event-quarantine');
  if (quarantineButton) {
    quarantineButton.onclick = () => {
      closeModal();
      quarantinePath(target.path, event.event_id, evidence.detection_name || '');
    };
  }
  $$('[data-event-status]').forEach((button) => {
    button.onclick = async () => {
      const status = button.dataset.eventStatus;
      const note = $('#event-note').value.trim();
      const labels = { acknowledged: '确认', investigating: '开始调查', resolved: '标记已解决', ignored: '忽略', new: '重新打开' };
      const ok = await confirmDialog('更新事件状态', `<p>将事件状态改为“${esc(labels[status] || status)}”。该操作会写入审计记录。</p>`, { confirmText: '确认' });
      if (!ok) return;
      try {
        await api(`/events/${event.event_id}`, { method: 'PATCH', body: { status, note: note || undefined } });
        toast('事件状态已更新');
        closeModal();
        if (state.page === 'events') await refreshEvents();
        else if (state.page === 'dashboard') await renderDashboard();
      } catch (err) { toast(err.message, true); }
    };
  });
}

/* ------------------------------------------------------------- quarantine */
async function quarantinePath(path, eventId, detectionName) {
  const ok = await confirmDialog(
    '隔离文件',
    `<div class="notice warn">隔离会移动原文件到仅守护进程可访问的隔离目录，并把哈希、原路径和检测信息写入审计。请先确认这是需要隔离的可疑文件。</div>
     <dl class="detail-grid">
       <dt>文件路径</dt><dd class="mono">${esc(path)}</dd>
       <dt>检测名</dt><dd>${esc(detectionName || '-')}</dd>
     </dl>`,
    { confirmText: '确认隔离', danger: true }
  );
  if (!ok) return;
  try {
    await api('/quarantine', {
      method: 'POST',
      body: { path, event_id: eventId || undefined, detection_name: detectionName || undefined, engine: 'clamav', confirm: true },
    });
    toast('文件已隔离');
    if (state.page === 'quarantine') await renderQuarantine();
    else if (state.page === 'events') await refreshEvents();
    else if (state.page === 'scan') await refreshScanTasks();
  } catch (err) { toast(err.message, true); }
}

async function renderQuarantine() {
  setPill('隔离区', 'info');
  const isAdmin = state.role === 'admin';
  const { items, total } = await api('/quarantine?limit=200');
  const rows = items.map((item) => `
    <tr>
      <td class="mono">${esc(item.item_id.slice(0, 8))}</td>
      <td><span class="truncate mono">${esc(item.original_path)}</span></td>
      <td>${fmtBytes(item.size)}</td>
      <td>${esc(item.detection_name || '-')}</td>
      <td>${statusBadge(item.status)}</td>
      <td class="muted">${esc(fmtTime(item.detected_at))}</td>
      <td><div class="row-actions">
        <button class="btn small" data-q-show="${esc(item.item_id)}">详情</button>
        ${isAdmin && item.status === 'quarantined' ? `
          <button class="btn small" data-q-restore="${esc(item.item_id)}">恢复</button>
          <button class="btn small danger" data-q-delete="${esc(item.item_id)}">删除</button>` : ''}
      </div></td>
    </tr>`).join('');
  $('#content').innerHTML = `
    <div class="card">
      <div class="card-head"><h2>隔离文件</h2><button class="btn small" id="q-refresh">刷新</button></div>
      <div class="notice">隔离区默认移动到守护进程专属目录，不直接删除文件。恢复和删除都需要二次确认并重新校验路径与哈希。</div>
      <div class="table-wrap"><table>
        <thead><tr><th>ID</th><th>原路径</th><th>大小</th><th>检测名</th><th>状态</th><th>隔离时间</th><th></th></tr></thead>
        <tbody>${rows || '<tr><td colspan="7">隔离区为空</td></tr>'}</tbody>
      </table></div>
      <p class="hint" style="margin-top:10px">共 ${total} 条</p>
    </div>`;
  $('#q-refresh').onclick = () => renderQuarantine().catch((err) => toast(err.message, true));
  $$('[data-q-show]').forEach((button) => { button.onclick = () => showQuarantineModal(button.dataset.qShow); });
  $$('[data-q-restore]').forEach((button) => {
    button.onclick = async () => {
      const ok = await confirmDialog('恢复隔离文件', '<div class="notice warn">恢复会把文件写回原路径，并在写入前重新校验哈希。若原路径已被占用则拒绝覆盖。恢复后的文件可能仍然危险，请自行确认。</div>', { confirmText: '确认恢复' });
      if (!ok) return;
      try { await api(`/quarantine/${button.dataset.qRestore}/restore`, { method: 'POST', body: { confirm: true } }); toast('文件已恢复'); await renderQuarantine(); }
      catch (err) { toast(err.message, true); }
    };
  });
  $$('[data-q-delete]').forEach((button) => {
    button.onclick = async () => {
      const ok = await confirmDialog('永久删除隔离文件', '<div class="notice danger">该操作会删除隔离区副本，不可恢复；审计记录会保留。</div>', { confirmText: '永久删除', danger: true });
      if (!ok) return;
      try { await api(`/quarantine/${button.dataset.qDelete}/delete`, { method: 'POST', body: { confirm: true } }); toast('隔离文件已删除'); await renderQuarantine(); }
      catch (err) { toast(err.message, true); }
    };
  });
}

async function showQuarantineModal(itemId) {
  try {
    const { item } = await api(`/quarantine/${itemId}`);
    openModal('隔离项详情', `
      <dl class="detail-grid">
        <dt>ID</dt><dd class="mono">${esc(item.item_id)}</dd>
        <dt>原路径</dt><dd class="mono">${esc(item.original_path)}</dd>
        <dt>存储路径</dt><dd class="mono">${esc(item.stored_path)}</dd>
        <dt>文件存在</dt><dd>${item.file_exists ? '是' : '否（状态可能异常）'}</dd>
        <dt>SHA256</dt><dd class="mono">${esc(item.sha256)}</dd>
        <dt>大小</dt><dd>${fmtBytes(item.size)}</dd>
        <dt>检测名 / 引擎</dt><dd>${esc(item.detection_name || '-')} / ${esc(item.engine || '-')}</dd>
        <dt>关联事件</dt><dd class="mono">${esc(item.event_id || '-')}</dd>
        <dt>隔离者 / 时间</dt><dd>${esc(item.quarantined_by)} / ${esc(fmtTime(item.detected_at))}</dd>
        <dt>状态</dt><dd>${statusBadge(item.status)}</dd>
      </dl>`, `<button class="btn" id="modal-cancel">关闭</button>`, { wide: true });
    $('#modal-cancel').onclick = () => closeModal();
  } catch (err) { toast(err.message, true); }
}

/* ------------------------------------------------------------- components */
async function renderComponents() {
  const { components } = await api('/components');
  const isAdmin = state.role === 'admin';
  setPill('组件状态来自真实探测', 'info');
  const rows = components.map((component) => `
    <tr>
      <td><strong>${esc(component.display_name)}</strong><div class="mono">${esc(component.component_id)}</div></td>
      <td>${component.installed ? badge('ok', '已安装') : badge('danger', '未安装')}</td>
      <td>${esc(component.version || '-')}</td>
      <td>${healthBadge(component.health_status)}</td>
      <td>${esc(STATUS_LABEL[component.service_status] || component.service_status)}</td>
      <td class="muted">${esc(component.error_message || '-')}</td>
      <td class="muted">${esc(fmtTime(component.last_check_at))}</td>
      <td><div class="row-actions">
        <button class="btn small" data-comp-show="${esc(component.component_id)}">详情</button>
        ${component.installed ? `<button class="btn small" data-comp-plan="${esc(component.component_id)}">安装来源</button>` : ''}
        ${isAdmin && component.component_id === 'clamav' ? `
          <button class="btn small" data-comp-start="${esc(component.component_id)}" ${component.service_status === 'running' ? 'disabled' : ''}>启动</button>
          <button class="btn small" data-comp-stop="${esc(component.component_id)}" ${component.service_status !== 'running' ? 'disabled' : ''}>停止</button>
          <button class="btn small" data-comp-update="${esc(component.component_id)}" ${!component.installed ? 'disabled' : ''}>更新病毒库</button>` : ''}
      </div></td>
    </tr>`).join('');
  $('#content').innerHTML = `
    <div class="card">
      <div class="card-head"><h2>组件清单</h2><div class="row-actions">
        <button class="btn small" id="comp-probe" ${isAdmin ? '' : 'disabled'}>重新探测</button>
      </div></div>
      <div class="notice">“已安装”不等于“正在防护”。健康状态区分未安装、未启动、正常运行、降级、权限不足和检查失败。</div>
      <div class="table-wrap"><table>
        <thead><tr><th>组件</th><th>安装</th><th>版本</th><th>健康</th><th>服务</th><th>说明</th><th>最近检查</th><th></th></tr></thead>
        <tbody>${rows || '<tr><td colspan="8">暂无组件</td></tr>'}</tbody>
      </table></div>
    </div>`;
  $('#comp-probe').onclick = async () => {
    try { await api('/components/probe', { method: 'POST', body: {}, timeout: 120000 }); toast('组件探测完成'); await renderComponents(); }
    catch (err) { toast(err.message, true); }
  };
  $$('[data-comp-show]').forEach((button) => { button.onclick = () => showComponentModal(button.dataset.compShow); });
  $$('[data-comp-plan]').forEach((button) => {
    button.onclick = async () => {
      try {
        const { plan } = await api(`/components/${button.dataset.compPlan}/install-plan`);
        openModal('安装来源与权限', `<div class="pre">${esc(JSON.stringify(plan, null, 2))}</div>`, '<button class="btn" id="modal-cancel">关闭</button>', { wide: true });
        $('#modal-cancel').onclick = () => closeModal();
      } catch (err) { toast(err.message, true); }
    };
  });
  $$('[data-comp-start]').forEach((button) => { button.onclick = () => componentAction(button.dataset.compStart, 'start'); });
  $$('[data-comp-stop]').forEach((button) => {
    button.onclick = async () => {
      const ok = await confirmDialog('停止 ClamAV', '<p>停止后按需扫描将不可用，当前正在执行的扫描任务可能失败。</p>', { confirmText: '停止', danger: true });
      if (ok) componentAction(button.dataset.compStop, 'stop');
    };
  });
  $$('[data-comp-update]').forEach((button) => { button.onclick = () => componentAction(button.dataset.compUpdate, 'update'); });
}

async function componentAction(componentId, action) {
  const label = { start: '启动', stop: '停止', update: '更新病毒库' }[action];
  if (action === 'update') {
    const ok = await confirmDialog('更新病毒库', '<p>将通过 freshclam 从官方更新源下载病毒库。需要容器具备出网能力；失败会如实报告并保留现有病毒库。</p>', { confirmText: '开始更新' });
    if (!ok) return;
  }
  try {
    toast(`${label}中…`);
    const payload = await api(`/components/${componentId}/${action}`, { method: 'POST', body: {}, timeout: 900000 });
    if (action === 'update') {
      const outcome = payload.update;
      toast(outcome.ok ? '病毒库更新成功' : `病毒库更新失败（退出码 ${outcome.exit_code}）`, !outcome.ok);
      openModal('病毒库更新结果', `
        <dl class="detail-grid">
          <dt>结果</dt><dd>${outcome.ok ? '成功' : '失败'}</dd>
          <dt>退出码</dt><dd>${esc(outcome.exit_code)}</dd>
          <dt>耗时</dt><dd>${esc(outcome.duration_seconds)} 秒</dd>
          <dt>病毒库</dt><dd class="mono">${esc(JSON.stringify(outcome.database || {}, null, 2))}</dd>
        </dl>
        <h3 style="font-size:14px;margin:16px 0 6px">输出（截断）</h3>
        <div class="pre">${esc(outcome.output_tail || '')}</div>`, '<button class="btn" id="modal-cancel">关闭</button>', { wide: true });
      $('#modal-cancel').onclick = () => closeModal();
    } else {
      toast(`${label}成功`);
    }
    await renderComponents();
  } catch (err) { toast(err.message, true); }
}

async function showComponentModal(componentId) {
  try {
    const { components } = await api('/components');
    const component = components.find((item) => item.component_id === componentId);
    if (!component) throw new Error('组件不存在');
    openModal(component.display_name, `
      <dl class="detail-grid">
        <dt>组件 ID</dt><dd class="mono">${esc(component.component_id)}</dd>
        <dt>已安装</dt><dd>${component.installed ? '是' : '否'}</dd>
        <dt>版本</dt><dd>${esc(component.version || '-')}</dd>
        <dt>服务状态</dt><dd>${esc(component.service_status)}</dd>
        <dt>健康状态</dt><dd>${healthBadge(component.health_status)}</dd>
        <dt>能力</dt><dd>${esc((component.capabilities || []).join(', ') || '无已声明能力')}</dd>
        <dt>错误</dt><dd>${esc(component.error_message || '-')}</dd>
        <dt>最近检查</dt><dd>${esc(fmtTime(component.last_check_at))}</dd>
      </dl>
      <h3 style="font-size:14px;margin:18px 0 6px">探测详情</h3>
      <div class="pre">${esc(JSON.stringify(component.details || {}, null, 2))}</div>
    `, '<button class="btn" id="modal-cancel">关闭</button>', { wide: true });
    $('#modal-cancel').onclick = () => closeModal();
  } catch (err) { toast(err.message, true); }
}

/* ----------------------------------------------------------------- policy */
async function renderPolicy() {
  const { settings, notes } = await api('/settings');
  const schedule = settings.scheduled_scan || {};
  const mode = settings.response_mode || 'suggest';
  setPill('处置默认建议模式', 'info');
  $('#content').innerHTML = `
    <div class="card">
      <div class="card-head"><h2>处置模式</h2></div>
      <div class="notice">自动处置默认关闭。当前版本不执行自动清除、杀进程或停止容器；所有隔离操作都需要人工确认。</div>
      <label class="checkline" style="margin-bottom:10px">
        <input type="radio" name="response-mode" value="alert" ${mode === 'alert' ? 'checked' : ''}>
        仅告警：只记录事件，不给出主动处置建议
      </label>
      <label class="checkline" style="margin-bottom:10px">
        <input type="radio" name="response-mode" value="suggest" ${mode === 'suggest' ? 'checked' : ''}>
        建议处置：给出处置建议，由管理员手动确认（默认）
      </label>
      <label class="checkline" style="margin-bottom:10px;opacity:.55">
        <input type="radio" disabled>
        受控自动处置：尚未实现，禁止在生产环境宣称已启用
      </label>
      <p class="hint">${esc(notes.response_mode || '')}</p>
    </div>

    <div class="card">
      <div class="card-head"><h2>定时扫描</h2></div>
      <div class="form-grid">
        <div class="form-row">
          <label class="checkline"><input type="checkbox" id="schedule-enabled" ${schedule.enabled ? 'checked' : ''}> 启用定时扫描</label>
          <p class="hint">只在守护进程运行期间调度；上次运行 ${esc(fmtTime(schedule.last_run_at))}</p>
        </div>
        <div class="form-row">
          <label class="f-label" for="schedule-type">扫描类型</label>
          <select id="schedule-type">
            <option value="quick" ${schedule.type === 'quick' ? 'selected' : ''}>快速扫描</option>
            <option value="full" ${schedule.type === 'full' ? 'selected' : ''}>全盘扫描</option>
          </select>
        </div>
        <div class="form-row">
          <label class="f-label" for="schedule-interval">间隔（小时）</label>
          <input type="number" id="schedule-interval" min="1" max="720" value="${esc(schedule.interval_hours || 24)}">
        </div>
      </div>
      <div class="form-actions">
        <button class="btn primary" id="policy-save" ${state.role !== 'admin' ? 'disabled' : ''}>保存策略</button>
        ${state.role !== 'admin' ? '<span class="hint">只读账号不能修改策略。</span>' : ''}
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h2>自动化边界</h2></div>
      <ul class="list-clean">
        <li>默认不自动删除文件，隔离只是移动到受控目录。</li>
        <li>不自动结束系统进程、停止容器或修改 SSH / 防火墙 / 网络配置。</li>
        <li>高危操作必须由管理员发起，带请求 ID，并写入审计记录。</li>
        <li>容器模式下不提供 ClamAV 实时访问检测；界面会如实显示“不支持”。</li>
      </ul>
    </div>`;
  $('#policy-save').onclick = async () => {
    const selected = $$('input[name=response-mode]').find((input) => input.checked);
    const payload = {
      response_mode: selected ? selected.value : 'suggest',
      scheduled_scan: {
        enabled: $('#schedule-enabled').checked,
        type: $('#schedule-type').value,
        interval_hours: Number($('#schedule-interval').value),
        last_run_at: schedule.last_run_at || null,
      },
    };
    try {
      await api('/settings', { method: 'PATCH', body: payload });
      toast('策略已保存');
      await renderPolicy();
    } catch (err) { toast(err.message, true); }
  };
}

/* ------------------------------------------------------------------- host */
async function renderHost() {
  const [{ capabilities }, { components }, { host }, { status }, { wazuh }] = await Promise.all([
    api('/capabilities'),
    api('/components'),
    api('/system/info'),
    api('/status'),
    api('/wazuh'),
  ]);
  const cap = capabilities.host_audit || {};
  const wazuhComponent = wazuh.component || {};
  const wazuhDetails = wazuhComponent.details || {};
  const wazuhManager = wazuhDetails.manager || {};
  const wazuhIngest = wazuh.ingest || {};
  const relevant = components.filter((component) => ['lynis', 'system', 'wazuh'].includes(component.component_id));
  const baseline = status.host_baseline || {};
  const last = baseline.last_audit || null;
  const stateKind = { current: 'ok', stale: 'warn', failed: 'danger', not_run: 'warn' }[baseline.state] || 'neutral';
  setPill(
    baseline.state === 'current' ? '主机基线有效' : '主机基线待确认',
    stateKind === 'danger' ? 'danger' : 'warn',
  );
  const rows = relevant.map((component) => `
    <tr>
      <td>${esc(component.display_name)}</td>
      <td>${component.installed ? '已安装' : '未安装'}</td>
      <td>${healthBadge(component.health_status)}</td>
      <td class="muted">${esc(component.error_message || '-')}</td>
    </tr>`).join('');
  $('#content').innerHTML = `
    <div class="notice ${baseline.state === 'failed' ? 'danger' : baseline.state === 'current' ? 'ok' : 'warn'}">
      <strong>主机基线：</strong>${statusBadge(baseline.state)} ${esc(baseline.note || '')}。体检为只读操作，不会自动修改系统配置。
    </div>
    <div class="grid-3">
      <div class="card"><div class="card-head"><h2>主机信息</h2></div>
        <dl class="detail-grid">
          <dt>主机名</dt><dd>${esc(host.hostname)}</dd>
          <dt>操作系统</dt><dd>${esc(host.os)}</dd>
          <dt>内核</dt><dd class="mono">${esc(host.kernel)}</dd>
          <dt>架构</dt><dd class="mono">${esc(host.machine)}</dd>
          <dt>容器环境</dt><dd>${host.container.containerized ? `是（${esc(host.container.runtime || '未知')}）` : '否'}</dd>
        </dl>
      </div>
      <div class="card" style="grid-column: span 2"><div class="card-head"><h2>最近体检</h2><button class="btn small ghost" data-goto="audit">安全体检</button></div>
        ${last ? `<dl class="detail-grid">
          <dt>状态</dt><dd>${statusBadge(last.status)}</dd>
          <dt>检查 / 发现 / 未能执行</dt><dd>${last.checks_total} / ${last.findings_count} / ${last.errors_count}</dd>
          <dt>风险级别</dt><dd>严重 ${last.severity_counts?.critical || 0} · 高危 ${last.severity_counts?.high || 0} · 中危 ${last.severity_counts?.medium || 0} · 低危 ${last.severity_counts?.low || 0}</dd>
          <dt>Lynis 加固指数</dt><dd>${last.hardening_index ?? '-'}</dd>
          <dt>完成时间</dt><dd>${esc(fmtTime(last.finished_at))}</dd>
        </dl>` : '<div class="empty">尚未运行主机体检；当前没有主机基线结论。</div>'}
      </div>
    </div>
    <div class="card"><div class="card-head"><h2>相关组件</h2><button class="btn small ghost" data-goto="components">组件管理</button></div>
      <div class="table-wrap"><table><thead><tr><th>组件</th><th>安装</th><th>健康</th><th>说明</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="4">无相关组件</td></tr>'}</tbody></table></div>
      <p class="hint" style="margin-top:10px">${esc(cap.reason || '')}</p>
    </div>
    <div class="card">
      <div class="card-head"><h2>Wazuh Agent（可选，仅本地）</h2>
        <div class="row-actions">
          <button class="btn small" id="wazuh-plan">安装计划</button>
          <button class="btn small ghost" data-goto="components">组件详情</button>
        </div>
      </div>
      <div class="notice ${wazuh.state === 'available' ? 'ok' : wazuh.state === 'disabled' ? 'info' : 'warn'}">
        <strong>能力状态：</strong>${statusBadge(wazuh.state)} ${esc(wazuh.reason || '')}
        <div class="hint" style="margin-top:6px">${esc(wazuh.note || '')}</div>
      </div>
      <dl class="detail-grid">
        <dt>安装 / 健康</dt><dd>${wazuhComponent.installed ? '已安装' : '未安装'} · ${healthBadge(wazuhComponent.health_status || 'unknown')}</dd>
        <dt>版本 / 服务</dt><dd class="mono">${esc(wazuhComponent.version || '-')} · ${esc(wazuhComponent.service_status || 'unknown')}</dd>
        <dt>Manager 配置</dt><dd>${wazuhManager.manager_configured ? '已配置' : '未配置'} <span class="mono">${esc(wazuhManager.address || '-')}:${esc(wazuhManager.port || '-')}</span></dd>
        <dt>Manager 连接验证</dt><dd>${badge('warn', '未验证')} <span class="hint">本客户端不是 Manager</span></dd>
        <dt>本地注册信息</dt><dd>${wazuhDetails.registration_present ? '存在' : '缺失或不可读'}</dd>
        <dt>本地告警接入</dt><dd>${wazuhIngest.ingest_enabled ? (wazuhIngest.running ? '运行中' : '已启用但未运行') : '未启用'}</dd>
        <dt>接入事件 / 解析错误</dt><dd>${Number(wazuhIngest.events_total || 0)} / ${Number(wazuhIngest.parse_errors || 0)}</dd>
        <dt>告警文件</dt><dd class="mono">${esc(wazuhIngest.alerts_path || wazuhDetails.alerts_path || '-')}</dd>
        <dt>最近事件</dt><dd>${esc(fmtTime(wazuhIngest.last_event_at))}</dd>
      </dl>
      ${wazuhIngest.last_error ? `<p class="hint">最近错误：${esc(wazuhIngest.last_error)}</p>` : ''}
      <p class="hint" style="margin-top:10px">只读取本地 Agent 状态与 alerts.json 的新增行；不管理其他 Agent、不调用 Manager API，也不会自动处置。</p>
    </div>
    <div class="card"><div class="card-head"><h2>文件完整性 / 异常登录 / 权限变更</h2></div>
      ${empty('除上述 Wazuh 本地告警接入外，本客户端不声称已提供文件完整性监控或登录审计；没有数据时不会以“已防护”展示。')}
    </div>`;
  $$('[data-goto]').forEach((button) => { button.onclick = () => navigate(button.dataset.goto); });
  const wazuhPlan = $('#wazuh-plan');
  if (wazuhPlan) {
    wazuhPlan.onclick = async () => {
      try {
        const payload = await api('/wazuh/install-plan');
        const plan = payload.plan || {};
        openModal('Wazuh Agent 安装计划（不会自动执行）', `
          <p>${esc(plan.privileges || '')}</p>
          <ol>${(plan.steps || []).map((step) => `<li>${esc(step)}</li>`).join('')}</ol>
          ${(plan.notes || []).map((note) => `<div class="notice warn">${esc(note)}</div>`).join('')}
        `, '<button class="btn" id="modal-cancel">关闭</button>');
        $('#modal-cancel').onclick = () => closeModal(false);
      } catch (err) { toast(err.message, true); }
    };
  }
}

/* ------------------------------------------------------------- containers */
async function renderContainers() {
  const [{ containers: snapshot }, { falco }, { components }, { capabilities }] = await Promise.all([
    api('/containers'),
    api('/falco'),
    api('/components'),
    api('/capabilities'),
  ]);
  const docker = components.find((component) => component.component_id === 'docker');
  const dockerDetails = docker?.details || {};
  const containerCap = capabilities.container_security || {};
  const monitorInfo = containerCap.monitor || {};
  const engine = snapshot.engine || {};
  const summary = snapshot.summary || {};
  const byRisk = summary.by_risk || {};
  const monitorState = snapshot.state || 'unknown';
  const isAdmin = state.role === 'admin';
  const stateText = STATUS_LABEL[monitorState] || monitorState;
  const pillKind = { monitored: 'ok', disabled: 'warn', initializing: 'info', degraded: 'warn', permission_denied: 'danger', unavailable: 'danger' }[monitorState] || 'neutral';
  setPill(monitorState === 'monitored' ? '容器监控中' : `容器监控：${stateText}`, pillKind);

  let notice;
  if (monitorState === 'disabled') {
    notice = `<div class="notice warn"><strong>容器监控未启用。</strong>${esc(snapshot.note || '')}。启用后通过只读 Docker API 代理读取清单，Web 进程不直接挂载 Docker Socket；不会展示虚构的容器或风险。</div>`;
  } else if (monitorState === 'permission_denied') {
    notice = `<div class="notice danger"><strong>Docker API 权限不足。</strong>${esc(snapshot.note || '')}。这不是“已保护”状态，请检查代理容器的 Socket 权限。</div>`;
  } else if (monitorState === 'unavailable' || monitorState === 'degraded') {
    notice = `<div class="notice danger"><strong>容器监控不可用或降级。</strong>${esc(snapshot.note || '')}${snapshot.stale ? ' 下方为上次成功采集的数据，已标记为过期。' : ''}</div>`;
  } else if (monitorState === 'initializing') {
    notice = `<div class="notice"><strong>正在等待首次容器采集。</strong>${esc(snapshot.note || '')}</div>`;
  } else {
    notice = `<div class="notice ok"><strong>容器监控正常。</strong>${esc(snapshot.note || '')}。仅做只读检查，不会自动停止、重启或修改任何容器。</div>`;
  }

  const staleBadge = snapshot.stale ? ` ${badge('warn', '数据已过期')}` : '';
  const rows = (snapshot.containers || []).map((item) => `
    <tr>
      <td><strong>${esc(item.name || '-')}</strong><div class="mono">${esc((item.container_id || '').slice(0, 12))}</div></td>
      <td><span class="truncate" title="${esc(item.image || '')}">${esc(item.image || '-')}</span></td>
      <td>${esc(item.state || '-')}${item.status_text ? `<div class="muted">${esc(item.status_text)}</div>` : ''}</td>
      <td>${esc(containerUptime(item))}</td>
      <td>${riskBadge(item.risk_level)}</td>
      <td>${Number(item.risk_count || 0)}${item.evaluated ? '' : '<div class="muted">未能评估</div>'}</td>
      <td><button class="btn small" data-container-open="${esc(item.container_id || item.name || '')}">详情</button></td>
    </tr>`).join('');

  const engineCard = engine.runtime ? `
    <dl class="detail-grid">
      <dt>运行时</dt><dd>Docker${engine.server_version ? ` ${esc(engine.server_version)}` : ''}</dd>
      <dt>API 版本</dt><dd class="mono">${esc(engine.api_version || '-')}</dd>
      <dt>宿主内核</dt><dd class="mono">${esc(engine.kernel || '-')}</dd>
      <dt>系统 / 架构</dt><dd>${esc(engine.os || '-')} / ${esc(engine.architecture || '-')}</dd>
      <dt>本次清单 运行 / 停止</dt><dd>${Number(summary.running || 0)} / ${Number(summary.stopped || 0)}</dd>
      <dt>上次成功采集</dt><dd>${esc(fmtTime(snapshot.last_success_at))}${staleBadge}</dd>
    </dl>` : empty('尚未读取到 Docker Engine 信息；当前没有容器清单。');

  const falcoComponent = falco.component || {};
  const falcoCap = falcoComponent.details?.capability || {};
  const falcoIngest = falco.event_ingest || {};
  const falcoState = falcoComponent.error_code === 'disabled' ? 'disabled'
    : !falcoComponent.installed ? 'not_installed' : (falcoCap.state || 'unknown');
  const falcoCapLabel = FALCO_CAPABILITY_LABEL[falcoCap.state] || (falcoState === 'disabled' ? '已禁用' : STATUS_LABEL[falcoState] || falcoState);
  const falcoHealth = falcoState === 'not_installed' ? 'unavailable' : falcoState === 'disabled' ? 'unknown' : (falcoComponent.health_status || 'unknown');
  const capFlag = (value) => value === true ? '是' : value === false ? '否' : '未知';

  $('#content').innerHTML = `
    ${notice}
    <div class="grid-4">
      <div class="stat">
        <div class="label">容器总数</div>
        <div class="value">${Number(summary.total || 0)}</div>
        <div class="sub">运行中 ${Number(summary.running || 0)} · 已停止 ${Number(summary.stopped || 0)}</div>
      </div>
      <div class="stat">
        <div class="label">存在配置风险</div>
        <div class="value">${Number(summary.risky || 0)}</div>
        <div class="sub">严重 ${Number(byRisk.critical || 0)} · 高危 ${Number(byRisk.high || 0)} · 中危 ${Number(byRisk.medium || 0)}</div>
      </div>
      <div class="stat">
        <div class="label">风险发现</div>
        <div class="value">${Number(summary.findings || 0)}</div>
        <div class="sub">检查项命中总数，不代表漏洞数量</div>
      </div>
      <div class="stat">
        <div class="label">未能评估</div>
        <div class="value">${Number(summary.unknown || 0)}</div>
        <div class="sub">缺少详情字段或读取失败的容器</div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <div><h2>容器清单</h2><p>${esc(snapshot.scope_note || '')}</p></div>
        ${isAdmin && monitorState !== 'disabled' ? '<button class="btn primary" id="container-refresh">立即刷新</button>' : ''}
      </div>
      ${(snapshot.containers || []).length ? `
      <div class="table-wrap"><table>
        <thead><tr><th>名称 / ID</th><th>镜像</th><th>状态</th><th>运行时长</th><th>风险</th><th>发现</th><th>操作</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>` : empty(monitorState === 'disabled' ? '容器监控未启用，没有容器清单。' : monitorState === 'initializing' ? '尚未完成首次容器采集。' : '当前没有可展示的容器。')}
      ${snapshot.truncated ? '<p class="hint">容器数量超过配置上限，清单已截断。</p>' : ''}
      ${(snapshot.inspect_errors || []).length ? `<p class="hint">${snapshot.inspect_errors.length} 个容器详情读取失败，风险结论不完整；这些容器在清单中显示为“未能评估”。</p>` : ''}
    </div>

    <div class="grid-3">
      <div class="card">
        <div class="card-head"><h2>Docker 运行时</h2><button class="btn small ghost" data-goto="components">组件详情</button></div>
        ${engineCard}
        <dl class="detail-grid" style="margin-top:12px">
          <dt>监控 API</dt><dd class="mono">${esc(monitorInfo.api_url || '-')}</dd>
          <dt>lsec 本地 Socket</dt><dd class="mono">${esc(dockerDetails.socket || '未检测到')}</dd>
          <dt>本地 Socket 可访问</dt><dd>${capFlag(dockerDetails.socket_accessible)}</dd>
          <dt>说明</dt><dd>${esc(docker?.error_message || '-')}</dd>
        </dl>
      </div>
      <div class="card">
        <div class="card-head"><h2>Falco 运行时安全</h2><button class="btn small ghost" data-goto="components">组件详情</button></div>
        <dl class="detail-grid">
          <dt>安装</dt><dd>${falcoComponent.installed ? '是' : '否'}</dd>
          <dt>版本</dt><dd class="mono">${esc(falcoComponent.version || '-')}</dd>
          <dt>能力状态</dt><dd>${esc(falcoCapLabel)}</dd>
          <dt>健康</dt><dd>${healthBadge(falcoHealth)}</dd>
          <dt>宿主内核</dt><dd class="mono">${esc(falcoCap.kernel_release || '-')}</dd>
          <dt>BTF</dt><dd>${capFlag(falcoCap.btf_available)}</dd>
          <dt>CAP_SYS_ADMIN</dt><dd>${capFlag(falcoCap.cap_sys_admin)}</dd>
          <dt>CAP_BPF / PERFMON</dt><dd>${capFlag(falcoCap.cap_bpf)} / ${capFlag(falcoCap.cap_perfmon)}</dd>
          <dt>运行验证</dt><dd>${falcoCap.running_verified ? '已验证' : '未验证（已安装不等于正在防护）'}</dd>
        </dl>
        <p class="hint" style="margin-top:10px">${esc(falcoCap.reason || falcoComponent.error_message || '没有 Falco 能力信息。')}</p>
        <div class="form-actions"><button class="btn" id="falco-plan">查看安装计划</button></div>
      </div>
      <div class="card">
        <div class="card-head"><h2>Falco 事件接入</h2></div>
        <dl class="detail-grid">
          <dt>接入状态</dt><dd>${falcoIngest.enabled ? '已启用' : '未启用'}</dd>
          <dt>接入端点</dt><dd class="mono">${esc(falcoIngest.endpoint || '/api/v1/integrations/falco')}</dd>
          <dt>独立令牌</dt><dd class="mono">${esc(falcoIngest.token_path || '-')}</dd>
          <dt>已接收事件</dt><dd>${Number(falcoIngest.events_total || 0)}</dd>
          <dt>最近事件</dt><dd>${esc(fmtTime(falcoIngest.last_event_at))}</dd>
        </dl>
        <p class="hint" style="margin-top:10px">该令牌只能写入 Falco 事件，不能读取其他 API；界面不会显示令牌内容。Falco 需要由宿主机管理员安装并确认运行，lsec 不会自动安装或加载驱动。</p>
        <p class="hint">${falco.install_plan_available ? '管理员可查看安装计划。' : ''}</p>
      </div>
    </div>

    <div class="card"><div class="card-head"><h2>能力边界与限制</h2></div>
      <ul class="list-clean">
        ${(snapshot.limitations || []).map((item) => `<li>${esc(item)}</li>`).join('')}
        <li>Containerd 当前只探测二进制与 Socket，不采集容器清单；清单只来自所连接的 Docker 运行时。</li>
        <li>配置检查是启发式规则，不等同于漏洞扫描、镜像扫描或运行时行为检测。</li>
        <li>已安装 Falco 不等于已验证运行；内核不兼容或权限不足会明确显示，不会显示为已保护。</li>
        <li>本客户端不提供容器停止、重启、删除或修改操作；Docker Socket 仍属于高权限组件，代理容器单独隔离。</li>
      </ul>
    </div>`;

  $$('[data-goto]').forEach((button) => { button.onclick = () => navigate(button.dataset.goto); });
  $$('[data-container-open]').forEach((button) => {
    button.onclick = () => showContainerModal(button.dataset.containerOpen);
  });
  const refreshButton = $('#container-refresh');
  if (refreshButton) {
    refreshButton.onclick = async () => {
      refreshButton.disabled = true;
      refreshButton.textContent = '刷新中…';
      try {
        await api('/containers/refresh', { method: 'POST', body: {} });
        toast('容器清单已刷新');
        await renderContainers();
      } catch (err) {
        toast(err.message, true);
        refreshButton.disabled = false;
        refreshButton.textContent = '立即刷新';
      }
    };
  }
  const planButton = $('#falco-plan');
  if (planButton) planButton.onclick = () => showFalcoPlan();
}

async function showContainerModal(containerRef) {
  let item;
  try {
    item = (await api(`/containers/${encodeURIComponent(containerRef)}`)).container;
  } catch (err) {
    toast(err.message, true);
    return;
  }
  const findings = (item.findings || []).map((finding) => `
    <li>
      <div style="display:flex;justify-content:space-between;gap:10px;align-items:flex-start">
        <strong>${esc(finding.title || finding.rule_id || finding.key)}</strong>${severityBadge(finding.severity)}
      </div>
      <div class="mono muted">${esc(finding.key || '')}</div>
      <div>${esc(finding.description || '')}</div>
      ${finding.recommendation ? `<div class="hint">建议：${esc(finding.recommendation)}</div>` : ''}
    </li>`).join('');
  const mounts = (item.mounts || []).map((mount) => `
    <li><span class="mono">${esc(mount.source || '-')}</span> → <span class="mono">${esc(mount.destination || '-')}</span>
      <span class="muted">${mount.read_only ? '只读' : '读写'} · ${esc(mount.type || 'unknown')}</span></li>`).join('');
  const ports = (item.ports || []).map((port) => `
    <li class="mono">${esc(port.container || '-')} → ${esc(`${port.host_ip || ''}:${port.host_port || '*'}`)}</li>`).join('');
  const caps = (item.cap_add || []).length ? item.cap_add.map((cap) => `<span class="badge neutral">${esc(cap)}</span>`).join(' ') : '<span class="muted">未额外添加</span>';
  const securityOpts = (item.security_opt || []).length ? item.security_opt.map(esc).join(', ') : '默认';
  openModal(`容器：${item.name || item.container_id?.slice(0, 12) || '-'}`, `
    ${item.evaluated === false ? `<div class="notice warn"><strong>该容器未能完成配置评估。</strong>${esc(item.evaluation_error || '缺少检查所需的详情字段')}。未知不等于安全。</div>` : ''}
    <dl class="detail-grid">
      <dt>容器 ID</dt><dd class="mono">${esc(item.container_id || '-')}</dd>
      <dt>镜像</dt><dd class="mono">${esc(item.image || '-')}</dd>
      <dt>状态</dt><dd>${esc(item.state || '-')} ${item.status_text ? `<span class="muted">${esc(item.status_text)}</span>` : ''}</dd>
      <dt>风险级别</dt><dd>${riskBadge(item.risk_level)} 共 ${Number(item.risk_count || 0)} 项</dd>
      <dt>创建 / 启动</dt><dd>${esc(fmtTime(item.created_at))} / ${esc(fmtTime(item.started_at))}</dd>
      <dt>PID / 重启 / OOM</dt><dd>${item.pid ?? '-'} / ${item.restart_count ?? '-'} / ${item.oom_killed ? '是' : '否'}</dd>
      <dt>运行用户</dt><dd>${esc(item.user || '-')}${item.user_is_root ? '（容器内 root）' : ''}</dd>
      <dt>特权模式</dt><dd>${item.privileged ? '<strong>是</strong>' : '否'}</dd>
      <dt>网络 / PID / IPC</dt><dd>${esc(item.network_mode || '-')} / ${esc(item.pid_mode || '默认')} / ${esc(item.ipc_mode || '默认')}</dd>
      <dt>User namespace</dt><dd>${esc(item.userns_mode || '默认')}</dd>
      <dt>根文件系统</dt><dd>${item.read_only_rootfs ? '只读' : '可写'}</dd>
      <dt>CapAdd</dt><dd>${caps}</dd>
      <dt>SecurityOpt</dt><dd class="mono">${esc(securityOpts)}</dd>
      <dt>重启策略</dt><dd>${esc(item.restart_policy || '-')}</dd>
    </dl>
    <h3 style="font-size:14px;margin:18px 0 6px">风险发现</h3>
    ${findings ? `<ul class="list-clean">${findings}</ul>` : (item.evaluated === false ? '<p class="hint">未能评估，因此没有风险结论。</p>' : '<p class="hint">未命中危险配置规则。</p>')}
    <h3 style="font-size:14px;margin:18px 0 6px">挂载</h3>
    ${mounts ? `<ul class="list-clean">${mounts}</ul>` : '<p class="hint">没有挂载。</p>'}
    <h3 style="font-size:14px;margin:18px 0 6px">端口映射</h3>
    ${ports ? `<ul class="list-clean">${ports}</ul>` : '<p class="hint">没有公开端口。</p>'}
    <div class="notice" style="margin-top:16px">本页面只展示配置风险，不提供启动、停止、重启或删除操作。</div>
  `, '<button class="btn" id="modal-cancel">关闭</button>', { wide: true });
  $('#modal-cancel').onclick = () => closeModal();
}

async function showFalcoPlan() {
  let plan;
  try {
    plan = (await api('/components/falco/install-plan')).plan || {};
  } catch (err) {
    toast(err.message, true);
    return;
  }
  const steps = (plan.steps || []).map((step, index) => `
    <li><strong>${index + 1}. ${esc(step.title || '')}</strong><div>${esc(step.detail || '')}</div></li>`).join('');
  const notes = (plan.notes || []).map((note) => `<li>${esc(note)}</li>`).join('');
  openModal('Falco 安装计划（只读）', `
    <div class="notice warn"><strong>不能从界面安装。</strong>${esc(plan.risk || '')}</div>
    <ol class="list-clean">${steps}</ol>
    ${notes ? `<h3 style="font-size:14px;margin:18px 0 6px">注意事项</h3><ul class="list-clean">${notes}</ul>` : ''}
    <p class="hint" style="margin-top:14px">安装、启动和驱动加载都需要宿主机管理员单独操作并确认；lsec 不会自动执行这些操作。</p>
  `, '<button class="btn" id="modal-cancel">关闭</button>', { wide: true });
  $('#modal-cancel').onclick = () => closeModal();
}

/* ------------------------------------------------------------------ audit */
function auditCheckRows(checks) {
  return checks.map((check) => `
    <tr>
      <td>${statusBadge(check.status)}</td>
      <td>${check.severity ? severityBadge(check.severity) : '-'}</td>
      <td class="mono">${esc(check.check_id)}</td>
      <td><strong>${esc(check.title)}</strong><div class="muted">${esc(check.detail || '')}</div></td>
      <td class="muted">${esc(check.remediation || '-')}</td>
    </tr>`).join('');
}

async function runHostAudit(button) {
  if (button.disabled) return;
  button.disabled = true;
  const original = button.textContent;
  button.textContent = '体检运行中…';
  try {
    const { audit } = await api('/audits', { method: 'POST', body: {} });
    toast('主机体检任务已创建');
    const terminal = ['succeeded', 'partial', 'failed'];
    let finished = false;
    for (let attempt = 0; attempt < 120; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 1500));
      const payload = await api(`/audits/${audit.audit_id}`);
      if (terminal.includes(payload.audit.status)) {
        toast(payload.audit.status === 'failed' ? '主机体检失败，请查看详情' : '主机体检完成');
        finished = true;
        break;
      }
    }
    await renderAudit();
    if (!finished) toast('体检仍在运行，请稍后在体检历史中查看结果', true);
  } catch (err) {
    toast(err.message, true);
    button.disabled = false;
    button.textContent = original;
  }
}

async function renderAudit() {
  const [{ capabilities }, { audits }, { report }] = await Promise.all([
    api('/capabilities'),
    api('/audits?limit=20'),
    api('/doctor'),
  ]);
  const cap = capabilities.host_audit || {};
  const latest = audits.find((item) => ['succeeded', 'partial', 'failed'].includes(item.status)) || null;
  let detail = null;
  if (latest) {
    try { detail = (await api(`/audits/${latest.audit_id}`)).audit; } catch (err) { detail = null; }
  }
  const summary = detail?.result_summary || {};
  const counts = summary.counts || {};
  const checks = summary.checks || [];
  const findings = checks.filter((check) => check.status === 'finding');
  const errors = checks.filter((check) => check.status === 'error');
  const lynis = summary.lynis || {};
  const systemInfo = summary.system_info || {};

  if (!latest) {
    setPill('尚未运行主机体检', 'warn');
  } else if (latest.status === 'failed') {
    setPill('最近体检失败', 'danger');
  } else if (latest.status === 'partial') {
    setPill('体检部分完成', 'warn');
  } else {
    setPill('主机体检完成', 'ok');
  }

  const isAdmin = state.role === 'admin';
  const runButton = isAdmin
    ? '<button class="btn small" id="audit-run">运行主机体检</button>'
    : '<span class="hint">只读账户不能发起体检</span>';
  const header = latest
    ? `<div class="detail-grid">
        <dt>体检 ID</dt><dd class="mono">${esc(latest.audit_id)}</dd>
        <dt>状态</dt><dd>${statusBadge(latest.status)}</dd>
        <dt>完成时间</dt><dd>${esc(fmtTime(latest.finished_at))}</dd>
        <dt>范围</dt><dd>${latest.scope === 'container' ? '容器可见环境' : '主机环境'}</dd>
        <dt>检查 / 发现 / 未能执行</dt><dd>${latest.checks_total} / ${latest.findings_count} / ${latest.errors_count}</dd>
        <dt>Lynis 加固指数</dt><dd>${latest.hardening_index ?? '-'}</dd>
        <dt>Lynis 版本</dt><dd class="mono">${latest.lynis_available ? esc(latest.lynis_version || '未知') : '不可用'}</dd>
        <dt>证据报告</dt><dd class="mono">${esc(latest.evidence_path || '-')}</dd>
        ${latest.error ? `<dt>错误</dt><dd>${esc(latest.error)}</dd>` : ''}
      </div>`
    : `<div class="empty">还没有主机体检记录。体检只读运行，不会修改系统配置。${cap.reason ? ` ${esc(cap.reason)}` : ''}</div>`;

  const findingsCard = findings.length ? `
    <div class="card">
      <div class="card-head"><h2>风险发现 (${findings.length})</h2><span class="hint">已写入事件 ${counts.events_ingested || 0} / ${findings.length}</span></div>
      <div class="table-wrap"><table>
        <thead><tr><th>状态</th><th>级别</th><th>检查</th><th>结果</th><th>建议</th></tr></thead>
        <tbody>${auditCheckRows(findings)}</tbody>
      </table></div>
    </div>` : '<div class="card"><div class="card-head"><h2>风险发现</h2></div><div class="empty">本次体检没有产生风险发现。</div></div>';

  const errorsCard = errors.length ? `
    <div class="card">
      <div class="card-head"><h2>未能执行的检查 (${errors.length})</h2><span class="hint">这些不是风险结论</span></div>
      <div class="table-wrap"><table>
        <thead><tr><th>状态</th><th>级别</th><th>检查</th><th>结果</th><th>建议</th></tr></thead>
        <tbody>${auditCheckRows(errors)}</tbody>
      </table></div>
    </div>` : '';

  const suggestions = lynis.suggestions || [];
  const suggestionsCard = suggestions.length ? `
    <div class="card">
      <div class="card-head"><h2>Lynis 加固建议 (${suggestions.length})</h2><span class="hint">保存在证据报告中，不逐条生成事件</span></div>
      <ul class="list-clean">
        ${suggestions.slice(0, 12).map((item) => `<li><span class="mono">${esc(item.test_id)}</span> ${esc(item.text)}</li>`).join('')}
      </ul>
      ${suggestions.length > 12 ? `<p class="hint">另有 ${suggestions.length - 12} 条，详见证据报告。</p>` : ''}
    </div>` : '';

  const historyRows = audits.map((item) => `
    <tr>
      <td class="mono">${esc(item.audit_id)}</td>
      <td>${statusBadge(item.status)}</td>
      <td>${item.scope === 'container' ? '容器' : '主机'}</td>
      <td>${item.checks_total}</td>
      <td>${item.findings_count}</td>
      <td>${item.errors_count}</td>
      <td>${item.hardening_index ?? '-'}</td>
      <td class="muted">${esc(fmtTime(item.finished_at || item.created_at))}</td>
    </tr>`).join('');

  const marker = { ok: ['ok', '正常'], warn: ['warn', '警告'], fail: ['danger', '失败'], info: ['neutral', '信息'] };
  const doctorRows = report.checks.map((check) => {
    const [kind, label] = marker[check.status] || ['neutral', check.status];
    return `<tr>
      <td>${badge(kind, label)}</td>
      <td><strong>${esc(check.title)}</strong></td>
      <td>${esc(check.detail)}</td>
      <td class="muted">${esc(check.remediation || '-')}</td>
    </tr>`;
  }).join('');

  $('#content').innerHTML = `
    <div class="notice ${latest && latest.status === 'failed' ? 'danger' : latest ? 'ok' : 'warn'}">
      <strong>主机体检为只读操作。</strong>${esc(summary.scope_note || cap.reason || '')}。检查失败与风险发现分开记录；不会自动修改系统配置。
    </div>

    <div class="card">
      <div class="card-head"><h2>主机安全体检</h2>${runButton}</div>
      ${header}
      ${counts.checks !== undefined ? `<p class="hint" style="margin-top:10px">检查 ${counts.checks} · 通过 ${counts.passed || 0} · 发现 ${counts.findings || 0} · 未能执行 ${counts.errors || 0} · 跳过 ${counts.skipped || 0} · 已生成事件 ${counts.events_ingested || 0}</p>` : ''}
    </div>

    ${findingsCard}
    ${errorsCard}

    ${systemInfo.os ? `
    <div class="card">
      <div class="card-head"><h2>系统信息</h2></div>
      <div class="detail-grid">
        <dt>主机名</dt><dd>${esc(systemInfo.hostname || '-')}</dd>
        <dt>操作系统</dt><dd>${esc(systemInfo.os || '-')}</dd>
        <dt>内核</dt><dd class="mono">${esc(systemInfo.kernel || '-')}</dd>
        <dt>架构</dt><dd>${esc(systemInfo.machine || '-')}</dd>
        <dt>容器环境</dt><dd>${systemInfo.container?.containerized ? `是（${esc(systemInfo.container.runtime || '未知')}）` : '否'}</dd>
        <dt>CPU</dt><dd>${systemInfo.cpu_count ?? '-'}</dd>
        <dt>运行时长</dt><dd>${fmtUptime(systemInfo.uptime_seconds)}</dd>
        <dt>负载</dt><dd class="mono">${(systemInfo.load_average || []).join(' / ') || '-'}</dd>
        <dt>内存</dt><dd>${fmtBytes(systemInfo.memory_total_bytes)} 总量 / ${fmtBytes(systemInfo.memory_available_bytes)} 可用</dd>
      </div>
    </div>` : ''}

    ${suggestionsCard}

    <div class="card">
      <div class="card-head"><h2>体检历史</h2></div>
      <div class="table-wrap"><table>
        <thead><tr><th>体检 ID</th><th>状态</th><th>范围</th><th>检查</th><th>发现</th><th>未能执行</th><th>加固指数</th><th>时间</th></tr></thead>
        <tbody>${historyRows || '<tr><td colspan="8">还没有体检记录</td></tr>'}</tbody>
      </table></div>
    </div>

    <div class="card">
      <div class="card-head"><h2>运行环境自检</h2><button class="btn small ghost" id="doctor-run">重新检查</button></div>
      <div class="table-wrap"><table>
        <thead><tr><th>结果</th><th>检查项</th><th>详情</th><th>建议</th></tr></thead>
        <tbody>${doctorRows}</tbody>
      </table></div>
      <p class="hint" style="margin-top:10px">通过 ${report.summary.ok} · 警告 ${report.summary.warn} · 失败 ${report.summary.fail} · 信息 ${report.summary.info} · 生成时间 ${esc(fmtTime(report.generated_at))}</p>
    </div>

    <div class="card"><div class="card-head"><h2>当前边界</h2></div>
      <ul class="list-clean">
        <li>所有检查只读；不会修改账户、权限、服务、内核参数或防火墙。</li>
        <li>Lynis 警告会生成统一事件；suggestion 仅保存在证据报告中。</li>
        <li>文件完整性、异常登录、Rootkit 实时监控属于后续阶段，当前不提供结论。</li>
      </ul>
    </div>`;
  const run = $('#audit-run');
  if (run) run.onclick = () => runHostAudit(run);
  $('#doctor-run').onclick = async () => { await renderAudit(); toast('自检完成'); };
  $$('[data-goto]').forEach((button) => { button.onclick = () => navigate(button.dataset.goto); });
}

/* --------------------------------------------------------------- settings */
async function renderSettings() {
  const [{ host, daemon }, { components }, { records }] = await Promise.all([
    api('/system/info'),
    api('/components'),
    api('/audit?limit=100'),
  ]);
  setPill('设置与日志', 'info');
  const componentRows = components.map((component) => `
    <li>${esc(component.display_name)}：${component.installed ? '已安装' : '未安装'}，健康 ${esc(STATUS_LABEL[component.health_status] || component.health_status)}，最近检查 ${esc(fmtTime(component.last_check_at))}</li>`).join('');
  const auditRows = records.map((record) => `
    <tr>
      <td class="muted">${esc(fmtTime(record.created_at))}</td>
      <td>${esc(record.action)}</td>
      <td>${esc(record.actor)}</td>
      <td class="mono">${esc(record.target || '-')}</td>
      <td>${record.result === 'success' ? badge('ok', '成功') : badge('danger', '失败')}</td>
      <td class="muted">${esc(record.error || '-')}</td>
    </tr>`).join('');
  $('#content').innerHTML = `
    <div class="grid-3">
      <div class="card"><div class="card-head"><h2>守护进程</h2></div>
        <dl class="detail-grid">
          <dt>版本</dt><dd>${esc(daemon.version)}</dd>
          <dt>API 版本</dt><dd>${esc(daemon.api_version)}</dd>
          <dt>启动时间</dt><dd>${esc(fmtTime(daemon.started_at))}</dd>
          <dt>运行时长</dt><dd>${esc(Math.floor(daemon.uptime_seconds / 60))} 分钟</dd>
          <dt>数据目录</dt><dd class="mono">${esc(daemon.data_dir)}</dd>
          <dt>配置文件</dt><dd class="mono">${esc(daemon.config_path)}${daemon.config_loaded ? '' : '（未找到，使用默认值）'}</dd>
        </dl>
      </div>
      <div class="card" style="grid-column: span 2"><div class="card-head"><h2>主机环境</h2></div>
        <dl class="detail-grid">
          <dt>主机名</dt><dd>${esc(host.hostname)}</dd>
          <dt>系统</dt><dd>${esc(host.os)}</dd>
          <dt>内核</dt><dd class="mono">${esc(host.kernel)}</dd>
          <dt>架构</dt><dd>${esc(host.machine)}</dd>
          <dt>容器</dt><dd>${host.container.containerized ? `是（${esc(host.container.runtime || '未知')}）` : '否'}</dd>
          <dt>权限</dt><dd>UID ${esc(host.uid)}</dd>
        </dl>
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h2>组件检查记录</h2><button class="btn small ghost" data-goto="components">组件管理</button></div>
      <ul class="list-clean">${componentRows || '<li>暂无组件数据</li>'}</ul>
    </div>

    <div class="card">
      <div class="card-head"><h2>操作审计</h2><span class="hint">普通用户不可修改或删除</span></div>
      <div class="table-wrap"><table>
        <thead><tr><th>时间</th><th>操作</th><th>操作者</th><th>目标</th><th>结果</th><th>错误</th></tr></thead>
        <tbody>${auditRows || '<tr><td colspan="6">没有审计记录</td></tr>'}</tbody>
      </table></div>
    </div>

    <div class="card">
      <div class="card-head"><h2>运行日志</h2>${state.role === 'admin' ? '<button class="btn small" id="load-logs">读取最近 200 行</button>' : ''}</div>
      ${state.role === 'admin'
        ? '<div id="log-view" class="pre" style="max-height:320px">点击按钮读取日志（只读，不包含访问令牌）。</div>'
        : '<div class="empty">运行日志仅管理员可读。</div>'}
    </div>`;
  $$('[data-goto]').forEach((button) => { button.onclick = () => navigate(button.dataset.goto); });
  const logsButton = $('#load-logs');
  if (logsButton) {
    logsButton.onclick = async () => {
      try {
        const { lines } = await api('/logs?lines=200');
        $('#log-view').textContent = lines.length ? lines.join('\n') : '日志为空';
      } catch (err) { toast(err.message, true); }
    };
  }
}

/* --------------------------------------------------------------- renderers */
const RENDERERS = {
  dashboard: renderDashboard,
  scan: renderScan,
  yara: renderYara,
  events: renderEvents,
  quarantine: renderQuarantine,
  components: renderComponents,
  policy: renderPolicy,
  host: renderHost,
  containers: renderContainers,
  audit: renderAudit,
  settings: renderSettings,
};

/* ------------------------------------------------------------------- boot */
async function boot() {
  $('#login-form').addEventListener('submit', doLogin);
  $('#logout').addEventListener('click', doLogout);
  $('#modal-close').addEventListener('click', () => closeModal(false));
  $('#modal').addEventListener('click', (event) => { if (event.target === $('#modal')) closeModal(false); });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !$('#modal').classList.contains('hidden')) closeModal(false);
  });
  $$('.nav-item').forEach((button) => {
    button.addEventListener('click', () => navigate(button.dataset.page));
  });
  window.addEventListener('hashchange', () => {
    const page = location.hash.replace('#', '') || 'dashboard';
    if (page !== state.page) navigate(page);
  });

  if (!state.csrf) {
    showLogin();
    return;
  }
  state.role = sessionStorage.getItem('lsec_role') || null;
  try {
    await api('/status');
    showApp();
    navigate(location.hash.replace('#', '') || 'dashboard');
  } catch (err) {
    if (err.status !== 401) showLogin(err.message);
  }
}

document.addEventListener('DOMContentLoaded', boot);
