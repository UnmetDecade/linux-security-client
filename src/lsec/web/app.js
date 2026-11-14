'use strict';

/* lsec Web UI - no frameworks, no external requests. All data comes from the
   local daemon API; nothing is mocked or fabricated. */

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const SEVERITY_LABEL = {
  critical: t('severity.critical'), high: t('severity.high'), medium: t('severity.medium'),
  low: t('severity.low'), info: t('severity.info'),
};
const STATUS_LABEL = {
  queued: t('status.queued'), cancel_requested: t('status.cancel_requested'), cancelled: t('status.cancelled'),
  succeeded: t('status.succeeded'), failed: t('status.failed'), partial: t('status.partial'),
  new: t('status.new'), acknowledged: t('status.acknowledged'), investigating: t('status.investigating'), resolved: t('status.resolved'), ignored: t('status.ignored'),
  quarantined: t('status.quarantined'), restored: t('status.restored'), deleted: t('status.deleted'), missing: t('status.missing'),
  ok: t('status.ok'), degraded: t('status.degraded'), unavailable: t('status.unavailable'), unknown: t('status.unknown'), incompatible: t('status.incompatible'),
  available: t('status.available'),
  check_failed: t('status.check_failed'), permission_denied: t('status.permission_denied'),
  not_installed: t('status.not_installed'), stopped: t('status.stopped'), running: t('status.running'),
  pass: t('status.pass'), finding: t('status.finding'), error: t('status.error'), skipped: t('status.skipped'),
  current: t('status.current'), stale: t('status.stale'), not_run: t('status.not_run'), ready: t('status.ready'),
  monitored: t('status.monitored'), disabled: t('status.disabled'), initializing: t('status.initializing'),
  compatible: t('status.compatible'), unsupported: t('status.unsupported'), requires_privileges: t('status.requires_privileges'),
  requires_setup: t('status.requires_setup'),
};
const RISK_LABEL = {
  critical: t('risk.critical'), high: t('risk.high'), medium: t('risk.medium'),
  low: t('risk.low'), none: t('risk.none'), unknown: t('risk.unknown'),
};
const FALCO_CAPABILITY_LABEL = {
  compatible: t('falco.compatible'), unsupported: t('falco.unsupported'),
  requires_privileges: t('falco.requires_privileges'), requires_setup: t('falco.requires_setup'), unknown: t('falco.unknown'),
};
const PAGE_META = {
  dashboard: [t('page.dashboard.title'), t('page.dashboard.sub')],
  scan: [t('page.scan.title'), t('page.scan.sub')],
  yara: [t('page.yara.title'), t('page.yara.sub')],
  host: [t('page.host.title'), t('page.host.sub')],
  containers: [t('page.containers.title'), t('page.containers.sub')],
  audit: [t('page.audit.title'), t('page.audit.sub')],
  events: [t('page.events.title'), t('page.events.sub')],
  quarantine: [t('page.quarantine.title'), t('page.quarantine.sub')],
  components: [t('page.components.title'), t('page.components.sub')],
  policy: [t('page.policy.title'), t('page.policy.sub')],
  settings: [t('page.settings.title'), t('page.settings.sub')],
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
/* Escape HTML for output. In Chinese mode known server-emitted strings are
   rendered in Chinese first; unknown text passes through unchanged. */
function esc(value) {
  const text = tServerText(value);
  return String(text === null || text === undefined ? '' : text)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function fmtTime(value) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return esc(value);
  return date.toLocaleString(LANG === 'zh' ? 'zh-CN' : 'en-US', { hour12: false });
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
  node.textContent = tServerText(message);
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
  return badge(kind, RISK_LABEL[risk] || risk || t('common.unknown'));
}
function fmtUptime(seconds) {
  const n = Number(seconds);
  if (!Number.isFinite(n)) return '-';
  const hours = Math.floor(n / 3600);
  if (hours < 1) return t('time.minutes', { n: Math.floor(n / 60) });
  if (hours < 48) return t('time.hours', { n: hours });
  return t('time.daysHours', { days: Math.floor(hours / 24), hours: hours % 24 });
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
    throw new ApiError(t('error.network'), 'network_error', 0);
  }
  clearTimeout(timer);
  let payload = null;
  try { payload = await response.json(); } catch (err) { payload = null; }
  if (response.status === 401 && path !== '/auth/login') {
    showLogin(t('auth.sessionExpired'));
    throw new ApiError(payload?.error?.message || t('auth.notSignedIn'), 'unauthorized', 401);
  }
  if (!response.ok || !payload || payload.ok === false) {
    const error = payload?.error || {};
    throw new ApiError(error.message || t('error.requestFailed', { status: response.status }), error.code, response.status, error.details);
  }
  return payload;
}

/* ----------------------------------------------------------------- modal */
function openModal(title, bodyHtml, footerHtml = '', options = {}) {
  $('#modal-title').textContent = tServerText(title);
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
      `<button class="btn" id="modal-cancel">${esc(t('common.cancel'))}</button>
       <button class="btn ${options.danger ? 'danger' : 'primary'}" id="modal-ok">${esc(options.confirmText || t('common.confirm'))}</button>`,
      { onClose: (result) => resolve(result === true) }
    );
    $('#modal-cancel').onclick = () => closeModal(false);
    $('#modal-ok').onclick = () => closeModal(true);
  });
}

function renderError(error) {
  $('#content').innerHTML = `<div class="notice danger">${esc(t('error.loadFailed', { message: error.message }))}</div>`;
  setPill(t('pill.dataUnavailable'), 'danger');
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
    error.textContent = tServerText(message);
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
  $('#role-badge').textContent = role === 'admin' ? t('role.admin') : t('role.readonly');
  document.body.dataset.role = role;
}

async function doLogin(event) {
  event.preventDefault();
  const button = $('#login-form button[type=submit]');
  const errorNode = $('#login-error');
  const token = $('#token').value.trim();
  if (!token) return;
  button.disabled = true;
  button.textContent = t('auth.signingIn');
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
    errorNode.textContent = tServerText(err.message);
    errorNode.classList.remove('hidden');
  } finally {
    button.disabled = false;
    button.textContent = t('auth.signIn');
  }
}

async function doLogout() {
  try { await api('/auth/logout', { method: 'POST', body: {} }); } catch (err) { /* ignore */ }
  showLogin(t('auth.signedOut'));
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
  $('#content').innerHTML = `<div class="empty">${esc(t('common.loading'))}</div>`;
  setPill(t('common.loading'), 'neutral');
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
  setPill(tServerLabel(status.overall_label), overallKind(status.overall));
  const p = status.protection;
  const realtimeText = p.real_time.state === 'active' ? t('realtime.enabled') : p.real_time.state === 'unsupported' ? t('realtime.unsupported') : t('realtime.disabled');
  const dbText = { current: t('db.current'), outdated: t('db.outdated'), missing: t('db.missing'), unknown: t('db.unknown') }[p.virus_database.state] || p.virus_database.state;
  const dbSub = p.virus_database.updated_at ? t('dashboard.virusDbUpdated', { time: fmtTime(p.virus_database.updated_at) }) : p.virus_database.age_hours !== null ? t('dashboard.virusDbAbout', { hours: p.virus_database.age_hours }) : t('dashboard.virusDbNone');
  const onDemandText = { ready: t('status.available'), degraded: t('status.degraded'), stopped: t('status.stopped'), unavailable: t('status.unavailable') }[p.on_demand.state] || p.on_demand.state;
  const last = status.last_scan;
  const highOpen = (status.events.high || 0) + (status.events.critical || 0);
  const isAdmin = state.role === 'admin';

  const reasons = (status.reasons || []).map((reason) => `<li>${esc(reason)}</li>`).join('');
  const componentRows = (status.components.items || []).map((component) => `
    <tr>
      <td><strong>${esc(component.display_name)}</strong><div class="mono">${esc(component.component_id)}</div></td>
      <td>${component.installed ? t('status.installed') : t('status.not_installed')}</td>
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
          <h2>${esc(tServerLabel(status.overall_label))}</h2>
          <p>${esc(status.summary)}</p>
        </div>
        <div class="row-actions">
          ${isAdmin ? `<button class="btn primary" id="dash-quick-scan">${esc(t('dashboard.quickScan'))}</button>` : ''}
          <button class="btn" data-goto="scan">${esc(t('dashboard.goScan'))}</button>
        </div>
      </div>
      ${reasons ? `<div class="hero-reasons"><strong>${esc(t('dashboard.attention'))}</strong><ul>${reasons}</ul></div>` : ''}
    </section>

    <div class="grid-4">
      <div class="stat">
        <div class="label">${esc(t('dashboard.realtime'))}</div>
        <div class="value">${esc(realtimeText)}</div>
        <div class="sub">${esc(p.real_time.reason || '')}</div>
      </div>
      <div class="stat">
        <div class="label">${esc(t('dashboard.virusDb'))}</div>
        <div class="value">${esc(dbText)}</div>
        <div class="sub">${esc(dbSub)}</div>
      </div>
      <div class="stat">
        <div class="label">${esc(t('dashboard.onDemand'))}</div>
        <div class="value">${esc(onDemandText)}</div>
        <div class="sub">${esc(p.on_demand.reason)}</div>
      </div>
      <div class="stat">
        <div class="label">${esc(t('dashboard.highOpen'))}</div>
        <div class="value">${highOpen}</div>
        <div class="sub">${esc(t('dashboard.totalOpen', { n: status.events.total_open }))}</div>
      </div>
    </div>

    <div class="grid-3">
      <div class="card">
        <div class="card-head"><h2>${esc(t('dashboard.recentScans'))}</h2><button class="btn small ghost" data-goto="scan">${esc(t('dashboard.view'))}</button></div>
        ${last ? `
          <div class="detail-grid">
            <dt>${esc(t('dashboard.taskType'))}</dt><dd>${esc(last.task_type)}</dd>
            <dt>${esc(t('table.status'))}</dt><dd>${statusBadge(last.status)}</dd>
            <dt>${esc(t('dashboard.finished'))}</dt><dd>${esc(fmtTime(last.finished_at))}</dd>
            <dt>${esc(t('dashboard.filesScanned'))}</dt><dd>${last.files_scanned}</dd>
            <dt>${esc(t('dashboard.detectionsErrors'))}</dt><dd>${last.detections_count} / ${last.errors_count}</dd>
          </div>` : `<div class="empty">${esc(t('dashboard.noScans'))}</div>`}
      </div>
      <div class="card">
        <div class="card-head"><h2>${esc(t('dashboard.hostContainers'))}</h2><button class="btn small ghost" data-goto="host">${esc(t('dashboard.hostDetails'))}</button></div>
        <div class="detail-grid">
          <dt>${esc(t('dashboard.hostBaseline'))}</dt><dd>${statusBadge(status.host_baseline.state)} ${esc(status.host_baseline.note)}</dd>
          <dt>${esc(t('dashboard.containerMonitoring'))}</dt><dd>${statusBadge(status.containers.state)} ${esc(status.containers.note)}</dd>
          <dt>${esc(t('dashboard.containerRisk'))}</dt><dd>${esc(t('dashboard.containerRiskValue', { risky: Number(status.containers.risky || 0), findings: Number(status.containers.findings || 0) }))}</dd>
          <dt>${esc(t('dashboard.yaraRules'))}</dt><dd>${statusBadge(status.yara.state)} ${esc(status.yara.note)}</dd>
        </div>
        <div class="form-actions"><button class="btn small" data-goto="containers">${esc(t('dashboard.containersBtn'))}</button><button class="btn small" data-goto="yara">${esc(t('dashboard.yaraBtn'))}</button></div>
        <p class="hint" style="margin-top:6px">${esc(t('dashboard.capabilityNote'))}</p>
      </div>
      <div class="card">
        <div class="card-head"><h2>${esc(t('dashboard.quarantine'))}</h2><button class="btn small ghost" data-goto="quarantine">${esc(t('dashboard.open'))}</button></div>
        <div class="detail-grid">
          <dt>${esc(t('dashboard.handlingMode'))}</dt><dd>${esc(status.quarantine.mode)}</dd>
          <dt>${esc(t('dashboard.autoQuarantine'))}</dt><dd>${status.quarantine.auto_quarantine_enabled ? t('common.enabled') : t('common.disabled')}</dd>
        </div>
        <p class="hint" style="margin-top:12px">${esc(t('dashboard.quarantineNote'))}</p>
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h2>${esc(t('dashboard.componentStatus'))}</h2><button class="btn small ghost" data-goto="components">${esc(t('common.components'))}</button></div>
      <div class="table-wrap"><table>
        <thead><tr><th>${esc(t('table.component'))}</th><th>${esc(t('table.installed'))}</th><th>${esc(t('table.health'))}</th><th>${esc(t('table.version'))}</th><th>${esc(t('table.description'))}</th></tr></thead>
        <tbody>${componentRows || `<tr><td colspan="5">${esc(t('dashboard.noComponentData'))}</td></tr>`}</tbody>
      </table></div>
    </div>

    <div class="card">
      <div class="card-head"><h2>${esc(t('dashboard.recentEvents'))}</h2><button class="btn small ghost" data-goto="events">${esc(t('dashboard.eventsBtn'))}</button></div>
      <div class="table-wrap"><table>
        <thead><tr><th>${esc(t('table.severity'))}</th><th>${esc(t('table.status'))}</th><th>${esc(t('table.title'))}</th><th>${esc(t('table.lastSeen'))}</th></tr></thead>
        <tbody>${eventRows || `<tr><td colspan="4">${esc(t('dashboard.noEvents'))}</td></tr>`}</tbody>
      </table></div>
    </div>`;

  $$('[data-goto]').forEach((button) => { button.onclick = () => navigate(button.dataset.goto); });
  $$('[data-event-id]').forEach((row) => {
    row.onclick = () => showEventModal(row.dataset.eventId);
  });
  const quick = $('#dash-quick-scan');
  if (quick) {
    quick.onclick = async () => {
      const ok = await confirmDialog(t('dashboard.startQuickTitle'), `<p>${esc(t('dashboard.startQuickBody'))}</p>`, { confirmText: t('dashboard.startScan') });
      if (!ok) return;
      try {
        await api('/scans', { method: 'POST', body: { type: 'quick', engines: ['clamav'] } });
        toast(t('dashboard.scanCreated'));
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
  setPill(ready ? t('yara.pillReady') : t('yara.pillNotReady'), ready ? 'ok' : 'warn');

  const versionRows = [];
  packs.forEach((pack) => {
    pack.versions.forEach((version) => {
      versionRows.push(`
        <tr>
          <td class="mono">${esc(pack.pack_id)}</td>
          <td>${esc(version.name || '-')}</td>
          <td class="mono">${esc(version.version)}</td>
          <td>${Number(version.rules_count || 0)}</td>
          <td>${version.signature_verified ? badge('ok', t('yara.verified')) : badge('warn', t('yara.unverified'))}</td>
          <td>${version.active ? badge('ok', t('yara.active')) : badge('neutral', t('yara.inactive'))}</td>
          <td class="muted">${esc(fmtTime(version.installed_at))}</td>
          <td>
            <div class="row-actions">
              ${isAdmin && !version.active ? `<button class="btn small" data-yara-activate="${esc(pack.pack_id)}" data-version="${esc(version.version)}">${esc(t('yara.activate'))}</button>` : ''}
              ${isAdmin && !version.active ? `<button class="btn small danger" data-yara-delete="${esc(pack.pack_id)}" data-version="${esc(version.version)}">${esc(t('common.delete'))}</button>` : ''}
            </div>
          </td>
        </tr>`);
    });
  });

  $('#content').innerHTML = `
    <div class="card">
      <div class="card-head">
        <div><h2>${esc(t('yara.statusTitle'))}</h2><p>${esc(t('yara.statusBody'))}</p></div>
        <button class="btn small" id="yara-refresh">${esc(t('common.refresh'))}</button>
      </div>
      <div class="notice ${ready ? 'info' : 'warn'}">
        ${ready
          ? esc(t('yara.activatedSummary', { n: Number(rules.active_count || 0) }))
          : esc(component.error_message || t('yara.notReadyBody'))}
      </div>
      <div class="detail-grid">
        <dt>${esc(t('common.installHealth'))}</dt><dd>${component.installed ? t('status.installed') : t('status.not_installed')} · ${statusBadge(component.health_status || 'unknown')}</dd>
        <dt>${esc(t('table.version'))}</dt><dd class="mono">${esc(component.version || '-')}</dd>
        <dt>${esc(t('yara.scanReady'))}</dt><dd>${ready ? badge('ok', t('common.yes')) : badge('warn', t('common.no'))}</dd>
        <dt>${esc(t('yara.rulePacksActivated'))}</dt><dd>${Number(rules.packs_count || 0)} / ${Number(rules.active_count || 0)}</dd>
        <dt>${esc(t('yara.signatureEnforcement'))}</dt><dd>${signature.required ? t('common.yes') : t('common.no')}</dd>
        <dt>${esc(t('yara.trustedKey'))}</dt><dd>${signature.public_key_present ? badge('ok', t('common.configured')) : badge('warn', t('common.missing'))} <span class="mono">${esc(signature.public_key || '-')}</span></dd>
        <dt>${esc(t('yara.rulesRoot'))}</dt><dd class="mono">${esc(rules.rules_dir || '-')}</dd>
        <dt>${esc(t('yara.inbox'))}</dt><dd class="mono">${esc(inbox || rules.inbox_dir || '-')}</dd>
      </div>
      ${rules.state_error ? `<div class="notice danger">${esc(t('yara.failedState', { error: rules.state_error }))}</div>` : ''}
      <p class="hint" style="margin-top:12px">${esc(t('yara.neverDownloadNote'))}</p>
    </div>

    ${isAdmin ? `
    <div class="card">
      <div class="card-head"><h2>${esc(t('yara.installTitle'))}</h2><p>${esc(t('yara.installBody'))}</p></div>
      <div class="form-grid">
        <div class="form-row full">
          <label class="f-label" for="yara-pack-path">${esc(t('yara.pathLabel'))}</label>
          <input type="text" id="yara-pack-path" placeholder="${esc(inbox || '/data/yara/inbox')}/my-rules-1.0.0.zip">
        </div>
        <div class="form-row">
          <label class="checkline"><input type="checkbox" id="yara-activate" checked> ${esc(t('yara.activateImmediately'))}</label>
        </div>
      </div>
      <div class="form-actions"><button class="btn primary" id="yara-install">${esc(t('yara.verifyInstall'))}</button></div>
    </div>` : `<div class="notice info">${esc(t('yara.readonlyNote'))}</div>`}

    <div class="card">
      <div class="card-head"><h2>${esc(t('yara.versionsTitle'))}</h2><span class="hint">${esc(t('yara.versionsHint'))}</span></div>
      <div class="table-wrap"><table>
        <thead><tr><th>${esc(t('yara.table.pack'))}</th><th>${esc(t('yara.table.name'))}</th><th>${esc(t('table.version'))}</th><th>${esc(t('yara.table.rules'))}</th><th>${esc(t('yara.table.signature'))}</th><th>${esc(t('table.status'))}</th><th>${esc(t('yara.table.installedAt'))}</th><th></th></tr></thead>
        <tbody>${versionRows.join('') || `<tr><td colspan="8">${esc(t('yara.noPacks'))}</td></tr>`}</tbody>
      </table></div>
    </div>`;

  $('#yara-refresh').onclick = () => renderYara().catch((err) => toast(err.message, true));

  $$('[data-yara-activate]').forEach((button) => {
    button.onclick = async () => {
      const packId = button.dataset.yaraActivate;
      const version = button.dataset.version;
      const ok = await confirmDialog(
        t('yara.activateTitle'),
        `<p>${t('yara.activateBody', { pack: esc(packId), version: esc(version) })}</p>`,
        { confirmText: t('yara.activate') },
      );
      if (!ok) return;
      try {
        await api(`/yara/packs/${encodeURIComponent(packId)}/${encodeURIComponent(version)}/activate`, {
          method: 'POST', body: { confirm: true },
        });
        toast(t('yara.activatedToast'));
        await renderYara();
      } catch (err) { toast(err.message, true); }
    };
  });

  $$('[data-yara-delete]').forEach((button) => {
    button.onclick = async () => {
      const packId = button.dataset.yaraDelete;
      const version = button.dataset.version;
      const ok = await confirmDialog(
        t('yara.deleteTitle'),
        `<p>${t('yara.deleteBody', { pack: esc(packId), version: esc(version) })}</p>`,
        { confirmText: t('common.delete'), danger: true },
      );
      if (!ok) return;
      try {
        await api(`/yara/packs/${encodeURIComponent(packId)}/${encodeURIComponent(version)}`, {
          method: 'DELETE', body: { confirm: true },
        });
        toast(t('yara.deletedToast'));
        await renderYara();
      } catch (err) { toast(err.message, true); }
    };
  });

  const install = $('#yara-install');
  if (install) {
    install.onclick = async () => {
      const path = $('#yara-pack-path').value.trim();
      if (!path) { toast(t('yara.enterPath'), true); return; }
      const activate = $('#yara-activate').checked;
      const ok = await confirmDialog(
        t('yara.installTitleConfirm'),
        `<p>${t('yara.installBodyConfirm', { path: esc(path) })}</p><p>${esc(activate ? t('yara.installWillActivate') : t('yara.installWillNotActivate'))}</p>`,
        { confirmText: t('yara.verifyInstall') },
      );
      if (!ok) return;
      install.disabled = true;
      try {
        const payload = await api('/yara/packs', {
          method: 'POST',
          body: { path, activate, confirm: true },
          timeout: 300000,
        });
        toast(t('yara.installedToast', { pack: payload.pack.pack_id, version: payload.pack.version }));
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
  setPill(anyReady ? t('scan.pillAvailable') : t('scan.pillUnavailable'), anyReady ? 'ok' : 'danger');
  const engineLine = (id, info, ready) => `
    <label class="checkline">
      <input type="checkbox" class="scan-engine" value="${id}" ${selected(id, ready) && ready ? 'checked' : ''} ${ready ? '' : 'disabled'}>
      ${ENGINE_LABEL[id]} ${statusBadge(info.state)}
      <span class="hint">${esc(info.reason || '')}</span>
    </label>`;

  $('#content').innerHTML = `
    <div class="card">
      <div class="card-head">
        <div><h2>${esc(t('scan.newTask'))}</h2><p>${esc(t('scan.newTaskBody'))}</p></div>
      </div>
      ${!anyReady ? `<div class="notice warn">${esc(t('scan.noEngine', { reason: scanCap.reason || yara.reason || '' }))}</div>` : ''}
      ${!yaraReady ? `<div class="notice info">${esc(t('scan.yaraUnavailable', { reason: yara.reason || '' }))}</div>` : ''}
      <div class="form-grid">
        <div class="form-row full">
          <label class="f-label">${esc(t('scan.typeLabel'))}</label>
          <div class="seg" id="scan-type">
            <button type="button" data-type="quick" class="${scanForm.type === 'quick' ? 'active' : ''}">${esc(t('scan.type.quick'))}</button>
            <button type="button" data-type="full" class="${scanForm.type === 'full' ? 'active' : ''}">${esc(t('scan.type.full'))}</button>
            <button type="button" data-type="custom" class="${scanForm.type === 'custom' ? 'active' : ''}">${esc(t('scan.type.custom'))}</button>
          </div>
        </div>
        <div class="form-row full ${scanForm.type === 'custom' ? '' : 'hidden'}" id="custom-paths">
          <label class="f-label" for="scan-paths">${esc(t('scan.pathsLabel'))}</label>
          <textarea id="scan-paths" placeholder="/scan/downloads&#10;/scan/home/user"></textarea>
        </div>
        <div class="form-row full">
          <label class="f-label">${esc(t('scan.enginesLabel'))}</label>
          ${engineLine('clamav', clamav, clamavReady)}
          ${engineLine('yara', yara, yaraReady)}
        </div>
        <div class="form-row">
          <label class="f-label">${esc(t('scan.descriptionLabel'))}</label>
          <p class="hint">${t('scan.descriptionHint')}</p>
        </div>
      </div>
      <div class="form-actions">
        <button class="btn primary" id="scan-start" ${!isAdmin || !anyReady ? 'disabled' : ''}>${esc(t('scan.start'))}</button>
        ${!isAdmin ? `<span class="hint">${esc(t('scan.readonlyNote'))}</span>` : ''}
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h2>${esc(t('scan.tasksTitle'))}</h2><span class="hint" id="scan-refresh-hint">${esc(t('scan.refreshHint'))}</span></div>
      <div id="scan-tasks">${empty(t('common.loading'))}</div>
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
      if (!chosen.length) { toast(t('scan.selectEngine'), true); return; }
      const body = { type: scanForm.type, engines: chosen };
      if (scanForm.type === 'custom') {
        const paths = $('#scan-paths').value.split('\n').map((line) => line.trim()).filter(Boolean);
        if (!paths.length) { toast(t('scan.enterPath'), true); return; }
        body.paths = paths;
      }
      const label = { quick: t('scan.type.quick'), full: t('scan.type.full'), custom: t('scan.type.customScan') }[body.type];
      const ok = await confirmDialog(t('scan.confirmStartTitle', { type: label }), `<p>${esc(t('scan.confirmStartBody', { engines: chosen.map((id) => ENGINE_LABEL[id]).join(' + ') }))}</p>`, { confirmText: t('scan.startBtn') });
      if (!ok) return;
      try {
        await api('/scans', { method: 'POST', body });
        toast(t('scan.created'));
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
      <td>${task.progress === null || task.progress === undefined ? `<span class="muted">${esc(t('common.unknown'))}</span>` : `${Number(task.progress).toFixed(1)}%`}</td>
      <td>${task.files_scanned}</td>
      <td>${task.detections_count}</td>
      <td>${task.errors_count}</td>
      <td class="muted">${esc(fmtTime(task.created_at))}</td>
      <td><div class="row-actions">
        <button class="btn small" data-task-show="${esc(task.task_id)}">${esc(t('common.details'))}</button>
        ${state.role === 'admin' && ['queued', 'running', 'cancel_requested'].includes(task.status)
          ? `<button class="btn small danger" data-task-cancel="${esc(task.task_id)}">${esc(t('scan.cancel'))}</button>` : ''}
      </div></td>
    </tr>`).join('');
  const target = $('#scan-tasks');
  if (!target) return;
  target.innerHTML = `${activeHtml}
    <div class="table-wrap"><table>
      <thead><tr><th>${esc(t('table.task'))}</th><th>${esc(t('table.type'))}</th><th>${esc(t('table.status'))}</th><th>${esc(t('table.progress'))}</th><th>${esc(t('table.files'))}</th><th>${esc(t('table.detections'))}</th><th>${esc(t('table.error'))}</th><th>${esc(t('table.created'))}</th><th></th></tr></thead>
      <tbody>${rows || `<tr><td colspan="9">${esc(t('scan.noTasks'))}</td></tr>`}</tbody>
    </table></div>`;
  $$('[data-task-show]').forEach((button) => { button.onclick = () => showTaskModal(button.dataset.taskShow); });
  $$('[data-task-cancel]').forEach((button) => {
    button.onclick = async () => {
      const ok = await confirmDialog(t('scan.cancelTitle'), `<p>${esc(t('scan.cancelBody'))}</p>`, { confirmText: t('scan.cancelTask'), danger: true });
      if (!ok) return;
      try { await api(`/scans/${button.dataset.taskCancel}/cancel`, { method: 'POST', body: {} }); toast(t('scan.cancelSent')); await refreshScanTasks(); }
      catch (err) { toast(err.message, true); }
    };
  });
}

function renderActiveTask(task) {
  const progress = task.progress;
  const progressText = progress === null ? t('scan.progressUnknown') : `${progress.toFixed(1)}%`;
  return `
    <div style="margin-bottom:16px">
      <div class="progress-track"><div class="progress-fill" style="width:${progress === null ? 0 : Math.min(100, progress)}%"></div></div>
      <div class="progress-label">
        <span>${esc(t('scan.progressSummary', { progress: progressText, files: task.files_scanned, detections: task.detections_count, errors: task.errors_count }))}</span>
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
      <td>${state.role === 'admin' ? `<button class="btn small danger" data-quarantine="${esc(detection.path)}" data-event="${esc(detection.event_id)}" data-name="${esc(detection.detection_name)}">${esc(t('common.quarantine'))}</button>` : ''}</td>
    </tr>`).join('');
  const errorRows = errors.slice(0, 20).map((error) => `
    <li><span class="mono">${esc(error.path || '')}</span> ${esc(error.error || '')}</li>`).join('');
  openModal(t('scan.modalTitle', { id: task.task_id.slice(0, 8) }), `
    <dl class="detail-grid">
      <dt>${esc(t('scan.taskId'))}</dt><dd class="mono">${esc(task.task_id)}</dd>
      <dt>${esc(t('scan.typeEngines'))}</dt><dd>${esc(task.task_type)} / ${esc((task.selected_engines || []).join(', '))}</dd>
      <dt>${esc(t('table.status'))}</dt><dd>${statusBadge(task.status)}</dd>
      <dt>${esc(t('scan.target'))}</dt><dd class="mono">${esc((task.target_paths || []).join(', '))}</dd>
      <dt>${esc(t('scan.createdStartedFinished'))}</dt><dd>${esc(fmtTime(task.created_at))} / ${esc(fmtTime(task.started_at))} / ${esc(fmtTime(task.finished_at))}</dd>
      <dt>${esc(t('scan.filesDetectionsErrors'))}</dt><dd>${task.files_scanned} / ${task.detections_count} / ${task.errors_count}</dd>
      <dt>${esc(t('scan.evidenceReport'))}</dt><dd class="mono">${esc(summary.evidence_path || '-')}</dd>
    </dl>
    <h3 style="font-size:14px;margin:20px 0 8px">${esc(t('scan.detectionsHeading'))}</h3>
    ${detectionRows ? `<div class="table-wrap"><table><thead><tr><th>${esc(t('table.path'))}</th><th>${esc(t('table.detection'))}</th><th>${esc(t('table.severity'))}</th><th></th></tr></thead><tbody>${detectionRows}</tbody></table></div>` : `<div class="empty">${esc(t('scan.noMalware'))}</div>`}
    <h3 style="font-size:14px;margin:20px 0 8px">${esc(t('scan.errorsHeading'))}</h3>
    ${errorRows ? `<ul class="list-clean">${errorRows}</ul>` : `<p class="muted">${esc(t('scan.noErrors'))}</p>`}
  `, `<button class="btn" id="modal-cancel">${esc(t('common.close'))}</button>`, { wide: true });
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
  setPill(t('events.pill'), 'info');
  $('#content').innerHTML = `
    <div class="card">
      <div class="card-head"><h2>${esc(t('events.list'))}</h2><div class="row-actions">
        <button class="btn small" id="events-refresh">${esc(t('common.refresh'))}</button>
        <button class="btn small" id="export-json">${esc(t('events.exportJson'))}</button>
        <button class="btn small" id="export-csv">${esc(t('events.exportCsv'))}</button>
      </div></div>
      <div class="filters">
        <div class="form-row"><label class="f-label">${esc(t('events.severityLabel'))}</label>
          <select id="f-severity"><option value="">${esc(t('common.all'))}</option>${Object.entries(SEVERITY_LABEL).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}</select>
        </div>
        <div class="form-row"><label class="f-label">${esc(t('events.statusLabel'))}</label>
          <select id="f-status"><option value="">${esc(t('common.all'))}</option>
            <option value="new">${esc(t('status.new'))}</option><option value="acknowledged">${esc(t('status.acknowledged'))}</option>
            <option value="investigating">${esc(t('status.investigating'))}</option><option value="resolved">${esc(t('status.resolved'))}</option><option value="ignored">${esc(t('status.ignored'))}</option>
          </select>
        </div>
        <div class="form-row"><label class="f-label">${esc(t('events.sourceLabel'))}</label>
          <select id="f-source"><option value="">${esc(t('common.all'))}</option>
            <option value="clamav">ClamAV</option><option value="falco">Falco</option><option value="wazuh">Wazuh</option>
            <option value="yara">YARA</option><option value="lynis">Lynis</option><option value="docker">${esc(t('events.source.docker'))}</option>
            <option value="system">${esc(t('events.source.system'))}</option>
          </select>
        </div>
        <div class="form-row"><label class="f-label">${esc(t('events.categoryLabel'))}</label>
          <select id="f-category"><option value="">${esc(t('common.all'))}</option>
            <option value="malware">${esc(t('events.category.malware'))}</option><option value="intrusion">${esc(t('events.category.intrusion'))}</option><option value="runtime">${esc(t('events.category.runtime'))}</option>
            <option value="integrity">${esc(t('events.category.integrity'))}</option><option value="vulnerability">${esc(t('events.category.vulnerability'))}</option><option value="configuration">${esc(t('events.category.configuration'))}</option>
          </select>
        </div>
        <div class="form-row grow"><label class="f-label">${esc(t('events.searchLabel'))}</label>
          <input type="text" id="f-q" placeholder="${esc(t('events.searchPlaceholder'))}">
        </div>
        <button class="btn primary" id="f-apply">${esc(t('events.filter'))}</button>
      </div>
      <div id="events-table">${empty(t('common.loading'))}</div>
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
        ? `<button class="btn small danger" data-quarantine="${esc(target.path)}" data-event="${esc(event.event_id)}" data-name="${esc((event.evidence || {}).detection_name || '')}">${esc(t('common.quarantine'))}</button>` : ''}</td>
    </tr>`;
  }).join('');
  $('#events-table').innerHTML = `
    <div class="table-wrap"><table>
      <thead><tr><th>${esc(t('table.severity'))}</th><th>${esc(t('table.status'))}</th><th>${esc(t('table.source'))}</th><th>${esc(t('table.title'))}</th><th>${esc(t('table.target'))}</th><th>${esc(t('table.count'))}</th><th>${esc(t('table.lastSeen'))}</th><th></th></tr></thead>
      <tbody>${rows || `<tr><td colspan="8">${esc(t('events.noMatching'))}</td></tr>`}</tbody>
    </table></div>
    <p class="hint" style="margin-top:10px">${esc(t('events.total', { total: payload.total, shown: payload.events.length }))}</p>`;
  $$('[data-event-open]').forEach((button) => { button.onclick = () => showEventModal(button.dataset.eventOpen); });
  $$('[data-quarantine]').forEach((button) => {
    button.onclick = () => quarantinePath(button.dataset.quarantine, button.dataset.event, button.dataset.name);
  });
}

async function downloadExport(format) {
  try {
    const response = await fetch(`/api/v1/events/export?${eventQuery()}&format=${format}`, { credentials: 'same-origin' });
    if (!response.ok) throw new Error(t('events.exportFailed', { status: response.status }));
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `lsec-events-${new Date().toISOString().slice(0, 10)}.${format}`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    toast(t('events.exported', { format: format.toUpperCase() }));
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
      <label class="f-label" for="event-note">${esc(t('events.noteLabel'))}</label>
      <textarea id="event-note" placeholder="${esc(t('events.notePlaceholder'))}"></textarea>
    </div>
    <div class="form-actions">
      ${event.status === 'new' ? `<button class="btn" data-event-status="acknowledged">${esc(t('events.confirm'))}</button><button class="btn" data-event-status="investigating">${esc(t('events.startInvestigation'))}</button>` : ''}
      ${['new', 'acknowledged', 'investigating'].includes(event.status) ? `<button class="btn primary" data-event-status="resolved">${esc(t('events.markResolved'))}</button><button class="btn" data-event-status="ignored">${esc(t('events.ignore'))}</button>` : ''}
      ${['resolved', 'ignored'].includes(event.status) ? `<button class="btn" data-event-status="new">${esc(t('events.reopen'))}</button>` : ''}
    </div>` : `<p class="hint">${esc(t('events.readonlyNote'))}</p>`;
  openModal(t('events.detailsTitle'), `
    <dl class="detail-grid">
      <dt>${esc(t('events.titleLabel'))}</dt><dd><strong>${esc(event.title)}</strong></dd>
      <dt>${esc(t('events.eventId'))}</dt><dd class="mono">${esc(event.event_id)}</dd>
      <dt>${esc(t('events.severitySource'))}</dt><dd>${severityBadge(event.severity)} ${esc(event.source)} / ${esc(event.category)}</dd>
      <dt>${esc(t('table.status'))}</dt><dd>${statusBadge(event.status)}</dd>
      <dt>${esc(t('events.firstLast'))}</dt><dd>${esc(fmtTime(event.first_seen_at))} / ${esc(fmtTime(event.last_seen_at))}</dd>
      <dt>${esc(t('events.occurrences'))}</dt><dd>${event.occurrences}</dd>
      <dt>${esc(t('table.target'))}</dt><dd class="mono">${esc(target.type || '')} ${esc(target.path || target.name || '')}</dd>
      <dt>${esc(t('events.containerId'))}</dt><dd class="mono">${esc(target.container_id || '-')}</dd>
      <dt>${esc(t('events.detection'))}</dt><dd>${esc(evidence.detection_name || '-')}</dd>
      <dt>SHA256</dt><dd class="mono">${esc(evidence.sha256 || '-')}</dd>
      <dt>${esc(t('events.task'))}</dt><dd class="mono">${esc(details.task_id || '-')}</dd>
      <dt>${esc(t('table.description'))}</dt><dd>${esc(event.description)}</dd>
    </dl>
    ${actions ? `<h3 style="font-size:14px;margin:18px 0 6px">${esc(t('events.recommendation'))}</h3><ul class="list-clean">${actions}</ul>` : ''}
    ${evidence.sha256 && isAdmin && target.path ? `<div class="form-actions"><button class="btn danger" id="event-quarantine">${esc(t('events.quarantineFile'))}</button></div>` : ''}
    ${transitionButtons}
  `, `<button class="btn" id="modal-cancel">${esc(t('common.close'))}</button>`, { wide: true });
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
      const labels = { acknowledged: t('events.confirm'), investigating: t('events.startInvestigation'), resolved: t('events.markResolved'), ignored: t('events.ignore'), new: t('events.reopen') };
      const ok = await confirmDialog(t('events.updateTitle'), `<p>${t('events.updateBody', { state: esc(labels[status] || status) })}</p>`, { confirmText: t('common.confirm') });
      if (!ok) return;
      try {
        await api(`/events/${event.event_id}`, { method: 'PATCH', body: { status, note: note || undefined } });
        toast(t('events.updated'));
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
    t('quarantine.confirmTitle'),
    `<div class="notice warn">${esc(t('quarantine.confirmBody'))}</div>
     <dl class="detail-grid">
       <dt>${esc(t('quarantine.filePath'))}</dt><dd class="mono">${esc(path)}</dd>
       <dt>${esc(t('quarantine.detection'))}</dt><dd>${esc(detectionName || '-')}</dd>
     </dl>`,
    { confirmText: t('quarantine.confirmQuarantine'), danger: true }
  );
  if (!ok) return;
  try {
    await api('/quarantine', {
      method: 'POST',
      body: { path, event_id: eventId || undefined, detection_name: detectionName || undefined, engine: 'clamav', confirm: true },
    });
    toast(t('quarantine.fileQuarantined'));
    if (state.page === 'quarantine') await renderQuarantine();
    else if (state.page === 'events') await refreshEvents();
    else if (state.page === 'scan') await refreshScanTasks();
  } catch (err) { toast(err.message, true); }
}

async function renderQuarantine() {
  setPill(t('quarantine.pill'), 'info');
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
        <button class="btn small" data-q-show="${esc(item.item_id)}">${esc(t('common.details'))}</button>
        ${isAdmin && item.status === 'quarantined' ? `
          <button class="btn small" data-q-restore="${esc(item.item_id)}">${esc(t('quarantine.restore'))}</button>
          <button class="btn small danger" data-q-delete="${esc(item.item_id)}">${esc(t('common.delete'))}</button>` : ''}
      </div></td>
    </tr>`).join('');
  $('#content').innerHTML = `
    <div class="card">
      <div class="card-head"><h2>${esc(t('quarantine.cardTitle'))}</h2><button class="btn small" id="q-refresh">${esc(t('common.refresh'))}</button></div>
      <div class="notice">${esc(t('quarantine.notice'))}</div>
      <div class="table-wrap"><table>
        <thead><tr><th>${esc(t('table.id'))}</th><th>${esc(t('table.originalPath'))}</th><th>${esc(t('table.size'))}</th><th>${esc(t('table.detection'))}</th><th>${esc(t('table.status'))}</th><th>${esc(t('table.quarantinedAt'))}</th><th></th></tr></thead>
        <tbody>${rows || `<tr><td colspan="7">${esc(t('quarantine.empty'))}</td></tr>`}</tbody>
      </table></div>
      <p class="hint" style="margin-top:10px">${esc(t('quarantine.total', { n: total }))}</p>
    </div>`;
  $('#q-refresh').onclick = () => renderQuarantine().catch((err) => toast(err.message, true));
  $$('[data-q-show]').forEach((button) => { button.onclick = () => showQuarantineModal(button.dataset.qShow); });
  $$('[data-q-restore]').forEach((button) => {
    button.onclick = async () => {
      const ok = await confirmDialog(t('quarantine.restoreTitle'), `<div class="notice warn">${esc(t('quarantine.restoreBody'))}</div>`, { confirmText: t('quarantine.confirmRestore') });
      if (!ok) return;
      try { await api(`/quarantine/${button.dataset.qRestore}/restore`, { method: 'POST', body: { confirm: true } }); toast(t('quarantine.restored')); await renderQuarantine(); }
      catch (err) { toast(err.message, true); }
    };
  });
  $$('[data-q-delete]').forEach((button) => {
    button.onclick = async () => {
      const ok = await confirmDialog(t('quarantine.deleteTitle'), `<div class="notice danger">${esc(t('quarantine.deleteBody'))}</div>`, { confirmText: t('quarantine.deletePermanently'), danger: true });
      if (!ok) return;
      try { await api(`/quarantine/${button.dataset.qDelete}/delete`, { method: 'POST', body: { confirm: true } }); toast(t('quarantine.deleted')); await renderQuarantine(); }
      catch (err) { toast(err.message, true); }
    };
  });
}

async function showQuarantineModal(itemId) {
  try {
    const { item } = await api(`/quarantine/${itemId}`);
    openModal(t('quarantine.detailsTitle'), `
      <dl class="detail-grid">
        <dt>${esc(t('table.id'))}</dt><dd class="mono">${esc(item.item_id)}</dd>
        <dt>${esc(t('table.originalPath'))}</dt><dd class="mono">${esc(item.original_path)}</dd>
        <dt>${esc(t('quarantine.storedPath'))}</dt><dd class="mono">${esc(item.stored_path)}</dd>
        <dt>${esc(t('quarantine.fileExists'))}</dt><dd>${item.file_exists ? t('common.yes') : t('quarantine.fileMissingInconsistent')}</dd>
        <dt>SHA256</dt><dd class="mono">${esc(item.sha256)}</dd>
        <dt>${esc(t('table.size'))}</dt><dd>${fmtBytes(item.size)}</dd>
        <dt>${esc(t('quarantine.detectionEngine'))}</dt><dd>${esc(item.detection_name || '-')} / ${esc(item.engine || '-')}</dd>
        <dt>${esc(t('quarantine.relatedEvent'))}</dt><dd class="mono">${esc(item.event_id || '-')}</dd>
        <dt>${esc(t('quarantine.quarantinedBy'))}</dt><dd>${esc(item.quarantined_by)} / ${esc(fmtTime(item.detected_at))}</dd>
        <dt>${esc(t('table.status'))}</dt><dd>${statusBadge(item.status)}</dd>
      </dl>`, `<button class="btn" id="modal-cancel">${esc(t('common.close'))}</button>`, { wide: true });
    $('#modal-cancel').onclick = () => closeModal();
  } catch (err) { toast(err.message, true); }
}

/* ------------------------------------------------------------- components */
async function renderComponents() {
  const { components } = await api('/components');
  const isAdmin = state.role === 'admin';
  setPill(t('components.pill'), 'info');
  const rows = components.map((component) => `
    <tr>
      <td><strong>${esc(component.display_name)}</strong><div class="mono">${esc(component.component_id)}</div></td>
      <td>${component.installed ? badge('ok', t('status.installed')) : badge('danger', t('status.not_installed'))}</td>
      <td>${esc(component.version || '-')}</td>
      <td>${healthBadge(component.health_status)}</td>
      <td>${esc(STATUS_LABEL[component.service_status] || component.service_status)}</td>
      <td class="muted">${esc(component.error_message || '-')}</td>
      <td class="muted">${esc(fmtTime(component.last_check_at))}</td>
      <td><div class="row-actions">
        <button class="btn small" data-comp-show="${esc(component.component_id)}">${esc(t('common.details'))}</button>
        ${component.installed ? `<button class="btn small" data-comp-plan="${esc(component.component_id)}">${esc(t('common.installSource'))}</button>` : ''}
        ${isAdmin && component.component_id === 'clamav' ? `
          <button class="btn small" data-comp-start="${esc(component.component_id)}" ${component.service_status === 'running' ? 'disabled' : ''}>${esc(t('common.start'))}</button>
          <button class="btn small" data-comp-stop="${esc(component.component_id)}" ${component.service_status !== 'running' ? 'disabled' : ''}>${esc(t('common.stop'))}</button>
          <button class="btn small" data-comp-update="${esc(component.component_id)}" ${!component.installed ? 'disabled' : ''}>${esc(t('components.action.update'))}</button>` : ''}
      </div></td>
    </tr>`).join('');
  $('#content').innerHTML = `
    <div class="card">
      <div class="card-head"><h2>${esc(t('components.inventory'))}</h2><div class="row-actions">
        <button class="btn small" id="comp-probe" ${isAdmin ? '' : 'disabled'}>${esc(t('components.probeAgain'))}</button>
      </div></div>
      <div class="notice">${esc(t('components.notice'))}</div>
      <div class="table-wrap"><table>
        <thead><tr><th>${esc(t('table.component'))}</th><th>${esc(t('table.installed'))}</th><th>${esc(t('table.version'))}</th><th>${esc(t('table.health'))}</th><th>${esc(t('table.service'))}</th><th>${esc(t('table.description'))}</th><th>${esc(t('table.lastCheck'))}</th><th></th></tr></thead>
        <tbody>${rows || `<tr><td colspan="8">${esc(t('components.none'))}</td></tr>`}</tbody>
      </table></div>
    </div>`;
  $('#comp-probe').onclick = async () => {
    try { await api('/components/probe', { method: 'POST', body: {}, timeout: 120000 }); toast(t('components.probeCompleted')); await renderComponents(); }
    catch (err) { toast(err.message, true); }
  };
  $$('[data-comp-show]').forEach((button) => { button.onclick = () => showComponentModal(button.dataset.compShow); });
  $$('[data-comp-plan]').forEach((button) => {
    button.onclick = async () => {
      try {
        const { plan } = await api(`/components/${button.dataset.compPlan}/install-plan`);
        openModal(t('components.installSourceTitle'), `<div class="pre">${esc(JSON.stringify(plan, null, 2))}</div>`, `<button class="btn" id="modal-cancel">${esc(t('common.close'))}</button>`, { wide: true });
        $('#modal-cancel').onclick = () => closeModal();
      } catch (err) { toast(err.message, true); }
    };
  });
  $$('[data-comp-start]').forEach((button) => { button.onclick = () => componentAction(button.dataset.compStart, 'start'); });
  $$('[data-comp-stop]').forEach((button) => {
    button.onclick = async () => {
      const ok = await confirmDialog(t('components.stopTitle'), `<p>${esc(t('components.stopBody'))}</p>`, { confirmText: t('common.stop'), danger: true });
      if (ok) componentAction(button.dataset.compStop, 'stop');
    };
  });
  $$('[data-comp-update]').forEach((button) => { button.onclick = () => componentAction(button.dataset.compUpdate, 'update'); });
}

async function componentAction(componentId, action) {
  const label = { start: t('components.action.start'), stop: t('components.action.stop'), update: t('components.action.update') }[action];
  if (action === 'update') {
    const ok = await confirmDialog(t('components.updateTitle'), `<p>${esc(t('components.updateBody'))}</p>`, { confirmText: t('components.startUpdate') });
    if (!ok) return;
  }
  try {
    toast(t('components.actionRunning', { label }));
    const payload = await api(`/components/${componentId}/${action}`, { method: 'POST', body: {}, timeout: 900000 });
    if (action === 'update') {
      const outcome = payload.update;
      toast(outcome.ok ? t('components.updated') : t('components.updateFailed', { code: outcome.exit_code }), !outcome.ok);
      openModal(t('components.updateResult'), `
        <dl class="detail-grid">
          <dt>${esc(t('components.result'))}</dt><dd>${outcome.ok ? t('common.success') : t('common.failed')}</dd>
          <dt>${esc(t('components.exitCode'))}</dt><dd>${esc(outcome.exit_code)}</dd>
          <dt>${esc(t('components.duration'))}</dt><dd>${esc(t('time.seconds', { n: outcome.duration_seconds }))}</dd>
          <dt>${esc(t('dashboard.virusDb'))}</dt><dd class="mono">${esc(JSON.stringify(outcome.database || {}, null, 2))}</dd>
        </dl>
        <h3 style="font-size:14px;margin:16px 0 6px">${esc(t('components.outputTruncated'))}</h3>
        <div class="pre">${esc(outcome.output_tail || '')}</div>`, `<button class="btn" id="modal-cancel">${esc(t('common.close'))}</button>`, { wide: true });
      $('#modal-cancel').onclick = () => closeModal();
    } else {
      toast(t('components.actionSucceeded', { label }));
    }
    await renderComponents();
  } catch (err) { toast(err.message, true); }
}

async function showComponentModal(componentId) {
  try {
    const { components } = await api('/components');
    const component = components.find((item) => item.component_id === componentId);
    if (!component) throw new Error(t('components.notFound'));
    openModal(component.display_name, `
      <dl class="detail-grid">
        <dt>${esc(t('components.componentId'))}</dt><dd class="mono">${esc(component.component_id)}</dd>
        <dt>${esc(t('components.installedYesNo'))}</dt><dd>${component.installed ? t('common.yes') : t('common.no')}</dd>
        <dt>${esc(t('table.version'))}</dt><dd>${esc(component.version || '-')}</dd>
        <dt>${esc(t('components.serviceStatus'))}</dt><dd>${esc(component.service_status)}</dd>
        <dt>${esc(t('components.healthStatus'))}</dt><dd>${healthBadge(component.health_status)}</dd>
        <dt>${esc(t('components.capabilities'))}</dt><dd>${esc((component.capabilities || []).join(', ') || t('components.noCapabilities'))}</dd>
        <dt>${esc(t('components.error'))}</dt><dd>${esc(component.error_message || '-')}</dd>
        <dt>${esc(t('components.lastCheck'))}</dt><dd>${esc(fmtTime(component.last_check_at))}</dd>
      </dl>
      <h3 style="font-size:14px;margin:18px 0 6px">${esc(t('components.probeDetails'))}</h3>
      <div class="pre">${esc(JSON.stringify(component.details || {}, null, 2))}</div>
    `, `<button class="btn" id="modal-cancel">${esc(t('common.close'))}</button>`, { wide: true });
    $('#modal-cancel').onclick = () => closeModal();
  } catch (err) { toast(err.message, true); }
}

/* ----------------------------------------------------------------- policy */
async function renderPolicy() {
  const { settings, notes } = await api('/settings');
  const schedule = settings.scheduled_scan || {};
  const mode = settings.response_mode || 'suggest';
  setPill(t('policy.pill'), 'info');
  $('#content').innerHTML = `
    <div class="card">
      <div class="card-head"><h2>${esc(t('policy.handlingMode'))}</h2></div>
      <div class="notice">${esc(t('policy.notice'))}</div>
      <label class="checkline" style="margin-bottom:10px">
        <input type="radio" name="response-mode" value="alert" ${mode === 'alert' ? 'checked' : ''}>
        ${esc(t('policy.alertOnly'))}
      </label>
      <label class="checkline" style="margin-bottom:10px">
        <input type="radio" name="response-mode" value="suggest" ${mode === 'suggest' ? 'checked' : ''}>
        ${esc(t('policy.recommend'))}
      </label>
      <label class="checkline" style="margin-bottom:10px;opacity:.55">
        <input type="radio" disabled>
        ${esc(t('policy.controlled'))}
      </label>
      <p class="hint">${esc(notes.response_mode || '')}</p>
    </div>

    <div class="card">
      <div class="card-head"><h2>${esc(t('policy.scheduled'))}</h2></div>
      <div class="form-grid">
        <div class="form-row">
          <label class="checkline"><input type="checkbox" id="schedule-enabled" ${schedule.enabled ? 'checked' : ''}> ${esc(t('policy.enableScheduled'))}</label>
          <p class="hint">${esc(t('policy.scheduledHint', { time: fmtTime(schedule.last_run_at) }))}</p>
        </div>
        <div class="form-row">
          <label class="f-label" for="schedule-type">${esc(t('policy.scanType'))}</label>
          <select id="schedule-type">
            <option value="quick" ${schedule.type === 'quick' ? 'selected' : ''}>${esc(t('scan.type.quick'))}</option>
            <option value="full" ${schedule.type === 'full' ? 'selected' : ''}>${esc(t('scan.type.full'))}</option>
          </select>
        </div>
        <div class="form-row">
          <label class="f-label" for="schedule-interval">${esc(t('policy.interval'))}</label>
          <input type="number" id="schedule-interval" min="1" max="720" value="${esc(schedule.interval_hours || 24)}">
        </div>
      </div>
      <div class="form-actions">
        <button class="btn primary" id="policy-save" ${state.role !== 'admin' ? 'disabled' : ''}>${esc(t('policy.save'))}</button>
        ${state.role !== 'admin' ? `<span class="hint">${esc(t('policy.readonly'))}</span>` : ''}
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h2>${esc(t('policy.automation'))}</h2></div>
      <ul class="list-clean">
        <li>${esc(t('policy.boundary1'))}</li>
        <li>${esc(t('policy.boundary2'))}</li>
        <li>${esc(t('policy.boundary3'))}</li>
        <li>${esc(t('policy.boundary4'))}</li>
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
      toast(t('policy.saved'));
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
    baseline.state === 'current' ? t('host.pillCurrent') : t('host.pillPending'),
    stateKind === 'danger' ? 'danger' : 'warn',
  );
  const rows = relevant.map((component) => `
    <tr>
      <td>${esc(component.display_name)}</td>
      <td>${component.installed ? t('status.installed') : t('status.not_installed')}</td>
      <td>${healthBadge(component.health_status)}</td>
      <td class="muted">${esc(component.error_message || '-')}</td>
    </tr>`).join('');
  $('#content').innerHTML = `
    <div class="notice ${baseline.state === 'failed' ? 'danger' : baseline.state === 'current' ? 'ok' : 'warn'}">
      <strong>${esc(t('host.baselineLabel'))}</strong>${statusBadge(baseline.state)} ${esc(baseline.note || '')}${esc(t('host.baselineTail'))}
    </div>
    <div class="grid-3">
      <div class="card"><div class="card-head"><h2>${esc(t('host.hostInfo'))}</h2></div>
        <dl class="detail-grid">
          <dt>${esc(t('host.hostname'))}</dt><dd>${esc(host.hostname)}</dd>
          <dt>${esc(t('host.os'))}</dt><dd>${esc(host.os)}</dd>
          <dt>${esc(t('host.kernel'))}</dt><dd class="mono">${esc(host.kernel)}</dd>
          <dt>${esc(t('host.architecture'))}</dt><dd class="mono">${esc(host.machine)}</dd>
          <dt>${esc(t('host.containerEnv'))}</dt><dd>${host.container.containerized ? esc(t('host.containerYes', { runtime: esc(host.container.runtime || t('common.unknownRuntime')) })) : t('host.no')}</dd>
        </dl>
      </div>
      <div class="card" style="grid-column: span 2"><div class="card-head"><h2>${esc(t('host.recentAudit'))}</h2><button class="btn small ghost" data-goto="audit">${esc(t('host.auditBtn'))}</button></div>
        ${last ? `<dl class="detail-grid">
          <dt>${esc(t('table.status'))}</dt><dd>${statusBadge(last.status)}</dd>
          <dt>${esc(t('host.checksFindingsErrors'))}</dt><dd>${last.checks_total} / ${last.findings_count} / ${last.errors_count}</dd>
          <dt>${esc(t('host.riskLevel'))}</dt><dd>${esc(t('host.riskCounts', { critical: last.severity_counts?.critical || 0, high: last.severity_counts?.high || 0, medium: last.severity_counts?.medium || 0, low: last.severity_counts?.low || 0 }))}</dd>
          <dt>${esc(t('host.hardeningIndex'))}</dt><dd>${last.hardening_index ?? '-'}</dd>
          <dt>${esc(t('dashboard.finished'))}</dt><dd>${esc(fmtTime(last.finished_at))}</dd>
        </dl>` : `<div class="empty">${esc(t('host.noAudit'))}</div>`}
      </div>
    </div>
    <div class="card"><div class="card-head"><h2>${esc(t('host.relatedComponents'))}</h2><button class="btn small ghost" data-goto="components">${esc(t('common.components'))}</button></div>
      <div class="table-wrap"><table><thead><tr><th>${esc(t('table.component'))}</th><th>${esc(t('table.installed'))}</th><th>${esc(t('table.health'))}</th><th>${esc(t('table.description'))}</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="4">${esc(t('host.noRelated'))}</td></tr>`}</tbody></table></div>
      <p class="hint" style="margin-top:10px">${esc(cap.reason || '')}</p>
    </div>
    <div class="card">
      <div class="card-head"><h2>${esc(t('host.wazuhTitle'))}</h2>
        <div class="row-actions">
          <button class="btn small" id="wazuh-plan">${esc(t('host.installPlan'))}</button>
          <button class="btn small ghost" data-goto="components">${esc(t('host.componentDetails'))}</button>
        </div>
      </div>
      <div class="notice ${wazuh.state === 'available' ? 'ok' : wazuh.state === 'disabled' ? 'info' : 'warn'}">
        <strong>${esc(t('host.capabilityState'))}</strong>${statusBadge(wazuh.state)} ${esc(wazuh.reason || '')}
        <div class="hint" style="margin-top:6px">${esc(wazuh.note || '')}</div>
      </div>
      <dl class="detail-grid">
        <dt>${esc(t('common.installHealth'))}</dt><dd>${wazuhComponent.installed ? t('status.installed') : t('status.not_installed')} · ${healthBadge(wazuhComponent.health_status || 'unknown')}</dd>
        <dt>${esc(t('host.versionService'))}</dt><dd class="mono">${esc(wazuhComponent.version || '-')} · ${esc(wazuhComponent.service_status || 'unknown')}</dd>
        <dt>${esc(t('host.managerConfig'))}</dt><dd>${wazuhManager.manager_configured ? t('common.configured') : t('host.notConfigured')} <span class="mono">${esc(wazuhManager.address || '-')}:${esc(wazuhManager.port || '-')}</span></dd>
        <dt>${esc(t('host.managerVerify'))}</dt><dd>${badge('warn', t('host.unverified'))} <span class="hint">${esc(t('host.notManager'))}</span></dd>
        <dt>${esc(t('host.localRegistration'))}</dt><dd>${wazuhDetails.registration_present ? t('host.present') : t('host.missingUnreadable')}</dd>
        <dt>${esc(t('host.localIngest'))}</dt><dd>${wazuhIngest.ingest_enabled ? (wazuhIngest.running ? t('host.running') : t('host.enabledNotRunning')) : t('common.disabled')}</dd>
        <dt>${esc(t('host.ingestedEvents'))}</dt><dd>${Number(wazuhIngest.events_total || 0)} / ${Number(wazuhIngest.parse_errors || 0)}</dd>
        <dt>${esc(t('host.alertsFile'))}</dt><dd class="mono">${esc(wazuhIngest.alerts_path || wazuhDetails.alerts_path || '-')}</dd>
        <dt>${esc(t('host.recentEvents'))}</dt><dd>${esc(fmtTime(wazuhIngest.last_event_at))}</dd>
      </dl>
      ${wazuhIngest.last_error ? `<p class="hint">${esc(t('host.lastError', { error: wazuhIngest.last_error }))}</p>` : ''}
      <p class="hint" style="margin-top:10px">${esc(t('host.wazuhNote'))}</p>
    </div>
    <div class="card"><div class="card-head"><h2>${esc(t('host.integrityTitle'))}</h2></div>
      ${empty(t('host.integrityEmpty'))}
    </div>`;
  $$('[data-goto]').forEach((button) => { button.onclick = () => navigate(button.dataset.goto); });
  const wazuhPlan = $('#wazuh-plan');
  if (wazuhPlan) {
    wazuhPlan.onclick = async () => {
      try {
        const payload = await api('/wazuh/install-plan');
        const plan = payload.plan || {};
        openModal(t('host.wazuhPlanTitle'), `
          <p>${esc(plan.privileges || '')}</p>
          <ol>${(plan.steps || []).map((step) => `<li>${esc(step)}</li>`).join('')}</ol>
          ${(plan.notes || []).map((note) => `<div class="notice warn">${esc(note)}</div>`).join('')}
        `, `<button class="btn" id="modal-cancel">${esc(t('common.close'))}</button>`);
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
  setPill(monitorState === 'monitored' ? t('containers.pillActive') : t('containers.pillPrefix', { state: stateText }), pillKind);

  let notice;
  if (monitorState === 'disabled') {
    notice = `<div class="notice warn"><strong>${esc(t('containers.notEnabledTitle'))}</strong>${esc(snapshot.note || '')}${esc(t('containers.notEnabledTail'))}</div>`;
  } else if (monitorState === 'permission_denied') {
    notice = `<div class="notice danger"><strong>${esc(t('containers.permissionTitle'))}</strong>${esc(snapshot.note || '')}${esc(t('containers.permissionTail'))}</div>`;
  } else if (monitorState === 'unavailable' || monitorState === 'degraded') {
    notice = `<div class="notice danger"><strong>${esc(t('containers.unavailableTitle'))}</strong>${esc(snapshot.note || '')}${snapshot.stale ? esc(t('containers.staleSuffix')) : ''}</div>`;
  } else if (monitorState === 'initializing') {
    notice = `<div class="notice"><strong>${esc(t('containers.waitingTitle'))}</strong>${esc(snapshot.note || '')}</div>`;
  } else {
    notice = `<div class="notice ok"><strong>${esc(t('containers.healthyTitle'))}</strong>${esc(snapshot.note || '')}${esc(t('containers.healthyTail'))}</div>`;
  }

  const staleBadge = snapshot.stale ? ` ${badge('warn', t('containers.dataStale'))}` : '';
  const rows = (snapshot.containers || []).map((item) => `
    <tr>
      <td><strong>${esc(item.name || '-')}</strong><div class="mono">${esc((item.container_id || '').slice(0, 12))}</div></td>
      <td><span class="truncate" title="${esc(item.image || '')}">${esc(item.image || '-')}</span></td>
      <td>${esc(item.state || '-')}${item.status_text ? `<div class="muted">${esc(item.status_text)}</div>` : ''}</td>
      <td>${esc(containerUptime(item))}</td>
      <td>${riskBadge(item.risk_level)}</td>
      <td>${Number(item.risk_count || 0)}${item.evaluated ? '' : `<div class="muted">${esc(t('containers.couldNotEvaluate'))}</div>`}</td>
      <td><button class="btn small" data-container-open="${esc(item.container_id || item.name || '')}">${esc(t('common.details'))}</button></td>
    </tr>`).join('');

  const engineCard = engine.runtime ? `
    <dl class="detail-grid">
      <dt>${esc(t('containers.runtime'))}</dt><dd>Docker${engine.server_version ? ` ${esc(engine.server_version)}` : ''}</dd>
      <dt>${esc(t('containers.apiVersion'))}</dt><dd class="mono">${esc(engine.api_version || '-')}</dd>
      <dt>${esc(t('containers.hostKernel'))}</dt><dd class="mono">${esc(engine.kernel || '-')}</dd>
      <dt>${esc(t('containers.systemArch'))}</dt><dd>${esc(engine.os || '-')} / ${esc(engine.architecture || '-')}</dd>
      <dt>${esc(t('containers.inventoryRunningStopped'))}</dt><dd>${Number(summary.running || 0)} / ${Number(summary.stopped || 0)}</dd>
      <dt>${esc(t('containers.lastSuccess'))}</dt><dd>${esc(fmtTime(snapshot.last_success_at))}${staleBadge}</dd>
    </dl>` : empty(t('containers.noEngine'));

  const falcoComponent = falco.component || {};
  const falcoCap = falcoComponent.details?.capability || {};
  const falcoIngest = falco.event_ingest || {};
  const falcoState = falcoComponent.error_code === 'disabled' ? 'disabled'
    : !falcoComponent.installed ? 'not_installed' : (falcoCap.state || 'unknown');
  const falcoCapLabel = FALCO_CAPABILITY_LABEL[falcoCap.state] || (falcoState === 'disabled' ? t('common.disabled') : STATUS_LABEL[falcoState] || falcoState);
  const falcoHealth = falcoState === 'not_installed' ? 'unavailable' : falcoState === 'disabled' ? 'unknown' : (falcoComponent.health_status || 'unknown');
  const capFlag = (value) => value === true ? t('common.yes') : value === false ? t('common.no') : t('common.unknown');

  $('#content').innerHTML = `
    ${notice}
    <div class="grid-4">
      <div class="stat">
        <div class="label">${esc(t('containers.totalContainers'))}</div>
        <div class="value">${Number(summary.total || 0)}</div>
        <div class="sub">${esc(t('containers.runningStoppedSub', { running: Number(summary.running || 0), stopped: Number(summary.stopped || 0) }))}</div>
      </div>
      <div class="stat">
        <div class="label">${esc(t('containers.configRisk'))}</div>
        <div class="value">${Number(summary.risky || 0)}</div>
        <div class="sub">${esc(t('containers.riskCounts', { critical: Number(byRisk.critical || 0), high: Number(byRisk.high || 0), medium: Number(byRisk.medium || 0) }))}</div>
      </div>
      <div class="stat">
        <div class="label">${esc(t('containers.riskFindings'))}</div>
        <div class="value">${Number(summary.findings || 0)}</div>
        <div class="sub">${esc(t('containers.findingsSub'))}</div>
      </div>
      <div class="stat">
        <div class="label">${esc(t('containers.evaluate'))}</div>
        <div class="value">${Number(summary.unknown || 0)}</div>
        <div class="sub">${esc(t('containers.evaluateSub'))}</div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <div><h2>${esc(t('containers.inventory'))}</h2><p>${esc(snapshot.scope_note || '')}</p></div>
        ${isAdmin && monitorState !== 'disabled' ? `<button class="btn primary" id="container-refresh">${esc(t('containers.refreshNow'))}</button>` : ''}
      </div>
      ${(snapshot.containers || []).length ? `
      <div class="table-wrap"><table>
        <thead><tr><th>${esc(t('table.nameId'))}</th><th>${esc(t('table.image'))}</th><th>${esc(t('table.status'))}</th><th>${esc(t('table.uptime'))}</th><th>${esc(t('table.risk'))}</th><th>${esc(t('table.findings'))}</th><th>${esc(t('table.action'))}</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>` : empty(monitorState === 'disabled' ? t('containers.noInventoryDisabled') : monitorState === 'initializing' ? t('containers.noInventoryInit') : t('containers.noContainers'))}
      ${snapshot.truncated ? `<p class="hint">${esc(t('containers.truncated'))}</p>` : ''}
      ${(snapshot.inspect_errors || []).length ? `<p class="hint">${esc(t('containers.inspectErrors', { n: snapshot.inspect_errors.length }))}</p>` : ''}
    </div>

    <div class="grid-3">
      <div class="card">
        <div class="card-head"><h2>${esc(t('containers.dockerRuntime'))}</h2><button class="btn small ghost" data-goto="components">${esc(t('host.componentDetails'))}</button></div>
        ${engineCard}
        <dl class="detail-grid" style="margin-top:12px">
          <dt>${esc(t('containers.monitoringApi'))}</dt><dd class="mono">${esc(monitorInfo.api_url || '-')}</dd>
          <dt>${esc(t('containers.localSocket'))}</dt><dd class="mono">${esc(dockerDetails.socket || t('containers.notDetected'))}</dd>
          <dt>${esc(t('containers.socketAccessible'))}</dt><dd>${capFlag(dockerDetails.socket_accessible)}</dd>
          <dt>${esc(t('table.description'))}</dt><dd>${esc(docker?.error_message || '-')}</dd>
        </dl>
      </div>
      <div class="card">
        <div class="card-head"><h2>${esc(t('containers.falcoTitle'))}</h2><button class="btn small ghost" data-goto="components">${esc(t('host.componentDetails'))}</button></div>
        <dl class="detail-grid">
          <dt>${esc(t('containers.installedLabel'))}</dt><dd>${falcoComponent.installed ? t('common.yes') : t('common.no')}</dd>
          <dt>${esc(t('table.version'))}</dt><dd class="mono">${esc(falcoComponent.version || '-')}</dd>
          <dt>${esc(t('containers.capabilityStatus'))}</dt><dd>${esc(falcoCapLabel)}</dd>
          <dt>${esc(t('containers.health'))}</dt><dd>${healthBadge(falcoHealth)}</dd>
          <dt>${esc(t('containers.hostKernel'))}</dt><dd class="mono">${esc(falcoCap.kernel_release || '-')}</dd>
          <dt>BTF</dt><dd>${capFlag(falcoCap.btf_available)}</dd>
          <dt>CAP_SYS_ADMIN</dt><dd>${capFlag(falcoCap.cap_sys_admin)}</dd>
          <dt>CAP_BPF / PERFMON</dt><dd>${capFlag(falcoCap.cap_bpf)} / ${capFlag(falcoCap.cap_perfmon)}</dd>
          <dt>${esc(t('containers.runtimeVerification'))}</dt><dd>${falcoCap.running_verified ? t('containers.verified') : t('containers.unverifiedRunning')}</dd>
        </dl>
        <p class="hint" style="margin-top:10px">${esc(falcoCap.reason || falcoComponent.error_message || t('containers.noFalcoInfo'))}</p>
        <div class="form-actions"><button class="btn" id="falco-plan">${esc(t('containers.viewPlan'))}</button></div>
      </div>
      <div class="card">
        <div class="card-head"><h2>${esc(t('containers.falcoIngest'))}</h2></div>
        <dl class="detail-grid">
          <dt>${esc(t('containers.ingestStatus'))}</dt><dd>${falcoIngest.enabled ? t('common.enabled') : t('common.disabled')}</dd>
          <dt>${esc(t('containers.ingestEndpoint'))}</dt><dd class="mono">${esc(falcoIngest.endpoint || '/api/v1/integrations/falco')}</dd>
          <dt>${esc(t('containers.dedicatedToken'))}</dt><dd class="mono">${esc(falcoIngest.token_path || '-')}</dd>
          <dt>${esc(t('containers.eventsReceived'))}</dt><dd>${Number(falcoIngest.events_total || 0)}</dd>
          <dt>${esc(t('containers.recentEvents'))}</dt><dd>${esc(fmtTime(falcoIngest.last_event_at))}</dd>
        </dl>
        <p class="hint" style="margin-top:10px">${esc(t('containers.tokenNote'))}</p>
        <p class="hint">${falco.install_plan_available ? esc(t('containers.adminsPlan')) : ''}</p>
      </div>
    </div>

    <div class="card"><div class="card-head"><h2>${esc(t('containers.boundaries'))}</h2></div>
      <ul class="list-clean">
        ${(snapshot.limitations || []).map((item) => `<li>${esc(item)}</li>`).join('')}
        <li>${esc(t('containers.limitation1'))}</li>
        <li>${esc(t('containers.limitation2'))}</li>
        <li>${esc(t('containers.limitation3'))}</li>
        <li>${esc(t('containers.limitation4'))}</li>
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
      refreshButton.textContent = t('containers.refreshing');
      try {
        await api('/containers/refresh', { method: 'POST', body: {} });
        toast(t('containers.refreshed'));
        await renderContainers();
      } catch (err) {
        toast(err.message, true);
        refreshButton.disabled = false;
        refreshButton.textContent = t('containers.refreshNow');
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
      ${finding.recommendation ? `<div class="hint">${esc(t('containers.recommendation', { text: finding.recommendation }))}</div>` : ''}
    </li>`).join('');
  const mounts = (item.mounts || []).map((mount) => `
    <li><span class="mono">${esc(mount.source || '-')}</span> → <span class="mono">${esc(mount.destination || '-')}</span>
      <span class="muted">${mount.read_only ? t('containers.readOnly') : t('containers.readWrite')} · ${esc(mount.type || t('common.unknown'))}</span></li>`).join('');
  const ports = (item.ports || []).map((port) => `
    <li class="mono">${esc(port.container || '-')} → ${esc(`${port.host_ip || ''}:${port.host_port || '*'}`)}</li>`).join('');
  const caps = (item.cap_add || []).length ? item.cap_add.map((cap) => `<span class="badge neutral">${esc(cap)}</span>`).join(' ') : `<span class="muted">${esc(t('containers.noneAdded'))}</span>`;
  const securityOpts = (item.security_opt || []).length ? item.security_opt.map(esc).join(', ') : t('containers.default');
  openModal(t('containers.modalTitle', { name: item.name || item.container_id?.slice(0, 12) || '-' }), `
    ${item.evaluated === false ? `<div class="notice warn"><strong>${esc(t('containers.evalTitle'))}</strong>${esc(item.evaluation_error || t('containers.missingFields'))}${esc(t('containers.unknownNotSafe'))}</div>` : ''}
    <dl class="detail-grid">
      <dt>${esc(t('containers.containerId'))}</dt><dd class="mono">${esc(item.container_id || '-')}</dd>
      <dt>${esc(t('table.image'))}</dt><dd class="mono">${esc(item.image || '-')}</dd>
      <dt>${esc(t('table.status'))}</dt><dd>${esc(item.state || '-')} ${item.status_text ? `<span class="muted">${esc(item.status_text)}</span>` : ''}</dd>
      <dt>${esc(t('containers.riskLevel'))}</dt><dd>${riskBadge(item.risk_level)} ${esc(t('containers.riskTotal', { n: Number(item.risk_count || 0) }))}</dd>
      <dt>${esc(t('containers.createdStarted'))}</dt><dd>${esc(fmtTime(item.created_at))} / ${esc(fmtTime(item.started_at))}</dd>
      <dt>${esc(t('containers.pidRestartsOom'))}</dt><dd>${item.pid ?? '-'} / ${item.restart_count ?? '-'} / ${item.oom_killed ? t('common.yes') : t('common.no')}</dd>
      <dt>${esc(t('containers.runAsUser'))}</dt><dd>${esc(item.user || '-')}${item.user_is_root ? esc(t('containers.rootInContainer')) : ''}</dd>
      <dt>${esc(t('containers.privileged'))}</dt><dd>${item.privileged ? `<strong>${esc(t('common.yes'))}</strong>` : t('common.no')}</dd>
      <dt>${esc(t('containers.networkPidIpc'))}</dt><dd>${esc(item.network_mode || '-')} / ${esc(item.pid_mode || t('containers.default'))} / ${esc(item.ipc_mode || t('containers.default'))}</dd>
      <dt>${esc(t('containers.userNamespace'))}</dt><dd>${esc(item.userns_mode || t('containers.default'))}</dd>
      <dt>${esc(t('containers.rootFilesystem'))}</dt><dd>${item.read_only_rootfs ? t('containers.readOnly') : t('containers.writable')}</dd>
      <dt>CapAdd</dt><dd>${caps}</dd>
      <dt>SecurityOpt</dt><dd class="mono">${esc(securityOpts)}</dd>
      <dt>${esc(t('containers.restartPolicy'))}</dt><dd>${esc(item.restart_policy || '-')}</dd>
    </dl>
    <h3 style="font-size:14px;margin:18px 0 6px">${esc(t('containers.findingsHeading'))}</h3>
    ${findings ? `<ul class="list-clean">${findings}</ul>` : (item.evaluated === false ? `<p class="hint">${esc(t('containers.evalNoConclusion'))}</p>` : `<p class="hint">${esc(t('containers.noRules'))}</p>`)}
    <h3 style="font-size:14px;margin:18px 0 6px">${esc(t('containers.mounts'))}</h3>
    ${mounts ? `<ul class="list-clean">${mounts}</ul>` : `<p class="hint">${esc(t('containers.noMounts'))}</p>`}
    <h3 style="font-size:14px;margin:18px 0 6px">${esc(t('containers.ports'))}</h3>
    ${ports ? `<ul class="list-clean">${ports}</ul>` : `<p class="hint">${esc(t('containers.noPorts'))}</p>`}
    <div class="notice" style="margin-top:16px">${esc(t('containers.pageNote'))}</div>
  `, `<button class="btn" id="modal-cancel">${esc(t('common.close'))}</button>`, { wide: true });
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
  openModal(t('containers.falcoPlanTitle'), `
    <div class="notice warn"><strong>${esc(t('containers.cannotInstall'))}</strong>${esc(plan.risk || '')}</div>
    <ol class="list-clean">${steps}</ol>
    ${notes ? `<h3 style="font-size:14px;margin:18px 0 6px">${esc(t('containers.notes'))}</h3><ul class="list-clean">${notes}</ul>` : ''}
    <p class="hint" style="margin-top:14px">${esc(t('containers.falcoPlanNote'))}</p>
  `, `<button class="btn" id="modal-cancel">${esc(t('common.close'))}</button>`, { wide: true });
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
  button.textContent = t('audit.running');
  try {
    const { audit } = await api('/audits', { method: 'POST', body: {} });
    toast(t('audit.created'));
    const terminal = ['succeeded', 'partial', 'failed'];
    let finished = false;
    for (let attempt = 0; attempt < 120; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 1500));
      const payload = await api(`/audits/${audit.audit_id}`);
      if (terminal.includes(payload.audit.status)) {
        toast(payload.audit.status === 'failed' ? t('audit.failedView') : t('audit.finished'));
        finished = true;
        break;
      }
    }
    await renderAudit();
    if (!finished) toast(t('audit.stillRunning'), true);
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
    setPill(t('audit.pillNotRun'), 'warn');
  } else if (latest.status === 'failed') {
    setPill(t('audit.pillFailed'), 'danger');
  } else if (latest.status === 'partial') {
    setPill(t('audit.pillPartial'), 'warn');
  } else {
    setPill(t('audit.pillCompleted'), 'ok');
  }

  const isAdmin = state.role === 'admin';
  const runButton = isAdmin
    ? `<button class="btn small" id="audit-run">${esc(t('audit.run'))}</button>`
    : `<span class="hint">${esc(t('audit.readonlyStart'))}</span>`;
  const header = latest
    ? `<div class="detail-grid">
        <dt>${esc(t('audit.auditId'))}</dt><dd class="mono">${esc(latest.audit_id)}</dd>
        <dt>${esc(t('table.status'))}</dt><dd>${statusBadge(latest.status)}</dd>
        <dt>${esc(t('dashboard.finished'))}</dt><dd>${esc(fmtTime(latest.finished_at))}</dd>
        <dt>${esc(t('audit.scope'))}</dt><dd>${latest.scope === 'container' ? t('audit.containerVisible') : t('audit.hostEnv')}</dd>
        <dt>${esc(t('common.checksFindingsErrors'))}</dt><dd>${latest.checks_total} / ${latest.findings_count} / ${latest.errors_count}</dd>
        <dt>${esc(t('audit.hardeningIndex'))}</dt><dd>${latest.hardening_index ?? '-'}</dd>
        <dt>${esc(t('audit.lynisVersion'))}</dt><dd class="mono">${latest.lynis_available ? esc(latest.lynis_version || t('common.unknown')) : t('audit.unavailable')}</dd>
        <dt>${esc(t('audit.evidenceReport'))}</dt><dd class="mono">${esc(latest.evidence_path || '-')}</dd>
        ${latest.error ? `<dt>${esc(t('audit.error'))}</dt><dd>${esc(latest.error)}</dd>` : ''}
      </div>`
    : `<div class="empty">${esc(t('audit.noRecords'))}${cap.reason ? ` ${esc(cap.reason)}` : ''}</div>`;

  const findingsCard = findings.length ? `
    <div class="card">
      <div class="card-head"><h2>${esc(t('audit.riskFindings', { n: findings.length }))}</h2><span class="hint">${esc(t('audit.eventsWritten', { written: counts.events_ingested || 0, total: findings.length }))}</span></div>
      <div class="table-wrap"><table>
        <thead><tr><th>${esc(t('table.status'))}</th><th>${esc(t('table.severity'))}</th><th>${esc(t('table.check'))}</th><th>${esc(t('table.result'))}</th><th>${esc(t('table.recommendation'))}</th></tr></thead>
        <tbody>${auditCheckRows(findings)}</tbody>
      </table></div>
    </div>` : `<div class="card"><div class="card-head"><h2>${esc(t('containers.riskFindings'))}</h2></div><div class="empty">${esc(t('audit.noFindings'))}</div></div>`;

  const errorsCard = errors.length ? `
    <div class="card">
      <div class="card-head"><h2>${esc(t('audit.errorsTitle', { n: errors.length }))}</h2><span class="hint">${esc(t('audit.notConclusions'))}</span></div>
      <div class="table-wrap"><table>
        <thead><tr><th>${esc(t('table.status'))}</th><th>${esc(t('table.severity'))}</th><th>${esc(t('table.check'))}</th><th>${esc(t('table.result'))}</th><th>${esc(t('table.recommendation'))}</th></tr></thead>
        <tbody>${auditCheckRows(errors)}</tbody>
      </table></div>
    </div>` : '';

  const suggestions = lynis.suggestions || [];
  const suggestionsCard = suggestions.length ? `
    <div class="card">
      <div class="card-head"><h2>${esc(t('audit.lynisRecs', { n: suggestions.length }))}</h2><span class="hint">${esc(t('audit.savedEvidence'))}</span></div>
      <ul class="list-clean">
        ${suggestions.slice(0, 12).map((item) => `<li><span class="mono">${esc(item.test_id)}</span> ${esc(item.text)}</li>`).join('')}
      </ul>
      ${suggestions.length > 12 ? `<p class="hint">${esc(t('audit.moreItems', { n: suggestions.length - 12 }))}</p>` : ''}
    </div>` : '';

  const historyRows = audits.map((item) => `
    <tr>
      <td class="mono">${esc(item.audit_id)}</td>
      <td>${statusBadge(item.status)}</td>
      <td>${item.scope === 'container' ? t('audit.scopeContainer') : t('audit.scopeHost')}</td>
      <td>${item.checks_total}</td>
      <td>${item.findings_count}</td>
      <td>${item.errors_count}</td>
      <td>${item.hardening_index ?? '-'}</td>
      <td class="muted">${esc(fmtTime(item.finished_at || item.created_at))}</td>
    </tr>`).join('');

  const marker = { ok: ['ok', t('audit.doctorOk')], warn: ['warn', t('audit.doctorWarn')], fail: ['danger', t('audit.doctorFail')], info: ['neutral', t('audit.doctorInfo')] };
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
      <strong>${esc(t('audit.readonlyTitle'))}</strong>${esc(summary.scope_note || cap.reason || '')}${esc(t('audit.readonlyTail'))}
    </div>

    <div class="card">
      <div class="card-head"><h2>${esc(t('audit.hostSecurity'))}</h2>${runButton}</div>
      ${header}
      ${counts.checks !== undefined ? `<p class="hint" style="margin-top:10px">${esc(t('audit.counts', { checks: counts.checks, passed: counts.passed || 0, findings: counts.findings || 0, errors: counts.errors || 0, skipped: counts.skipped || 0, events: counts.events_ingested || 0 }))}</p>` : ''}
    </div>

    ${findingsCard}
    ${errorsCard}

    ${systemInfo.os ? `
    <div class="card">
      <div class="card-head"><h2>${esc(t('audit.systemInfo'))}</h2></div>
      <div class="detail-grid">
        <dt>${esc(t('host.hostname'))}</dt><dd>${esc(systemInfo.hostname || '-')}</dd>
        <dt>${esc(t('host.os'))}</dt><dd>${esc(systemInfo.os || '-')}</dd>
        <dt>${esc(t('host.kernel'))}</dt><dd class="mono">${esc(systemInfo.kernel || '-')}</dd>
        <dt>${esc(t('host.architecture'))}</dt><dd>${esc(systemInfo.machine || '-')}</dd>
        <dt>${esc(t('host.containerEnv'))}</dt><dd>${systemInfo.container?.containerized ? esc(t('host.containerYes', { runtime: esc(systemInfo.container.runtime || t('common.unknownRuntime')) })) : t('host.no')}</dd>
        <dt>CPU</dt><dd>${systemInfo.cpu_count ?? '-'}</dd>
        <dt>${esc(t('audit.uptime'))}</dt><dd>${fmtUptime(systemInfo.uptime_seconds)}</dd>
        <dt>${esc(t('audit.load'))}</dt><dd class="mono">${(systemInfo.load_average || []).join(' / ') || '-'}</dd>
        <dt>${esc(t('audit.memoryLabel'))}</dt><dd>${esc(t('audit.memory', { total: fmtBytes(systemInfo.memory_total_bytes), available: fmtBytes(systemInfo.memory_available_bytes) }))}</dd>
      </div>
    </div>` : ''}

    ${suggestionsCard}

    <div class="card">
      <div class="card-head"><h2>${esc(t('audit.history'))}</h2></div>
      <div class="table-wrap"><table>
        <thead><tr><th>${esc(t('table.auditId'))}</th><th>${esc(t('table.status'))}</th><th>${esc(t('table.scope'))}</th><th>${esc(t('table.check'))}</th><th>${esc(t('table.findings'))}</th><th>${esc(t('table.couldNotRun'))}</th><th>${esc(t('table.hardeningIndex'))}</th><th>${esc(t('table.time'))}</th></tr></thead>
        <tbody>${historyRows || `<tr><td colspan="8">${esc(t('audit.noHistory'))}</td></tr>`}</tbody>
      </table></div>
    </div>

    <div class="card">
      <div class="card-head"><h2>${esc(t('audit.selfCheck'))}</h2><button class="btn small ghost" id="doctor-run">${esc(t('audit.checkAgain'))}</button></div>
      <div class="table-wrap"><table>
        <thead><tr><th>${esc(t('table.result'))}</th><th>${esc(t('table.check'))}</th><th>${esc(t('common.details'))}</th><th>${esc(t('table.recommendation'))}</th></tr></thead>
        <tbody>${doctorRows}</tbody>
      </table></div>
      <p class="hint" style="margin-top:10px">${esc(t('audit.summary', { ok: report.summary.ok, warn: report.summary.warn, fail: report.summary.fail, info: report.summary.info, time: fmtTime(report.generated_at) }))}</p>
    </div>

    <div class="card"><div class="card-head"><h2>${esc(t('audit.boundaries'))}</h2></div>
      <ul class="list-clean">
        <li>${esc(t('audit.boundary1'))}</li>
        <li>${esc(t('audit.boundary2'))}</li>
        <li>${esc(t('audit.boundary3'))}</li>
      </ul>
    </div>`;
  const run = $('#audit-run');
  if (run) run.onclick = () => runHostAudit(run);
  $('#doctor-run').onclick = async () => { await renderAudit(); toast(t('audit.selfCheckDone')); };
  $$('[data-goto]').forEach((button) => { button.onclick = () => navigate(button.dataset.goto); });
}

/* --------------------------------------------------------------- settings */
async function renderSettings() {
  const [{ host, daemon }, { components }, { records }] = await Promise.all([
    api('/system/info'),
    api('/components'),
    api('/audit?limit=100'),
  ]);
  setPill(t('settings.pill'), 'info');
  const componentRows = components.map((component) => `
    <li>${esc(t('settings.componentLine', { name: component.display_name, installed: component.installed ? t('status.installed') : t('status.not_installed'), health: STATUS_LABEL[component.health_status] || component.health_status, time: fmtTime(component.last_check_at) }))}</li>`).join('');
  const auditRows = records.map((record) => `
    <tr>
      <td class="muted">${esc(fmtTime(record.created_at))}</td>
      <td>${esc(record.action)}</td>
      <td>${esc(record.actor)}</td>
      <td class="mono">${esc(record.target || '-')}</td>
      <td>${record.result === 'success' ? badge('ok', t('common.success')) : badge('danger', t('common.failed'))}</td>
      <td class="muted">${esc(record.error || '-')}</td>
    </tr>`).join('');
  $('#content').innerHTML = `
    <div class="grid-3">
      <div class="card"><div class="card-head"><h2>${esc(t('settings.daemon'))}</h2></div>
        <dl class="detail-grid">
          <dt>${esc(t('table.version'))}</dt><dd>${esc(daemon.version)}</dd>
          <dt>${esc(t('settings.apiVersion'))}</dt><dd>${esc(daemon.api_version)}</dd>
          <dt>${esc(t('settings.startedAt'))}</dt><dd>${esc(fmtTime(daemon.started_at))}</dd>
          <dt>${esc(t('settings.uptime'))}</dt><dd>${esc(t('settings.minutes', { n: Math.floor(daemon.uptime_seconds / 60) }))}</dd>
          <dt>${esc(t('settings.dataDir'))}</dt><dd class="mono">${esc(daemon.data_dir)}</dd>
          <dt>${esc(t('settings.configFile'))}</dt><dd class="mono">${esc(daemon.config_path)}${daemon.config_loaded ? '' : esc(t('settings.configNotFound'))}</dd>
        </dl>
      </div>
      <div class="card" style="grid-column: span 2"><div class="card-head"><h2>${esc(t('settings.hostEnv'))}</h2></div>
        <dl class="detail-grid">
          <dt>${esc(t('host.hostname'))}</dt><dd>${esc(host.hostname)}</dd>
          <dt>${esc(t('settings.system'))}</dt><dd>${esc(host.os)}</dd>
          <dt>${esc(t('host.kernel'))}</dt><dd class="mono">${esc(host.kernel)}</dd>
          <dt>${esc(t('host.architecture'))}</dt><dd>${esc(host.machine)}</dd>
          <dt>${esc(t('settings.container'))}</dt><dd>${host.container.containerized ? esc(t('host.containerYes', { runtime: esc(host.container.runtime || t('common.unknownRuntime')) })) : t('host.no')}</dd>
          <dt>${esc(t('settings.permissions'))}</dt><dd>UID ${esc(host.uid)}</dd>
        </dl>
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h2>${esc(t('settings.componentRecords'))}</h2><button class="btn small ghost" data-goto="components">${esc(t('common.components'))}</button></div>
      <ul class="list-clean">${componentRows || `<li>${esc(t('settings.noComponentData'))}</li>`}</ul>
    </div>

    <div class="card">
      <div class="card-head"><h2>${esc(t('settings.operationAudit'))}</h2><span class="hint">${esc(t('settings.regularUsers'))}</span></div>
      <div class="table-wrap"><table>
        <thead><tr><th>${esc(t('table.time'))}</th><th>${esc(t('table.timeAction'))}</th><th>${esc(t('table.actor'))}</th><th>${esc(t('table.target'))}</th><th>${esc(t('table.result'))}</th><th>${esc(t('table.error'))}</th></tr></thead>
        <tbody>${auditRows || `<tr><td colspan="6">${esc(t('settings.noAudit'))}</td></tr>`}</tbody>
      </table></div>
    </div>

    <div class="card">
      <div class="card-head"><h2>${esc(t('settings.logs'))}</h2>${state.role === 'admin' ? `<button class="btn small" id="load-logs">${esc(t('settings.readLogs'))}</button>` : ''}</div>
      ${state.role === 'admin'
        ? `<div id="log-view" class="pre" style="max-height:320px">${esc(t('settings.logReadHint'))}</div>`
        : `<div class="empty">${esc(t('settings.logsAdminOnly'))}</div>`}
    </div>`;
  $$('[data-goto]').forEach((button) => { button.onclick = () => navigate(button.dataset.goto); });
  const logsButton = $('#load-logs');
  if (logsButton) {
    logsButton.onclick = async () => {
      try {
        const { lines } = await api('/logs?lines=200');
        $('#log-view').textContent = lines.length ? lines.join('\n') : t('settings.logEmpty');
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
