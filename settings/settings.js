'use strict';
(() => {
  // Pages cannot host the API. Keep operator sessions on the WSGI host using
  // top-level navigation, with no cross-site cookies, CORS credentials or tokens.
  // Publish this route only AFTER the protected PythonAnywhere app is verified.
  if (['https://chillibek.online', 'https://www.chillibek.online'].includes(window.location.origin)) {
    window.location.replace('https://kali.pythonanywhere.com/settings/');
    return;
  }
  const modules = [
    ['sql_injection', 'SQL Injection Protection', 'Inspect requests for SQL keywords, boolean injection, and comment operators.'],
    ['xss', 'XSS Protection', 'Detect script tags, event handlers, and JavaScript URLs.'],
    ['path_traversal', 'Path Traversal Protection', 'Detect encoded traversal sequences and sensitive file paths.'],
    ['rate_limiting', 'Rate Limiting', 'Limit request bursts per client IP.'],
    ['suspicious_headers', 'Suspicious Header Detection', 'Detect ambiguous framing, method overrides, and control characters.'],
    ['request_size', 'Request Size Protection', 'Inspect incoming body size before forwarding to the application.']
  ];
  const $ = id => document.getElementById(id);
  let snapshot = null;
  let busy = false;
  const switches = new Map();
  function control(key, label) {
    const box = document.createElement('div');
    box.className = 'control';
    const state = document.createElement('span');
    state.className = 'state unknown';
    state.textContent = '—';
    const button = document.createElement('button');
    button.type = 'button'; button.className = 'switch'; button.disabled = true;
    button.setAttribute('role', 'switch'); button.setAttribute('aria-label', label);
    button.setAttribute('aria-checked', 'false'); button.appendChild(document.createElement('span'));
    button.addEventListener('click', () => change(key));
    box.append(state, button); switches.set(key, {state, button});
    return box;
  }
  modules.forEach(([key, label, description], index) => {
    const row = document.createElement('div'); row.className = 'rule';
    const number = document.createElement('span'); number.className = 'rule-number';
    number.textContent = String(index + 1).padStart(2, '0');
    const copy = document.createElement('div'); copy.className = 'rule-copy';
    const title = document.createElement('h3'); title.textContent = label;
    const detail = document.createElement('p'); detail.id = `${key}Detail`; detail.textContent = description;
    copy.append(title, detail); row.append(number, copy, control(key, label)); $('rules').appendChild(row);
  });
  $('loggingControl').appendChild(control('event_logging', 'Security Event Logging'));
  switches.set('mode', {state: $('modeState'), button: $('mode')});
  $('mode').addEventListener('click', () => change('mode'));
  function notice(message, kind = '') { $('notice').textContent = message; $('notice').className = `notice ${kind}`; }
  function lock() {
    for (const {button} of switches.values()) button.disabled = busy || !snapshot;
    $('save').disabled = $('reset').disabled = busy || !snapshot;
    $('refresh').disabled = busy;
    $('saveHint').textContent = busy ? 'Waiting for server confirmation…' : snapshot ? 'Changes are saved as you toggle. Save re-applies the confirmed policy.' : 'A live connection is required to change settings.';
    $('rules').setAttribute('aria-busy', String(busy));
  }
  function render(data) {
    if (!data || !data.policy || !Number.isInteger(data.revision) || !data.csrf_token || !['block', 'monitor'].includes(data.policy.mode) ||
        [...switches.keys()].some(key => key !== 'mode' && typeof data.policy[key] !== 'boolean')) {
      throw new Error('The WAF returned an invalid policy.');
    }
    snapshot = data;
    for (const [key, {state, button}] of switches) {
      const enabled = key === 'mode' ? data.policy.mode === 'block' : data.policy[key];
      button.setAttribute('aria-checked', String(enabled));
      state.textContent = key === 'mode' ? (enabled ? 'BLOCK' : 'MONITOR') : (enabled ? 'ON' : 'OFF');
      state.className = `state ${enabled ? '' : key === 'mode' ? 'monitor' : 'off'}`;
    }
    const enabledCount = modules.filter(([key]) => data.policy[key]).length;
    $('protection').textContent = data.policy.mode === 'block' ? (enabledCount ? 'Block mode' : 'No blocking rules') : 'Monitor mode';
    $('protection').className = `status-value ${data.policy.mode === 'monitor' || !enabledCount ? 'monitor' : ''}`;
    $('protectionDetail').textContent = `${enabledCount} of ${modules.length} detection modules enabled`;
    $('updated').textContent = data.updated_at ? new Date(data.updated_at).toLocaleString() : 'Default configuration';
    $('updatedBy').textContent = data.updated_at ? `Updated by ${data.updated_by}` : 'No operator changes yet';
    $('connection').textContent = 'Connected'; $('connection').className = 'status-value';
    $('revision').textContent = `Confirmed policy · revision ${data.revision}`;
    $('auth').hidden = true;
    if (data.limits) {
      $('rate_limitingDetail').textContent = `Allow ${data.limits.rate_requests} requests per ${data.limits.rate_window_seconds}s per client IP in a fixed window.`;
      $('request_sizeDetail').textContent = `Inspect request body size against a ${data.limits.request_bytes.toLocaleString()} byte limit.`;
    }
  }
  function unknown() {
    snapshot = null;
    for (const {state, button} of switches.values()) {
      state.textContent = '—'; state.className = 'state unknown'; button.setAttribute('aria-checked', 'false');
    }
    $('protection').textContent = 'Unknown'; $('protection').className = 'status-value unknown';
    $('protectionDetail').textContent = 'Current policy could not be verified';
    $('connection').textContent = 'WAF API not connected'; $('connection').className = 'status-value unknown';
    $('revision').textContent = 'Refresh to reconnect';
    $('updated').textContent = '—'; $('updatedBy').textContent = 'No confirmed configuration';
  }
  async function api(path = '', method = 'GET', body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);
    try {
      const response = await fetch(`/waf-api/settings${path}`, {
        method, credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
        headers: body ? {'Content-Type': 'application/json', 'X-CSRF-Token': snapshot.csrf_token} : {},
        body: body ? JSON.stringify(body) : undefined
      });
      if (response.status === 401) { const error = new Error('Your operator session is required. Sign in to continue.'); error.auth = true; throw error; }
      const data = await response.json().catch(() => { throw new Error('WAF API not connected. Management controls require the authenticated WAF API.'); });
      if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `Settings rejected (HTTP ${response.status}).`);
      return data;
    } finally { clearTimeout(timer); }
  }
  async function refresh(quiet = false) {
    if (busy) return;
    busy = true; lock();
    try { render(await api()); if (!quiet) notice('Current policy loaded from the WAF backend.', 'success'); }
    catch (error) { unknown(); $('auth').hidden = !error.auth; notice(error.message || 'Unable to reach the WAF backend.', 'error'); }
    finally { busy = false; lock(); }
  }
  async function write(policy, reset = false) {
    if (busy || !snapshot) return;
    busy = true; lock(); notice(reset ? 'Resetting the server policy…' : 'Saving the server policy…');
    try {
      const body = reset ? {revision: snapshot.revision} : {revision: snapshot.revision, policy};
      render(await api(reset ? '/reset' : '', reset ? 'POST' : 'PUT', body));
      notice(reset ? 'Default protections restored and persisted.' : 'Settings confirmed by the WAF. Policy saved and active.', 'success');
    } catch (error) {
      // Reconcile even after timeouts: a server may have committed before the response was lost.
      try { render(await api()); notice(`${error.message} Current server policy reloaded; verify the switches before retrying.`, 'error'); }
      catch (reloadError) { unknown(); $('auth').hidden = !(error.auth || reloadError.auth); notice(`${error.message} The current policy could not be verified. Refresh to reconnect.`, 'error'); }
    } finally { busy = false; lock(); }
  }
  function change(key) {
    if (!snapshot || busy) return;
    const policy = {...snapshot.policy};
    policy[key] = key === 'mode' ? (policy.mode === 'block' ? 'monitor' : 'block') : !policy[key];
    write(policy);
  }
  $('save').addEventListener('click', () => snapshot && write({...snapshot.policy}));
  $('reset').addEventListener('click', () => write(null, true));
  $('refresh').addEventListener('click', () => refresh());
  window.addEventListener('focus', () => refresh(true));
  setInterval(() => { if (!document.hidden) refresh(true); }, 30000);
  refresh();
})();
