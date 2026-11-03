'use strict';
(() => {
  const modules = [
    ['sql_injection', 'SQL Injection Protection', 'Inspect parsed fields for SQL sequences, boolean conditions, delay functions, and obfuscation.'],
    ['xss', 'XSS Protection', 'Detect script tags, event handlers, and JavaScript URLs.'],
    ['path_traversal', 'Path Traversal Protection', 'Detect encoded traversal sequences and sensitive file paths.'],
    ['command_injection', 'Command Injection Protection', 'Detect shell substitution and chained executable commands.'],
    ['suspicious_headers', 'Suspicious Header Detection', 'Detect method-override headers. Unsafe HTTP framing is always rejected.'],
    ['rate_limiting', 'Global and Route Rate Limiting', 'Limit request bursts per client IP and route.'],
    ['request_size', 'Request Size Protection', 'Apply the configured body-size limit. A hard resource ceiling always remains active.'],
    ['brute_force', 'Login Abuse Protection', 'Use the shared persistent account and IP failure policy. Production keeps this control mandatory.'],
    ['bot_detection', 'Scanner Behavior Protection', 'Detect repeated missing-endpoint probing without trusting User-Agent labels.']
  ];
  const fields = [
    ['rate_limit_requests', 'Global requests per IP', 1, 10000],
    ['rate_limit_window_seconds', 'Global window (seconds)', 1, 3600],
    ['route_limit_requests', 'Requests per route and IP', 1, 5000],
    ['route_limit_window_seconds', 'Route window (seconds)', 1, 3600],
    ['bot_detection_limit', 'Scanner probes per IP', 1, 1000],
    ['bot_detection_window_seconds', 'Scanner tracking window (seconds)', 1, 3600],
    ['request_size_bytes', 'Request body limit (bytes)', 1024, 4194304],
    ['login_max_attempts', 'Failed attempts per account', 1, 100],
    ['login_ip_max_attempts', 'Failed attempts per IP', 1, 1000],
    ['login_window_seconds', 'Login tracking window (seconds)', 60, 86400],
    ['login_initial_lockout_seconds', 'Initial lockout (seconds)', 5, 3600],
    ['login_lockout_multiplier', 'Progressive lockout multiplier', 1, 10],
    ['login_max_lockout_seconds', 'Maximum lockout (seconds)', 30, 86400]
  ];
  const $ = id => document.getElementById(id);
  const cspDirectives = ['script_src', 'style_src', 'img_src', 'connect_src', 'object_src', 'base_uri', 'frame_ancestors', 'form_action'];
  for (const key of cspDirectives) {
    const label = document.createElement('label'); label.textContent = key.replaceAll('_', '-');
    const input = document.createElement('input'); input.id = `csp-${key}`; input.maxLength = 2048;
    input.dataset.cspField = key; input.disabled = true;
    label.appendChild(input); $('cspFields').appendChild(label);
  }
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
    const heading = {sql_injection: 'Request content', rate_limiting: 'Resource limits', brute_force: 'Behavior and login abuse'}[key];
    if (heading) {
      const group = document.createElement('h3'); group.className = 'nav-label'; group.textContent = heading;
      $('rules').appendChild(group);
    }
    const row = document.createElement('div'); row.className = 'rule';
    const number = document.createElement('span'); number.className = 'rule-number';
    number.textContent = String(index + 1).padStart(2, '0');
    const copy = document.createElement('div'); copy.className = 'rule-copy';
    const title = document.createElement('h3'); title.textContent = label;
    const detail = document.createElement('p'); detail.id = `${key}Detail`; detail.textContent = description;
    copy.append(title, detail); row.append(number, copy, control(key, label)); $('rules').appendChild(row);
  });
  for (const [key, label, min, max] of fields) {
    const labelElement = document.createElement('label');
    labelElement.textContent = label;
    const input = document.createElement('input');
    input.type = 'number'; input.id = `field-${key}`; input.dataset.policyField = key;
    input.min = String(min); input.max = String(max); input.step = '1'; input.required = true;
    labelElement.appendChild(input); $('policyFields').appendChild(labelElement);
  }
  $('loggingControl').appendChild(control('event_logging', 'Security Event Logging'));
  switches.set('mode', {state: $('modeState'), button: $('mode')});
  $('mode').addEventListener('click', () => change('mode'));
  function notice(message, kind = '') { $('notice').textContent = message; $('notice').className = `notice ${kind}`; }
  function lock() {
    for (const [key, {button}] of switches) {
      button.disabled = busy || !snapshot ||
        (key === 'brute_force' && !snapshot.capabilities.allow_disabled_mode) ||
        (key !== 'mode' && snapshot.policy.mode === 'disabled');
    }
    $('save').disabled = $('reset').disabled = busy || !snapshot;
    $('refresh').disabled = busy;
    for (const id of ['cspMode', 'cspTrustedTypes', 'cspSave', ...cspDirectives.map(key => `csp-${key}`)]) $(id).disabled = busy || !snapshot;
    for (const input of document.querySelectorAll('[data-policy-field]')) input.disabled = busy || !snapshot;
    for (const id of ['blockKind', 'blockValue', 'blockDuration', 'blockReason', 'createBlock']) $(id).disabled = busy || !snapshot;
    $('saveHint').textContent = busy ? 'Waiting for server confirmation…' : snapshot ? 'Policy changes are saved after server confirmation.' : 'A live connection is required to change settings.';
    $('rules').setAttribute('aria-busy', String(busy));
  }
  function addText(parent, tag, value, className = '') {
    const element = document.createElement(tag);
    element.textContent = value == null ? '—' : String(value);
    if (className) element.className = className;
    parent.appendChild(element);
    return element;
  }
  function renderBlocks(data) {
    const enforcedBlocks = data.blocks.filter(item => item.enforced).length;
    $('blockCount').textContent = `${enforcedBlocks} ENFORCED · ${data.blocks.length - enforcedBlocks} SUSPENDED`;
    const target = $('blocks');
    target.replaceChildren();
    if (!data.blocks.length) addText(target, 'p', 'No active blocks.');
    for (const item of data.blocks) {
      const row = document.createElement('div'); row.className = 'block-row';
      const info = document.createElement('div'); info.className = 'block-info';
      addText(info, 'strong', `${item.kind.toUpperCase()} · ${item.identifier}`);
      addText(info, 'span', `${item.enforced ? 'Enforced' : 'Suspended by policy mode'} (${item.scope || 'staff login'}) · ${item.reason} · ${item.rule_id} · ${item.attempts} attempts · ${item.manual ? 'Manual' : 'Automatic'}`);
      addText(info, 'small', `Started ${new Date(item.started_at).toLocaleString()} · Expires ${item.expires_at ? new Date(item.expires_at).toLocaleString() : 'never'}`);
      const remaining = addText(info, 'small', item.remaining_seconds == null ? 'No expiry' : `${item.remaining_seconds}s remaining`);
      if (item.remaining_seconds != null) {
        remaining.dataset.remainingSeconds = String(item.remaining_seconds);
        remaining.dataset.startedAt = String(Date.now());
      }
      const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'button danger';
      remove.textContent = 'Unblock'; remove.addEventListener('click', () => unblock(item.id));
      row.append(info, remove); target.appendChild(row);
    }
    const history = $('blockHistory');
    history.replaceChildren();
    if (!data.block_history.length) addText(history, 'p', 'No block actions recorded.');
    for (const item of data.block_history) {
      const row = document.createElement('div'); row.className = 'history-row';
      addText(row, 'strong', `${item.action.replaceAll('_', ' ').toUpperCase()} · ${item.details.kind} · ${item.details.identifier}`);
      addText(row, 'span', `${item.details.reason} · ${item.details.rule_id} · ${item.actor || 'system'} · ${new Date(item.timestamp).toLocaleString()}`);
      history.appendChild(row);
    }
  }
  function updateBlockCountdowns() {
    if (document.hidden) return;
    for (const element of document.querySelectorAll('[data-remaining-seconds]')) {
      const elapsed = Math.floor((Date.now() - Number(element.dataset.startedAt)) / 1000);
      element.textContent = `${Math.max(0, Number(element.dataset.remainingSeconds) - elapsed)}s remaining`;
    }
  }
  function render(data) {
    if (!data || !data.policy || !Number.isInteger(data.revision) || !data.csrf_token ||
        !['block', 'monitor', 'disabled'].includes(data.policy.mode) ||
        [...switches.keys()].some(key => key !== 'mode' && typeof data.policy[key] !== 'boolean') ||
        fields.some(([key]) => !Number.isInteger(data.policy[key])) ||
        !data.capabilities || typeof data.capabilities.allow_disabled_mode !== 'boolean' ||
        !data.effective || !Number.isInteger(data.effective.rate_limit_requests) ||
        !Number.isInteger(data.effective.rate_limit_window_seconds) ||
        !Number.isInteger(data.effective.route_limit_requests) ||
        !Number.isInteger(data.effective.route_limit_window_seconds) ||
        !Number.isInteger(data.effective.request_size_bytes) ||
        !Number.isInteger(data.effective.hard_request_size_bytes) ||
        !Array.isArray(data.blocks) || data.blocks.some(item => typeof item.enforced !== 'boolean') ||
        !Array.isArray(data.block_history) || !data.csp_coverage || !data.policy.csp ||
        !['enforce', 'off', 'report-only'].includes(data.policy.csp.mode) ||
        cspDirectives.some(key => !Array.isArray(data.policy.csp[key]))) {
      throw new Error('The WAF returned an invalid policy.');
    }
    snapshot = data;
    $('cspMode').value = data.policy.csp.mode;
    $('cspTrustedTypes').checked = data.policy.csp.trusted_types;
    $('cspEffective').textContent = `SERVED HTML: ${data.csp_coverage.effective_mode.toUpperCase()}`;
    $('cspCoverage').textContent = `Management: ${data.csp_coverage.management}. Restaurant: ${data.csp_coverage.restaurant}. GitHub Pages: ${data.csp_coverage.github_pages}. Live production deployment: unverified.`;
    for (const key of cspDirectives) $(`csp-${key}`).value = data.policy.csp[key].join(' ');
    for (const [key, {state, button}] of switches) {
      const configured = key === 'mode' ? data.policy.mode === 'block' : data.policy[key];
      const enabled = key === 'mode' ? configured : configured && data.policy.mode !== 'disabled';
      button.setAttribute('aria-checked', String(enabled));
      state.textContent = key === 'mode'
        ? data.policy.mode.toUpperCase()
        : data.policy.mode === 'disabled' ? 'INACTIVE'
          : key === 'brute_force' && !data.capabilities.allow_disabled_mode ? 'REQUIRED' : enabled ? 'ON' : 'OFF';
      state.className = `state ${enabled ? '' : key === 'mode' || data.policy.mode === 'disabled' ? 'monitor' : 'off'}`;
    }
    const enabledCount = data.policy.mode === 'disabled' ? 0 : modules.filter(([key]) => data.policy[key]).length;
    $('protection').textContent = data.policy.mode === 'disabled'
      ? 'Disabled · isolated test only'
      : data.policy.mode === 'block' ? 'Block mode' : 'Monitor mode';
    $('protection').className = `status-value ${data.policy.mode === 'monitor' || data.policy.mode === 'disabled' ? 'monitor' : ''}`;
    $('protectionDetail').textContent = `${enabledCount} of ${modules.length} detection modules active · Login abuse: ${data.effective.login_abuse.replaceAll('_', ' ')}`;
    $('updated').textContent = data.updated_at ? new Date(data.updated_at).toLocaleString() : 'Default configuration';
    $('updatedBy').textContent = data.updated_at ? `Updated by ${data.updated_by}` : 'No operator changes yet';
    $('connection').textContent = 'Connected'; $('connection').className = 'status-value';
    $('revision').textContent = `Confirmed policy · revision ${data.revision}`;
    $('auth').hidden = true;
    $('mode').setAttribute('aria-label', `Firewall mode: ${data.policy.mode}`);
    for (const [key] of fields) $(`field-${key}`).value = data.policy[key];
    const bodyMode = data.policy.mode === 'disabled' || !data.policy.request_size
      ? 'Optional body-size protection is inactive'
      : data.policy.mode === 'monitor' ? 'Monitor only' : 'Enforced';
    $('request_sizeDetail').textContent =
      `${bodyMode}: ${data.effective.request_size_bytes.toLocaleString()} bytes; hard resource ceiling: ${data.effective.hard_request_size_bytes.toLocaleString()} bytes.` +
      (data.effective.backend_body_size_bytes ? ` Backend JSON parsing ceiling: ${data.effective.backend_body_size_bytes.toLocaleString()} bytes (always active).` : '');
    const rateMode = data.policy.mode === 'disabled' || !data.policy.rate_limiting
      ? 'Inactive'
      : data.policy.mode === 'monitor' ? 'Monitor only' : 'Enforced';
    $('rate_limitingDetail').textContent =
      `${rateMode}. Effective limits: ${data.effective.rate_limit_requests} requests per IP / ${data.effective.rate_limit_window_seconds}s; ${data.effective.route_limit_requests} per route and IP / ${data.effective.route_limit_window_seconds}s. Deployment ceilings may reduce the configured thresholds.`;
    $('brute_forceDetail').textContent = data.policy.mode === 'disabled'
      ? 'Optional controls are inactive in this isolated test mode; password verification and operator security remain active.'
      : data.capabilities.allow_disabled_mode
      ? 'Isolated test mode only: disabling login abuse throttling never disables password verification.'
      : `Enforced in production, including Monitor mode: ${data.policy.login_max_attempts} failures per account or ${data.policy.login_ip_max_attempts} per IP in ${data.policy.login_window_seconds}s.`;
    renderBlocks(data);
  }
  function unknown() {
    snapshot = null;
    $('cspEffective').textContent = 'UNKNOWN';
    $('cspCoverage').textContent = 'Coverage not verified. GitHub Pages HTML is not covered by backend headers.';
    for (const {state, button} of switches.values()) {
      state.textContent = '—'; state.className = 'state unknown'; button.setAttribute('aria-checked', 'false');
    }
    $('protection').textContent = 'Unknown'; $('protection').className = 'status-value unknown';
    $('protectionDetail').textContent = 'Current policy could not be verified';
    $('connection').textContent = 'WAF API not connected'; $('connection').className = 'status-value unknown';
    $('revision').textContent = 'Refresh to reconnect';
    $('updated').textContent = '—'; $('updatedBy').textContent = 'No confirmed configuration';
    $('blocks').replaceChildren(); $('blockHistory').replaceChildren();
  }
  async function api(path = '', method = 'GET', body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);
    try {
      const url = path.startsWith('/waf-api/') ? path : `/waf-api/settings${path}`;
      const response = await fetch(url, {
        method, credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
        headers: method === 'GET' ? {} : {
          'Content-Type': 'application/json', 'X-CSRF-Token': snapshot.csrf_token
        },
        body: method === 'GET' ? undefined : JSON.stringify(body || {})
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
    try { render(await api()); if (!quiet) notice('Current policy and active blocks loaded from the WAF backend.', 'success'); }
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
      try { render(await api()); notice(`${error.message} Current server policy reloaded; verify the switches before retrying.`, 'error'); }
      catch (reloadError) { unknown(); $('auth').hidden = !(error.auth || reloadError.auth); notice(`${error.message} The current policy could not be verified. Refresh to reconnect.`, 'error'); }
    } finally { busy = false; lock(); }
  }
  function policyFromForm() {
    const policy = {...snapshot.policy};
    policy.csp = {...snapshot.policy.csp, mode: $('cspMode').value, trusted_types: $('cspTrustedTypes').checked};
    for (const key of cspDirectives) policy.csp[key] = $(`csp-${key}`).value.trim().split(/\s+/);
    for (const [key] of fields) {
      const input = $(`field-${key}`);
      const value = input.valueAsNumber;
      if (!input.checkValidity() || !Number.isInteger(value)) {
        input.reportValidity();
        return null;
      }
      policy[key] = value;
    }
    return policy;
  }
  function change(key) {
    if (!snapshot || busy || (key !== 'mode' && snapshot.policy.mode === 'disabled')) return;
    const policy = {...snapshot.policy};
    if (key === 'mode') {
      policy.mode = policy.mode === 'block' ? 'monitor'
        : policy.mode === 'monitor' && snapshot.capabilities.allow_disabled_mode ? 'disabled' : 'block';
    } else {
      policy[key] = !policy[key];
    }
    write(policy);
  }
  async function blockAction(path, method, body, message) {
    if (busy || !snapshot) return;
    busy = true; lock();
    try { render(await api(path, method, body)); notice(message, 'success'); }
    catch (error) { notice(error.message || 'Block operation failed.', 'error'); }
    finally { busy = false; lock(); }
  }
  function unblock(id) {
    blockAction(`/waf-api/blocks/${encodeURIComponent(id)}`, 'DELETE', {}, 'Block removed and login enforcement state cleared.');
  }
  $('blockForm').addEventListener('submit', event => {
    event.preventDefault();
    const value = $('blockValue').value.trim();
    const reason = $('blockReason').value.trim();
    const duration = $('blockDuration').valueAsNumber;
    if (!$('blockForm').checkValidity() || !Number.isInteger(duration)) {
      $('blockForm').reportValidity();
      return;
    }
    blockAction('/waf-api/blocks', 'POST', {
      kind: $('blockKind').value, value, reason, duration_seconds: duration
    }, 'Manual block saved; enforcement depends on the active policy mode.');
  });
  $('save').addEventListener('click', () => {
    if (!snapshot) return;
    const policy = policyFromForm();
    if (policy) write(policy);
  });
  $('reset').addEventListener('click', () => write(null, true));
  $('cspSave').addEventListener('click', () => {
    if (!snapshot || busy) return;
    const policy = policyFromForm(); if (policy) write(policy);
  });
  $('refresh').addEventListener('click', () => refresh());
  window.addEventListener('focus', () => refresh(true));
  setInterval(updateBlockCountdowns, 1000);
  setInterval(() => { if (!document.hidden) refresh(true); }, 30000);
  refresh();
})();
