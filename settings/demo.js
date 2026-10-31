'use strict';
(() => {
  const $ = id => document.getElementById(id);
  let state = null;
  let busy = false;

  function notice(message, kind = '') {
    $('notice').textContent = message;
    $('notice').className = `notice ${kind}`;
  }

  function text(parent, tag, value, className = '') {
    const element = document.createElement(tag);
    element.textContent = value == null ? '—' : String(value);
    if (className) element.className = className;
    parent.appendChild(element);
    return element;
  }

  function lock() {
    for (const id of ['threshold', 'lockout', 'savePolicy', 'turnOff', 'turnOn', 'username', 'password', 'sendOne', 'sendTwenty']) {
      $(id).disabled = busy || !state;
    }
  }

  async function api(path = '/waf-api/demo', method = 'GET', body) {
    const response = await fetch(path, {
      method,
      credentials: 'same-origin',
      cache: 'no-store',
      headers: method === 'GET' ? {} : {
        'Content-Type': 'application/json',
        'X-CSRF-Token': state.csrf_token
      },
      body: method === 'GET' ? undefined : JSON.stringify(body)
    });
    const data = await response.json().catch(() => {
      throw new Error('The authenticated WAF API returned an unreadable response.');
    });
    if (!response.ok) {
      const error = new Error(typeof data.detail === 'string' ? data.detail
        : typeof data.message === 'string' ? data.message : `WAF API failed (HTTP ${response.status}).`);
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function renderBlocks(blocks) {
    const target = $('activeBlock');
    target.replaceChildren();
    const active = blocks.filter(block => block.enforced);
    if (!active.length) {
      text(target, 'p', blocks.length ? 'Stored demo blocks are currently suspended while WAF is OFF.' : 'No active demo blocks.');
      return;
    }
    for (const block of active) {
      const row = document.createElement('div');
      row.className = 'block-row';
      const info = document.createElement('div');
      info.className = 'block-info';
      text(info, 'strong', `${block.identifier} · ${block.rule_id} · ${block.attempts} failed attempts`);
      text(info, 'small', block.reason);
      const countdown = text(info, 'small', `${block.remaining_seconds}s remaining`, 'countdown');
      countdown.dataset.remainingSeconds = String(block.remaining_seconds);
      countdown.dataset.startedAt = String(Date.now());
      const unblock = document.createElement('button');
      unblock.type = 'button';
      unblock.className = 'button danger';
      unblock.textContent = 'Unblock now';
      unblock.addEventListener('click', () => removeBlock(block.id));
      row.append(info, unblock);
      target.appendChild(row);
    }
  }

  function renderHistory(items) {
    const target = $('history');
    target.replaceChildren();
    if (!items.length) text(target, 'p', 'No demo block audit events yet.');
    for (const item of items) {
      const row = document.createElement('div');
      row.className = 'history-row';
      text(row, 'strong', `${item.action.replaceAll('_', ' ').toUpperCase()} · ${item.details.identifier}`);
      text(row, 'span', `${item.details.reason} · ${item.actor || 'system'} · ${new Date(item.timestamp).toLocaleString()}`);
      target.appendChild(row);
    }
  }

  function updateCountdowns() {
    if (document.hidden) return;
    for (const element of document.querySelectorAll('[data-remaining-seconds]')) {
      const elapsed = Math.floor((Date.now() - Number(element.dataset.startedAt)) / 1000);
      element.textContent = `${Math.max(0, Number(element.dataset.remainingSeconds) - elapsed)}s remaining`;
    }
  }

  function render(data) {
    if (!data || !Number.isInteger(data.revision) || typeof data.enabled !== 'boolean' ||
        !Number.isInteger(data.threshold) || !Number.isInteger(data.lockout_seconds) ||
        !data.csrf_token || data.demo_account?.username !== 'demo_waiter' ||
        !Array.isArray(data.blocks) || !Array.isArray(data.block_history)) {
      throw new Error('The WAF returned an invalid demo policy.');
    }
    state = data;
    $('state').textContent = data.enabled ? 'ON · BLOCK' : 'OFF · NO THROTTLE';
    $('state').className = `status-value ${data.enabled ? '' : 'monitor'}`;
    $('enabledLabel').textContent = data.enabled ? 'ON' : 'OFF';
    $('policySummary').textContent = `${data.threshold} failed attempts · ${data.lockout_seconds}s lockout · isolated from staff logins`;
    $('demoPassword').textContent = data.demo_account.password;
    $('threshold').value = data.threshold;
    $('lockout').value = data.lockout_seconds;
    renderBlocks(data.blocks);
    renderHistory(data.block_history);
    lock();
  }

  function addResult(status, message) {
    const target = $('attemptResults');
    const row = document.createElement('div');
    row.className = 'history-row';
    text(row, 'strong', `HTTP ${status}`);
    text(row, 'span', message);
    target.prepend(row);
    while (target.children.length > 40) target.lastElementChild.remove();
    $('lastStatus').textContent = `HTTP ${status}`;
    $('lastStatus').className = `status-value ${status === 429 ? 'monitor' : ''}`;
    $('lastMessage').textContent = message;
  }

  async function refresh() {
    if (busy) return;
    busy = true;
    lock();
    try {
      render(await api());
      notice('Isolated demo policy and block state loaded from the WAF.', 'success');
    } catch (error) {
      state = null;
      lock();
      notice(`${error.message} Sign in again if your operator session expired.`, 'error');
    } finally {
      busy = false;
      lock();
    }
  }

  async function savePolicy(enabled) {
    if (busy || !state) return;
    const threshold = $('threshold').valueAsNumber;
    const lockoutSeconds = $('lockout').valueAsNumber;
    if (!Number.isInteger(threshold) || !Number.isInteger(lockoutSeconds) ||
        !$('threshold').checkValidity() || !$('lockout').checkValidity()) {
      $('threshold').reportValidity();
      $('lockout').reportValidity();
      return;
    }
    busy = true;
    lock();
    try {
      render(await api('/waf-api/demo', 'PUT', {
        revision: state.revision, enabled,
        threshold, lockout_seconds: lockoutSeconds
      }));
      notice(`Demo login-abuse protection is ${enabled ? 'ON' : 'OFF'}; only the synthetic account is affected.`, 'success');
    } catch (error) {
      notice(error.message, 'error');
      try {
        render(await api());
      } catch (reloadError) {
        state = null;
        lock();
        notice(`${error.message} Current demo policy could not be verified: ${reloadError.message}`, 'error');
      }
    } finally {
      busy = false;
      lock();
    }
  }

  async function sendAttempt() {
    const response = await fetch('/waf-api/demo/login', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': state.csrf_token},
      body: JSON.stringify({username: 'demo_waiter', password: $('password').value})
    });
    const data = await response.json().catch(() => ({}));
    addResult(response.status, data.message || (data.success ? 'Synthetic demo login verified.' : 'Request rejected.'));
    return response.status;
  }

  async function runAttempts(count) {
    if (busy || !state) return;
    busy = true;
    lock();
    notice(`Sending ${count === 1 ? 'one' : 'up to 20'} synthetic request${count === 1 ? '' : 's'}…`);
    try {
      for (let index = 0; index < count; index++) {
        const status = await sendAttempt();
        if (status === 429) break;
      }
      await refreshAfterAction();
    } catch (error) {
      notice(error.message, 'error');
    } finally {
      busy = false;
      lock();
    }
  }

  async function removeBlock(id) {
    if (busy || !state) return;
    busy = true;
    lock();
    try {
      render(await api(`/waf-api/demo/blocks/${encodeURIComponent(id)}`, 'DELETE', {}));
      notice('Synthetic account unblocked immediately.', 'success');
    } catch (error) {
      notice(error.message, 'error');
    } finally {
      busy = false;
      lock();
    }
  }

  async function refreshAfterAction() {
    render(await api());
    notice('Synthetic requests completed. Status codes above are real WAF endpoint responses.', 'success');
  }

  $('policyForm').addEventListener('submit', event => {
    event.preventDefault();
    savePolicy(state?.enabled ?? false);
  });
  $('turnOff').addEventListener('click', () => savePolicy(false));
  $('turnOn').addEventListener('click', () => savePolicy(true));
  $('attemptForm').addEventListener('submit', event => {
    event.preventDefault();
    runAttempts(1);
  });
  $('sendTwenty').addEventListener('click', () => runAttempts(20));
  refresh();
  setInterval(updateCountdowns, 1000);
  setInterval(async () => {
    if (document.hidden) return;
    try {
      render(await api());
    } catch (error) {
      notice(`Unable to refresh isolated demo state: ${error.message}`, 'error');
    }
  }, 30000);
})();
