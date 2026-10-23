// Optional real-browser checks using Node 24's built-in WebSocket and Chrome CDP.
// Start the synthetic server documented in browser_fixture.py, then a dedicated
// headless Chrome with --remote-debugging-port=9222 and an isolated user-data-dir.
// Run: node waf/tests/browser_settings.mjs
import assert from 'node:assert/strict';
import {mkdir, writeFile} from 'node:fs/promises';

const target = await fetch('http://127.0.0.1:9222/json/new?about:blank', {method: 'PUT'}).then(r => r.json());
const socket = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {socket.addEventListener('open', resolve, {once: true}); socket.addEventListener('error', reject, {once: true});});
let sequence = 0;
const pending = new Map();
let rejectWrites = false;
let rejectedWrites = 0;
const errors = [];
socket.addEventListener('message', ({data}) => {
  const message = JSON.parse(data);
  if (message.id) {
    const request = pending.get(message.id); pending.delete(message.id);
    if (request) message.error ? request.reject(new Error(JSON.stringify(message.error))) : request.resolve(message.result);
  }
  if (message.method === 'Runtime.exceptionThrown') errors.push(message.params.exceptionDetails.text);
  if (message.method === 'Fetch.requestPaused') {
    const event = message.params;
    if (rejectWrites && event.request.method === 'PUT') {
      rejectedWrites++;
      command('Fetch.fulfillRequest', {requestId: event.requestId, responseCode: 403,
        responseHeaders: [{name: 'Content-Type', value: 'application/json'}],
        body: Buffer.from(JSON.stringify({detail: 'Synthetic rejection for browser verification.'})).toString('base64')}).catch(error => errors.push(error.message));
    } else command('Fetch.continueRequest', {requestId: event.requestId}).catch(error => errors.push(error.message));
  }
});
function command(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    pending.set(id, {resolve, reject}); socket.send(JSON.stringify({id, method, params}));
  });
}
async function evaluate(expression) {
  const result = await command('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true});
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
  return result.result.value;
}
async function waitFor(expression) {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (await evaluate(expression)) return;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error(`Timed out: ${expression}`);
}
const switchFor = label => `document.querySelector('button[aria-label="${label}"]')`;
const checked = label => `${switchFor(label)}?.getAttribute('aria-checked')`;
const enabled = label => `${switchFor(label)} && !${switchFor(label)}.disabled`;
const snapshot = `fetch('/waf-api/settings',{cache:'no-store'}).then(r=>r.json())`;
const click = expression => evaluate(`${expression}.click()`);
let passed = 0;
function pass(name) { passed++; process.stdout.write(`PASS ${name}\n`); }
try {
  await command('Page.enable'); await command('Runtime.enable'); await command('Network.enable');
  await command('Page.navigate', {url: 'http://127.0.0.1:8765/settings'});
  await waitFor(`document.getElementById('auth') && !document.getElementById('auth').hidden`);
  assert.equal(await evaluate(`document.getElementById('protection').textContent`), 'Unknown');
  assert.equal(await evaluate(`${switchFor('SQL Injection Protection')}.disabled`), true);
  pass('Unauthenticated page shows Unknown and disabled controls');

  await command('Page.navigate', {url: 'http://127.0.0.1:8765/dashboard/login?next=/settings'});
  await waitFor(`document.querySelector('input[name="password"]') !== null`);
  await evaluate(`document.querySelector('input[name="username"]').value='synthetic-operator';
    document.querySelector('input[name="password"]').value='synthetic-browser-password';
    document.querySelector('form').requestSubmit()`);
  await waitFor(`location.pathname === '/settings/' && ${enabled('SQL Injection Protection')}`);
  assert.equal(await evaluate(checked('SQL Injection Protection')), 'true');
  pass('Real dashboard login loads confirmed server policy');

  await click(switchFor('SQL Injection Protection'));
  await waitFor(`${enabled('SQL Injection Protection')} && ${checked('SQL Injection Protection')} === 'false'`);
  assert.equal((await evaluate(snapshot)).policy.sql_injection, false);
  assert.equal(await evaluate(checked('XSS Protection')), 'true');
  const response = await evaluate(`fetch('/api/menu?q='+encodeURIComponent("' OR 1=1 --")).then(r=>r.status)`);
  assert.equal(response, 200);
  await command('Page.reload');
  await waitFor(`${enabled('SQL Injection Protection')} && ${checked('SQL Injection Protection')} === 'false'`);
  pass('Toggle changes the real policy and survives a page reload');

  await command('Fetch.enable', {patterns: [{urlPattern: '*waf-api/settings', requestStage: 'Request'}]});
  rejectWrites = true;
  await click(switchFor('SQL Injection Protection'));
  await waitFor(`document.getElementById('notice').textContent.includes('Synthetic rejection') && ${enabled('SQL Injection Protection')}`);
  assert.equal(rejectedWrites, 1);
  assert.equal(await evaluate(checked('SQL Injection Protection')), 'false');
  assert.equal((await evaluate(snapshot)).policy.sql_injection, false);
  rejectWrites = false;
  await command('Fetch.disable');
  pass('Rejected ON update retains the actual OFF state and reports the error');

  await click(`document.getElementById('mode')`);
  await waitFor(`${enabled('Master WAF Block mode')} && document.getElementById('modeState').textContent === 'MONITOR'`);
  assert.equal((await evaluate(snapshot)).policy.mode, 'monitor');
  await click(`document.getElementById('save')`);
  await waitFor(`document.getElementById('notice').textContent.includes('Policy saved and active') && !document.getElementById('save').disabled`);
  await click(`document.getElementById('reset')`);
  await waitFor(`${enabled('SQL Injection Protection')} && ${checked('SQL Injection Protection')} === 'true' && document.getElementById('modeState').textContent === 'BLOCK'`);
  const defaults = await evaluate(snapshot);
  assert.equal(defaults.policy.mode, 'block');
  assert.equal(defaults.policy.event_logging, true);
  assert.equal(await evaluate(`fetch('/api/menu?q='+encodeURIComponent("' OR 1=1 --")).then(r=>r.status)`), 403);
  pass('Master mode, Save Settings and Reset to Defaults affect the real server');

  for (const [key, label] of [
    ['mode', 'Master WAF Block mode'], ['sql_injection', 'SQL Injection Protection'],
    ['xss', 'XSS Protection'], ['path_traversal', 'Path Traversal Protection'],
    ['rate_limiting', 'Rate Limiting'], ['suspicious_headers', 'Suspicious Header Detection'],
    ['request_size', 'Request Size Protection'], ['event_logging', 'Security Event Logging'],
    ['command_injection', 'Command Injection Protection'], ['brute_force', 'Login Abuse Protection'],
    ['bot_detection', 'Scanner Behavior Protection']
  ]) {
    const before = await evaluate(snapshot);
    const changed = key === 'mode' ? 'monitor' : false;
    await click(switchFor(label));
    await waitFor(`${enabled(label)} && ${checked(label)} === 'false'`);
    const saved = await evaluate(snapshot);
    assert.equal(saved.policy[key], changed);
    assert.deepEqual(Object.keys(before.policy).filter(name => before.policy[name] !== saved.policy[name]), [key]);
    // The marker disappears only when a new page has actually loaded; this avoids
    // accidentally checking the old DOM while the browser is still reloading.
    await evaluate('window.__wafReloadMarker = true');
    await command('Page.reload');
    await waitFor(`window.__wafReloadMarker !== true && ${enabled(label)} && ${checked(label)} === 'false'`);
    assert.equal((await evaluate(snapshot)).policy[key], changed);
    await click(switchFor(label));
    await waitFor(`${enabled(label)} && ${checked(label)} === 'true'`);
    assert.deepEqual((await evaluate(snapshot)).policy, before.policy);
  }
  pass('All eleven switches save independently, survive page refresh, and restore');

  await mkdir('waf/local', {recursive: true});
  for (const [name, width, height] of [['desktop', 1440, 1300], ['mobile', 390, 844]]) {
    await command('Emulation.setDeviceMetricsOverride', {width, height, deviceScaleFactor: 1, mobile: width < 500});
    assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true);
    const picture = await command('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true});
    await writeFile(`waf/local/settings-${name}.png`, Buffer.from(picture.data, 'base64'));
  }
  pass('Desktop and mobile layouts fit their viewports (screenshots saved)');

  await command('Network.setBlockedURLs', {urls: ['*waf-api/settings*']});
  await click(`document.getElementById('refresh')`);
  await waitFor(`document.getElementById('protection').textContent === 'Unknown' && document.getElementById('connection').textContent === 'WAF API not connected'`);
  assert.equal(await evaluate(`${switchFor('SQL Injection Protection')}.disabled`), true);
  await command('Network.setBlockedURLs', {urls: []});
  await click(`document.getElementById('refresh')`);
  await waitFor(enabled('SQL Injection Protection'));
  await command('Network.clearBrowserCookies');
  await click(`document.getElementById('refresh')`);
  await waitFor(`!document.getElementById('auth').hidden && document.getElementById('protection').textContent === 'Unknown'`);
  pass('Unavailable API and expired login clear statuses and disable all controls');
  assert.deepEqual(errors, []);
  process.stdout.write(`${passed} browser checks passed; no uncaught JavaScript exceptions.\n`);
} finally {
  await command('Browser.close').catch(() => {});
  socket.close();
}
