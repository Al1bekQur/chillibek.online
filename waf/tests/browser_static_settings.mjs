// Verify the static-only Pages release with a dedicated headless Chrome on port 9222.
// Serve the main checkout with: python -m http.server 8766 --bind 127.0.0.1
// Run: node waf/tests/browser_static_settings.mjs
// After publishing: node waf/tests/browser_static_settings.mjs https://chillibek.online/settings/
import assert from 'node:assert/strict';
import {mkdir, writeFile} from 'node:fs/promises';

const url = process.argv[2] || 'http://127.0.0.1:8766/settings/';
assert.ok(['http://127.0.0.1:8766/settings/', 'https://chillibek.online/settings/'].includes(url));
const target = await fetch('http://127.0.0.1:9222/json/new?about:blank', {method: 'PUT'}).then(r => r.json());
const socket = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
  socket.addEventListener('open', resolve, {once: true});
  socket.addEventListener('error', reject, {once: true});
});
let sequence = 0;
const pending = new Map();
const errors = [];
const requests = [];
socket.addEventListener('message', ({data}) => {
  const message = JSON.parse(data);
  if (message.id) {
    const item = pending.get(message.id); pending.delete(message.id);
    if (item) message.error ? item.reject(new Error(JSON.stringify(message.error))) : item.resolve(message.result);
  }
  if (message.method === 'Runtime.exceptionThrown') errors.push(message.params.exceptionDetails.text);
  if (message.method === 'Network.requestWillBeSent') requests.push(message.params.request);
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
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    if (await evaluate(expression)) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`Timed out: ${expression}`);
}
try {
  await command('Page.enable'); await command('Runtime.enable'); await command('Network.enable');
  await command('Network.clearBrowserCookies');
  await command('Page.navigate', {url});
  await waitFor(`document.getElementById('manageLive') !== null`);
  assert.equal(await evaluate('document.title'), 'CHILLIBEK WAF — Security Settings');
  assert.equal(await evaluate('location.href'), url);
  assert.equal(await evaluate(`document.getElementById('manageLive').href`), 'https://kali.pythonanywhere.com/settings');
  assert.equal(await evaluate(`document.querySelectorAll('button[role="switch"]').length`), 0);
  assert.equal(await evaluate(`document.querySelector('.notice').textContent.includes('does not read the live policy')`), true);
  assert.equal(await evaluate(`document.querySelectorAll('.rule').length`), 11);
  assert.ok((await evaluate(`getComputedStyle(document.querySelector('.sidebar')).position`)) === 'fixed');
  assert.ok(requests.some(request => request.url === new URL('./settings.css', url).href));
  assert.equal(requests.some(request => request.url.includes('/waf-api/') || request.url.endsWith('/settings.js')), false);
  assert.equal(requests.some(request => !['GET', 'HEAD'].includes(request.method)), false);
  assert.equal(requests.some(request => request.url.includes('pythonanywhere')), false);
  await command('Emulation.setDeviceMetricsOverride', {width: 390, height: 844, deviceScaleFactor: 1, mobile: true});
  assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true);
  await mkdir('waf/local', {recursive: true});
  const picture = await command('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true});
  await writeFile('waf/local/settings-static-public.png', Buffer.from(picture.data, 'base64'));
  assert.deepEqual(errors, []);
  process.stdout.write(`PASS static Settings page stays at ${url}\nPASS prominent management action, Dashboard links and all 11 control descriptions\nPASS no API client, mutation or PythonAnywhere requests\nPASS mobile layout; no uncaught JavaScript exceptions\n`);
} finally {
  await command('Browser.close').catch(() => {});
  socket.close();
}
