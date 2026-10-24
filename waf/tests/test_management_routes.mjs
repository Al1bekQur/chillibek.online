import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

const read = path => readFileSync(new URL(path, import.meta.url), 'utf8');
const gateway = read('../../settings/index.html');
const panel = read('../templates/settings.html');
const source = read('../../settings/settings.js');

test('Public Settings stays accessible and offers an explicit fixed management link', () => {
  assert.match(gateway, /id="manageLive"[^>]+href="https:\/\/kali\.pythonanywhere\.com\/settings"/);
  assert.ok(gateway.includes('Manage live WAF ↗'));
  assert.doesNotMatch(gateway, /<script|http-equiv="refresh"|\/waf-api\//i);
  assert.ok(gateway.includes('This public page does not read the live policy.'));
  assert.equal((gateway.match(/class="rule"/g) || []).length, 11);
});

test('Public navigation opens Dashboard on the management host', () => {
  assert.ok(gateway.includes('href="https://kali.pythonanywhere.com/dashboard"'));
  assert.doesNotMatch(gateway, /href="\/dashboard/);
});

test('Authenticated template keeps the existing design and same-origin navigation', () => {
  assert.ok(panel.includes('href="./settings.css"'));
  assert.ok(panel.includes('src="./settings.js"'));
  assert.ok(panel.includes('href="/dashboard"'));
  assert.ok(panel.includes('href="/dashboard/login?next=/settings"'));
  assert.ok(panel.includes('href="https://chillibek.online/"'));
  assert.doesNotMatch(source, /window\.location\.replace|localStorage|sessionStorage|credentials:\s*['"]include/);
  assert.ok(source.includes('fetch(`/waf-api/settings${path}`'));
  assert.ok(source.includes("credentials: 'same-origin'"));
});

test('Public Dashboard gateway points only to the authenticated backend route', () => {
  const dashboard = read('../../dashboard/index.html');
  assert.ok(dashboard.includes('content="0;url=https://kali.pythonanywhere.com/dashboard"'));
  assert.ok(dashboard.includes('href="https://kali.pythonanywhere.com/dashboard"'));
  assert.doesNotMatch(dashboard, /(?:password|secret|api[_-]?key)\s*[:=]/i);
});
