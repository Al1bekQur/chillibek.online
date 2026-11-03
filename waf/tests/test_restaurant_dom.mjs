import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const context = {window: {}, URL};
vm.runInNewContext(readFileSync(new URL('../../restaurant-dom.js', import.meta.url), 'utf8'), context);
const D = context.window.RestaurantDOM;
const plain = value => JSON.parse(JSON.stringify(value));
const item = {id: 1, category: 'snacks', price: 1000, name: 'Soup', description: 'Fresh',
  weight: '100g', image_url: 'https://images.unsplash.com/photo'};

test('menu text stays literal, including stored markup and entities', () => {
  for (const payload of ['<img src=x onerror=alert(1)>', '</p><script>alert(1)</script>', '&lt;svg onload=alert(1)&gt;', 'Сырники 🧀']) {
    const value = D.menu([{...item, name: payload, description: payload, weight: payload}])[0];
    assert.equal(value.name, payload); assert.equal(value.description, payload); assert.equal(value.weight, payload);
  }
});

test('unsafe IDs and prices never become action targets', () => {
  for (const id of ['1);alert(1)//', '__proto__', '1', 0, -1, 1.5, NaN, Infinity, 2 ** 53, null, {}]) {
    assert.equal(D.menu([{...item, id}]).length, 0);
    assert.equal(D.validId(id), false);
  }
  for (const price of ['<svg onload=alert(1)>', 0, -1, Infinity, 1.2]) assert.equal(D.menu([{...item, price}]).length, 0);
  assert.equal(D.menu([{...item, category: '__proto__'}]).length, 0);
});

test('image URLs accept HTTP(S) images but no executable schemes, credentials or controls', () => {
  for (const url of ['javascript:alert(1)', 'data:image/svg+xml,<svg onload=alert(1)>', 'file:///tmp/image',
    '//example.test/a', 'https://user:pass@example.test/a', 'https://example.test/\na', 'https:\\example.test/a', {}, null]) {
    assert.equal(D.imageUrl(url), null);
  }
  assert.equal(D.imageUrl('https://images.unsplash.com/a b'), 'https://images.unsplash.com/a%20b');
  assert.equal(D.imageUrl('http://example.test/photo?q=1&size=2'), 'http://example.test/photo?q=1&size=2');
});

test('API objects are not coerced through toString and cannot alter prototypes', () => {
  const hostile = {toString() { throw new Error('Do not coerce'); }};
  const value = D.menu([{...item, name: hostile, description: hostile}])[0];
  assert.equal(value.name, ''); assert.equal(value.description, '');
  const supplied = JSON.parse('{"__proto__":{"polluted":true}}');
  D.menu([{...item, ...supplied}]);
  assert.equal({}.polluted, undefined);
});

test('order text and nested items stay data; invalid response shapes fail predictably', () => {
  const payload = '<img src=x onerror=alert(1)>';
  const value = plain(D.orders([{id: 1, status: 'pending', table_number: payload,
    total_price: 1000, items: [{name: payload, qty: payload}, null]}]))[0];
  assert.equal(value.table_number, payload); assert.deepEqual(value.items, [{name: payload, qty: payload}]);
  assert.equal(D.orders([{id: '1);alert(1)', status: 'pending', items: []}]).length, 0);
  assert.equal(D.orders([{id: 1, status: 'unknown', items: []}]).length, 0);
  for (const value of [null, {}, 'not an array']) {
    assert.throws(() => D.menu(value), /Invalid menu response/);
    assert.throws(() => D.orders(value), /Invalid orders response/);
  }
});
