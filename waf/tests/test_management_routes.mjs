// Execute the actual public entry script without network access or credentials.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('../../settings/settings.js', import.meta.url), 'utf8');
for (const origin of ['https://chillibek.online', 'https://www.chillibek.online']) {
  for (const search of ['', '?next=https://untrusted.invalid&token=synthetic-never-forward']) {
    test(`Public settings navigates to a fixed secure management URL: ${origin}${search}`, () => {
      const destinations = [];
      const context = {window: {location: {origin, search, hash: '#untrusted-fragment', replace: url => destinations.push(url)}}};
      // A public entry must return before touching DOM state, cookies, storage or APIs.
      vm.runInNewContext(source, context);
      assert.deepEqual(destinations, ['https://kali.pythonanywhere.com/settings/']);
    });
  }
}
test('Backend and staging origins render the existing same-origin policy panel', () => {
  for (const origin of ['https://kali.pythonanywhere.com', 'http://127.0.0.1:8765', 'https://chillibek.online.untrusted.invalid']) {
    let rendered = false;
    const context = {
      window: {location: {origin, replace: () => assert.fail('Unexpected management redirect')}},
      document: {createElement: () => { rendered = true; throw new Error('Reached local panel rendering'); }},
    };
    assert.throws(() => vm.runInNewContext(source, context), /Reached local panel rendering/);
    assert.equal(rendered, true);
  }
});
test('Public Dashboard gateway points only to the authenticated backend route', () => {
  const gateway = readFileSync(new URL('../../dashboard/index.html', import.meta.url), 'utf8');
  assert.ok(gateway.includes('content="0;url=https://kali.pythonanywhere.com/dashboard"'));
  assert.ok(gateway.includes('href="https://kali.pythonanywhere.com/dashboard"'));
  assert.equal(/(?:password|secret|api[_-]?key)\s*[:=]/i.test(gateway), false);
});
