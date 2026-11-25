import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { readerPanel } from '../src/reader-panel.js';

const source = await readFile(new URL('../public/reader/field-guides.json', import.meta.url), 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));

function fixture(t, fetcher) {
  const previousDocument = globalThis.document, previousFetch = globalThis.fetch;
  const nodes = new Map();
  const $ = id => {
    if (!nodes.has(id)) nodes.set(id, {
      value: '', textContent: '', checked: false, hidden: false, disabled: false,
      replaceChildren(...options) { this.options = options; },
    });
    return nodes.get(id);
  };
  globalThis.document = { baseURI: 'https://example.com/meshfirmware/', createElement: () => ({}) };
  globalThis.fetch = fetcher;
  t.after(() => { globalThis.document = previousDocument; globalThis.fetch = previousFetch; });
  let operations = 0, serial = 0;
  readerPanel({ $, operation: fn => { ++operations; return fn(); }, linkOperation: () => { ++serial; },
    getTarget: () => ({}), allowed: () => false, busy: () => false, confirmRemove: () => false });
  return { $, calls: () => ({ operations, serial }) };
}

test('guides load on page load and selected text is readable without contacting the radio', async t => {
  const requests = [];
  const ui = fixture(t, async url => { requests.push(url.href); return { ok: true, text: async () => source }; });
  await tick();
  assert.deepEqual(requests, ['https://example.com/meshfirmware/reader/field-guides.json']);
  assert.deepEqual(ui.$('reader-imported').options.map(option => option.textContent), ['Survivor Guide', 'Land Navigation', 'First Aid']);
  assert.match(ui.$('reader-text').textContent, /^Survivor Guide\n\nBefore You Leave/);
  ui.$('reader-imported').value = '1';
  ui.$('reader-imported').onchange();
  assert.match(ui.$('reader-text').textContent, /^Land Navigation\n\n/);
  ui.$('reader-imported').value = '2';
  ui.$('reader-imported').onchange();
  assert.match(ui.$('reader-text').textContent, /^First Aid\n\n/);
  assert.deepEqual(ui.calls(), { operations: 0, serial: 0 });
});

test('late guide loading preserves early imported selection and status and displays untrusted text as text', async t => {
  let finish;
  const ui = fixture(t, () => new Promise(resolve => { finish = resolve; }));
  const content = '# Notes\n## Heading\n<img src=x onerror=alert(1)> & text';
  const other = '# Other\nAn earlier book.';
  ui.$('reader-files').files = [other, content].map((text, i) => ({ name: `${i}.md`, size: text.length, arrayBuffer: async () => new TextEncoder().encode(text).buffer }));
  await ui.$('reader-files').onchange();
  ui.$('reader-imported').value = '1';
  ui.$('reader-imported').onchange();
  ui.$('reader-status').textContent = 'Radio operation in progress';
  finish({ ok: true, text: async () => source });
  await tick();
  assert.equal(ui.$('reader-imported').value, '1');
  assert.deepEqual(ui.$('reader-imported').options.map(option => option.textContent), ['Other', 'Notes', 'Survivor Guide', 'Land Navigation', 'First Aid']);
  assert.equal(ui.$('reader-text').textContent, 'Notes\n\nHeading\n\n<img src=x onerror=alert(1)> & text');
  assert.equal(ui.$('reader-text').innerHTML, undefined);
  assert.equal(ui.$('reader-status').textContent, 'Radio operation in progress');
  assert.equal(ui.calls().serial, 0);
});

test('failed loading can be retried without duplicating guides, even with repeated requests', async t => {
  let calls = 0, finish;
  const ui = fixture(t, () => {
    ++calls;
    return calls === 1 ? Promise.reject(new Error('offline')) : new Promise(resolve => { finish = resolve; });
  });
  await tick();
  assert.equal(ui.$('reader-guides').hidden, false);
  assert.match(ui.$('reader-guide-status').textContent, /could not be loaded/);
  const first = ui.$('reader-guides').onclick(), second = ui.$('reader-guides').onclick();
  assert.equal(calls, 2);
  finish({ ok: true, text: async () => source });
  await Promise.all([first, second]);
  await ui.$('reader-guides').onclick();
  assert.equal(calls, 2);
  assert.equal(ui.$('reader-imported').options.length, 3);
  assert.equal(ui.$('reader-guides').hidden, true);
});
