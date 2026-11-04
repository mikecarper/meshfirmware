import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { fetchFirmwareBytes } from '../src/downloads.js';
import { hash } from '../src/firmware.js';

const base = new URL('https://flasher.test/meshfirmware/firmware/');
const source = 'https://github.com/mikecarper/MeshCore/releases/download/full-v1.18.0/board_repeater-v1.18.0.zip';
function piece(bytes) {
  const gzip = new Uint8Array(gzipSync(bytes)), sha256 = hash(bytes);
  return { bytes, gzip, entry: { sha256, size: bytes.length, gzipSha256: hash(gzip), gzipSize: gzip.length, path: sha256 + '.gz' } };
}
const raw = new TextEncoder().encode('verified complete original release');
const index = entries => ({ schemaVersion: 1, entries, warnings: [] });
const json = value => new Response(JSON.stringify(value));
const load = (fetchImpl, extra = {}) => fetchFirmwareBytes(source, { fetchImpl, mirrorBase: base, pageOrigin: base.origin, ...extra });

test('mirror provenance callback runs once after complete raw size/hash verification without a catalog digest', async () => {
  const part = piece(raw), events = [];
  const fetchImpl = async url => { events.push(url.endsWith('index.json') ? 'index' : 'asset'); return url.endsWith('index.json') ? json(index([{ url: source, ...part.entry }])) : new Response(part.gzip); };
  const result = await load(fetchImpl, { onVerified(value) { events.push(value); assert.ok(Object.isFrozen(value)); } });
  assert.deepEqual(result, raw); assert.deepEqual(events, ['index', 'asset', { sha256: hash(raw), sourceUrl: source }]);
});

test('multipart callback reports only the final original digest, not individual valid part digests', async () => {
  const a = piece(raw.subarray(0, 12)), b = piece(raw.subarray(12)), events = [];
  const full = { url: source, sha256: hash(raw), size: raw.length, parts: [a.entry, b.entry] };
  const fetchImpl = async url => {
    if (url.endsWith('index.json')) return json(index([full]));
    const part = url.endsWith(a.entry.path) ? a : b; events.push(part.entry.sha256); return new Response(part.gzip);
  };
  assert.deepEqual(await load(fetchImpl, { onVerified(value) { events.push(value); } }), raw);
  assert.deepEqual(events, [a.entry.sha256, b.entry.sha256, { sha256: hash(raw), sourceUrl: source }]);
});

test('direct downloads report only a supplied matching expected hash and normalize its case', async () => {
  for (const indexUnavailable of [false, true]) {
    const callback = [], fetchImpl = async url => url.endsWith('index.json') ? indexUnavailable ? new Response('', { status: 404 }) : json(index([])) : new Response(raw);
    assert.deepEqual(await load(fetchImpl, { expectedSha256: hash(raw).toUpperCase(), onVerified: value => callback.push(value) }), raw);
    assert.deepEqual(callback, [{ sha256: hash(raw), sourceUrl: source }]);
  }
  const callback = [], fetchImpl = async url => url.endsWith('index.json') ? json(index([])) : new Response(raw);
  assert.deepEqual(await load(fetchImpl, { onVerified: value => callback.push(value) }), raw); assert.deepEqual(callback, []);
});

test('integrity failures at any mirror stage or direct mismatch never call onVerified or fall back', async () => {
  for (const failure of ['gzip', 'raw', 'aggregate', 'catalog', 'direct']) {
    const a = piece(raw.subarray(0, 12)), b = piece(raw.subarray(12)), single = piece(raw), callback = [], fetches = [];
    const entry = failure === 'aggregate' ? { url: source, sha256: 'a'.repeat(64), size: raw.length, parts: [a.entry, b.entry] } : { url: source, ...single.entry };
    if (failure === 'raw') entry.sha256 = 'b'.repeat(64), entry.path = entry.sha256 + '.gz';
    const fetchImpl = async url => {
      fetches.push(url); if (url.endsWith('index.json')) return json(index(failure === 'direct' ? [] : [entry]));
      if (!url.startsWith(base.href)) return new Response(raw);
      const bytes = failure === 'aggregate' ? url.endsWith(a.entry.path) ? a.gzip : b.gzip : single.gzip.slice();
      if (failure === 'gzip') bytes[12] ^= 1; return new Response(bytes);
    };
    await assert.rejects(load(fetchImpl, { ...(failure === 'catalog' || failure === 'direct' ? { expectedSha256: 'c'.repeat(64) } : {}), onVerified: value => callback.push(value) }));
    assert.deepEqual(callback, [], failure); if (failure !== 'direct') assert.ok(fetches.every(url => url.startsWith(base.href)), failure);
  }
});

test('HTTP-decoded mirror bytes must pass raw verification before provenance is reported', async () => {
  const part = piece(new Uint8Array(4096).fill(7)), callback = [];
  const fetchImpl = async url => url.endsWith('index.json') ? json(index([{ url: source, ...part.entry }])) : new Response(part.bytes, { headers: { 'Content-Encoding': 'gzip', 'Content-Length': String(part.gzip.length) } });
  assert.deepEqual(await load(fetchImpl, { onVerified: value => callback.push(value) }), part.bytes);
  assert.deepEqual(callback, [{ sha256: part.entry.sha256, sourceUrl: source }]);
});

test('the callback is awaited and its error stops the download result instead of claiming success', async () => {
  const part = piece(raw), fetchImpl = async url => url.endsWith('index.json') ? json(index([{ url: source, ...part.entry }])) : new Response(part.gzip);
  let resolve, finished = false;
  const downloading = load(fetchImpl, { onVerified: () => new Promise(done => { resolve = done; }) }).then(value => { finished = true; return value; });
  while (!resolve) await new Promise(done => setImmediate(done)); assert.equal(finished, false); resolve(); assert.deepEqual(await downloading, raw);
  await assert.rejects(load(fetchImpl, { onVerified() { throw new Error('selection changed'); } }), /selection changed/);
  let fetched = false; await assert.rejects(load(async () => { fetched = true; }, { onVerified: true }), /callback/); assert.equal(fetched, false);
});
