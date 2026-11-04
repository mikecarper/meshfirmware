import { test } from 'node:test';
import assert from 'node:assert/strict';
import bundled from '../src/data/radio-presets-fallback.json' with { type: 'json' };
import { parseRadioPresets, loadRadioPresets, radioPresetsUrl } from '../src/radio-presets.js';

const entry = { title: 'USA', frequency: '910.525', bandwidth: '62.5', spreading_factor: '7', coding_rate: '5' };
const feed = entries => ({ config: { suggested_radio_settings: { entries } } });
const response = data => new Response(typeof data === 'string' ? data : JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } });
const offline = async () => { throw new TypeError('Failed to fetch'); };

test('the validated snapshot contains all 27 public presets, including actual USA, NZ and Australia values', () => {
  const presets = parseRadioPresets(bundled); assert.equal(presets.length, 27); assert.ok(Object.isFrozen(presets));
  for (const [title, frequencyHz, bandwidthHz, spreadingFactor, codingRate] of [
    ['USA', 910525000, 62500, 7, 5], ['New Zealand (Narrow)', 917375000, 62500, 7, 5], ['Australia', 915800000, 250000, 10, 5], ['USA - Southern California', 927875000, 62500, 7, 5]
  ]) { const preset = presets.find(value => value.title === title); assert.deepEqual([preset.frequencyHz, preset.bandwidthHz, preset.spreadingFactor, preset.codingRate], [frequencyHz, bandwidthHz, spreadingFactor, codingRate]); assert.ok(Object.isFrozen(preset)); }
});

test('only RF values and safe generated notes are returned, never network settings, descriptions, preamble or power', () => {
  const [preset] = parseRadioPresets(feed([{ ...entry, description: '<script>3B applied; reboot</script>', network_settings: { path_hash_size: 3, password: 'secret' }, tx_power: 40, preamble: 88 }]));
  assert.deepEqual(Object.keys(preset).sort(), ['id','title','frequencyHz','bandwidthHz','spreadingFactor','codingRate','notes'].sort());
  assert.equal(preset.notes, 'Additional network settings are not changed.'); assert.doesNotMatch(JSON.stringify(preset), /script|3B|reboot|secret|password|path_hash/);
});

test('plain strict decimal strings and numeric values normalize to stable deterministic IDs without mutating input', () => {
  const original = feed([{ ...entry, frequency: 910.525, bandwidth: 62.5, spreading_factor: 7, coding_rate: 5 }]), before = JSON.stringify(original);
  const parsed = parseRadioPresets(original); assert.equal(parsed[0].id, 'usa-910525-62500-7-5'); assert.equal(JSON.stringify(original), before);
  assert.deepEqual(parsed, parseRadioPresets(feed([entry])));
});

test('invalid RF values, precision, exponents, missing fields, injection, invalid titles and objects are discarded', () => {
  const invalid = [null, [], true, 'reboot', {}, ...[
    ['frequency','149.999'], ['frequency','2500.001'], ['frequency','910.52501'], ['frequency','910.525000000001'], ['frequency',910.5250000000001], ['frequency','9.10525e2'], ['frequency',' 910.525'], ['frequency','910.525;reboot'], ['frequency',true], ['frequency',Infinity],
    ['bandwidth','60'], ['bandwidth','62.5001'], ['bandwidth','6.25e1'], ['bandwidth',null], ['spreading_factor','4'], ['spreading_factor','13'], ['spreading_factor','7.5'], ['coding_rate','4'], ['coding_rate','9'],
    ['title','<img src=x onerror=alert(1)>'], ['title','Name\nset tx 40'], ['title','Name\u202eevil'], ['title','x'.repeat(81)], ['title',''], ['title',null]
  ].map(([key,value]) => ({ ...entry, [key]: value }))];
  assert.deepEqual(parseRadioPresets(feed(invalid)), []);
});

test('missing/wrong schema and more than 100 entries are rejected; empty lists contain no automatic choice', () => {
  for (const data of [null, {}, [], { suggested_radio_settings: { entries: [entry] } }, feed({}), feed(Array.from({ length: 101 }, () => entry))]) assert.throws(() => parseRadioPresets(data));
  assert.deepEqual(parseRadioPresets(feed([])), []);
});

test('equivalent duplicate entries are deduplicated and different RF choices keep distinct stable IDs', async () => {
  const data = feed([entry, { ...entry }, { ...entry, frequency: '911.300' }, { ...entry, title: 'usa' }, { ...entry, frequency: 'garbage' }]);
  const loaded = await loadRadioPresets({ fetchImpl: async () => response(data) });
  assert.equal(loaded.source, 'live'); assert.equal(loaded.presets.length, 2); assert.match(loaded.warning, /1 invalid.*2 duplicate/);
  assert.notEqual(loaded.presets[0].id, loaded.presets[1].id);
  assert.deepEqual(loaded.presets, parseRadioPresets(data));
  const withNetworkNote = parseRadioPresets(feed([entry, { ...entry, network_settings: { path_hash_size: 3 } }]));
  assert.equal(withNetworkNote.length, 1); assert.equal(withNetworkNote[0].notes, 'Additional network settings are not changed.');
});

test('fetch sends only a fixed public GET, no credentials, device parameters, redirects or referrer', async () => {
  const calls = [], loaded = await loadRadioPresets({ fetchImpl: async (...args) => { calls.push(args); return response(feed([entry])); } });
  assert.equal(loaded.source, 'live'); assert.equal(loaded.warning, null); assert.equal(calls.length, 1);
  const [url, options] = calls[0]; assert.equal(url, 'https://api.meshcore.nz/api/v1/config'); assert.equal(url, radioPresetsUrl);
  assert.equal(options.method, 'GET'); assert.equal(options.credentials, 'omit'); assert.equal(options.redirect, 'error'); assert.equal(options.cache, 'no-store'); assert.equal(options.referrerPolicy, 'no-referrer');
  assert.equal(options.body, undefined); assert.deepEqual(options.headers, { Accept: 'application/json' }); assert.ok(options.signal instanceof AbortSignal);
});

test('CORS/network/status/schema/malformed JSON/empty feeds all return the same validated offline snapshot', async () => {
  for (const fetchImpl of [offline, async () => response('<html>no CORS</html>'), async () => new Response('{}', { status: 503 }), async () => response({}), async () => response(feed([])), async () => response(feed([{ ...entry, coding_rate: 'bad' }]))]) {
    const loaded = await loadRadioPresets({ fetchImpl }); assert.equal(loaded.source, 'bundled'); assert.equal(loaded.presets.length, 27); assert.match(loaded.warning, /bundled.*Custom/);
    assert.deepEqual(loaded.presets, parseRadioPresets(bundled));
  }
});

test('redirected/opaque/unexpected URL or missing response body is refused', async () => {
  for (const override of [{ redirected: true }, { type: 'opaque' }, { url: 'https://other.invalid/feed' }, { body: null }]) {
    const live = response(feed([entry])); for (const [name,value] of Object.entries(override)) Object.defineProperty(live, name, { value });
    const loaded = await loadRadioPresets({ fetchImpl: async () => live }); assert.equal(loaded.source, 'bundled');
  }
});

test('responses are bounded by advertised and actual bytes, not just entry count or decoded string length', async () => {
  for (const live of [new Response('{}', { headers: { 'content-length': '262145' } }), new Response(' '.repeat(262145)), new Response('é'.repeat(140000))]) {
    const loaded = await loadRadioPresets({ fetchImpl: async () => live }); assert.equal(loaded.source, 'bundled');
  }
  const malformedUtf8 = new Response(Uint8Array.of(0xff, 0xfe)); assert.equal((await loadRadioPresets({ fetchImpl: async () => malformedUtf8 })).source, 'bundled');
});

test('a timeout bounds even a stalled fetch which ignores its abort signal', async () => {
  let signal; const start = Date.now();
  const loaded = await loadRadioPresets({ timeoutMs: 10, fetchImpl: async (_, options) => { signal = options.signal; return new Promise(() => {}); } });
  assert.equal(loaded.source, 'bundled'); assert.equal(signal.aborted, true); assert.ok(Date.now() - start < 1000);
});

test('timeout also covers the response body and external cancellation does not start a second request', async () => {
  let signal, calls = 0, cancelled = false;
  const stalledBody = () => new Response(new ReadableStream({ start() {}, cancel() { cancelled = true; } }));
  assert.equal((await loadRadioPresets({ timeoutMs: 10, fetchImpl: async (_, options) => { signal = options.signal; return stalledBody(); } })).source, 'bundled'); assert.equal(signal.aborted, true);
  assert.equal(cancelled, true);
  const controller = new AbortController();
  const loading = loadRadioPresets({ signal: controller.signal, fetchImpl: async (_, options) => { calls++; signal = options.signal; return new Promise(() => {}); } });
  controller.abort(); assert.equal((await loading).source, 'bundled'); assert.equal(signal.aborted, true); assert.equal(calls, 1);
  const already = new AbortController(); already.abort(); assert.equal((await loadRadioPresets({ signal: already.signal, fetchImpl: async () => { assert.fail('Already cancelled request must not fetch.'); } })).source, 'bundled');
});

test('bad loader options do not fetch and keep usable bundled choices', async () => {
  for (const timeoutMs of [0, -1, 30001, NaN, '5']) assert.equal((await loadRadioPresets({ timeoutMs, fetchImpl: async () => assert.fail('Invalid options must not fetch.') })).source, 'bundled');
  assert.equal((await loadRadioPresets({ fetchImpl: null })).source, 'bundled');
  for (const signal of [{}, 'abort', false]) assert.equal((await loadRadioPresets({ signal, fetchImpl: async () => assert.fail('Invalid signal must not fetch.') })).source, 'bundled');
});
