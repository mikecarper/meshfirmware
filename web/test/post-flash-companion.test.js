import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPostFlashCompanionRequest } from '../src/post-flash-companion.js';
import { createPostFlashSettingsPlan, applyPostFlashSettings } from '../src/post-flash-settings.js';

const key = 'ab'.repeat(32), device = { protocol: 13, publicKey: key };
function deviceInfo({ protocol = 13, repeat = 0, model = 'Test Companion', version = '1.18.0.1' } = {}) {
  const bytes = new Uint8Array(82); bytes.set([13, protocol]); bytes[80] = repeat;
  bytes.set(new TextEncoder().encode(model), 20); bytes.set(new TextEncoder().encode(version), 60); return bytes;
}
function selfInfo({ frequency = 910525, bandwidth = 125000, sf = 7, cr = 5, tx = -9, maxTx = 22 } = {}) {
  const bytes = new Uint8Array(58), view = new DataView(bytes.buffer);
  bytes.set([5, 1, tx & 255, maxTx & 255]); bytes.fill(0xab, 4, 36);
  view.setUint32(48, frequency, true); view.setUint32(52, bandwidth, true); bytes[56] = sf; bytes[57] = cr;
  return bytes;
}
function fixture(overrides = {}) {
  const calls = [], mc = {
    async self() { calls.push(['self']); return selfInfo(); },
    async info() { calls.push(['info']); return deviceInfo(); },
    async request(command, code) { calls.push(['request', [...command], code]); return Uint8Array.of(0); },
    async cli(command) { calls.push(['cli', command]); return '> native'; }, ...overrides
  };
  return { calls, mc, request: createPostFlashCompanionRequest(mc, device) };
}

test('protocol 14+ uses the ordinary CLI, not a binary workaround', async () => {
  for (const protocol of [14, 15, 255]) {
    const { mc, calls } = fixture(), request = createPostFlashCompanionRequest(mc, { ...device, protocol });
    assert.equal(await request('set radio.preamble 32'), '> native');
    assert.deepEqual(calls, [['cli', 'set radio.preamble 32']]);
  }
});

test('legacy queries decode whole-kHz frequency, whole-Hz bandwidth, and signed TX', async () => {
  const { request, calls } = fixture();
  assert.equal(await request('get radio'), '> 910.525,125,7,5');
  assert.equal(await request('get tx'), '> -9');
  assert.deepEqual(calls, [['self'], ['self']]);
});

test('SELF_INFO byte views use their actual offset and uppercase known keys match', async () => {
  const backing = new Uint8Array(100); backing.set(selfInfo({ bandwidth: 31250 }), 10);
  const { mc } = fixture({ async self() { return backing.subarray(10, 68); } });
  const request = createPostFlashCompanionRequest(mc, { ...device, publicKey: key.toUpperCase() });
  assert.equal(await request('get radio'), '> 910.525,31.25,7,5');
});

test('legacy setters send only the documented binary commands after identity preflight', async () => {
  const { request, calls } = fixture();
  assert.equal(await request('set radio 911.300,31.250,10,8'), '> OK');
  assert.equal(await request('set tx -9'), '> OK');
  assert.deepEqual(calls, [
    ['info'], ['self'], ['request', [11, 196, 231, 13, 0, 18, 122, 0, 0, 10, 8, 0], 0],
    ['self'], ['request', [12, 247], 0]
  ]);
});

test('legacy unsupported settings never use CMD66 or send any command', async () => {
  const { request, calls } = fixture();
  for (const command of ['get radio2', 'set radio2 911.3,500,8,7', 'get radio.preamble', 'set radio.preamble 32', 'set radio2.cross on', 'version', 'set name Other'])
    assert.equal(await request(command), '> Error: unsupported setting', command);
  assert.deepEqual(calls, []);
});

test('invalid and unrepresentable radio values fail before opening a binary transaction', async () => {
  for (const tuple of ['910.52501,125,7,5', '910.525,125.0001,7,5', '149.999,125,7,5', '2500.001,125,7,5', '910.525,6.999,7,5', '910.525,500.001,7,5', '910.525,125,4,5', '910.525,125,13,5', '910.525,125,7,4', '910.525,125,7,9', '910.525,125,7,5,32', '9e2,125,7,5', 'Infinity,125,7,5', '910.525,125,7.5,5']) {
    const { request, calls } = fixture(); await assert.rejects(request(`set radio ${tuple}`)); assert.deepEqual(calls, [], tuple);
  }
});

test('exact extra decimal zeroes are accepted without relaxing wire precision', async () => {
  const { request, calls } = fixture(); await request('set radio 910.525000,125.000000,7,5');
  const wire = Uint8Array.from(calls[2][1]), view = new DataView(wire.buffer);
  assert.equal(view.getUint32(1, true), 910525); assert.equal(view.getUint32(5, true), 125000);
});

test('TX bounds, fractions, and actual board maximum are checked before writes', async () => {
  for (const power of ['-10', '41', '2.5', 'NaN', '1e1', '+1']) {
    const { request, calls } = fixture(); await assert.rejects(request(`set tx ${power}`)); assert.deepEqual(calls, []);
  }
  const { request, calls } = fixture(); await assert.rejects(request('set tx 23'), /22 dBm/); assert.deepEqual(calls, [['self']]);
});

test('a changed public key prevents both reads and writes, including a later changed read', async () => {
  let frame = selfInfo(); const { request, calls } = fixture({ async self() { calls.push(['self']); return frame; } });
  assert.equal(await request('get tx'), '> -9'); frame = frame.slice(); frame[4] ^= 1;
  for (const command of ['get radio', 'get tx', 'set radio 910.525,125,7,5', 'set tx 1']) await assert.rejects(request(command), /public key changed/);
  assert.ok(calls.every(call => ['self', 'info'].includes(call[0])));
});

test('bad SELF_INFO framing, radio tuples, and TX limits never permit writes', async () => {
  const wrongCode = selfInfo(); wrongCode[0] = 0;
  const wrongRole = selfInfo(); wrongRole[1] = 2;
  for (const frame of [new Uint8Array(57), new Uint8Array(91), [...selfInfo()], wrongCode, wrongRole, selfInfo({ frequency: 1 }), selfInfo({ bandwidth: 0 }), selfInfo({ sf: 4 }), selfInfo({ cr: 4 }), selfInfo({ maxTx: 41 }), selfInfo({ tx: 23 }), selfInfo({ tx: -10 })]) {
    const { request, calls } = fixture({ async self() { return frame; } });
    await assert.rejects(request('set tx 1')); assert.deepEqual(calls, []);
  }
});

test('malformed or rejected write responses cannot become an OK result', async () => {
  for (const reply of [null, [0], Uint8Array.of(1), Uint8Array.of(0, 1), new Uint8Array()]) {
    const { request } = fixture({ async request() { return reply; } });
    await assert.rejects(request('set tx 1'), /did not acknowledge/);
  }
  const { request } = fixture({ async request() { throw new Error('transport failed'); } });
  await assert.rejects(request('set tx 1'), /transport failed/);
});

test('stale sessions stop before a request and after every awaited transport operation', async () => {
  for (const protocol of [13, 14]) {
    const { mc, calls } = fixture(); let current = false;
    const request = createPostFlashCompanionRequest(mc, { ...device, protocol }, { isCurrent: () => current });
    await assert.rejects(request('get radio'), /session changed/); assert.deepEqual(calls, []);
  }
  let current = true;
  const { mc, calls } = fixture({ async self() { current = false; return selfInfo(); } });
  const request = createPostFlashCompanionRequest(mc, device, { isCurrent: () => current });
  await assert.rejects(request('set tx 1'), /session changed/); assert.deepEqual(calls, []);
  current = true;
  mc.self = async () => selfInfo(); mc.request = async () => { current = false; return Uint8Array.of(0); };
  await assert.rejects(request('set tx 1'), /session changed/);
  current = true; mc.cli = async () => { current = false; return '> OK'; };
  await assert.rejects(createPostFlashCompanionRequest(mc, { ...device, protocol: 14 }, { isCurrent: () => current })('get radio'), /session changed/);
});

test('throwing session guards are supported and invalid protocols/keys fail closed', async () => {
  const { mc } = fixture();
  for (const protocol of [undefined, null, '13', 0, 256, 13.5]) assert.throws(() => createPostFlashCompanionRequest(mc, { ...device, protocol }), /protocol/);
  assert.throws(() => createPostFlashCompanionRequest(mc, { ...device, publicKey: 'ab' }), /public key/);
  const request = createPostFlashCompanionRequest(mc, device, { isCurrent: () => { throw new Error('replaced'); } });
  await assert.rejects(request('get radio'), /replaced/);
});

test('legacy command injection is rejected without transport activity', async () => {
  for (const command of ['get radio\rset tx 1', 'set tx 1\n', 'get tx\0', null]) {
    const { request, calls } = fixture(); await assert.rejects(request(command), /Invalid.*command/); assert.deepEqual(calls, []);
  }
});

test('protocol 9–13 preserves enabled and disabled repeat instead of clearing it', async () => {
  for (const protocol of [9, 10, 13]) for (const repeat of [0, 1]) {
    const { mc, calls } = fixture({ async info() { calls.push(['info']); return deviceInfo({ protocol, repeat }); } });
    const request = createPostFlashCompanionRequest(mc, { ...device, protocol, model: 'Test Companion', version: '1.18.0.1' });
    await request('set radio 910.525,125,7,5');
    assert.deepEqual(calls.map(call => call[0]), ['info', 'self', 'request']);
    assert.equal(calls[2][1].length, 12); assert.equal(calls[2][1][11], repeat);
  }
});

test('protocols below 9 use the original tuple without reading unsupported repeat metadata', async () => {
  for (const protocol of [3, 8]) {
    const { mc, calls } = fixture(), request = createPostFlashCompanionRequest(mc, { ...device, protocol });
    delete mc.info; await request('set radio 910.525,125,7,5');
    assert.deepEqual(calls.map(call => call[0]), ['self', 'request']); assert.equal(calls[1][1].length, 11);
  }
});

test('missing, malformed, changed, or invalid DEVICE_INFO never writes a legacy radio tuple', async () => {
  const wrongCode = deviceInfo(); wrongCode[0] = 0;
  for (const info of [null, [...deviceInfo()], new Uint8Array(80), new Uint8Array(129), wrongCode,
    deviceInfo({ protocol: 12 }), deviceInfo({ repeat: 2 }), deviceInfo({ model: '' }), deviceInfo({ version: '' }),
    deviceInfo({ model: 'Different Board' }), deviceInfo({ version: '1.18.0.2' })]) {
    const { mc, calls } = fixture({ async info() { return info; } });
    const request = createPostFlashCompanionRequest(mc, { ...device, model: 'Test Companion', shortVersion: '1.18.0.1', version: 'Full version text' });
    await assert.rejects(request('set radio 910.525,125,7,5')); assert.deepEqual(calls, []);
  }
  const { mc, calls } = fixture(); delete mc.info;
  await assert.rejects(createPostFlashCompanionRequest(mc, device)('set radio 910.525,125,7,5'), /preserve.*repeat/); assert.deepEqual(calls, []);
});

test('session replacement while reading repeat metadata cannot reach SELF_INFO or write', async () => {
  let current = true;
  const { mc, calls } = fixture({ async info() { current = false; return deviceInfo(); } });
  const request = createPostFlashCompanionRequest(mc, device, { isCurrent: () => current });
  await assert.rejects(request('set radio 910.525,125,7,5'), /session changed/); assert.deepEqual(calls, []);
});

test('the settings runner applies and reads back a legacy tuple/TX while preserving repeat and explicitly skipping MediaMesh', async () => {
  let frame = selfInfo(); const commands = [];
  const mc = {
    async self() { return frame.slice(); }, async info() { return deviceInfo({ repeat: 1 }); },
    async request(command, code) {
      commands.push([...command]); assert.equal(code, 0);
      if (command[0] === 11) { assert.equal(command[11], 1); frame.set(command.subarray(1, 11), 48); }
      else if (command[0] === 12) frame[2] = command[1];
      else assert.fail('An unsupported command was sent to the legacy companion.');
      return Uint8Array.of(0);
    }, async cli() { assert.fail('Legacy settings must not use CMD66.'); }
  };
  const plan = createPostFlashSettingsPlan({ primary: { enabled: true, frequencyHz: 911300000, bandwidthHz: 250000, spreadingFactor: 8, codingRate: 7, preambleSymbols: null, txPowerDbm: 10 }, mediaMesh: { preset: 'mediamesh', cross: 'on' } });
  const result = await applyPostFlashSettings(plan, { request: createPostFlashCompanionRequest(mc, device), isCurrent: () => true });
  assert.equal(result.complete, false); assert.deepEqual(result.errors, []);
  assert.equal(result.applied[0].section, 'primary'); assert.equal(result.applied[0].preambleVerified, false); assert.equal(result.applied[0].txPowerVerified, true);
  assert.equal(result.skipped[0].section, 'mediaMesh'); assert.match(result.warnings[0], /preamble is unsupported/);
  assert.deepEqual(result.readbacks['get radio'], { frequencyMHz: 911.3, bandwidthKHz: 250, spreadingFactor: 8, codingRate: 7, frequencyPlaces: 1, bandwidthPlaces: 0 });
  assert.equal(result.readbacks['get tx'], 10); assert.deepEqual(commands.map(command => command[0]), [11, 12]);
});
