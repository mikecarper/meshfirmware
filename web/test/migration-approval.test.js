import {test} from 'node:test';
import assert from 'node:assert/strict';
import {hash, inspectFirmware, md5hex, partitionTable} from '../src/firmware.js';
import {MigrationApproval} from '../src/migration-approval.js';

const hexBytes = value => Uint8Array.from(value.match(/../g), pair => parseInt(pair, 16));
function image(seed = 0, chip = 9, flashBytes = 4 << 20) {
  const data = new Uint8Array(64), view = new DataView(data.buffer);
  data[0] = 0xe9; data[1] = 1; data[12] = chip; data[3] = (Math.log2(flashBytes) - 20) << 4;
  view.setUint32(28, 16, true); view.setUint32(32, 0xabcd5432, true);
  data[36] = seed;
  let checksum = 0xef;
  for (const byte of data.subarray(32, 48)) checksum ^= byte;
  data[63] = checksum;
  return data;
}
function table(expanded, flashBytes = 4 << 20) {
  const data = new Uint8Array(4096).fill(255), view = new DataView(data.buffer);
  const [slotSize, app1, fsAddress, fsSize] = {
    [4 << 20]: [0x1f0000, 0x200000, 0x3f0000, 0x10000],
    [8 << 20]: [0x330000, 0x340000, 0x670000, 0x180000],
    [16 << 20]: [0x640000, 0x650000, 0xc90000, 0x360000]
  }[flashBytes];
  const entries = [
    [1, 2, 0x9000, 0x5000, 'nvs'], [1, 0, 0xe000, 0x2000, 'otadata'],
    [0, 0x10, 0x10000, expanded ? slotSize : 0x140000, 'app0'],
    [0, 0x11, expanded ? app1 : 0x150000, expanded ? slotSize : 0x140000, 'app1'],
    [1, 0x82, expanded ? fsAddress : 0x290000, expanded ? fsSize : flashBytes - 0x290000, 'spiffs'],
    ...(expanded && flashBytes > (4 << 20) ? [[1, 3, flashBytes - 0x10000, 0x10000, 'coredump']] : [])
  ];
  entries.forEach(([type, subtype, offset, size, name], index) => {
    const at = index * 32;
    data.fill(0, at, at + 32); view.setUint16(at, 0x50aa, true);
    data[at + 2] = type; data[at + 3] = subtype;
    view.setUint32(at + 4, offset, true); view.setUint32(at + 8, size, true);
    data.set(new TextEncoder().encode(name), at + 12);
  });
  const checksumAt = entries.length * 32;
  view.setUint16(checksumAt, 0xebeb, true);
  data.set(hexBytes(md5hex(data.subarray(0, checksumAt))), checksumAt + 16);
  return data;
}
function fixture({chip = 9, flashBytes = 4 << 20} = {}) {
  const pkg = inspectFirmware('heltec_v4_repeater-v1.18.0.2.bin', image(1, chip, flashBytes)), bridge = image(2, chip, flashBytes), source = table(false, flashBytes), target = table(true, flashBytes);
  const initial = {
    format: 'meshcore-usb-partition-expansion-v2', ok: true, needed: true, verified: false, usb_safe: true,
    sha256: pkg.sha256, payloadHash: pkg.payloadHash, firmware_sha256: pkg.sha256,
    mac: 'aa:bb:cc:dd:ee:ff', device_mac: 'AABBCCDDEEFF', chip, flash_bytes: flashBytes,
    board: 'Heltec v4', target: 'heltec_v4_repeater', bridge: Array.from(bridge), bridge_bytes: bridge.length, bridge_sha256: hash(bridge),
    bridge_offsets: [0x150000, 0x10000], app_offsets: [0x150000, 0x10000], addresses: [0x150000, 0x10000], active_offset: 0x10000,
    source_table_sha256: hash(source), parts: partitionTable(source, flashBytes),
    target_table_sha256: hash(target), targetTable: Array.from(target), installMode: 'update'
  };
  const targetParts = partitionTable(target, flashBytes), finalOffsets = [targetParts.find(part => part.type === 0 && part.subtype === 0x11).offset, 0x10000];
  const final = {
    ok: true, verified: true, sha256: pkg.sha256, payloadHash: pkg.payloadHash, firmware_sha256: pkg.sha256,
    mac: initial.mac, flash_bytes: initial.flash_bytes, target: initial.target,
    identity_restored: true, configuration_restored: true,
    completed_bridge_sha256: initial.bridge_sha256, completed_source_table_sha256: initial.source_table_sha256, completed_target_table_sha256: initial.target_table_sha256,
    completed_bridge_segments: initial.bridge_offsets.map(address => ({address, sourceOffset: 0, length: initial.bridge_bytes, payloadHash: initial.bridge_sha256})),
    parts: targetParts, addresses: [...finalOffsets], app_offsets: [...finalOffsets], active_offset: 0x10000, installMode: 'update'
  };
  const identity = {publicKey: '12'.repeat(32), model: 'Heltec V4.2', role: 'repeater', version: 'v1.18.0.1'};
  return {pkg, initial, final, identity};
}
function waitingRom(options = {}) {
  const data = fixture(), approval = new MigrationApproval(data.pkg, data.initial, options);
  approval.beginBridge(data.pkg, data.initial).bridgeVerified(data.pkg, data.initial);
  return {...data, approval};
}

test('one approval completes only in bridge / ROM / final / application order', () => {
  const {pkg, initial, final, identity} = fixture(), approval = new MigrationApproval(pkg, initial, {identity});
  assert.equal(approval.phase, 'bridge-ready'); assert.equal(approval.mac, initial.mac); assert.equal(approval.sha256, pkg.sha256);
  assert.deepEqual(approval.identity, identity);
  assert.equal(approval.beginBridge(pkg, initial), approval); assert.equal(approval.phase, 'bridge-writing');
  approval.bridgeVerified(pkg, initial); assert.equal(approval.phase, 'waiting-rom');
  approval.beginFinal(pkg, final); assert.equal(approval.phase, 'final-writing');
  approval.finalVerified(pkg, final); assert.equal(approval.phase, 'waiting-application');
  approval.complete(); assert.equal(approval.phase, 'complete');
  assert.throws(() => approval.beginBridge(pkg, initial), /cannot be replayed/); assert.equal(approval.phase, 'revoked');
});
test('all native reviewed chip/capacity combinations can use a qualified embedded USB bridge', () => {
  for (const chip of [0, 5, 9]) for (const flashBytes of [4 << 20, 8 << 20, 16 << 20]) {
    const {pkg, initial, final} = fixture({chip, flashBytes}), approval = new MigrationApproval(pkg, initial);
    approval.beginBridge(pkg, initial).bridgeVerified(pkg, initial).beginFinal(pkg, final).finalVerified(pkg, final).complete();
    assert.equal(approval.phase, 'complete');
  }
});
test('identity is optional, copied and immutable; private authorization is not serializable', () => {
  const {pkg, initial, identity} = fixture(), approval = new MigrationApproval(pkg, initial, {identity});
  identity.model = 'changed';
  assert.equal(approval.identity.model, 'Heltec V4.2');
  assert.ok(Object.isFrozen(approval.identity)); assert.throws(() => { approval.identity.role = 'companion'; }, TypeError);
  assert.equal(JSON.stringify(approval), '{}');
  assert.equal(new MigrationApproval(pkg, initial).identity, null);
  assert.throws(() => new MigrationApproval(pkg, initial, {identity: {publicKey: 'truncated'}}), /identity/);
});
test('completion requires successful final-write readback and separately verified application startup', () => {
  for (const phase of ['bridge-ready', 'bridge-writing', 'waiting-rom', 'final-writing']) {
    const {pkg, initial, final} = fixture(), approval = new MigrationApproval(pkg, initial);
    if (phase !== 'bridge-ready') approval.beginBridge(pkg, initial);
    if (['waiting-rom', 'final-writing'].includes(phase)) approval.bridgeVerified(pkg, initial);
    if (phase === 'final-writing') approval.beginFinal(pkg, final);
    assert.throws(() => approval.complete(), /expected waiting-application/); assert.equal(approval.phase, 'revoked');
  }
});
test('revocation is terminal and idempotent from every phase', () => {
  const {pkg, initial, approval} = waitingRom();
  approval.revoke(); approval.revoke(); assert.equal(approval.phase, 'revoked');
  assert.throws(() => approval.beginBridge(pkg, initial), /cannot be replayed/);
  assert.equal(approval.phase, 'revoked');
});
test('phase skipping and final/bridge replay revoke authorization', () => {
  for (const action of [a => a.bridgeVerified, a => a.beginFinal, a => a.finalVerified]) {
    const {pkg, initial, final} = fixture(), approval = new MigrationApproval(pkg, initial);
    assert.throws(() => action(approval).call(approval, pkg, final), /expected/);
    assert.equal(approval.phase, 'revoked');
  }
  const {pkg, final, approval} = waitingRom();
  approval.beginFinal(pkg, final);
  assert.throws(() => approval.beginFinal(pkg, final), /cannot be replayed/); assert.equal(approval.phase, 'revoked');
});
test('unsupported, partial, resumed or override plans cannot acquire automatic approval', () => {
  const mutations = [
    ({pkg}) => { pkg.architecture = 'nrf52'; }, ({pkg}) => { pkg.merged = true; }, ({pkg}) => { pkg.expert = true; },
    ({pkg}) => { pkg.destructive = true; }, ({initial}) => { initial.format = 'v1'; }, ({initial}) => { initial.ok = false; },
    ({initial}) => { initial.needed = false; }, ({initial}) => { initial.verified = true; }, ({initial}) => { initial.verified = 'true'; }, ({initial}) => { initial.usb_safe = false; },
    ({initial}) => { initial.resume = true; }, ({initial}) => { initial.resume = 'true'; }, ({initial}) => { initial.started = true; }, ({initial}) => { initial.completed = true; },
    ({initial}) => { initial.chip = 13; }, ({initial}) => { initial.flash_bytes = 32 << 20; },
    ({initial}) => { initial.requiresRevisionOverride = true; }, ({initial}) => { initial.chunkedRecovery = true; },
    ({initial}) => { initial.merged = true; }, ({initial}) => { initial.expert = true; },
    ({initial}) => { initial.segments = []; }, ({initial}) => { initial.installMode = 'erase'; }
  ];
  for (const mutate of mutations) { const data = fixture(); mutate(data); assert.throws(() => new MigrationApproval(data.pkg, data.initial)); }
});
test('malformed MAC, payload, bridge bytes, hashes and geometry are refused', () => {
  const mutations = [
    ({initial}) => { initial.mac = 'unknown'; }, ({initial}) => { initial.mac = '00:00:00:00:00:00'; },
    ({initial}) => { initial.device_mac = 'AABBCCDDEE00'; }, ({pkg}) => { pkg.payload[36] ^= 1; },
    ({pkg}) => { pkg.chipId = 0; }, ({initial}) => { initial.sha256 = '00'.repeat(32); },
    ({initial}) => { initial.payloadHash = '00'.repeat(32); }, ({initial}) => { initial.firmware_sha256 = '00'.repeat(32); },
    ({initial}) => { initial.bridge[36] ^= 1; }, ({initial}) => { initial.bridge[0] = 256; },
    ({initial}) => { initial.bridge_bytes += 4; }, ({initial}) => { initial.bridge_sha256 = 'invalid'; },
    ({initial}) => { initial.bridge_offsets = [0x150000, 0x150000]; }, ({initial}) => { initial.addresses = [0x10000, 0x150000]; },
    ({initial}) => { initial.app_offsets[0] += 4096; }, ({initial}) => { initial.active_offset = 0x150000; },
    ({initial}) => { initial.parts[2].size = 0; }, ({initial}) => { initial.parts[3].offset = 0x10000; },
    ({initial}) => { initial.source_table_sha256 = null; }, ({initial}) => { initial.targetTable = null; },
    ({initial}) => { initial.targetTable.pop(); }, ({initial}) => { initial.targetTable[144] ^= 1; },
    ({initial}) => { initial.target_table_sha256 = '00'.repeat(32); }, ({initial}) => { initial.board = ''; },
    ({initial}) => { initial.target = ''; }
  ];
  for (const mutate of mutations) { const data = fixture(); mutate(data); assert.throws(() => new MigrationApproval(data.pkg, data.initial)); }
});
test('initial approval snapshot detects bound-field changes before bridge or after its readback', () => {
  const mutations = [
    ({pkg}) => { pkg.name = 'another.bin'; }, ({initial}) => { initial.board = 'another board'; },
    ({initial}) => { initial.target = 'another target'; }, ({initial}) => { initial.source_table_sha256 = '01'.repeat(32); },
    ({initial}) => { initial.mac = 'aa:bb:cc:dd:ee:00'; initial.device_mac = 'AABBCCDDEE00'; },
    ({initial}) => { initial.parts[2].label = 'different'; },
    ({initial}) => { initial.bridge_offsets.reverse(); initial.addresses.reverse(); initial.app_offsets.reverse(); initial.active_offset = 0x150000; },
    ({initial}) => { const next = image(3); initial.bridge = Array.from(next); initial.bridge_sha256 = hash(next); }
  ];
  for (const duringReadback of [false, true]) for (const mutate of mutations) {
    const data = fixture(), approval = new MigrationApproval(data.pkg, data.initial);
    if (duringReadback) approval.beginBridge(data.pkg, data.initial);
    mutate(data);
    assert.throws(() => duringReadback ? approval.bridgeVerified(data.pkg, data.initial) : approval.beginBridge(data.pkg, data.initial));
    assert.equal(approval.phase, 'revoked');
  }
});
test('final proof requires all restoration, original bridge provenance and approved target geometry', () => {
  const mutations = [
    ({final}) => { final.verified = false; }, ({final}) => { final.identity_restored = false; }, ({final}) => { final.configuration_restored = false; },
    ({final}) => { final.mac = 'aa:bb:cc:dd:ee:00'; }, ({final}) => { final.flash_bytes = 8 << 20; }, ({final}) => { final.target = 'another'; },
    ({final}) => { final.firmware_sha256 = '00'.repeat(32); }, ({final}) => { final.completed_bridge_sha256 = '00'.repeat(32); },
    ({final}) => { final.completed_source_table_sha256 = '00'.repeat(32); }, ({final}) => { delete final.completed_target_table_sha256; },
    ({final}) => { final.completed_target_table_sha256 = '00'.repeat(32); }, ({final}) => { final.completed_bridge_segments.pop(); },
    ({final}) => { final.completed_bridge_segments[0].address = 0x200000; }, ({final}) => { final.completed_bridge_segments[0].sourceOffset = 4; },
    ({final}) => { final.completed_bridge_segments[0].length += 4; }, ({final}) => { final.completed_bridge_segments[0].payloadHash = '00'.repeat(32); },
    ({final}) => { final.parts[2].size -= 4096; }, ({final}) => { final.parts[4].label = 'wrong-filesystem'; },
    ({final}) => { final.addresses[0] = 0x150000; final.app_offsets[0] = 0x150000; },
    ({final}) => { final.addresses.reverse(); }, ({final}) => { final.active_offset = 0x200000; },
    ({final}) => { final.requiresRevisionOverride = true; }, ({final}) => { final.chunkedRecovery = true; },
    ({final}) => { final.segments = []; }, ({final}) => { final.expert = true; }, ({final}) => { final.merged = true; },
    ({pkg}) => { pkg.merged = true; }, ({pkg}) => { pkg.payload[36] ^= 1; }
  ];
  for (const duringReadback of [false, true]) for (const mutate of mutations) {
    const data = waitingRom();
    if (duringReadback) data.approval.beginFinal(data.pkg, data.final);
    mutate(data);
    assert.throws(() => duringReadback ? data.approval.finalVerified(data.pkg, data.final) : data.approval.beginFinal(data.pkg, data.final));
    assert.equal(data.approval.phase, 'revoked');
  }
});
test('a different valid final active-slot order cannot replace the authorized final write', () => {
  const {pkg, final, approval} = waitingRom();
  approval.beginFinal(pkg, final);
  final.addresses.reverse(); final.app_offsets.reverse(); final.active_offset = 0x200000;
  assert.throws(() => approval.finalVerified(pkg, final), /final write plan changed/); assert.equal(approval.phase, 'revoked');
});
test('volatile UI metadata does not alter the one approved write geometry', () => {
  const {pkg, initial, final} = fixture(), approval = new MigrationApproval(pkg, initial);
  initial.generation = 2; initial.port = {}; initial.transportMode = 'native';
  approval.beginBridge(pkg, initial);
  initial.written = true;
  approval.bridgeVerified(pkg, initial).beginFinal(pkg, final);
  final.written = true; final.generation = 3;
  approval.finalVerified(pkg, final).complete(); assert.equal(approval.phase, 'complete');
});
