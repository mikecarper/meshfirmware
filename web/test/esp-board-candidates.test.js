import test from 'node:test';
import assert from 'node:assert/strict';
import {espBoardCandidates} from '../src/esp-board-candidates.js';

const item = (hardware, extra = {}) => ({project: 'MeshCore', architecture: 'esp32', hardware, ...extra});
const usb = id => {const [usbVendorId, usbProductId] = id.split(':').map(value => parseInt(value, 16)); return {usbVendorId, usbProductId};};
const check = (items, chipInfo, more = {}) => espBoardCandidates({items, chipInfo, ...more});

test('actual S3 ROM evidence narrows processor candidates without identifying a board', () => {
  const items = ['LilyGo T-Deck', 'Heltec v4', 'Heltec v4 R8', 'Heltec v2', 'Seeed Studio Xiao C3', 'Seeed Studio Xiao C6', 'LilyGo T-Deck Pro', 'Unknown custom board'].map(name => item(name));
  items.push(item('Seeed Studio SenseCAP T1000-E', {architecture: 'nrf52'}));
  const result = check(items, {chipId: 9, chip: 'ESP32-S3', flashBytes: 16 << 20, psramBytes: 8 << 20});
  assert.equal(result.architecture, 'esp32');assert.equal(result.chipFamily, 'ESP32-S3');assert.equal(result.source, 'rom-chip');
  assert.deepEqual(result.candidates, ['Heltec v4', 'Heltec v4 R8', 'LilyGo T-Deck', 'LilyGo T-Deck Pro', 'Unknown custom board']);
  assert.deepEqual(result.excluded, ['Heltec v2', 'Seeed Studio Xiao C3', 'Seeed Studio Xiao C6']);
  assert.deepEqual(result.unknown, ['LilyGo T-Deck Pro', 'Unknown custom board']);
  assert.match(result.reason, /not physical-board proof or permission/);
  for (const field of ['hardware', 'approved', 'boardOverride', 'write', 'profile']) assert.equal(Object.hasOwn(result, field), false);
});

test('reviewed exact native USB identities narrow architecture only, never S3 or memory', () => {
  const items = ['LilyGo T-Deck', 'Heltec v2', 'Seeed Studio Xiao C3', 'Seeed Studio Xiao C6', 'Unknown board'].map(name => item(name));
  items.push(item('nRF board', {architecture: 'nrf52'}));
  for (const id of ['303a:1001', '303a:0002']) {
    const result = espBoardCandidates({items, usbInfo: usb(id)});
    assert.equal(result.architecture, 'esp32');assert.equal(result.source, 'usb-hint');assert.equal(result.chipFamily, '');
    assert.deepEqual(result.candidates, items.slice(0, -1).map(i => i.hardware).sort());assert.deepEqual(result.excluded, []);
    assert.match(result.reason, /exact chip, memory and physical board are not identified/);
  }
});

test('generic USB bridges, arbitrary Espressif IDs and malformed identities do not scope hardware', () => {
  const items = [item('LilyGo T-Deck'), item('Heltec v2')];
  for (const usbInfo of [usb('10c4:ea60'), usb('1a86:7523'), usb('1a86:55d4'), usb('303a:ffff'), usb('2886:0059'), {}, null, {usbVendorId: '303a', usbProductId: 0x1001}, {usbVendorId: 0x303a, usbProductId: -1}]) {
    const result = espBoardCandidates({items, usbInfo});
    assert.equal(result.architecture, '');assert.equal(result.source, 'unknown');assert.deepEqual(result.candidates, []);assert.deepEqual(result.excluded, []);
  }
});

test('chip IDs and supported ROM names are exact, and contradictory ROM fields retain all ESP boards', () => {
  const items = [item('Heltec v2'), item('Seeed Studio Xiao C3'), item('LilyGo T-Deck'), item('Seeed Studio Xiao C6')];
  for (const [chipId, chipFamily] of [[0, 'ESP32'], [2, 'ESP32-S2'], [5, 'ESP32-C3'], [9, 'ESP32-S3'], [13, 'ESP32-C6']]) {
    assert.equal(check(items, {chipId}).chipFamily, chipFamily);
    assert.equal(check(items, {chip: chipFamily}).chipFamily, chipFamily);
    assert.equal(check(items, {name: `${chipFamily} (revision v0.2)`}).chipFamily, chipFamily);
    assert.equal(check(items, {chipName: chipFamily.toLowerCase()}).chipFamily, chipFamily);
  }
  const conflict = check(items, {chipId: 9, chip: 'ESP32-C3'});
  assert.equal(conflict.architecture, 'esp32');assert.equal(conflict.chipFamily, '');assert.deepEqual(conflict.excluded, []);
  assert.deepEqual(conflict.candidates, items.map(i => i.hardware).sort());assert.match(conflict.reason, /disagree/);
  for (const chipInfo of [{chipId: '9'}, {chipId: 999}, {chip: 'ESP32-S3pretend'}, {chip: 'LilyGo T-Deck ESP32-S3'}, {chip: 'ESP32-S3\n'}, {chip: 'ESP32-S3'.repeat(30)}, null, 'ESP32-S3']) assert.equal(check(items, chipInfo).architecture, '');
});

test('missing, unsupported and conflicting catalog metadata is retained instead of guessed', () => {
  const items = [
    item('Known chip', {chipFamily: 'ESP32-C3'}),
    item('No metadata'),
    item('Missing variant', {chipFamily: 'ESP32-C3'}), item('Missing variant'),
    item('Conflicting variant', {chipFamily: 'ESP32-C3'}), item('Conflicting variant', {chipFamily: 'ESP32-S3'}),
    item('Unrecognized chip', {chipFamily: 'ESP32-C999'}),
    item('Heltec v2', {chipFamily: 'ESP32-S3'}),
    item('ESP32-C3 name is not evidence'),
  ];
  const result = check(items, {chipId: 9});
  assert.deepEqual(result.excluded, ['Known chip']);
  assert.deepEqual(result.candidates, ['Conflicting variant', 'ESP32-C3 name is not evidence', 'Heltec v2', 'Missing variant', 'No metadata', 'Unrecognized chip']);
  assert.deepEqual(result.unknown, result.candidates);
  // Provider/role subsets must not be fed to this helper to manufacture a
  // unanimous board profile; the caller supplies the complete catalog.
  const entire = check([...items, item('Known chip', {chipFamily: 'ESP32-S3', provider: 'Other provider'})], {chipId: 9});
  assert.ok(entire.candidates.includes('Known chip'));
});

test('memory fields, release notes, filenames and selected/proposed hardware do not prune boards', () => {
  const items = [
    item('LilyGo T-Deck', {flashBytes: 32 << 20, flashSize: '32MB', psramBytes: 16 << 20}),
    item('Heltec v4', {flashBytes: 4 << 20, psramBytes: 2 << 20}),
    item('LilyGo T-Beam Supreme (SX1262)', {name: 'nrf52.bin', releaseNotes: 'ESP32-C6'}),
    item('Unknown memory', {minimumFlashBytes: 32 << 20, minimumPsramBytes: 16 << 20}),
  ];
  const before = check(items, {chipId: 9});
  assert.deepEqual(check(items, {chipId: 9, flashBytes: 16 << 20, psramBytes: 8 << 20}).candidates, before.candidates);
  assert.deepEqual(check(items, {chipId: 9, flashBytes: 1, psramBytes: 0}).candidates, before.candidates);
  assert.deepEqual(espBoardCandidates({items, hardware: 'LilyGo T-Deck', pkg: {chipId: 9}, usbInfo: usb('10c4:ea60')}).candidates, []);
});

test('reviewed source recipes cover the real legacy, C3, C6 and S3 board groups', () => {
  const groups = [
    [0, ['GEPRC Linkflow 900', 'Generic E22', 'Heltec v2', 'LilyGo LoRa32 V2.1_1.6', 'LilyGo T-Beam (SX1262)', 'LilyGo T-Beam 1.2 (SX1276)', 'Meshadventurer']],
    [5, ['Generic ESP-NOW', 'Heltec CT62', 'Seeed Studio Xiao C3', 'Tenstar C3']],
    [13, ['LilyGo T-LoRa C6', 'M5Stack Unit C6L', 'Meshimi', 'Seeed Studio Xiao C6', 'WHY2025 Badge']],
    [9, ['Ebyte EoRa-S3', 'Elecrow ThinkNode M2', 'Elecrow ThinkNode M5', 'Elecrow ThinkNode M7', 'Elecrow ThinkNode M9', 'Heltec RC32', 'Heltec Vision Master E213', 'Heltec Vision Master E290', 'Heltec Vision Master T190', 'Heltec WSL3', 'Heltec Wireless Paper', 'Heltec Wireless Tracker', 'Heltec Wireless Tracker v1.1', 'Heltec Wireless Tracker v2', 'Heltec v3', 'Heltec v4', 'Heltec v4 + Expansion Kit (Touch)', 'Heltec v4 R8', 'LilyGo T-Beam 1W', 'LilyGo T-Beam Supreme (SX1262)', 'LilyGo T-Deck', 'LilyGo T-ETH Elite (SX1262)', 'LilyGo T3 S3 (SX126x)', 'LilyGo T3 S3 (SX127x)', 'MKE S3', 'Meshnology W12', 'Nibble Screen Connect', 'Nibble Zero Connect', 'RAK WisBlock 3112', 'Seeed Studio SenseCAP Indicator ESP-NOW', 'Seeed Studio SenseCAP Indicator LoRa', 'Seeed Studio Xiao S3', 'Seeed Studio Xiao S3 WIO', 'Seeed Wio Tracker L2', 'UnitEng Station G2', 'UnitEng/BQ Voyage Station G3', 'Waveshare ESP32-S3 LR1121', 'Elecrow CrowPanel Advance 3.5', 'Elecrow CrowPanel Advance 5.0', 'LilyGo T-Lora Pager (SX1262)', 'LilyGo T-Lora Pager (LR1121)']],
  ];
  const names = groups.flatMap(([, names]) => names), unknown = ['LilyGo T-Deck Pro', 'LilyGo T-Display Pro'];
  assert.equal(new Set(names).size, 57);
  const items = [...names, ...unknown].map(name => item(name));
  for (const [chipId, compatible] of groups) {
    const result = check(items, {chipId});
    assert.deepEqual(result.candidates, [...compatible, ...unknown].sort());
    assert.deepEqual(result.unknown, [...unknown].sort());
    assert.deepEqual(result.excluded, names.filter(name => !compatible.includes(name)).sort());
  }
});

test('aliases canonicalize, candidates deduplicate, and one candidate is never an automatic model match', () => {
  const result = check([item('Heltec Heltec Wireless Paper'), item('Heltec Wireless Paper'), item('Heltec Wireless Paper', {architecture: 'nrf52'}), item('Foreign', {project: 'Other'})], {chipId: 9});
  assert.deepEqual(result.candidates, ['Heltec Wireless Paper']);assert.deepEqual(result.unknown, []);
  assert.equal(Object.hasOwn(result, 'hardware'), false);assert.match(result.reason, /not physical-board proof/);
});

test('inputs are not mutated and calls do not expose mutable shared candidate state', () => {
  const items = Object.freeze([Object.freeze(item('LilyGo T-Deck')), Object.freeze(item('Heltec v2'))]), chipInfo = Object.freeze({chipId: 9}), usbInfo = Object.freeze(usb('303a:1001'));
  const before = structuredClone(items), result = espBoardCandidates({items, chipInfo, usbInfo});
  result.candidates.push('Forged');result.excluded.length = 0;
  assert.deepEqual(check(items, chipInfo).candidates, ['LilyGo T-Deck']);assert.deepEqual(check(items, chipInfo).excluded, ['Heltec v2']);assert.deepEqual(items, before);
  for (const invalid of [null, {}, 'board']) assert.deepEqual(check(invalid, chipInfo).candidates, []);
});
