import test from 'node:test';
import assert from 'node:assert/strict';
import {nrfBoardCandidates} from '../src/nrf-board-candidates.js';

const item = (hardware, more = {}) => ({project: 'MeshCore', architecture: 'nrf52', hardware, ...more});
const usb = id => {const [usbVendorId, usbProductId] = id.split(':').map(value => parseInt(value, 16)); return {usbVendorId, usbProductId};};
const candidates = (items, id, more = {}) => nrfBoardCandidates({items, usbInfo: usb(id), ...more});

test('an exact previously identified nRF52 hardware target outranks shared USB hints without selecting it', () => {
  const items = [item('RAK WisMesh 1W Booster (3401 + 13302)'), item('RAK WisBlock / WisMesh (RAK 4631)'), item('Heltec v4', {architecture: 'esp32'})];
  const result = candidates(items, '239a:002a', {hardware: 'RAK WisMesh 1W Booster (3401 + 13302)'});
  assert.deepEqual(result.candidates, ['RAK WisMesh 1W Booster (3401 + 13302)']);
  assert.equal(result.source, 'identified-hardware');
  for (const field of ['hardware', 'approved', 'boardOverride', 'write', 'profile']) assert.equal(Object.hasOwn(result, field), false);
  assert.match(result.reason, /not independent physical-board proof/);
  assert.equal(candidates(items, '239a:002a', {hardware: 'Heltec v4'}).source, 'usb-hint');
  assert.equal(candidates(items, '239a:002a', {hardware: 'RAK3401'}).source, 'usb-hint');
});

test('the shared Adafruit USB union retains all represented brands, even when no bootloader catalog metadata is available', () => {
  const names = ['RAK WisMesh 1W Booster (3401 + 13302)', 'RAK WisBlock / WisMesh (RAK 4631)', 'RAK WisMesh Tag', 'Muzi Works R1 Neo', 'GAT-IoT GAT562 30s', 'GAT-IoT GAT562 EVB Pro', 'GAT-IoT GAT562 Tracker', 'GAT-IoT GAT562 Mesh Watch13', 'Minewsemi ME25LS01', 'Meshtiny'];
  const items = [...names.map(name => item(name)), item('Heltec T114'), item('Heltec v4', {architecture: 'esp32'}), item('Other nRF52 board'), item('LilyGo T-Echo')];
  assert.deepEqual(candidates(items, '239a:002a').candidates, [...names].sort());
  assert.deepEqual(candidates(items, '239a:0029').candidates, [...names, 'LilyGo T-Echo'].sort());
  const one = candidates([item(names[0])], '239a:002a');
  assert.deepEqual(one.candidates, [names[0]]);assert.equal(Object.hasOwn(one, 'hardware'), false);assert.match(one.reason, /not board proof/);
});

test('other exact USB groups include factory/current source aliases and exclude unrelated architectures and brands', () => {
  const groups = [
    ['239a:0071', ['Heltec T114', 'Heltec Mesh Node T096', 'Heltec Mesh Node T1', 'Heltec MeshPocket', 'Heltec MeshTower V2', 'Heltec MeshSolar / MeshTower']],
    ['239a:0081', ['Muzi Works Base Duo', 'Muzi Works Base Uno']],
    ['239a:00b3', ['Keepteen LT1', 'ProMicro nrf52 (faketec)']],
    ['239a:00da', ['Elecrow ThinkNode M1', 'Elecrow ThinkNode M3', 'Elecrow ThinkNode M6', 'LilyGo T-Echo Lite', 'LilyGo T-Echo Card', 'LilyGo T-Impulse Plus nRF52840']],
    ['2886:0044', ['Seeed Studio Xiao nRF52 WIO', 'Ikoka Handheld nRF E22 30 dBm', 'Ikoka Nano', 'Ikoka Stick', 'SolarXiao', 'Seeed Studio SenseCAP Solar']],
    ['2886:0045', ['Seeed Studio Xiao nRF52 WIO']],
    ['2886:0057', ['Seeed Studio SenseCAP T1000-E', 'Seeed SenseCAP MeshTracker X1']],
    ['2886:1667', ['Seeed Studio Wio Tracker L1 Pro', 'Seeed Studio Wio Tracker L1 E-Ink', 'Seeed WioTracker L1 1W']],
    ['4251:8695', ['UnitEng Nano G2 Ultra']],
  ];
  const items = [...new Set(groups.flatMap(([, names]) => names))].map(name => item(name));
  items.push(item('Heltec v4', {architecture: 'esp32'}), item('Unknown nRF52 board'));
  for (const [id, names] of groups) assert.deepEqual(candidates(items, id).candidates, [...names].sort(), id);
});

test('exact reviewed profile metadata adds catalog display aliases but never uses a similar or unreviewed profile', () => {
  const profile = {tag: 'v0.11.0-OTAFIX2.4.12', profile: 'wiscore_rak4631_auto'};
  const items = [item('Reviewed carrier alias', {bootloaderInfo: profile}), item('Similar profile', {bootloaderInfo: {...profile, profile: 'wiscore_rak4631_auto_extra'}}), item('New release alias', {bootloaderInfo: {...profile, tag: 'v0.11.0-OTAFIX2.4.13'}}), item('Wrong architecture', {architecture: 'esp32', bootloaderInfo: profile}), item('Foreign project', {project: 'Other', bootloaderInfo: profile})];
  assert.deepEqual(candidates(items, '239a:002a').candidates, ['Reviewed carrier alias']);
  assert.deepEqual(candidates(items, '2886:0044').candidates, []);
});

test('known display aliases canonicalize and deduplicate without fuzzy matching', () => {
  const items = [item('Seeed Studio SenseCAP Solar'), item('Seeed Studio SenseCAP Solar Node P1'), item('Seeed Studio SenseCAP Solar extra'), item('Seeed Studio SenseCAP MeshTracker X1'), item('Seeed SenseCAP MeshTracker X1'), item('Seeed Studio Wio Tracker L1 EINK'), item('Seeed Studio Wio Tracker L1 E-Ink')];
  assert.deepEqual(candidates(items, '2886:0044').candidates, ['Seeed Studio SenseCAP Solar']);
  assert.deepEqual(candidates(items, '2886:0057').candidates, ['Seeed SenseCAP MeshTracker X1']);
  assert.deepEqual(candidates(items, '2886:1667').candidates, ['Seeed Studio Wio Tracker L1 E-Ink']);
  assert.deepEqual(candidates(items, '2886:0044', {hardware: 'Seeed Studio SenseCAP Solar Node P1'}).candidates, ['Seeed Studio SenseCAP Solar']);
});

test('unknown/malformed USB identities and missing candidates fall back to the unrestricted nRF52 list', () => {
  const items = [item('Heltec T114')];
  for (const usbInfo of [{}, null, {usbVendorId: 0x239a}, {usbVendorId: '239a', usbProductId: 0x0071}, {usbVendorId: 0x239a, usbProductId: -1}, {usbVendorId: 65536, usbProductId: 0x0071}, {usbVendorId: 0x303a, usbProductId: 0x1001}, {usbVendorId: 0x2886, usbProductId: 0x8044}]) {
    const result = nrfBoardCandidates({items, usbInfo});assert.deepEqual(result.candidates, []);assert.equal(result.source, 'unknown');
  }
  for (const invalid of [null, {}, 'Heltec T114']) assert.deepEqual(nrfBoardCandidates({items: invalid, usbInfo: usb('239a:0071')}).candidates, []);
  assert.deepEqual(candidates([item('Unknown nRF52 board')], '239a:0071').candidates, []);
  assert.match(candidates([item('Unknown nRF52 board')], '239a:0071').reason, /Keep all nRF52 hardware available/);
});

test('the helper never mutates callers or leaves shared candidate state mutable', () => {
  const items = Object.freeze([Object.freeze(item('Heltec T114')), Object.freeze(item('Heltec T114')), Object.freeze(item('Heltec T114', {project: 'Other'})), Object.freeze(item('Heltec T114', {architecture: 'esp32'}))]);
  const usbInfo = Object.freeze(usb('239a:0071')), before = structuredClone(items);
  const result = nrfBoardCandidates({items, usbInfo});assert.deepEqual(result.candidates, ['Heltec T114']);result.candidates.push('Other');
  assert.deepEqual(nrfBoardCandidates({items, usbInfo}).candidates, ['Heltec T114']);assert.deepEqual(items, before);
});
