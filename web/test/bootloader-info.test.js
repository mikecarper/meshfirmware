import test from 'node:test';
import assert from 'node:assert/strict';
import {parseBootloaderInfo, detectBootloaderBoard} from '../src/bootloader-info.js';

const item = (hardware, architecture = 'nrf52', more = {}) => ({project: 'MeshCore', hardware, architecture, ...more});
const contents = ({version = '0.11.0-OTAFIX2.4.12', model = 'HT-n5262', boardId = 'HT-n5262', softDevice = 'S140 0x00B6', date = 'Oct 28 2026'} = {}) =>
  `UF2 Bootloader ${version}\r\nModel: ${model}\r\nBoard-ID: ${boardId}\r\n${date ? `Date: ${date}\r\n` : ''}${softDevice ? `SoftDevice: ${softDevice}\r\n` : ''}`;
const info = values => parseBootloaderInfo(contents(values));

test('parser accepts complete stock/OTAFIX files and returns only bounded identity values', () => {
  assert.deepEqual(info(), {version: '0.11.0-OTAFIX2.4.12', model: 'HT-n5262', boardId: 'HT-n5262', softDevice: 'S140 0x00B6'});
  assert.deepEqual(info({version: '0.9.2', softDevice: 'S140 6.1.1', date: 'Jul  9 2024'}), {version: '0.9.2', model: 'HT-n5262', boardId: 'HT-n5262', softDevice: 'S140 6.1.1'});
  assert.equal(parseBootloaderInfo(contents().replace(/\r\n/g, '\n')).version, '0.11.0-OTAFIX2.4.12');
  assert.equal(info({version: 'v0.11.0-OTAFIX2.4.12', date: '', softDevice: ''}).softDevice, undefined);
  assert.equal(info({softDevice: 'S140 182'}).softDevice, 'S140 182');
  assert.equal(info({softDevice: 'not found'}).softDevice, 'not found');
  assert.equal(info({version: 'BL_0x02040CFF'}).version, 'BL_0x02040CFF');
});

test('factory dependency descriptions are validated, not interpreted or mistaken for the version', () => {
  // Exact header recovered read-only from Heltec's public 2024-07-09 factory HEX.
  const header = '0.9.0-2-g836c8dc-dirty lib/nrfx (v2.0.0) lib/tinyusb (0.12.0-145-g9775e7691) lib/uf2 (remotes/origin/configupdate-9-gadbb8c7)';
  assert.equal(info({version: header}).version, '0.9.0-2-g836c8dc-dirty');
  for (const version of ['0.9.2 run firmware', '0.9.2 lib/nrfx (v2.0.0) lib/nrfx (v2.0.0)', '0.9.2 lib/unknown (1.0.0)', '0.9.2 lib/uf2 (one;run)', '0.9.2 lib/uf2 (unterminated']) assert.throws(() => info({version}), /Invalid INFO_UF2/);
});

test('exact reviewed OTAFIX T114 pair and explicit Tower model distinguish the same shared Board-ID', () => {
  const items = [item('Heltec T114'), item('Heltec T114', 'nrf52', {provider: 'Other'}), item('Heltec MeshTower V2'), item('Heltec MeshPocket'), item('Heltec v2', 'esp32')];
  const usbInfo = {usbVendorId: 0x239a, usbProductId: 0x0071};
  const t114 = detectBootloaderBoard({items, info: info(), usbInfo});
  assert.equal(t114.hardware, 'Heltec T114');
  assert.deepEqual(t114.candidates, ['Heltec T114']);
  assert.equal(t114.source, 'bootloader-info');
  assert.equal(t114.architecture, 'nrf52');
  assert.match(t114.reason, /not physical-board proof/);
  assert.match(t114.reason, /not.*board-safety override/);
  const tower = detectBootloaderBoard({items, info: info({model: 'Heltec MeshTower V2'}), usbInfo});
  assert.equal(tower.hardware, 'Heltec MeshTower V2');
  assert.deepEqual(tower.candidates, ['Heltec MeshTower V2']);
  assert.equal(detectBootloaderBoard({items: [item('Heltec v2', 'esp32')], info: info()}).hardware, null);
});

test('stock or unreviewed generic HT-n5262 remains manual even when the catalog is filtered', () => {
  for (const version of ['0.9.2', '0.9.0-2-g836c8dc-dirty', '0.11.0-OTAFIX2.4.11', '0.11.0-OTAFIX2.4.13', '0.11.0-OTAFIX2.4.12-preview.1']) {
    for (const items of [[item('Heltec T114')], [item('Heltec T114'), item('Heltec MeshTower V2'), item('Heltec MeshPocket')]]) {
      const result = detectBootloaderBoard({items, info: info({version})});
      assert.equal(result.hardware, null);
      assert.deepEqual(result.candidates, items.map(entry => entry.hardware).sort());
      assert.match(result.reason, /shared by Heltec/);
    }
  }
});

test('reviewed exact model/board pairs map only the corresponding nRF52 hardware', () => {
  const cases = [
    ['HT-n5262G', 'HT-n5262G', 'Heltec Mesh Node T096'],
    ['Heltec Mesh Node T1', 'Heltec-Mesh-Node-T1', 'Heltec Mesh Node T1'],
    ['Heltec Mesh Pocket', 'Heltec-Mesh-Pocket', 'Heltec MeshPocket'],
    ['Seeed T1000-E for Meshtastic', 'nRF52840-T1000-E-v1', 'Seeed Studio SenseCAP T1000-E'],
    ['Keepteen LT1', 'Keepteen-LT1', 'Keepteen LT1'],
    ['LilyGo T-Echo', 'nRF52840-TEcho-v1', 'LilyGo T-Echo'],
    ['LilyGo T-Echo Lite', 'T-Echo-Lite-nRF52840', 'LilyGo T-Echo Lite'],
    ['ELECROW ThinkNodeM1', 'nRF52840-ThinkNodeM1-v1', 'Elecrow ThinkNode M1'],
    ['ELECROW ThinkNode-M3', 'nRF52840-ThinkNode-M3-v1', 'Elecrow ThinkNode M3'],
    ['ELECROW ThinkNodeM6', 'nRF52840-ThinkNodeM6-v1', 'Elecrow ThinkNode M6'],
    ['MinewSemi MX25LE01', 'MinewSemi-MX25LE01', 'Minewsemi ME25LS01'],
    ['WisMesh Tag', 'WisMesh-Tag', 'RAK WisMesh Tag'],
  ];
  const items = cases.map(([, , hardware]) => item(hardware));
  for (const [model, boardId, hardware] of cases) assert.equal(detectBootloaderBoard({items, info: info({model, boardId})}).hardware, hardware);
});

test('shared RAK, GAT, XIAO, ProMicro, L1 and Solar identities remain manual after filtering', () => {
  const cases = [
    ['MTools Tec GAT562', 'GAT562-Family', 'GAT-IoT GAT562 30s'],
    ['WisBlock RAK4631 Board', 'WisBlock-RAK4631-Board', 'RAK WisBlock / WisMesh (RAK 4631)'],
    ['RAK4631', '4631A', 'RAK WisBlock / WisMesh (RAK 4631)'],
    ['WisBlock RAK3401', 'WisBlock-RAK3401', 'RAK WisMesh 1W Booster (3401 + 13302)'],
    ['RAK3401', '3401A', 'RAK WisMesh 1W Booster (3401 + 13302)'],
    ['Seeed XIAO nRF52840', 'nRF52840-SeeedXiao-v1', 'Seeed Studio Xiao nRF52 WIO'],
    ['Seeed XIAO nRF52840', 'nRF52840-SeeedXiaoSense-v1', 'Seeed Studio Xiao nRF52 WIO'],
    ['Seeed TRACKER L1', 'TRACKER L1', 'Seeed Studio Wio Tracker L1 Pro'],
    ['Seeed Solar Node P1', 'nRF52840-SeeedSenseCAPSolarP1-v1', 'Seeed Studio SenseCAP Solar Node P1'],
    ['ProMicro NRF52840', 'nRF52840-promicro', 'ProMicro nrf52 (faketec)'],
  ];
  for (const [model, boardId, hardware] of cases) {
    const result = detectBootloaderBoard({items: [item(hardware)], info: info({model, boardId})});
    assert.equal(result.hardware, null);
    assert.deepEqual(result.candidates, [hardware]);
    assert.match(result.reason, /manually/);
  }
});

test('Board-ID alone, mismatched pairs, similar names and unsupported models never select a target', () => {
  const items = [item('Heltec T114'), item('Heltec MeshTower V2'), item('Seeed Studio SenseCAP T1000-E')];
  for (const values of [{model: 'Unknown'}, {model: 'ht-n5262'}, {model: 'HT-n5262 extra'}, {boardId: 'HT-n526'}, {boardId: 'nRF52840-T1000-E-v1'}, {model: 'Seeed T1000-E for Meshtastic'}, {model: 'HT-n5262G'}]) {
    const result = detectBootloaderBoard({items, info: info(values), usbInfo: {usbVendorId: 0x239a, usbProductId: 0x0071}});
    assert.equal(result.hardware, null);
    assert.deepEqual(result.candidates, []);
    assert.equal(result.architecture, undefined);
  }
});

test('USB may reject conflicting metadata but can never substitute for a file identity', () => {
  const items = [item('Heltec T114')];
  assert.equal(detectBootloaderBoard({items, info: info()}).hardware, 'Heltec T114');
  for (const usbInfo of [{usbVendorId: 0x2886, usbProductId: 0x0057}, {usbVendorId: 0x239a}, {usbVendorId: '239a', usbProductId: 0x0071}, {usbVendorId: 0x239a, usbProductId: -1}]) {
    const result = detectBootloaderBoard({items, info: info(), usbInfo});
    assert.equal(result.hardware, null);
    assert.deepEqual(result.candidates, []);
    assert.match(result.reason, /conflicts/);
  }
  assert.equal(detectBootloaderBoard({items, usbInfo: {usbVendorId: 0x239a, usbProductId: 0x0071}}).hardware, null);
});

test('recovery/test versions are displayable but cannot auto-select physical hardware', () => {
  for (const version of ['R_0x02040CFF', 'TEST_0x02040C01']) {
    const result = detectBootloaderBoard({items: [item('Elecrow ThinkNode M1')], info: info({version, model: 'ELECROW ThinkNodeM1', boardId: 'nRF52840-ThinkNodeM1-v1'})});
    assert.equal(result.hardware, null);
    assert.deepEqual(result.candidates, ['Elecrow ThinkNode M1']);
    assert.match(result.reason, /recovery\/test/i);
  }
});

test('parser rejects duplicates, missing/truncated fields, malformed versions, control text and HTML', () => {
  const good = contents();
  const invalid = [undefined, null, 123, {}, '', 'x'.repeat(4097), good.slice(0, -2),
    good.replace('Model: HT-n5262\r\n', ''), good.replace('Board-ID: HT-n5262\r\n', ''),
    good + 'Model: HT-n5262\r\n', good.replace('Date: Oct 28 2026', 'Model: HT-n5262'),
    good.replace('Date: Oct 28 2026', 'Date: Feb 30 2026'), good.replace('Date: Oct 28 2026', 'Date: Oct 2'),
    good.replace('HT-n5262', '<script>'), good.replace('HT-n5262', '&lt;script&gt;'),
    good.replace('HT-n5262', 'HT-n5262\u0000'), good.replace('HT-n5262', 'HT-n5262\u001b[31m'),
    good.replace('HT-n5262', 'HT-n5262\t'), good.replace('HT-n5262', 'HT-n5262\u202e'),
    good.replace('HT-n5262', 'Héltec'), good.replace(/\r\n/g, '\r'), good + '\r\n',
    good.replace('Date: Oct 28 2026', 'Command: flash --erase'), good.replace('S140 0x00B6', 'S140 seven'),
    ...['0.9', '0.09.2', '0.9.2.', '0.9.2-', '0.9.2;erase', 'unknown', 'R_123', 'v0.11.0-OTAFIX2.4.12 extra'].map(version => contents({version})),
  ];
  for (const value of invalid) assert.throws(() => parseBootloaderInfo(value), /Invalid INFO_UF2/, String(value).slice(0, 70));
});

test('matcher rejects unvalidated objects, foreign catalog entries and fuzzy target labels without mutation', () => {
  const parsed = info();
  const items = Object.freeze([Object.freeze(item('Heltec T114')), Object.freeze(item('Heltec T114', 'esp32')), Object.freeze(item('Heltec T114', 'nrf52', {project: 'Other'}))]);
  const original = structuredClone(items);
  const result = detectBootloaderBoard({items, info: parsed});
  result.candidates.push('Other');
  assert.deepEqual(items, original);
  assert.deepEqual(detectBootloaderBoard({items, info: parsed}).candidates, ['Heltec T114']);
  for (const invalid of [null, {}, {version: '0.9.2', model: 'HT-n5262'}, {...parsed, model: '<script>'}, {...parsed, hardware: 'Heltec T114'}, {...parsed, version: 'bad'}]) assert.equal(detectBootloaderBoard({items, info: invalid}).hardware, null);
  for (const hardware of ['HELTEC_T114', 'Heltec T114 V2', 'heltec t114', 'Heltec T114 extra']) assert.equal(detectBootloaderBoard({items: [item(hardware)], info: parsed}).hardware, null);
  for (const invalidItems of [null, {}, 'Heltec T114']) assert.equal(detectBootloaderBoard({items: invalidItems, info: parsed}).hardware, null);
  for (const field of ['publicKey','role','boardOverride','profile','writeApproved']) assert.equal(Object.hasOwn(result, field), false);
});
