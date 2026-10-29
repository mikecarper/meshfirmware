import test from 'node:test';
import assert from 'node:assert/strict';
import {detectMeshtasticBoard} from '../src/meshtastic-boards.js';

const item = (hardware, architecture = 'nrf52', more = {}) => ({project: 'MeshCore', hardware, architecture, ...more});

test('T114 V2/H2T enum 69 selects nRF52 T114, never the ESP32 Heltec v2', () => {
  const items = [item('Heltec v2', 'esp32'), item('Heltec T114'), item('Heltec T114', 'nrf52', {provider: 'Second provider'})];
  const result = detectMeshtasticBoard({items, hwModel: 69});
  assert.equal(result.hardware, 'Heltec T114');
  assert.deepEqual(result.candidates, ['Heltec T114']);
  assert.equal(result.source, 'meshtastic-hardware');
  assert.equal(result.model, 'Heltec Mesh Node T114');
  assert.match(result.reason, /not a role, firmware file or independent physical-board proof/);
  assert.equal(detectMeshtasticBoard({items: [item('Heltec v2', 'esp32')], hwModel: 69}).hardware, null);
});

test('ESP32 Heltec V2.1, V3, V4 and R8 have separate exact mappings', () => {
  const items = ['Heltec v2', 'Heltec v3', 'Heltec v4', 'Heltec v4 R8', 'Heltec v4 + Expansion Kit (Touch)'].map(name => item(name, 'esp32'));
  items.push(item('Heltec T114'));
  for (const [hwModel, hardware] of [[10, 'Heltec v2'], [43, 'Heltec v3'], [110, 'Heltec v4'], [132, 'Heltec v4 R8']]) {
    assert.equal(detectMeshtasticBoard({items, hwModel}).hardware, hardware);
  }
  // The older V2.0 battery ADC pin differs from the reviewed MeshCore V2.
  assert.equal(detectMeshtasticBoard({items, hwModel: 5}).hardware, null);
  assert.equal(detectMeshtasticBoard({items, hwModel: 86}).hardware, null);
});

test('reviewed nRF52 and ESP32 models select only their exact target labels', () => {
  const cases = [
    [3, 'LilyGo LoRa32 V2.1_1.6', 'esp32'], [7, 'LilyGo T-Echo', 'nrf52'],
    [18, 'UnitEng Nano G2 Ultra', 'nrf52'], [31, 'UnitEng Station G2', 'esp32'],
    [44, 'Heltec WSL3', 'esp32'], [49, 'Heltec Heltec Wireless Paper', 'esp32'],
    [50, 'LilyGo T-Deck', 'esp32'], [53, 'Heltec CT62', 'esp32'],
    [61, 'Ebyte EoRa-S3', 'esp32'], [66, 'Heltec Vision Master T190', 'esp32'],
    [67, 'Heltec Vision Master E213', 'esp32'], [68, 'Heltec Vision Master E290', 'esp32'],
    [71, 'Seeed Studio SenseCAP T1000-E', 'nrf52'], [75, 'Minewsemi ME25LS01', 'nrf52'],
    [88, 'Seeed Studio Xiao nRF52 WIO', 'nrf52'], [89, 'Elecrow ThinkNode M1', 'nrf52'],
    [90, 'Elecrow ThinkNode M2', 'esp32'], [94, 'Heltec MeshPocket', 'nrf52'],
    [101, 'Muzi Works R1 Neo', 'nrf52'], [102, 'LilyGo T-Deck Pro', 'esp32'],
    [103, 'LilyGo T-Lora Pager', 'esp32'], [105, 'RAK WisMesh Tag', 'nrf52'],
    [107, 'Elecrow ThinkNode M5', 'esp32'], [108, 'Heltec MeshSolar / MeshTower', 'nrf52'],
    [109, 'LilyGo T-Echo Lite', 'nrf52'], [111, 'M5Stack Unit C6L', 'esp32'],
    [113, 'Heltec Wireless Tracker v2', 'esp32'], [115, 'Elecrow ThinkNode M3', 'nrf52'],
    [119, 'Elecrow ThinkNode M4', 'nrf52'], [120, 'Elecrow ThinkNode M6', 'nrf52'],
    [122, 'LilyGo T-Beam 1W', 'esp32'], [126, 'LilyGo T-Display Pro', 'esp32'],
    [127, 'Heltec Mesh Node T096', 'nrf52'], [129, 'Elecrow ThinkNode M7', 'esp32'],
    [130, 'Elecrow ThinkNode M8', 'nrf52'], [131, 'Elecrow ThinkNode M9', 'esp32'],
    [133, 'Heltec Mesh Node T1', 'nrf52'], [134, 'UnitEng/BQ Voyage Station G3', 'esp32'],
    [135, 'LilyGo T-Impulse Plus nRF52840', 'nrf52'], [136, 'LilyGo T-Echo Card', 'nrf52'],
    [137, 'Seeed Wio Tracker L2', 'esp32'], [139, 'Heltec MeshTower V2', 'nrf52'],
    [141, 'Heltec RC32', 'esp32'], [144, 'Seeed WioTracker L1 1W', 'nrf52'],
    [145, 'Meshnology W12', 'esp32'],
  ];
  const items = cases.map(([, hardware, architecture]) => item(hardware, architecture));
  for (const [hwModel, hardware] of cases) assert.equal(detectMeshtasticBoard({items, hwModel}).hardware, hardware, `enum ${hwModel}`);
});

test('known shared enums remain manual even with a filtered single catalog candidate', () => {
  const cases = [
    [4, ['LilyGo T-Beam (SX1262)', 'LilyGo T-Beam 1.2 (SX1276)'], 'esp32'],
    [9, ['RAK WisBlock / WisMesh (RAK 4631)'], 'nrf52'],
    [16, ['LilyGo T3 S3 (SX126x)', 'LilyGo T3 S3 (SX127x)'], 'esp32'],
    [48, ['Heltec Wireless Tracker', 'Heltec Wireless Tracker v1.1'], 'esp32'],
    [63, ['ProMicro nrf52 (faketec)'], 'nrf52'],
    [70, ['Seeed Studio SenseCAP Indicator ESP-NOW', 'Seeed Studio SenseCAP Indicator LoRa'], 'esp32'],
    [81, ['Seeed Studio Xiao S3', 'Seeed Studio Xiao S3 WIO'], 'esp32'],
    [91, ['LilyGo T-ETH Elite (SX1262)'], 'esp32'],
    [93, ['Muzi Works Base Duo', 'Muzi Works Base Uno'], 'nrf52'],
    [95, ['Seeed Studio SenseCAP Solar', 'Seeed Studio SenseCAP Solar Node P1'], 'nrf52'],
    [99, ['Seeed Studio Wio Tracker L1 Pro', 'Seeed WioTracker L1 1W'], 'nrf52'],
    [117, ['RAK WisMesh 1W Booster (3401 + 13302)'], 'nrf52'],
  ];
  for (const [hwModel, names, architecture] of cases) {
    for (const available of [names, names.slice(0, 1)]) {
      const result = detectMeshtasticBoard({items: available.map(name => item(name, architecture)), hwModel});
      assert.equal(result.hardware, null, `enum ${hwModel}`);
      assert.deepEqual(result.candidates, [...available].sort());
      assert.match(result.reason, /manually/);
    }
  }
});

test('multiple exact catalog labels remain ambiguous rather than choosing the first', () => {
  const items = [item('Seeed Studio Wio Tracker L1 EINK'), item('Seeed Studio Wio Tracker L1 E-Ink')];
  const result = detectMeshtasticBoard({items, hwModel: 100});
  assert.equal(result.hardware, null);
  assert.deepEqual(result.candidates, items.map(entry => entry.hardware).sort());
  assert.match(result.reason, /multiple exact catalog/);
});

test('unknown, unset, generic, private and malformed enums never use names or USB fallback', () => {
  const items = [item('Heltec T114'), item('Heltec v2', 'esp32')];
  for (const hwModel of [undefined, null, '69', 'HELTEC_MESH_NODE_T114', -1, 69.1, NaN, Infinity, 0x80000000, {}, [], 0, 36, 86, 106, 152, 255, 987654]) {
    const result = detectMeshtasticBoard({items, hwModel, deviceModel: 'Heltec T114', usbInfo: {usbVendorId: 0x239a, usbProductId: 0x0071}});
    assert.equal(result.hardware, null);
    assert.deepEqual(result.candidates, []);
    assert.equal(result.source, 'meshtastic-hardware');
    assert.match(result.reason, /manual/);
  }
});

test('foreign projects, wrong architectures, fuzzy labels and proposed hardware IDs are not substituted', () => {
  const items = [null, {}, item('Heltec T114', 'esp32'), item('Heltec T114', 'nrf52', {project: 'Meshtastic'}),
    item('HELTEC_T114'), item('Heltec T114 V2'), item('Heltec T114 extra'), item('heltec t114'),
    item('Unrelated', 'nrf52', {bootloaderInfo: {hardwareId: 'Heltec_t114'}})];
  assert.deepEqual(detectMeshtasticBoard({items, hwModel: 69}).candidates, []);
  for (const invalidItems of [null, {}, 'Heltec T114']) assert.equal(detectMeshtasticBoard({items: invalidItems, hwModel: 69}).hardware, null);
});

test('board detection never mutates catalog inputs or leaks mutable internal candidates', () => {
  const items = [item('Heltec T114', 'nrf52', {provider: 'Example', bootloaderInfo: {profile: 'heltec_t114'}})];
  const original = structuredClone(items);
  Object.freeze(items[0].bootloaderInfo); Object.freeze(items[0]); Object.freeze(items);
  const result = detectMeshtasticBoard({items, hwModel: 69});
  result.candidates.push('Injected board');
  assert.deepEqual(items, original);
  assert.deepEqual(detectMeshtasticBoard({items, hwModel: 69}).candidates, ['Heltec T114']);
  assert.equal(Object.hasOwn(result, 'role'), false);
  assert.equal(Object.hasOwn(result, 'image'), false);
});
