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

test('shared GAT, XIAO, ProMicro, L1 and Muzi Base identities remain manual after filtering', () => {
  const cases = [
    ['MTools Tec GAT562', 'GAT562-Family', 'GAT-IoT GAT562 30s'],
    ['Seeed XIAO nRF52840', 'nRF52840-SeeedXiao-v1', 'Seeed Studio Xiao nRF52 WIO'],
    ['Seeed XIAO nRF52840', 'nRF52840-SeeedXiaoSense-v1', 'Seeed Studio Xiao nRF52 WIO'],
    ['Seeed TRACKER L1', 'TRACKER L1', 'Seeed Studio Wio Tracker L1 Pro'],
    ['Muzi Base', 'muzi-Base-Board', 'Muzi Works Base Uno'],
    ['ProMicro NRF52840', 'nRF52840-promicro', 'ProMicro nrf52 (faketec)'],
  ];
  for (const [model, boardId, hardware] of cases) {
    const result = detectBootloaderBoard({items: [item(hardware)], info: info({model, boardId})});
    assert.equal(result.hardware, null);
    assert.deepEqual(result.candidates, [hardware]);
    assert.match(result.reason, /manually/);
  }
});

const addedFactoryPairs = [
  ['B and Q Nano G2 Ultra','nRF52840-BQ-rev1','UnitEng Nano G2 Ultra',[0x4251,0x8695]],
  ['T-Echo Card','LilyGo-T-Echo-Card','LilyGo T-Echo Card',[0x239a,0x00da]],
  ['T-Impulse Plus','LilyGo-T-Impulse-Plus','LilyGo T-Impulse Plus nRF52840',[0x239a,0x00da]],
  ['Meshtiny Board','Meshtiny-MT001-Board','Meshtiny',[0x239a,0x0029]],
  ['GAT562 Mesh Watch13','GAT562-Watch13','GAT-IoT GAT562 Mesh Watch13',[0x239a,0x002a]],
];

test('source-confirmed factory bootloader identities select the corresponding application board without qualifying a bootloader download',()=>{
  const items=addedFactoryPairs.map(([, , hardware])=>item(hardware));
  for(const [model,boardId,hardware,[usbVendorId,usbProductId]] of addedFactoryPairs)for(const version of ['0.9.2','0.11.0-OTAFIX2.4.12']){
    const result=detectBootloaderBoard({items,info:info({model,boardId,version}),usbInfo:{usbVendorId,usbProductId}});
    assert.equal(result.hardware,hardware);assert.deepEqual(result.candidates,[hardware]);assert.equal(result.architecture,'nrf52');assert.match(result.reason,/not physical-board proof/);
    for(const field of ['bootloader','bootloaderInfo','download','approved','reset','erase'])assert.equal(Object.hasOwn(result,field),false);
    assert.equal(items.some(candidate=>Object.hasOwn(candidate,'bootloaderInfo')),false);
  }
});

test('new factory hints still reject mismatched identities, conflicting USB, unavailable targets and recovery loaders',()=>{
  for(const [model,boardId,hardware] of addedFactoryPairs){
    const items=[item(hardware)],parsed=info({model,boardId});
    for(const value of [{model:model+' extra',boardId},{model,boardId:boardId+' extra'},{model:'Unknown',boardId},{model,boardId:'Unknown'}])assert.equal(detectBootloaderBoard({items,info:info(value)}).hardware,null);
    for(const usbInfo of [{usbVendorId:0x2886,usbProductId:0x0057},{usbVendorId:0x239a,usbProductId:0x0071},{usbVendorId:0x239a},{usbVendorId:'239a',usbProductId:0x0029}])assert.equal(detectBootloaderBoard({items,info:parsed,usbInfo}).hardware,null);
    for(const available of [[],[item(hardware,'esp32')],[item(hardware,'nrf52',{project:'Meshtastic'})],[item('Some other board')]])assert.equal(detectBootloaderBoard({items:available,info:parsed}).hardware,null);
    for(const version of ['R_0x02040CFF','TEST_0x02040C01']){const result=detectBootloaderBoard({items,info:info({model,boardId,version})});assert.equal(result.hardware,null);assert.match(result.reason,/recovery\/test/i);}
    assert.equal(detectBootloaderBoard({items,usbInfo:{usbVendorId:0x239a,usbProductId:0x0029}}).hardware,null);
  }
  for(const [model,boardId,hardware] of addedFactoryPairs)for(const [,otherBoardId] of addedFactoryPairs)if(boardId!==otherBoardId)assert.equal(detectBootloaderBoard({items:[item(hardware)],info:info({model,boardId:otherBoardId})}).hardware,null);
});

test('all exact normal RAK4631 profiles select the universal family, never infer R1 Neo or another shared-USB board',()=>{
  const hardware='RAK WisBlock / WisMesh (RAK 4631)',pairs=[['WisBlock RAK4631 Board','WisBlock-RAK4631-Board'],['RAK4631','4631A'],['WisBlock RAK4631 + W25Q16','WisBlock-RAK4631-W25Q16'],['WisBlock RAK4631 + RAK15001 C','WisBlock-RAK4631-RAK15001-Slot-C']];
  const items=[item(hardware),item('Muzi Works R1 Neo'),item('RAK WisMesh Tag'),item('RAK WisMesh 1W Booster (3401 + 13302)')];
  for(const [model,boardId] of pairs){
    const result=detectBootloaderBoard({items,info:info({model,boardId}),usbInfo:{usbVendorId:0x239a,usbProductId:0x0029}});assert.equal(result.hardware,hardware);assert.deepEqual(result.candidates,[hardware]);assert.match(result.reason,/not physical-board proof/);
    assert.equal(detectBootloaderBoard({items:items.slice(1),info:info({model,boardId})}).hardware,null);
    assert.equal(detectBootloaderBoard({items,info:info({model,boardId,version:'R_0x02040CFF'})}).hardware,null);
  }
});

test('the exact Solar P1 identity collapses reviewed provider-label aliases but not other Seeed boards',()=>{
  const parsed=info({model:'Seeed Solar Node P1',boardId:'nRF52840-SeeedSenseCAPSolarP1-v1'}),hardware='Seeed Studio SenseCAP Solar';
  for(const items of [[item(hardware)],[item('Seeed Studio SenseCAP Solar Node P1')],[item(hardware),item('Seeed Studio SenseCAP Solar Node P1')]]){
    const result=detectBootloaderBoard({items,info:parsed,usbInfo:{usbVendorId:0x2886,usbProductId:0x0044}});assert.equal(result.hardware,hardware);assert.deepEqual(result.candidates,[hardware]);
  }
  assert.equal(detectBootloaderBoard({items:[item('Seeed Studio Xiao nRF52 WIO')],info:parsed}).hardware,null);
});

test('Muzi Base USB and an exact Base file retain Uno/Duo ambiguity independently of catalog filtering',()=>{
  for(const items of [[item('Muzi Works Base Uno')],[item('Muzi Works Base Duo')],[item('Muzi Works Base Uno'),item('Muzi Works Base Duo')]]){
    const result=detectBootloaderBoard({items,info:info({model:'Muzi Base',boardId:'muzi-Base-Board'}),usbInfo:{usbVendorId:0x239a,usbProductId:0x0081}});assert.equal(result.hardware,null);assert.match(result.reason,/manually/);assert.equal(result.architecture,'nrf52');assert.deepEqual(result.candidates,items.map(candidate=>candidate.hardware).sort());
  }
});

const rak3401Pairs = [
  ['WisBlock RAK3401', 'WisBlock-RAK3401'],
  ['RAK3401', '3401A'],
  ['WisBlock RAK3401 + RAK13302 + W25Q16', 'WisBlock-RAK3401-RAK13302-W25Q16'],
];
const rak3401Hardware = 'RAK WisMesh 1W Booster (3401 + 13302)';

test('all exact RAK3401 bootloader profiles select the same universal family without a storage prompt', () => {
  const items = [item(rak3401Hardware), item(rak3401Hardware, 'nrf52', {provider:'Other'}), item('RAK WisBlock / WisMesh (RAK 4631)'), item('RAK WisMesh Tag')];
  for (const [model, boardId] of rak3401Pairs) for (const version of ['0.9.2', '0.11.0-OTAFIX2.4.12', 'BL_0x02040CFF']) {
    for (const usbInfo of [{}, {usbVendorId:0x239a, usbProductId:0x0029}, {usbVendorId:0x239a, usbProductId:0x002a}]) {
      const result = detectBootloaderBoard({items, info:info({model, boardId, version}), usbInfo});
      assert.equal(result.hardware, rak3401Hardware, `${model} ${version}`);assert.deepEqual(result.candidates, [rak3401Hardware]);assert.equal(result.architecture, 'nrf52');assert.equal(result.model, model);
      assert.doesNotMatch(result.reason, /storage profile|choose hardware manually/);assert.match(result.reason, /not physical-board proof/);assert.match(result.reason, /not.*board-safety override/);
    }
  }
});

test('universal RAK3401 selection still requires an exact pair, compatible USB and a matching catalog target', () => {
  for (const [model, boardId] of rak3401Pairs) {
    const parsed = info({model, boardId}), items = [item(rak3401Hardware)];
    for (const wrong of [{model:'Unknown',boardId}, {model:model+' extra',boardId}, {model,boardId:'Unknown'}, {model,boardId:'WisBlock-RAK4631-Board'}]) {
      assert.equal(detectBootloaderBoard({items, info:info(wrong)}).hardware, null);
    }
    for (const usbInfo of [{usbVendorId:0x2886,usbProductId:0x0044}, {usbVendorId:0x239a,usbProductId:0x0071}, {usbVendorId:0x239a}]) {
      const result = detectBootloaderBoard({items, info:parsed, usbInfo});assert.equal(result.hardware, null);assert.match(result.reason, /conflicts/);
    }
    for (const available of [[], [item(rak3401Hardware,'esp32')], [item(rak3401Hardware,'nrf52',{project:'Other'})], [item('RAK3401')], [item('RAK WisBlock / WisMesh (RAK 4631)')]]) {
      const result = detectBootloaderBoard({items:available, info:parsed});assert.equal(result.hardware, null);assert.deepEqual(result.candidates, []);
    }
    assert.equal(detectBootloaderBoard({items, usbInfo:{usbVendorId:0x239a,usbProductId:0x0029}}).hardware, null);
    for (const version of ['R_0x02040CFF', 'TEST_0x02040C01']) {
      const result = detectBootloaderBoard({items, info:info({model, boardId, version})});assert.equal(result.hardware, null);assert.deepEqual(result.candidates, [rak3401Hardware]);assert.match(result.reason, /recovery\/test/i);
    }
  }
  // Even though all known profiles select one family, cross-pair combinations
  // are not aliases and cannot be manufactured from independent fields.
  for (const [model, boardId] of rak3401Pairs) for (const [, otherBoardId] of rak3401Pairs) if (boardId !== otherBoardId) {
    assert.equal(detectBootloaderBoard({items:[item(rak3401Hardware)],info:info({model,boardId:otherBoardId})}).hardware, null);
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
