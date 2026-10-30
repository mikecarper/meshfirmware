import test from 'node:test';
import assert from 'node:assert/strict';
import {detectBoard,detectRecoveryProfile} from '../src/board-detection.js';
const item=(hardware,more={})=>({project:'MeshCore',hardware,...more});

test('exact complete application model selects hardware despite duplicate provider releases',()=>{
  const result=detectBoard({items:[item('Heltec v4'),item('Heltec v4'),item('Heltec v4 R8')],deviceModel:' HELTEC_V4 '});
  assert.equal(result.hardware,'Heltec v4');assert.equal(result.source,'application-model');assert.deepEqual(result.candidates,['Heltec v4']);
});
test('reviewed manufacturer aliases select Station G3, T1000-E and RAK4631',()=>{
  for(const [model,hardware] of [['Station G3 ESP32','UnitEng/BQ Voyage Station G3'],['Seeed Tracker T1000-E','Seeed Studio SenseCAP T1000-E'],['RAK 4631','RAK WisBlock / WisMesh (RAK 4631)']])assert.equal(detectBoard({items:[item(hardware)],deviceModel:model}).hardware,hardware);
});

test('reviewed complete manufacturer aliases bridge Wireless Paper, Nano and distinct Wio L1 firmware names',()=>{
  for(const [deviceModel,hardware] of [['Heltec Wireless Paper','Heltec Wireless Paper'],['Nano G2 Ultra','UnitEng Nano G2 Ultra'],['Seeed Wio Tracker L1 Pro','Seeed Studio Wio Tracker L1 Pro'],['Seeed Wio Tracker L1 E-Ink','Seeed Studio Wio Tracker L1 E-Ink'],['Seeed Wio Tracker L1 1W','Seeed WioTracker L1 1W'],['Seeed SenseCAP Indicator LoRa','Seeed Studio SenseCAP Indicator LoRa'],['Seeed SenseCAP Indicator ESP-NOW','Seeed Studio SenseCAP Indicator ESP-NOW']]){
    const items=['Heltec Wireless Paper','UnitEng Nano G2 Ultra','Seeed Studio Wio Tracker L1 Pro','Seeed Studio Wio Tracker L1 E-Ink','Seeed WioTracker L1 1W','Seeed Studio SenseCAP Indicator LoRa','Seeed Studio SenseCAP Indicator ESP-NOW'].map(name=>item(name));
    assert.equal(detectBoard({items,deviceModel}).hardware,hardware);
  }
  for(const deviceModel of ['Nano G2','Seeed Wio Tracker L1 Pro unknown','Heltec Wireless Paper V2'])assert.equal(detectBoard({items:[item('UnitEng Nano G2 Ultra'),item('Heltec Wireless Paper')],deviceModel}).hardware,null);
});

test('equivalent provider labels collapse while true L1 hardware variants remain ambiguous',()=>{
  for(const [deviceModel,legacy,canonical] of [['Seeed SenseCap Solar','Seeed Studio SenseCAP Solar Node P1','Seeed Studio SenseCAP Solar'],['Seeed Wio Tracker L1 E-Ink','Seeed Studio Wio Tracker L1 EINK','Seeed Studio Wio Tracker L1 E-Ink'],['Seeed Studio SenseCAP MeshTracker X1','Seeed Studio SenseCAP MeshTracker X1','Seeed SenseCAP MeshTracker X1'],['Heltec Wireless Paper','Heltec Heltec Wireless Paper','Heltec Wireless Paper']]){
    for(const names of [[legacy],[legacy,canonical]]){const result=detectBoard({items:names.map(name=>item(name)),deviceModel});assert.equal(result.hardware,canonical);assert.deepEqual(result.candidates,[canonical]);}
  }
  const result=detectBoard({items:['Seeed Studio Wio Tracker L1 Pro','Seeed Studio Wio Tracker L1 E-Ink','Seeed WioTracker L1 1W'].map(name=>item(name)),deviceModel:'Seeed Wio Tracker L1'});assert.equal(result.hardware,null);assert.equal(result.candidates.length,3);
});

test('explicit GAT562 manufacturer identity outranks another boards copied bootloader utility hint',()=>{
  const items=[item('GAT-IoT GAT562 Tracker',{bootloaderInfo:{hardwareId:'GAT562_Mesh_Tracker_Pro'}}),item('GAT-IoT GAT562 30s',{bootloaderInfo:{hardwareId:'GAT562_Mesh_Tracker_Pro'}})];
  for(const inventory of [items,items.toReversed()])assert.equal(detectBoard({items:inventory,deviceModel:'GAT562 Mesh Tracker Pro'}).hardware,'GAT-IoT GAT562 Tracker');
  assert.equal(detectBoard({items:items.slice(1),deviceModel:'GAT562 Mesh Tracker Pro'}).hardware,null,'a missing explicit Tracker target must not substitute the unrelated 30S utility hint');
});

test('old and updated V4 OLED model strings select normal V4 without guessing TFT or R8',()=>{
  const items=[item('Heltec v4'),item('Heltec v4 R8'),item('Heltec v4 + Expansion Kit (Touch)')];
  for(const deviceModel of ['Heltec V4 OLED','Heltec V4.2 OLED','Heltec V4.3 OLED'])assert.equal(detectBoard({items,deviceModel}).hardware,'Heltec v4');
  for(const deviceModel of ['Heltec V4.3','Heltec V4.3 TFT','Heltec V4.3 OLED R8'])assert.equal(detectBoard({items,deviceModel}).hardware,null);
});

test('exact headless V4 model strings select the base hardware without a USB or display guess',()=>{
  const items=[item('Heltec v4'),item('Heltec v4 R8'),item('Heltec v4 + Expansion Kit (Touch)')];
  for(const deviceModel of ['Heltec V4.2 none detected','Heltec V4.3 none detected','  HELTEC_V4.2_NONE_DETECTED  ']){
    const result=detectBoard({items,deviceModel,usbInfo:{usbVendorId:0x303a,usbProductId:0x1001}});
    assert.equal(result.hardware,'Heltec v4');assert.equal(result.source,'application-model');assert.deepEqual(result.candidates,['Heltec v4']);
  }
  for(const deviceModel of ['Heltec V4 none detected','Heltec V4.4 none detected','Heltec V4.2 none','Heltec V4.2 none detected R8','Heltec V4.2 off','Heltec V4.2 display initialization failed','Unknown Heltec V4.2 none detected']){
    assert.equal(detectBoard({items,deviceModel}).hardware,null,deviceModel);
  }
  assert.equal(detectBoard({items:[item('Heltec v4 R8')],deviceModel:'Heltec V4.2 none detected'}).hardware,null);
});
test('exact manifest hardware ID selects only one corresponding catalog hardware',()=>{
  const items=[item('Seeed Studio SenseCAP T1000-E',{bootloaderInfo:{hardwareId:'t1000e'}}),item('Something else')];
  assert.equal(detectBoard({items,deviceModel:'t1000e'}).hardware,'Seeed Studio SenseCAP T1000-E');
  items.push(item('Conflict',{bootloaderInfo:{hardwareId:'t1000e'}}));assert.equal(detectBoard({items,deviceModel:'t1000e'}).hardware,null);
});
test('complete names only: revisions, truncated names, prefixes and similar vendors are not guessed',()=>{
  const items=[item('Heltec v4 R8'),item('UnitEng/BQ Voyage Station G3'),item('Seeed Studio SenseCAP T1000-E')];
  for(const deviceModel of ['Heltec v4','Station G3 ESP','Seeed Tracker T1000','Station G3 ESP32 logging','Unknown Station G3 ESP32'])assert.equal(detectBoard({items,deviceModel}).hardware,null);
});
test('known identical model strings remain ambiguous across board variants',()=>{
  const result=detectBoard({items:[item('Seeed Studio Wio Tracker L1 Pro'),item('Seeed WioTracker L1 1W')],deviceModel:'Seeed Wio Tracker L1'});
  assert.equal(result.hardware,null);assert.equal(result.candidates.length,2);
  for(const [deviceModel,hardware] of [['Seeed Wio Tracker L1','Seeed Studio Wio Tracker L1 Pro'],['Seeed SenseCAP Indicator','Seeed Studio SenseCAP Indicator LoRa']]){
    const filtered=detectBoard({items:[item(hardware)],deviceModel});assert.equal(filtered.hardware,null);assert.deepEqual(filtered.candidates,[hardware]);assert.match(filtered.reason,/filtering the catalog/);
  }
});
test('conflicting exact display and explicit manufacturer alias never chooses first',()=>{
  const result=detectBoard({items:[item('Station G3 ESP32'),item('UnitEng/BQ Voyage Station G3')],deviceModel:'Station G3 ESP32'});
  assert.equal(result.hardware,null);assert.equal(result.candidates.length,2);
});
test('exact DFU and application USB identities provide candidates only, not auto selection',()=>{
  const info=profile=>({bootloaderInfo:{profile,tag:'v0.11.0-OTAFIX2.4.12'}}),items=[item('Seeed Studio SenseCAP T1000-E',info('t1000_e')),item('Seeed Studio Xiao nRF52 WIO',info('xiao_nrf52840_ble')),item('Ikoka Stick',info('xiao_nrf52840_ble'))];
  let result=detectBoard({items,usbInfo:{usbVendorId:0x2886,usbProductId:0x0057}});assert.equal(result.hardware,null);assert.deepEqual(result.candidates,['Seeed Studio SenseCAP T1000-E']);assert.equal(result.source,'usb-hint');
  result=detectBoard({items,usbInfo:{usbVendorId:0x2886,usbProductId:0x0044}});assert.equal(result.hardware,null);assert.equal(result.candidates.length,2);
  result=detectBoard({items,usbInfo:{usbVendorId:0x2886,usbProductId:0x8044}});assert.equal(result.hardware,null);assert.equal(result.candidates.length,2);
});
test('generic UART bridges and ESP USB never suggest a specific board, no neighboring PID ranges',()=>{
  for(const [usbVendorId,usbProductId] of [[0x303a,0x1001],[0x1a86,0x7523],[0x10c4,0xea60],[0x239a,0x802a],[0x2886,0x0058]]){
    const result=detectBoard({items:[item('UnitEng/BQ Voyage Station G3'),item('Seeed Studio SenseCAP T1000-E')],usbInfo:{usbVendorId,usbProductId}});assert.equal(result.hardware,null);assert.deepEqual(result.candidates,[]);
  }
});
test('unknown application model is not replaced by a USB guess',()=>{
  const result=detectBoard({items:[item('Seeed Studio SenseCAP T1000-E')],deviceModel:'Wrong firmware target',usbInfo:{usbVendorId:0x2886,usbProductId:0x0057}});assert.equal(result.hardware,null);assert.deepEqual(result.candidates,[]);assert.equal(result.source,'application-model');
});
test('invalid and foreign catalog entries are ignored and invalid USB data is harmless',()=>{
  assert.equal(detectBoard({items:[null,{project:'Meshtastic',hardware:'Heltec v4'}],deviceModel:'Heltec v4'}).hardware,null);
  for(const usbInfo of [null,{}, {usbVendorId:'2886',usbProductId:87},{usbVendorId:0x2886,usbProductId:-1}])assert.deepEqual(detectBoard({usbInfo}).candidates,[]);
});
const profiles=[{id:'gat562',installedIdentity:'GAT562BOOT'},{id:'xiao_nrf52840_ble',installedIdentity:'XIAO_DFU'},{id:'xiao_nrf52840_ble_sense',installedIdentity:'XIAO_DFU'}];
test('unique exact installed identity or explicit R profile selects recovery independently of physical board',()=>{
  for(const installedIdentity of ['gat562boot','GAT562','R_gat562'])assert.equal(detectRecoveryProfile({profiles,installedIdentity}).profile,'gat562');
});
test('shared recovery USB product identity requires manual selection; exact profile disambiguates',()=>{
  const result=detectRecoveryProfile({profiles,installedIdentity:'XIAO_DFU'});assert.equal(result.profile,null);assert.equal(result.candidates.length,2);
  assert.equal(detectRecoveryProfile({profiles,installedIdentity:'xiao_nrf52840_ble_sense'}).profile,'xiao_nrf52840_ble_sense');
});
test('recovery never guesses physical board, truncated identity, or a substring',()=>{
  for(const installedIdentity of ['','RAK4631','GAT562BO','USB GAT562BOOT','GAT562BOOT more'])assert.equal(detectRecoveryProfile({profiles,installedIdentity}).profile,null);
});

const reviewedIds=['gat562','heltec_mesh_pocket','heltec_mesh_tower_v2_sdcard','heltec_t096','heltec_t1','heltec_t114','keepteen_lt1','lilygo_techo','lilygo_techo_lite','minewsemi_mx25le01','pca10056','promicro_nrf52840','sensecap_solar_p1','t1000_e','thinknode_m1','thinknode_m3','thinknode_m6','wio_tracker_l1','wiscore_rak3401','wiscore_rak3401_auto','wiscore_rak3401_rak13302_w25q16','wiscore_rak4631_auto','wiscore_rak4631_board','wiscore_rak4631_board_rak15001_slot_c','wiscore_rak4631_w25q16','wismesh_tag','xiao_nrf52840_ble','xiao_nrf52840_ble_sense'];
const reviewedProfiles=reviewedIds.map(id=>({id,installedIdentity:id.startsWith('xiao_')?'XIAO_DFU':id==='gat562'?'GAT562_DFU':id+'_DFU'}));
const reviewed={profiles:reviewedProfiles,tag:'v0.11.0-OTAFIX2.4.12'};
const usb=(usbVendorId,usbProductId)=>({usbVendorId,usbProductId});
test('unique exact reviewed release DFU IDs select installed recovery profile, not physical hardware',()=>{
  for(const [pid,expected] of [[0x0057,'t1000_e'],[0x1667,'wio_tracker_l1'],[0x0045,'xiao_nrf52840_ble_sense']]){
    const result=detectRecoveryProfile({...reviewed,usbInfo:usb(0x2886,pid)});assert.equal(result.profile,expected);assert.equal(result.source,'usb');
  }
});
test('all shared reviewed recovery PID groups remain ambiguous',()=>{
  for(const [vid,pid,count] of [[0x2886,0x0044,2],[0x239a,0x0029,11],[0x239a,0x002a,10],[0x239a,0x0071,5],[0x239a,0x00b3,2],[0x239a,0x00da,5]]){
    const result=detectRecoveryProfile({...reviewed,usbInfo:usb(vid,pid)});assert.equal(result.profile,null);assert.equal(result.candidates.length,count);
  }
});
test('filtered incomplete inventories, new or duplicate profiles, and unreviewed tags never make USB unique',()=>{
  const usbInfo=usb(0x2886,0x0057);
  for(const overrides of [{profiles:reviewedProfiles.filter(p=>p.id==='t1000_e')},{profiles:[...reviewedProfiles,{id:'new_board'}]},{profiles:[...reviewedProfiles.slice(1),reviewedProfiles[1]]},{tag:'v0.11.0-OTAFIX2.4.13'},{tag:''}])assert.equal(detectRecoveryProfile({...reviewed,...overrides,usbInfo}).profile,null);
  const oneXiao={profiles:[reviewedProfiles.find(p=>p.id==='xiao_nrf52840_ble')],tag:reviewed.tag};
  assert.equal(detectRecoveryProfile({...oneXiao,installedIdentity:'XIAO_DFU'}).profile,null);
  assert.equal(detectRecoveryProfile({...oneXiao,installedIdentity:'xiao_nrf52840_ble'}).profile,'xiao_nrf52840_ble');
});
test('exact tagged bootloader volume and explicit profile can disambiguate shared USB IDs',()=>{
  let result=detectRecoveryProfile({...reviewed,usbInfo:usb(0x239a,0x002a),installedIdentity:'GAT562BOOT'});assert.equal(result.profile,'gat562');assert.equal(result.source,'identity');
  result=detectRecoveryProfile({...reviewed,usbInfo:usb(0x2886,0x0044),installedIdentity:'XIAO_DFU'});assert.equal(result.profile,'xiao_nrf52840_ble');
  result=detectRecoveryProfile({...reviewed,usbInfo:usb(0x2886,0x0045),installedIdentity:'XIAO_DFU'});assert.equal(result.profile,'xiao_nrf52840_ble_sense');
  assert.equal(detectRecoveryProfile({...reviewed,installedIdentity:'RAK4631'}).profile,null); // Same volume label on board + Tag.
  assert.equal(detectRecoveryProfile({...reviewed,installedIdentity:'HT-n5262'}).profile,null); // Same inherited label on T114 + Tower V2.
  assert.equal(detectRecoveryProfile({...reviewed,installedIdentity:'4631A'}).profile,'wiscore_rak4631_auto');
});
test('text and USB conflict or unknown text prevents automatic recovery selection',()=>{
  for(const installedIdentity of ['gat562','GAT562BOOT','T1KE_DF','Unknown']){
    const result=detectRecoveryProfile({...reviewed,usbInfo:usb(0x2886,0x0057),installedIdentity});assert.equal(result.profile,null);assert.deepEqual(result.candidates,[]);
  }
});
test('normal board USB hints follow exact reviewed profile groups, never mistaken native classifier meaning',()=>{
  const items=[item('GAT-IoT GAT562 30s',{bootloaderInfo:{profile:'gat562',tag:reviewed.tag}}),item('Heltec Mesh Node T1',{bootloaderInfo:{profile:'heltec_t1',tag:reviewed.tag}}),item('Heltec MeshTower V2',{bootloaderInfo:{profile:'heltec_mesh_tower_v2_sdcard',tag:reviewed.tag}})];
  assert.deepEqual(detectBoard({items,usbInfo:usb(0x239a,0x0029)}).candidates,['GAT-IoT GAT562 30s']);
  assert.deepEqual(detectBoard({items,usbInfo:usb(0x239a,0x0071)}).candidates,['Heltec Mesh Node T1','Heltec MeshTower V2']);
});
