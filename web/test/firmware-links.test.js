import test from 'node:test';
import assert from 'node:assert/strict';
import {firmwareFilesLinks} from '../src/firmware-links.js';

const picker='https://mikecarper.github.io/MeshCore/firmware_picker/';
const result='#firmware-picker-1-results';
const asset='https://github.com/mikecarper/MeshCore/releases/download/v1.18.0.1/GAT562_30S_Mesh_Kit_companion.zip';
const entry=(hardware='GAT-IoT GAT562 30s',id='GAT562_30S_Mesh_Kit',role='companionFull',more={})=>({provider:'Keymind Cascade',hardware,role,url:asset,releaseNotes:'SETUP - '+picker+'?hardware='+encodeURIComponent(id),...more});
const selection=url=>{const value=new URL(url).searchParams.get('s');return value?Object.fromEntries(value.split('.').slice(1).map(part=>[part[0],decodeURIComponent(part.slice(1))])):{};};

test('requested GAT562 hardware/companion selection produces the picker link exactly',()=>{
  const item=entry(),links=firmwareFilesLinks({item});
  assert.equal(links.browseUrl,picker+'?s=1.hGAT562_30S_Mesh_Kit.rcompanion'+result);assert.equal(links.downloadUrl,asset);assert.match(links.detail,/current/);assert.match(links.detail,/exact selected file and version/);
});

test('XIAO and Heltec use exact published setup IDs, with no filename or display-name guesses',()=>{
  for(const [hardware,id,role,pickerRole]of [['Seeed Studio Xiao nRF52 WIO','Xiao_nrf52','repeater','repeater'],['Heltec v4','heltec_v4','roomServer','room']]){
    const links=firmwareFilesLinks({item:entry(hardware,id,role)});assert.deepEqual(selection(links.browseUrl),{h:id,r:pickerRole});
  }
  const unknown=firmwareFilesLinks({item:{provider:'Keymind Cascade',hardware:'Xiao_nrf52',role:'repeater',name:'Xiao_nrf52_repeater.zip',url:asset}});
  assert.deepEqual(selection(unknown.browseUrl),{r:'repeater'});assert.match(unknown.detail,/choose hardware/);
});

test('role aliases are explicit and unknown or GUI roles are not guessed',()=>{
  for(const role of ['companionBle','companionUsb','companionFull'])assert.equal(selection(firmwareFilesLinks({item:entry(undefined,undefined,role)}).browseUrl).r,'companion');
  for(const [role,expected]of [['sensor','sensor'],['kissRadio','kiss'],['roomServer','room']])assert.equal(selection(firmwareFilesLinks({role}).browseUrl).r,expected);
  for(const role of ['gui','guiSD','unknown','companion-experimental','constructor','toString','__proto__'])assert.equal(selection(firmwareFilesLinks({role}).browseUrl).r,undefined);
});

test('an exact selected artifact outranks empty or stale provider, hardware and role filters',()=>{
  const item=entry(),other=entry('Other board','different_board','sensor');
  const links=firmwareFilesLinks({items:[other],item,provider:'MeshCore',hardware:'Other board',role:'sensor'});
  assert.deepEqual(selection(links.browseUrl),{h:'GAT562_30S_Mesh_Kit',r:'companion'});assert.equal(links.downloadUrl,asset);
});

test('unselected inventory is filtered by exact provider/hardware/role and never chooses a download',()=>{
  const items=[entry(),entry('GAT-IoT GAT562 30s','unrelated_role','sensor'),entry('Other board','other_board','companionFull'),entry('GAT-IoT GAT562 30s','stock_board','companionFull',{provider:'MeshCore'})];
  const links=firmwareFilesLinks({items,hardware:'GAT-IoT GAT562 30s',role:'companionFull'});
  assert.deepEqual(selection(links.browseUrl),{h:'GAT562_30S_Mesh_Kit',r:'companion'});assert.equal(links.downloadUrl,null);
  assert.equal(selection(firmwareFilesLinks({items}).browseUrl).h,undefined);
});

test('ambiguous setup IDs or conflicting declared bootloader hardware omit preselection',()=>{
  const hardware='Same display name',one=entry(hardware,'one','repeater'),two=entry(hardware,'two','repeater');
  assert.deepEqual(selection(firmwareFilesLinks({items:[one,two],hardware,role:'repeater'}).browseUrl),{r:'repeater'});
  assert.equal(selection(firmwareFilesLinks({item:{...one,bootloaderInfo:{hardwareId:'two'}}}).browseUrl).h,undefined);
  assert.equal(selection(firmwareFilesLinks({item:{...one,releaseNotes:one.releaseNotes+'\nSETUP - '+picker+'?hardware=two'}}).browseUrl).h,undefined);
  assert.equal(selection(firmwareFilesLinks({item:{...one,bootloaderInfo:{hardwareId:'one'}}}).browseUrl).h,'one');
  assert.equal(selection(firmwareFilesLinks({item:{...one,releaseNotes:'',bootloaderInfo:{hardwareId:'verified_board'}}}).browseUrl).h,'verified_board');
});

test('SETUP metadata cannot redirect browsing or inject duplicate hardware, unsafe IDs or private query values',()=>{
  for(const setup of ['https://evil.example/MeshCore/firmware_picker/?hardware=wrong','https://mikecarper.github.io:443/MeshCore/firmware_picker/?hardware=wrong','https://mikecarper.github.io:444/MeshCore/firmware_picker/?hardware=wrong','https://user:secret@mikecarper.github.io/MeshCore/firmware_picker/?hardware=wrong',picker+'?hardware=one&hardware=two',picker+'?hardware=board%0D%0Asecret','https://mikecarper.github.io/other/?hardware=wrong']){
    const links=firmwareFilesLinks({item:entry(undefined,undefined,undefined,{releaseNotes:'SETUP - '+setup})});assert.equal(selection(links.browseUrl).h,undefined,setup);assert.equal(new URL(links.browseUrl).origin,'https://mikecarper.github.io');
  }
  const links=firmwareFilesLinks({item:entry(undefined,undefined,undefined,{releaseNotes:'SETUP - '+picker+'?hardware=safe_board&private_key=SECRET&role=sensor#private'}),role:'sensor'});
  assert.deepEqual(selection(links.browseUrl),{h:'safe_board',r:'companion'});assert.ok(!links.browseUrl.includes('SECRET'));assert.equal(new URL(links.browseUrl).hash,result);
});

test('compact links escape dot delimiters and share only whitelisted public choices',()=>{
  const item=entry('Sample','board.v2-1','repeater',{private_key:'PRIVATE',publicKey:'NODEID',nodeName:'Secret node',usbIdentity:{serialNumber:'SERIAL'}});
  const links=firmwareFilesLinks({item,hardware:'Private node name',role:'repeater',publicKey:'EXTRA'});
  assert.deepEqual(selection(links.browseUrl),{h:'board.v2-1',r:'repeater'});
  for(const secret of ['PRIVATE','NODEID','Secret','SERIAL','EXTRA'])assert.ok(!links.browseUrl.includes(secret));
  assert.equal(new URL(links.browseUrl).searchParams.getAll('s').length,1);
});

test('stock selection browses the exact official release without switching provider or version',()=>{
  const url='https://github.com/meshcore-dev/MeshCore/releases/download/repeater-v1.17.1/heltec_v4_repeater-v1.17.1.bin';
  const links=firmwareFilesLinks({item:entry('Heltec v4','heltec_v4','repeater',{provider:'MeshCore',url})});
  assert.equal(links.browseUrl,'https://github.com/meshcore-dev/MeshCore/releases/tag/repeater-v1.17.1');assert.equal(links.downloadUrl,url);assert.ok(!links.browseUrl.includes('mikecarper.github.io'));
  assert.equal(firmwareFilesLinks({provider:'MeshCore'}).browseUrl,'https://github.com/meshcore-dev/MeshCore/releases');
  assert.equal(firmwareFilesLinks({item:{provider:'MeshCore',url:asset}}).browseUrl,'https://github.com/meshcore-dev/MeshCore/releases');
});

test('only credential-free HTTPS exact item URLs become download links',()=>{
  for(const url of ['javascript:alert(1)','http://example.test/file.zip','https://user:secret@example.test/file.zip','https://example.test/file\n.zip',null,42]){
    const links=firmwareFilesLinks({item:entry(undefined,undefined,undefined,{url})});assert.equal(links.downloadUrl,null,String(url));
  }
  const direct='https://public.example.test/exact-old-version.zip';assert.equal(firmwareFilesLinks({item:{provider:'Keymind Cascade',url:direct}}).downloadUrl,direct);
  assert.equal(firmwareFilesLinks().downloadUrl,null);assert.equal(firmwareFilesLinks().browseUrl,picker+result);
});

test('legacy logging provider links normalize without mutating caller metadata',()=>{
  const item=entry(undefined,undefined,undefined,{provider:'Keymind Cascade Logging'}),before=JSON.stringify(item);
  assert.equal(selection(firmwareFilesLinks({item}).browseUrl).h,'GAT562_30S_Mesh_Kit');assert.equal(JSON.stringify(item),before);
});
