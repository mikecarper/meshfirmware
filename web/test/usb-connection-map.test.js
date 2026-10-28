import test from 'node:test';
import assert from 'node:assert/strict';
import {validateUsbConnectionMap,lookupUsbConnectionMap} from '../src/usb-connection-map.js';

const version='v1.18.0.2-halo-keymind-cascade-dev-observer-28a6d5947';
const usbInfo={usbVendorId:0x303a,usbProductId:0x1001};
const profile=(more={})=>({hardware:'Heltec v4',architecture:'esp32',role:'repeater',usbMode:'hardware-cdc-jtag',usbIds:['303a:1001'],targets:['heltec_v4_repeater_full_usb_wifi_ota'],evidence:['platformio.ini','variants/heltec_v4/platformio.ini'],...more});
const build=(more={})=>({version,source:{repository:'https://github.com/mikecarper/MeshCore',revision:'a'.repeat(40)},profiles:[profile()],...more});
const map=(profiles=[profile()])=>({schemaVersion:1,builds:[build({profiles})]});
const device=(more={})=>({model:'Heltec V4.2 none detected',architecture:'esp32',role:'common-cli',catalogRole:'repeater',version:version+' (Build: 28-Oct-2026)',...more});
const lookup=(more={})=>lookupUsbConnectionMap({map:map(),hardware:'Heltec v4',device:device(),usbInfo,...more});

test('reviewed USB map validates exact source and build provenance without changing the input',()=>{
  const value=map(),original=JSON.stringify(value);
  assert.equal(validateUsbConnectionMap(value),value);assert.equal(JSON.stringify(value),original);
  assert.deepEqual(validateUsbConnectionMap({schemaVersion:1,builds:[]}),{schemaVersion:1,builds:[]});
  for(const usbMode of ['hardware-cdc-jtag','tinyusb','uart','unknown'])assert.doesNotThrow(()=>validateUsbConnectionMap(map([profile({usbMode})])));
});

test('bad schema, source references, bounds and profile rows are rejected',()=>{
  const cases=[null,[],{}, {...map(),schemaVersion:2},{...map(),extra:true},{schemaVersion:1,builds:new Array(257).fill(build())}];
  for(const change of [
    value=>value.builds[0].version='>=1.18.0',
    value=>value.builds[0].version=version+' ',
    value=>value.builds[0].source.repository='http://github.com/mikecarper/MeshCore',
    value=>value.builds[0].source.repository='https://github.com/mikecarper/MeshCore/tree/main',
    value=>value.builds[0].source.repository='https://github.com/mikecarper/MeshCore?ref=main',
    value=>value.builds[0].source.repository='https://github.com/mikecarper/..',
    value=>value.builds[0].source.revision='main',
    value=>value.builds[0].source.revision='A'.repeat(40),
    value=>value.builds[0].profiles=[],
    value=>value.builds[0].profiles[0].hardware='',
    value=>value.builds[0].profiles[0].hardware='x'.repeat(257),
    value=>value.builds[0].profiles[0].architecture='esp32s3',
    value=>value.builds[0].profiles[0].role='companion',
    value=>value.builds[0].profiles[0].usbMode='usb_reset',
    value=>value.builds[0].profiles[0].usbIds=['303A:1001'],
    value=>value.builds[0].profiles[0].usbIds=['303a:*'],
    value=>value.builds[0].profiles[0].usbIds=['303a:1001','303a:1001'],
    value=>value.builds[0].profiles[0].targets=[],
    value=>value.builds[0].profiles[0].targets=['../other'],
    value=>value.builds[0].profiles[0].evidence=[],
    value=>value.builds[0].profiles[0].evidence=['../platformio.ini'],
    value=>value.builds[0].profiles[0].evidence=['/platformio.ini'],
    value=>value.builds[0].profiles[0].evidence=['https://github.com/repo/file'],
    value=>value.builds[0].profiles[0].evidence=['src/file.h#L3'],
    value=>value.builds[0].profiles[0].ignored=true,
  ]){const value=map();change(value);cases.push(value);}
  for(const value of cases){assert.throws(()=>validateUsbConnectionMap(value),TypeError);assert.equal(lookup({map:value}).usbMode,null);}
});

test('exact running CommonCLI version and known build trailers select a reviewed mode',()=>{
  for(const running of [version,version+' (Build: 28-Oct-2026)',version+' (Build: 28 Oct 2026)',version+' (Build: Oct 28 2026)',version+' (Build: 2026-10-28)']){
    const result=lookup({device:device({version:running})});
    assert.equal(result.usbMode,'hardware-cdc-jtag',running);assert.equal(result.version,version);assert.equal(result.source,'firmware-map');
  }
  const stock='v1.17.1';assert.equal(lookup({map:{schemaVersion:1,builds:[build({version:stock})]},device:device({version:stock})}).usbMode,'hardware-cdc-jtag');
});

test('changed runtime version, suffix, hash and arbitrary trailing text never match the loaded-build history',()=>{
  for(const running of [version.replace('1.18.0.2','1.18.0.1'),version.replace('observer-',''),version.replace('28a6d5947','28a6d594'),version.slice(0,20),version+' extra',version+'\n',version+' (Build: made up)',version+' (Build: 28-Oct-2026) extra','> '+version]){
    assert.equal(lookup({device:device({version:running})}).usbMode,null,running);
  }
  assert.equal(lookup({device:device({version:'v0.0.1'}),selectedVersion:version,filename:version+'.bin'}).usbMode,null);
});

test('companion uses only a complete full-version CLI reply, never a raw DEVICE_INFO token',()=>{
  const value=map([profile({role:'companionFull'})]);
  for(const running of ['Companion '+version+' (protocol 14, build 28-Oct-2026)','Companion '+version+' (protocol 255, build 28 Oct 2026)'])assert.equal(lookup({map:value,device:device({role:'companion',catalogRole:null,version:running})}).usbMode,'hardware-cdc-jtag');
  for(const running of [version,version.slice(0,20),'v1.17.1','Companion '+version+' (protocol 256, build 28-Oct-2026)','Companion '+version+' (protocol 14, build 28-Oct-2026) extra'])assert.equal(lookup({map:value,device:device({role:'companion',catalogRole:null,version:running})}).usbMode,null,running);
});

test('unknown exact hardware, model, architecture, role or USB ID remains manual',()=>{
  for(const more of [
    {hardware:'Heltec v4 R8'},
    {hardware:''},
    {device:device({model:''})},
    {device:device({model:'bad\nmodel'})},
    {device:device({architecture:'nrf52'})},
    {device:device({architecture:null})},
    {device:device({catalogRole:'companionFull'})},
    {device:device({catalogRole:'unknown'})},
    {device:device({role:'unknown',catalogRole:null})},
    {usbInfo:{usbVendorId:0x303a,usbProductId:0x1002}},
    {usbInfo:{usbVendorId:'303a',usbProductId:0x1001}},
    {usbInfo:{usbVendorId:0x303a,usbProductId:-1}},
    {usbInfo:null},
  ])assert.equal(lookup(more).usbMode,null,JSON.stringify(more));
});

test('known catalog role narrows profiles but an unknown CommonCLI role requires all common-role profiles to agree',()=>{
  const profiles=[profile(),profile({role:'roomServer',usbMode:'tinyusb'}),profile({role:'companionFull',usbMode:'tinyusb'})];
  assert.equal(lookup({map:map(profiles)}).usbMode,'hardware-cdc-jtag');
  assert.equal(lookup({map:map(profiles),device:device({catalogRole:'roomServer'})}).usbMode,'tinyusb');
  assert.equal(lookup({map:map(profiles),device:device({catalogRole:null})}).usbMode,null);
  assert.equal(lookup({map:map([profile(),profile({role:'sensor'})]),device:device({catalogRole:null})}).usbMode,'hardware-cdc-jtag');
});

test('unknown companion variant requires every applicable companion profile to agree',()=>{
  const runtime=device({role:'companion',catalogRole:null,version:'Companion '+version+' (protocol 14, build 28-Oct-2026)'});
  const profiles=[profile({role:'companionFull'}),profile({role:'companionBle',usbMode:'tinyusb'}),profile({role:'repeater',usbMode:'unknown'})];
  assert.equal(lookup({map:map(profiles),device:runtime}).usbMode,null);
  assert.equal(lookup({map:map(profiles),device:{...runtime,catalogRole:'companionFull'}}).usbMode,'hardware-cdc-jtag');
  assert.equal(lookup({map:map([profile({role:'companionFull'}),profile({role:'companionUsb'})]),device:runtime}).usbMode,'hardware-cdc-jtag');
});

test('unknown modes and empty USB identities cannot disappear to manufacture a unique mapping',()=>{
  for(const uncertain of [profile({usbMode:'unknown'}),profile({usbIds:[]}),profile({role:'sensor',usbIds:[]})]){
    const result=lookup({map:map([profile(),uncertain]),device:device({catalogRole:null})});assert.equal(result.usbMode,null);assert.match(result.reason,/unknown USB/);
  }
  assert.equal(lookup({map:map([profile({usbIds:[]})])}).usbMode,null);
});

test('all matching rows and duplicate build versions participate, never the first matching row only',()=>{
  for(const profiles of [[profile(),profile({usbMode:'tinyusb'})],[profile({usbMode:'tinyusb'}),profile()]])assert.equal(lookup({map:map(profiles)}).usbMode,null);
  const conflicting={schemaVersion:1,builds:[build(),build({source:{repository:'https://github.com/meshcore-dev/MeshCore',revision:'b'.repeat(40)},profiles:[profile({usbMode:'tinyusb'})]})]};
  assert.equal(lookup({map:conflicting}).usbMode,null);
  conflicting.builds[1].profiles[0].usbMode='hardware-cdc-jtag';assert.equal(lookup({map:conflicting}).usbMode,'hardware-cdc-jtag');
});

test('positively reviewed other USB IDs cannot match the selected interface',()=>{
  const profiles=[profile(),profile({usbMode:'uart',usbIds:['1a86:7523']})];
  assert.equal(lookup({map:map(profiles)}).usbMode,'hardware-cdc-jtag');
  assert.equal(lookup({map:map(profiles),usbInfo:{usbVendorId:0x1a86,usbProductId:0x7523}}).usbMode,'uart');
});

test('lookup does not mutate running evidence or map data and malformed inputs fail closed',()=>{
  const value=map(),runtime=device(),original=JSON.stringify({value,runtime});Object.freeze(runtime);Object.freeze(usbInfo);
  assert.equal(lookup({map:value,device:runtime}).usbMode,'hardware-cdc-jtag');assert.equal(JSON.stringify({value,runtime}),original);
  assert.equal(lookupUsbConnectionMap().usbMode,null);
  assert.equal(lookup({device:null}).usbMode,null);
  assert.equal(lookup({map:{schemaVersion:1,builds:[]}}).usbMode,null);
});
