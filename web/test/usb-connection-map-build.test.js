import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createSourceResolver,resolveUsbProfile,buildUsbConnectionMap,flagOperations} from '../scripts/build-usb-connection-map.mjs';
import {validateUsbConnectionMap,lookupUsbConnectionMap} from '../src/usb-connection-map.js';

const source={repository:'https://github.com/mikecarper/MeshCore',revision:'a'.repeat(40)};
const item=(overrides={})=>({provider:'Keymind Cascade',hardware:'Exact board',architecture:'esp32',role:'repeater',version:'v1.18.0.1-test-aaaaaaaa',runtimeVersion:'v1.18.0.1-test-observer-aaaaaaaa',source,target:'published_repeater',environment:'test_repeater',profile:'full',artifact:'app.bin',...overrides});
function files({mode=1,cdc=1,board='test',mcu='esp32s3',body='',flags='',unflags=''}={}){
  return new Map([
    ['platformio.ini',`[platformio]\nextra_configs = variants/*/platformio.ini\n[base]\nplatform = platformio/espressif32@6.11.0\nboard = ${board}\nbuild_flags = -D SOME_BASE=1\n`],
    ['variants/test/platformio.ini',`[env:test_repeater]\nextends = base\nbuild_flags = \n  \${base.build_flags}\n  -I variants/test\n  ${flags}\nbuild_unflags = ${unflags}\n${body}`],
    ['boards/test.json',JSON.stringify({build:{mcu,variant:'test',extra_flags:[`-DARDUINO_USB_MODE=${mode}`,`-DARDUINO_USB_CDC_ON_BOOT=${cdc}`],hwids:[['0x303a','0x1001']]}})],
  ]);
}
const classify=(fileMap,overrides={})=>resolveUsbProfile(item(overrides),createSourceResolver(fileMap));

test('exact inherited source recipe qualifies hardware USB, not a display/model name',()=>{
  const value=classify(files());assert.equal(value.usbMode,'hardware-cdc-jtag');assert.deepEqual(value.usbIds,['303a:1001']);
  assert.deepEqual(value.evidence,['boards/test.json','platformio.ini','variants/test/platformio.ini']);
  assert.equal(classify(files({board:'sdk_only'})).usbMode,'unknown');
  assert.equal(classify(files(),{environment:'similar_unpublished_repeater'}).usbMode,'unknown');
});

test('indented -DMACRO=value remains a multiline flag and exact unflags remove only their intended definition',()=>{
  const changed=classify(files({flags:'-DARDUINO_USB_MODE=0',unflags:'-DARDUINO_USB_MODE=1'}));
  assert.equal(changed.usbMode,'tinyusb');assert.deepEqual(changed.usbIds,[]);
  assert.equal(classify(files({flags:'-DARDUINO_USB_MODE=0'})).usbMode,'unknown');
  assert.equal(classify(files({flags:'-UARDUINO_USB_CDC_ON_BOOT'})).usbMode,'uart');
  assert.deepEqual(flagOperations('-D FOO -DBAR=1 -U FOO'),[{kind:'D',name:'FOO',value:null},{kind:'D',name:'BAR',value:'1'},{kind:'U',name:'FOO',value:null}]);
});

test('last extends parent wins like PlatformIO while cycles and host interpolation fail closed',()=>{
  const tree=files();tree.set('variants/test/platformio.ini','[first]\nboard = missing\n[second]\nboard = test\n[env:test_repeater]\nextends = first, second, base\n');
  assert.equal(classify(tree).usbMode,'hardware-cdc-jtag');
  tree.set('variants/test/platformio.ini','[first]\nboard = missing\n[second]\nboard = test\n[env:test_repeater]\nextends = base, first, second\n');
  assert.equal(classify(tree).usbMode,'hardware-cdc-jtag');
  const cyclic=files({body:'extends = loop\n[loop]\nextends = env:test_repeater\n'});assert.equal(classify(cyclic).usbMode,'unknown');
  assert.equal(classify(files({flags:'${sysenv.PRIVATE_FLAGS}'})).usbMode,'unknown');
});

test('TinyUSB IDs require application descriptors and do not inherit upload-only DFU hwids',()=>{
  const tree=files({mode:0});let value=classify(tree);assert.equal(value.usbMode,'tinyusb');assert.deepEqual(value.usbIds,[]);
  tree.set('variants/test/pins_arduino.h','#define USB_VID 0x303a\n#define USB_PID 0x1001\n');value=classify(tree);assert.deepEqual(value.usbIds,['303a:1001']);
});

test('primary Serial overrides and unreviewed chip/framework definitions remain explicit unknown',()=>{
  const tree=files();tree.set('variants/test/Board.h','#undef Serial\n#define Serial Serial1\n');assert.equal(classify(tree).usbMode,'unknown');
  assert.equal(classify(files({flags:'-DSerial=Serial1'})).usbMode,'unknown');
  assert.equal(classify(files({mcu:'esp32c6'})).usbMode,'unknown');
  assert.equal(classify(files({body:'platform = https://example.invalid/custom.zip\n'})).usbMode,'unknown');
  assert.equal(classify(files({body:'platform_packages = framework-arduinoespressif32 @ https://example.invalid/custom.zip\n'})).usbMode,'unknown');
  assert.equal(classify(files(),{runtimeVersion:null}).usbMode,'unknown');
});

test('nRF52 without source-bound TinyUSB selection stays manual, including custom UART aliases',()=>{
  assert.equal(classify(files(),{architecture:'nrf52'}).usbMode,'unknown');
  const tree=files({flags:'-DUSE_TINYUSB -DUSB_VID=0x239a -DUSB_PID=0x8029'});assert.equal(classify(tree,{architecture:'nrf52'}).usbMode,'tinyusb');
  assert.deepEqual(classify(tree,{architecture:'nrf52'}).usbIds,['239a:8029']);
  tree.set('variants/test/Board.h','#define Serial Serial1\n');assert.equal(classify(tree,{architecture:'nrf52'}).usbMode,'unknown');
});

test('all profiles are retained across exact versions, conflicting modes and unavailable source without leaking private metadata',()=>{
  const normal=item({privateKey:'DO-NOT-EXPORT',usbIdentity:'COM37'}),other=item({target:'other',environment:'test_uart'});
  const tree=files();tree.set('variants/test/platformio.ini',tree.get('variants/test/platformio.ini')+'\n[env:test_uart]\nextends = env:test_repeater\nbuild_unflags = -DARDUINO_USB_CDC_ON_BOOT=1\nbuild_flags = -DARDUINO_USB_CDC_ON_BOOT=0\n');
  const data=buildUsbConnectionMap({schemaVersion:1,items:[normal,{...normal,artifact:'app-merged.bin'},other,item({runtimeVersion:null,version:'unproven-version'})]}, {sourceFor:()=>tree});
  assert.equal(data.builds.length,2);const profiles=data.builds.find(row=>row.version===normal.runtimeVersion).profiles;
  assert.deepEqual(profiles.map(row=>row.usbMode).sort(),['hardware-cdc-jtag','uart']);
  assert.equal(data.builds.find(row=>row.version==='unproven-version').profiles[0].usbMode,'unknown');
  assert.ok(!JSON.stringify(data).includes('DO-NOT-EXPORT'));assert.ok(!JSON.stringify(data).includes('COM37'));
  const missing=buildUsbConnectionMap({schemaVersion:1,items:[normal]},{sourceFor:()=>{throw new Error('Pinned commit unavailable');}});
  assert.equal(missing.builds[0].profiles[0].usbMode,'unknown');
  assert.throws(()=>buildUsbConnectionMap({schemaVersion:1,items:[item({source:{...source,revision:'main'}})]},{sourceFor:()=>tree}),/provenance/);
});

test('generated JSON satisfies the exact public schema including unknown and catalog KISS rows',()=>{
  const data=buildUsbConnectionMap({schemaVersion:1,items:[item(),item({role:'kissRadio'}),item({runtimeVersion:null,version:'v1.18.0-unproven'})]}, {sourceFor:()=>files()});
  assert.equal(validateUsbConnectionMap(data),data);
  assert.deepEqual(Object.keys(data.builds[0].profiles[0]).sort(),['architecture','evidence','hardware','role','targets','usbIds','usbMode']);
  assert.equal(lookupUsbConnectionMap({map:data,hardware:'Exact board',device:{role:'kissRadio',model:'Exact board',architecture:'esp32',version:item().runtimeVersion},usbInfo:{usbVendorId:0x303a,usbProductId:0x1001}}).usbMode,null);
});

test('checked-in generated map preserves exact historical evidence and unknown blockers',()=>{
  const map=validateUsbConnectionMap(JSON.parse(readFileSync(new URL('../src/data/usb-connection-map.json',import.meta.url),'utf8')));
  const preview=map.builds.find(build=>build.version==='v1.18.0.2-halo-keymind-cascade-dev-observer-eab29a12');
  assert.ok(preview&&preview.source.revision.startsWith('eab29a12'));
  const matching=lookupUsbConnectionMap({map,hardware:'Heltec v4',device:{role:'common-cli',architecture:'esp32',model:'Heltec V4.2 none detected',version:preview.version+' (Build: 27-Oct-2026)'},usbInfo:{usbVendorId:0x303a,usbProductId:0x1001}});
  assert.equal(matching.usbMode,'hardware-cdc-jtag');
  const old=map.builds.find(build=>build.version==='v1.16.0-07a3ca9');
  assert.equal(old.profiles.find(profile=>profile.hardware==='Heltec v4'&&profile.role==='repeater').usbMode,'tinyusb');
  const published=map.builds.find(build=>build.version==='v1.18.0.1-halo-keymind-cascade-dev-observer-03214a16');
  assert.equal(published.profiles.find(profile=>profile.hardware==='UnitEng/BQ Voyage Station G3'&&profile.role==='repeater').usbMode,'hardware-cdc-jtag');
  assert.ok(published.profiles.some(profile=>profile.hardware==='Seeed Studio Xiao S3 WIO'&&profile.usbMode==='unknown'&&!profile.usbIds.length));
  for(const build of map.builds)for(const profile of build.profiles)if(profile.usbMode==='unknown')assert.deepEqual(profile.usbIds,[]);
});
