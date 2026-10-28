import test from 'node:test';
import assert from 'node:assert/strict';
import {backupCommonCli,MeshCore,publicFromPrivate,sealBackup,verifyBackup,parseBackup} from '../src/meshcore.js';
import {nativePayloadFromWeb} from '../src/backup-native.js';
import {backupCoverage} from '../src/backup-coverage.js';
import {CAPABILITY_KEYS,parseSettingCapabilities} from '../src/setting-capabilities.js';
import {words} from '../src/firmware.js';

const privateKey=new Uint8Array(64);privateKey[0]=1;
const publicKey=publicFromPrivate(privateKey),hex=bytes=>Buffer.from(bytes).toString('hex');
const exportOptions={usbIdentity:{vendor_id:0x2886,product_id:0x8044}};
function report({na=[],fixed=[],unreadable=[],unknown=[]}={}){
  const masks={get:0,set:0,fixed:0,na:0};
  for(const [index,key]of CAPABILITY_KEYS.entries()){
    const bit=2**index;
    if(na.includes(key)){masks.na|=bit;continue;}
    if(!unreadable.includes(key)&&!unknown.includes(key))masks.get|=bit;
    if(fixed.includes(key))masks.fixed|=bit;else if(!unknown.includes(key))masks.set|=bit;
  }
  return 'config.cap v1 '+Object.entries(masks).map(([key,value])=>`${key}=${value.toString(16).padStart(8,'0')}`).join(' ');
}
const record=options=>({state:'complete',data:parseSettingCapabilities(report(options))});
function commonLink(manifest,overrides={}){
  const calls=[];return {calls,async command(command){calls.push(command);
    if(command==='get config.cap'){if(manifest instanceof Error)throw manifest;return manifest;}
    if(Object.hasOwn(overrides,command))return overrides[command];
    if(command==='get public.key')return `> ${publicKey}`;
    if(command==='get prv.key')return `> ${hex(privateKey)}`;
    if(command==='get radio.preamble')return '> auto';
    if(command==='get bluetooth.name')return '> MeshCore-Bench (default from node name)';
    if(command.startsWith('region'))return 'Unknown command';
    return '> value';
  }};
}
function commonArchive(capabilities,replies={}){
  return sealBackup({role:'common-cli',publicKey,safeForWipe:false,capabilities,replies:{'get public.key':`> ${publicKey}`,'get prv.key':`> ${hex(privateKey)}`,...replies}});
}
function companion(manifest){
  const calls=[],self=new Uint8Array(62),info=new Uint8Array(82),view=new DataView(self.buffer);
  self.set([5,1,20,22]);self.set(privateToPublic(),4);self.set([10,5],56);self.set(new TextEncoder().encode('test'),58);view.setUint32(48,910525,true);view.setUint32(52,125000,true);
  info.set([13,14,2,0]);info.set(new TextEncoder().encode('test-build'),8);info.set(new TextEncoder().encode('test-model'),20);info.set(new TextEncoder().encode('v1.18'),60);
  const core=new MeshCore({});core.self=async()=>self;core.info=async()=>info;core.contacts=async()=>[];
  core.cli=async command=>{calls.push(command);if(command==='get config.cap')return manifest;if(command==='get radio.preamble')return '> 32';if(command==='get bluetooth.name')return '> MeshCore-test (default from node name)';return 'Unknown command';};
  core.request=async command=>{if(command[0]===23)return Uint8Array.from([14,...privateKey]);if(command[0]===59)return Uint8Array.of(25,1);if(command[0]===43)return Uint8Array.from([23,...words(1,2)]);if(command[0]===40)return Uint8Array.of(21);if(command[0]===64)return Uint8Array.of(28);if(command[0]===20)return Uint8Array.from([12,0xa0,0x0f]);throw Error('Unexpected read');};
  return {core,calls};
}
function privateToPublic(){return Buffer.from(publicKey,'hex');}

test('CommonCLI capability discovery skips only confirmed non-configurable omissions and runs once',async()=>{
  const options={na:['bluetooth','display.rotation'],fixed:['radio.cad'],unreadable:['radio.cad']},link=commonLink(report(options)),archive=await backupCommonCli(link),p=verifyBackup(archive),native=nativePayloadFromWeb(archive,exportOptions);
  assert.equal(link.calls.filter(command=>command==='get config.cap').length,1);
  for(const command of ['get bluetooth','get display.rotation','get radio.cad']){assert.ok(!link.calls.includes(command));assert.ok(!Object.hasOwn(p.replies,command));}
  assert.ok(link.calls.includes('get radio.fem.txgain'));assert.ok(link.calls.includes('get radio.preamble'));assert.deepEqual(p.capabilities,record(options));
  assert.equal(native.sections.radio_cad.state,'not_applicable');assert.equal(native.sections.radio_cad.capability_state,'fixed');assert.equal(native.sections.display_rotation.capability_state,'not_applicable');
  assert.equal(native.sections.config_capabilities.required,false);assert.deepEqual(native.sections.config_capabilities.data,p.capabilities.data);
  assert.ok(!link.calls.some(command=>/^set |reboot|erase|message/i.test(command)));assert.equal(native.completeness.safe_for_wipe,false);assert.equal(native.completeness.safe_for_restore,false);
});

test('legacy, malformed and failed capability discovery still query every individual optional getter',async()=>{
  for(const manifest of ['Unknown command','config.cap v2 get=00000fff set=00000fff fixed=00000000 na=00000000','config.cap v1 get=00000000 set=00000000 fixed=00000000 na=80000000',new Error('private transport details')]){
    const link=commonLink(manifest),p=verifyBackup(await backupCommonCli(link));
    assert.ok(['unsupported','error'].includes(p.capabilities.state));assert.ok(!JSON.stringify(p.capabilities).includes('private transport details'));
    for(const key of CAPABILITY_KEYS)assert.ok(link.calls.includes(`get ${key}`),`${String(manifest)}: ${key}`);
  }
  const link=commonLink(report({unknown:['radio.cad']}));await backupCommonCli(link);assert.ok(link.calls.includes('get radio.cad'));
});

test('fixed but readable settings are queried and genuine read failures are not hidden',async()=>{
  const link=commonLink(report({fixed:['radio.cad']}),{'get radio.cad':'Error: query failed'}),archive=await backupCommonCli(link),native=nativePayloadFromWeb(archive,exportOptions),coverage=backupCoverage(archive,{payload:native});
  assert.ok(link.calls.includes('get radio.cad'));assert.equal(native.sections.radio_cad.state,'error');assert.ok(native.completeness.optional_errors.includes('radio_cad'));assert.ok(coverage.failed.some(item=>item.label==='Radio CAD timings'));
});

test('companion capability discovery uses the framed CLI wrapper and preserves honest setting states',async()=>{
  const options={na:['bluetooth','display.rotation'],fixed:['radio.cad'],unreadable:['radio.cad']},stub=companion(report(options)),archive=await stub.core.backup(),p=verifyBackup(archive),native=nativePayloadFromWeb(archive,exportOptions);
  assert.equal(stub.calls.filter(command=>command==='get config.cap').length,1);assert.deepEqual(p.capabilities,record(options));
  for(const command of ['get bluetooth','get display.rotation','get radio.cad'])assert.ok(!stub.calls.includes(command));
  assert.ok(stub.calls.includes('get usb.debug'));assert.ok(stub.calls.includes('get system.watchdog'));assert.ok(stub.calls.includes('get radio.rxps.rfrx_disabled'));
  assert.equal(native.sections.radio_cad.state,'not_applicable');assert.equal(native.sections.usb_debug.state,'unsupported');assert.deepEqual(native.sections.radio_preamble.data,{text:'> 32',value:32});
  const legacy=companion('Unknown command');await legacy.core.backup();for(const key of CAPABILITY_KEYS)assert.ok(legacy.calls.includes(`get ${key}`),key);
});

test('native metadata cannot conceal a real query error and unsupported capabilities do not invent saved values',async()=>{
  const capabilities=record({na:['display.rotation'],fixed:['radio.cad'],unreadable:['radio.cad']}),archive=commonArchive(capabilities,{'get radio.cad':'Error: query failed'}),payload=nativePayloadFromWeb(archive,exportOptions);
  assert.equal(payload.sections.radio_cad.state,'error');payload.sections.radio_cad={state:'not_applicable',required:false,command:'get radio.cad',capability_state:'fixed'};
  const coverage=backupCoverage(archive,{payload});assert.ok(coverage.failed.some(item=>item.label==='Radio CAD timings'));assert.ok(!coverage.notIncluded.some(item=>item.label==='Display rotation'));assert.doesNotMatch(coverage.notIncludedText,/Preferences without an export command/);
  const imported=verifyBackup(await parseBackup(JSON.stringify({schema:'org.meshfirmware.meshcore-backup/v1',payload}),{validatePython:async()=>({payload})}));
  assert.match(imported.replies['get radio.cad'],/^Error:/);assert.ok(!Object.hasOwn(imported.replies,'get display.rotation'));assert.deepEqual(imported.capabilities,capabilities);
  const malformed=structuredClone(archive.payload);malformed.capabilities.data.version=2;assert.throws(()=>verifyBackup(sealBackup(malformed)),/capability/i);
});

test('primary preamble captures auto or a bounded saved symbol count without inventing a default',()=>{
  for(const [text,value]of [['> auto','auto'],['> 0','auto'],['> radio.preamble 8',8],['> 32',32],['get radio.preamble\n -> > 65528',65528]]){
    const payload=nativePayloadFromWeb(commonArchive(record(),{'get radio.preamble':text}),exportOptions);assert.equal(payload.sections.radio_preamble.state,'complete');assert.deepEqual(payload.sections.radio_preamble.data,{text,value});
  }
  for(const text of ['> 3','> 4','> 7','> 65529','> 65535','> 65536','> 4.5','> 32\nreboot'])assert.equal(nativePayloadFromWeb(commonArchive(record(),{'get radio.preamble':text}),exportOptions).sections.radio_preamble.state,'error',text);
  assert.equal(nativePayloadFromWeb(commonArchive(record(),{'get radio.preamble':'Unknown command'}),exportOptions).sections.radio_preamble.state,'unsupported');
});

test('a malformed optional companion preamble read is reported without discarding the rest of the backup',async()=>{
  const stub=companion(report()),original=stub.core.cli.bind(stub.core);stub.core.cli=command=>command==='get radio.preamble'?Promise.resolve('> 64\0'):original(command);
  const archive=await stub.core.backup(),native=nativePayloadFromWeb(archive,exportOptions);assert.equal(verifyBackup(archive).cli['get radio.preamble'],null);assert.equal(native.sections.radio_preamble.state,'error');assert.ok(backupCoverage(archive,{payload:native}).failed.some(row=>row.label==='Primary radio preamble'));assert.equal(native.sections.self_info.state,'complete');
});
