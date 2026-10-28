import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { loadPyodide } from 'pyodide';
import { createPlannerService } from '../src/planner-runtime.js';
import { hash,words } from '../src/firmware.js';
import { sealBackup,parseBackup,verifyBackup,publicFromPrivate } from '../src/meshcore.js';
import { exportNativeBackup } from '../src/backup-native.js';

const sources={};for(const name of ['meshcore_partition_expansion.py','meshcore_backup.py'])sources[name]=new Uint8Array(await readFile(new URL('../../tools/'+name,import.meta.url)));
const manifest=JSON.stringify(Object.fromEntries(Object.entries(sources).map(([name,data])=>[name,hash(data)])));
const service=createPlannerService({persistent:false,loadRuntime:()=>loadPyodide({indexURL:fileURLToPath(new URL('../node_modules/pyodide/',import.meta.url)),stdout:()=>{},stderr:()=>{}}),readValidator:async name=>name==='integrity.json'?manifest:sources[name]});
const hex=b=>Buffer.from(b).toString('hex'),enc=s=>new TextEncoder().encode(s);
function snapshot() {
  const key=new Uint8Array(64);key[0]=1;const pub=publicFromPrivate(key),self=new Uint8Array(62),v=new DataView(self.buffer),info=new Uint8Array(82),iv=new DataView(info.buffer);
  self.set([5,1,20,22]);self.set(Buffer.from(pub,'hex'),4);self[56]=10;self[57]=5;self.set(enc('test'),58);v.setUint32(48,910525,true);v.setUint32(52,125000,true);v.setInt32(36,1250000,true);v.setInt32(40,-2500000,true);
  info.set([13,14,2,1]);iv.setUint32(4,123456,true);info.set(enc('test-build'),8);info.set(enc('test-model'),20);info.set(enc('v1.18'),60);
  const channel=new Uint8Array(50);channel[0]=18;channel.set(enc('#public'),2);channel.set(new Uint8Array(16).fill(3),34);
  return sealBackup({role:'companion',publicKey:pub,self:hex(self),info:hex(info),privateKey:'0e'+hex(key),channels:[hex(channel)],contacts:[],options:{autoadd:'190103',tuning:'17'+hex(words(3,2000)),scope:'1c',custom:'15'+hex(enc('gps:1'))},cli:{version:'Companion v1.18.0.1-halo-keymind-cascade (protocol 14)', 'get bluetooth.name':{name:'MeshCore-test',default:true},'get usb.logging':'> usb.logging off'},batteryAndStorage:{level:4000,used_kb:3,total_kb:256},safeForWipe:false});
}
const options={usbIdentity:{usbVendorId:0x2886,usbProductId:0x8044},sealNative:args=>service.call('sealBackup',args)};
test('browser native export seals with exact Python and round-trips through native validator and browser restore import',async()=>{
  const input=snapshot(),native=await exportNativeBackup(input,options),p=native.payload;
  assert.equal(native.kind,'meshcore-logical-usb');assert.equal(p.source.physical_usb_identity.serial,null);assert.equal(p.source.physical_usb_identity.attestation,'browser-port-permission');assert.equal(p.sections.device_info.data.ver,'v1.18');assert.equal(p.sections.device_info.data.ver_full,'v1.18.0.1-halo-keymind-cascade');assert.equal(p.completeness.status,'api-snapshot-complete');
  const imported=await parseBackup(JSON.stringify(native),{validatePython:args=>service.call('validateBackup',args)}),restored=verifyBackup(imported);
  assert.equal(restored.privateKey,input.payload.privateKey);assert.equal(restored.self,input.payload.self);assert.deepEqual(restored.channels,input.payload.channels);assert.equal(restored.options.autoadd,input.payload.options.autoadd);assert.deepEqual(restored.batteryAndStorage,input.payload.batteryAndStorage);
  const damaged=structuredClone(native);damaged.payload.sections.self_info.data.tx_power=7;
  await assert.rejects(()=>parseBackup(JSON.stringify(damaged),{validatePython:args=>service.call('validateBackup',args)}),/digest mismatch/);
});
test('partial CommonCLI native exports retain identity and configuration for an explicit supported-settings restore',async()=>{
  const input=snapshot(),p=input.payload,common=sealBackup({role:'common-cli',publicKey:p.publicKey,replies:{'get public.key':'> '+p.publicKey,'get prv.key':'> '+p.privateKey.slice(2),ver:'MeshCore Repeater test','get acl':'empty',region:'empty'},safeForWipe:false});
  const native=await exportNativeBackup(common,options);assert.equal(native.payload.completeness.status,'partial');assert.equal(native.payload.completeness.safe_for_wipe,false);
  const imported=await parseBackup(JSON.stringify(native),{validatePython:args=>service.call('validateBackup',args)}),restored=verifyBackup(imported);assert.equal(restored.role,'common-cli');assert.equal(restored.replies['get prv.key'],'> '+p.privateKey.slice(2));assert.equal(restored.replies['get acl'],'empty');assert.equal(restored.replies.region,'empty');assert.equal(restored.nativeCompleteness.safe_for_wipe,false);assert.equal(native.payload.restore_plan.executor_implemented,false);
});

test('script-shaped CommonCLI settings and separately typed identity/ACL/regions pass the exact validator before browser import',async()=>{
  const p=snapshot().payload,common=sealBackup({role:'common-cli',publicKey:p.publicKey,replies:{'get public.key':'> '+p.publicKey,'get prv.key':'> '+p.privateKey.slice(2),ver:'MeshCore Repeater test','get role':'> repeater','get name':'> Bench','get acl':'ACL: empty',region:'0: Global'},safeForWipe:false});
  const original=await exportNativeBackup(common,options),payload=structuredClone(original.payload);
  payload.sections.settings.data=Object.fromEntries(Object.entries(payload.sections.settings.data).map(([command,value])=>[command,{ok:true,text:value}]));
  payload.sections.acl.data={raw:'ACL: empty'};payload.sections.regions.data={raw:'0: Global'};
  const sealed=await service.call('sealBackup',{payload,privateHex:p.privateKey.slice(2),expectedPub:p.publicKey}),raw=JSON.stringify(sealed.archive),imported=await parseBackup(raw,{validatePython:args=>service.call('validateBackup',args)}),restored=verifyBackup(imported);
  assert.equal(restored.replies['get name'],'> Bench');assert.equal(restored.replies['get prv.key'],'> '+p.privateKey.slice(2));assert.equal(restored.replies['get acl'],'ACL: empty');assert.equal(restored.replies.region,'0: Global');
  const damaged=structuredClone(sealed.archive);damaged.payload.sections.settings.data['get name'].text='changed';await assert.rejects(()=>parseBackup(JSON.stringify(damaged),{validatePython:args=>service.call('validateBackup',args)}),/digest mismatch/);
});
