import test from 'node:test';
import assert from 'node:assert/strict';
import { ESP32ROM } from '../node_modules/esptool-js/lib/targets/esp32.js';
import { ESP32S2ROM } from '../node_modules/esptool-js/lib/targets/esp32s2.js';
import { ESP32S3ROM } from '../node_modules/esptool-js/lib/targets/esp32s3.js';
import { ESP32C3ROM } from '../node_modules/esptool-js/lib/targets/esp32c3.js';
import { ESP32C6ROM } from '../node_modules/esptool-js/lib/targets/esp32c6.js';
import { EspSession } from '../src/esp.js';
import { inspectFirmware, md5hex, hash } from '../src/firmware.js';
import { imageRevisionRequirements, readChipRevision, revisionIncompatibility, assessEspCompatibility } from '../src/esp-compatibility.js';

function image({chip=9,app=false,min=0,minFull=0,maxFull=0}={}) {
  const data=new Uint8Array(64),view=new DataView(data.buffer);data.set([0xe9,1]);view.setUint16(12,chip,true);data[14]=min;view.setUint16(15,minFull,true);view.setUint16(17,maxFull,true);view.setUint32(28,16,true);if(app)view.setUint32(32,0xabcd5432,true);
  let checksum=0xef;for(const byte of data.subarray(32,48))checksum^=byte;data[63]=checksum;return data;
}
function session(chip=new ESP32S3ROM(),registers={}) {
  const writes=[],reads=[],s=new EspSession({getInfo:()=>({})},()=>{});s.mac='aa:bb:cc:dd:ee:ff';s.flashBytes=4<<20;
  chip.readMac=async()=>s.mac;s.loader={chip,debug(){},readReg:async address=>{reads.push(address);return (registers[address]||0)|0;},writeFlash:async options=>writes.push(options),flashMd5sum:async()=>md5hex(writes.at(-1).fileArray[0].data)};
  return {s,writes,reads,registers};
}
test('revision requirements follow native legacy/full precedence and C3 minor semantics',()=>{
  const revision={major:1,minor:3,full:103};
  assert.equal(imageRevisionRequirements(image({min:2,maxFull:65535})).full,false);
  assert.match(revisionIncompatibility(imageRevisionRequirements(image({min:2})),revision),/major/);
  assert.equal(revisionIncompatibility(imageRevisionRequirements(image({chip:5,min:2})),revision),null);
  assert.equal(revisionIncompatibility(imageRevisionRequirements(image({min:250,minFull:100,maxFull:199})),revision),null);
  assert.match(revisionIncompatibility(imageRevisionRequirements(image({minFull:104,maxFull:65535})),revision),/1.4/);
  assert.match(revisionIncompatibility(imageRevisionRequirements(image({maxFull:102})),revision),/1.2/);
  assert.equal(revisionIncompatibility(imageRevisionRequirements(image({maxFull:65535})),null),null);
});
test('actual target readers report full ESP32/S2/S3/C3/C6 revisions without writes',async()=>{
  const cases=[
    [new ESP32ROM(),{0x3ff5a00c:1<<15,0x3ff5a014:(1<<20)|(2<<24),0x3ff6607c:0x80000000},{major:3,minor:2,full:302}],
    [new ESP32S2ROM(),{0x3f41a050:(2<<18)|(1<<20),0x3f41a054:1<<4},{major:2,minor:9,full:209}],
    [new ESP32S3ROM(),{0x60007050:2<<18,0x60007058:1<<24},{major:1,minor:2,full:102}],
    [new ESP32C3ROM(),{0x60008850:1<<18,0x60008858:(1<<24)|(1<<23)},{major:1,minor:9,full:109}],
    [new ESP32C6ROM(),{0x600b0850:(2<<22)|(13<<18)},{major:2,minor:13,full:213}]
  ];
  for(const [chip,registers,expected]of cases){const {s,writes,reads}=session(chip,registers);assert.deepEqual(await readChipRevision(s.loader),expected);assert.equal(writes.length,0);if(chip.IMAGE_CHIP_ID===13)assert.deepEqual(reads,[0x600b0850]);}
});
test('constrained bootloader cannot write without explicit revision acknowledgement',async()=>{
  const {s,writes,reads}=session(),pkg=inspectFirmware('bootloader.bin',image({min:250})),plan=await s.prepare(pkg,{expertOffset:0});
  assert.equal(plan.requiresRevisionOverride,true);assert.equal(plan.revisionOverrideToken,'FORCE CHIP REVISION');assert.match(plan.compatibilityWarnings[0],/BOOTLOADER/);assert.ok(reads.length>0);
  await assert.rejects(s.flash(pkg,()=>{}),/FORCE CHIP REVISION/);assert.equal(writes.length,0);
  await s.flash(pkg,()=>{},{allowRevisionMismatch:true});assert.equal(writes.length,1);assert.equal(writes[0].eraseAll,false);
});
test('unknown constrained revision fails closed and evidence changes require inspection again',async()=>{
  const {s,writes,registers}=session(),pkg=inspectFirmware('bootloader.bin',image({minFull:100,maxFull:65535}));
  s.loader.readReg=async()=>{throw Error('no revision response');};let plan=await s.prepare(pkg,{expertOffset:0});assert.equal(plan.requiresRevisionOverride,true);assert.match(plan.compatibilityWarnings[0],/could not be read/);
  await assert.rejects(s.flash(pkg,()=>{}),/FORCE CHIP REVISION/);assert.equal(writes.length,0);
  const other=session();plan=await other.s.prepare(pkg,{expertOffset:0});other.registers[0x60007058]=1<<24;
  await assert.rejects(other.s.flash(pkg,()=>{},{allowRevisionMismatch:true}),/evidence changed/);assert.equal(other.writes.length,0);
});
function partitionTable(){const data=new Uint8Array(4096).fill(255),view=new DataView(data.buffer),enc=new TextEncoder();for(const [i,type,subtype,offset,size,label]of [[0,1,0,0xe000,8192,'ota'],[1,0,0x10,0x10000,0x100000,'app0'],[2,0,0x11,0x110000,0x100000,'app1']]){const at=i*32;data.fill(0,at,at+32);view.setUint16(at,0x50aa,true);data[at+2]=type;data[at+3]=subtype;view.setUint32(at+4,offset,true);view.setUint32(at+8,size,true);data.set(enc.encode(label),at+12);}return data;}
test('merged bootloader revision mismatch stops before whole-chip erase or any slot write',async()=>{
  const bytes=new Uint8Array(0x10000+64).fill(255);bytes.set(image({min:1}),0);bytes.set(partitionTable(),0x8000);bytes.set(image({app:true}),0x10000);
  const pkg=inspectFirmware('merged.bin',bytes),{s,writes}=session(),plan=await s.prepare(pkg);assert.equal(plan.requiresRevisionOverride,true);assert.ok(plan.compatibilityWarnings.some(w=>w.startsWith('BOOTLOADER')));
  await assert.rejects(s.flash(pkg,()=>{}),/FORCE CHIP REVISION/);assert.equal(writes.length,0);
  await s.flash(pkg,()=>{},{allowRevisionMismatch:true});assert.equal(writes.length,2);assert.equal(writes[0].eraseAll,true);assert.equal(writes[1].eraseAll,false);
});
test('application mismatches are explicitly labelled advisory-class rather than bootloader errors',async()=>{
  const pkg=inspectFirmware('app.bin',image({app:true,min:1})),{s}=session();const plan={addresses:[0x10000],parts:[]},result=await assessEspCompatibility(s.loader,pkg,plan);assert.equal(result.requiresRevisionOverride,true);assert.ok(result.compatibilityWarnings.every(w=>w.startsWith('APPLICATION')));
});
test('unconstrained legacy images need no revision reader and cannot bypass image or plan checks',async()=>{
  const {s,writes}=session(),pkg=inspectFirmware('bootloader.bin',image());s.loader.readReg=async()=>{throw Error('should not read unconstrained revision');};const plan=await s.prepare(pkg,{expertOffset:0});assert.equal(plan.requiresRevisionOverride,false);await s.flash(pkg,()=>{});assert.equal(writes.length,1);
  const other=session(),constrained=inspectFirmware('bootloader.bin',image({min:1}));await other.s.prepare(constrained,{expertOffset:0});other.s.plan.requiresRevisionOverride=false;await assert.rejects(other.s.flash(constrained,()=>{},{allowRevisionMismatch:true}),/plan changed/);assert.equal(other.writes.length,0);
  constrained.payload[14]=0;await assert.rejects(other.s.flash(constrained,()=>{},{allowRevisionMismatch:true}),/Firmware changed/);assert.notEqual(hash(constrained.payload),constrained.payloadHash);
});
