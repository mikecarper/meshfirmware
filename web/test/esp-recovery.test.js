import test from 'node:test';
import assert from 'node:assert/strict';
import { EspSession, validateEspWriteRecovery } from '../src/esp.js';
import { inspectFirmware, md5hex } from '../src/firmware.js';

function image({size=0xb000,app=true,min=0}={}){
  const bytes=new Uint8Array(size),view=new DataView(bytes.buffer);bytes.set([0xe9,1]);view.setUint16(12,9,true);bytes[14]=min;view.setUint32(28,size-48,true);bytes.fill(0x45,32,size-16);if(app)view.setUint32(32,0xabcd5432,true);
  let sum=0xef;for(const byte of bytes.subarray(32,size-16))sum^=byte;bytes[size-1]=sum;return bytes;
}
function table(){
  const bytes=new Uint8Array(4096).fill(255),view=new DataView(bytes.buffer);for(const [i,type,subtype,offset,size,label]of [[0,1,0,0xe000,8192,'ota'],[1,0,0x10,0x10000,0x100000,'app0'],[2,0,0x11,0x110000,0x100000,'app1']]){const at=i*32;bytes.fill(0,at,at+32);view.setUint16(at,0x50aa,true);bytes[at+2]=type;bytes[at+3]=subtype;view.setUint32(at+4,offset,true);view.setUint32(at+8,size,true);bytes.set(new TextEncoder().encode(label),at+12);}return bytes;
}
function merged(){const bytes=new Uint8Array(0x1b000).fill(255);bytes.set(image({size:64,app:false}),0);bytes.set(table(),0x8000);bytes.set(image(),0x10000);return bytes;}
function session(memory=new Uint8Array(4<<20).fill(255),{failWrite=false,failErase=false,mac='aa:bb:cc:dd:ee:ff'}={}){
  const calls=[],signals=[],s=new EspSession({getInfo:()=>({}),setSignals:async value=>signals.push(value)},()=>{});s.mac=mac;s.flashBytes=memory.length;s.connectMode='no_reset';let securityReads=0;
  s.loader={chip:{IMAGE_CHIP_ID:9,CHIP_NAME:'ESP32-S3',readMac:async()=>s.mac},readFlash:async(at,len)=>memory.slice(at,at+len),getSecurityInfo:async()=>{securityReads++;return {parsedFlags:{SECURE_BOOT_EN:false,SECURE_DOWNLOAD_ENABLE:false},flashCryptCnt:0};},flashMd5sum:async(at,len)=>md5hex(memory.subarray(at,at+len)),writeFlash:async options=>{
    calls.push(options);const {data,address}=options.fileArray[0];if(options.eraseAll){memory.fill(255);if(failErase)throw Error('device disconnected during whole-chip erase');}
    options.reportProgress?.(0,0,data.length);if(failWrite){memory.set(data.subarray(0,Math.min(16384,data.length)),address);throw Error('device disconnected during write');}
    memory.set(data,address);options.reportProgress?.(0,data.length,data.length);
  }};return {s,memory,calls,signals,get securityReads(){return securityReads;}};
}
function ordinary(){const memory=new Uint8Array(4<<20).fill(255);memory.set(table(),0x8000);return memory;}
async function interrupted(pkg,options={}){const fixture=session(pkg.merged?undefined:ordinary(),{failWrite:true,...options});await fixture.s.prepare(pkg,pkg.expert?{expertOffset:0}:{});let error;try{await fixture.s.flash(pkg,()=>{},{allowRevisionMismatch:true});}catch(e){error=e;}assert.ok(error?.recovery);await assert.rejects(fixture.s.finish(false),/verified/);assert.equal(fixture.signals.length,0);return {...fixture,recovery:JSON.parse(JSON.stringify(error.recovery))};}

test('interrupted updates resume as independently verified 16 KiB operations, inactive slot first, without reset or erase',async()=>{
  const pkg=inspectFirmware('app.bin',image()),first=await interrupted(pkg),retry=session(first.memory),plan=await retry.s.prepare(pkg,{recovery:first.recovery});assert.equal(plan.chunkedRecovery,true);validateEspWriteRecovery(first.recovery);
  await assert.rejects(retry.s.flash(pkg,()=>{}),/RETRY IN CHUNKS/);assert.equal(retry.calls.length,0);
  await retry.s.flash(pkg,()=>{},{chunkedRecovery:true});assert.ok(retry.securityReads>0);assert.equal(retry.signals.length,0);
  assert.deepEqual(retry.calls.map(c=>c.fileArray[0].address),[0x114000,0x118000,0x10000,0x14000,0x18000]);
  assert.ok(retry.calls.every(c=>c.eraseAll===false&&c.fileArray[0].data.length<=16384));assert.equal(md5hex(retry.memory.subarray(0x10000,0x1b000)),md5hex(pkg.payload));assert.equal(md5hex(retry.memory.subarray(0x110000,0x11b000)),md5hex(pkg.payload));
  await retry.s.finish(false);assert.equal(retry.signals.length,2);await assert.rejects(retry.s.finish(false),/once/);
});

test('recovery binds the exact chip, image, layout, segment ordering and explicit no-reset session',async()=>{
  const pkg=inspectFirmware('app.bin',image()),first=await interrupted(pkg);
  for(const change of [r=>r.mac='11:22:33:44:55:66',r=>r.sha256='0'.repeat(64),r=>r.stage='bridge',r=>r.segments.reverse(),r=>r.segments[0].address+=4096,r=>r.partitionHash='0'.repeat(64),r=>r.revisionProof='0'.repeat(64)]){
    const retry=session(first.memory),record=structuredClone(first.recovery);change(record);await assert.rejects(retry.s.prepare(pkg,{recovery:record}));assert.equal(retry.calls.length,0);
  }
  const resetting=session(first.memory);resetting.s.connectMode='default_reset';await assert.rejects(resetting.s.prepare(pkg,{recovery:first.recovery}),/no-reset/);
  const unbound=session(first.memory);await unbound.s.prepare(pkg);await assert.rejects(unbound.s.flash(pkg,()=>{},{chunkedRecovery:true}),/descriptor/);assert.equal(unbound.calls.length,0);
});

test('chunk recovery never waives security, revision, payload or readback gates',async()=>{
  const pkg=inspectFirmware('app.bin',image({min:1})),first=await interrupted(pkg),retry=session(first.memory);await retry.s.prepare(pkg,{recovery:first.recovery});
  await assert.rejects(retry.s.flash(pkg,()=>{},{chunkedRecovery:true}),/FORCE CHIP REVISION/);assert.equal(retry.calls.length,0);
  retry.s.loader.getSecurityInfo=async()=>({parsedFlags:{SECURE_BOOT_EN:true,SECURE_DOWNLOAD_ENABLE:false},flashCryptCnt:0});await assert.rejects(retry.s.flash(pkg,()=>{},{chunkedRecovery:true,allowRevisionMismatch:true}),/Secure boot/);assert.equal(retry.calls.length,0);
  const corrupt=session(first.memory);await corrupt.s.prepare(pkg,{recovery:first.recovery});corrupt.s.loader.flashMd5sum=async()=> '0'.repeat(32);await assert.rejects(corrupt.s.flash(pkg,()=>{},{chunkedRecovery:true,allowRevisionMismatch:true}),error=>/Chunk target MD5/.test(error.message)&&error.recovery.attempts===1);await assert.rejects(corrupt.s.finish(false),/verified/);
});

test('confirmed merged erase is never repeated by chunk recovery; uncertain erase cannot be silently skipped',async()=>{
  const pkg=inspectFirmware('full-merged.bin',merged()),first=await interrupted(pkg);assert.equal(first.recovery.eraseComplete,true);assert.equal(first.calls[0].eraseAll,true);
  const retry=session(first.memory);await retry.s.prepare(pkg,{recovery:first.recovery});await retry.s.flash(pkg,()=>{},{chunkedRecovery:true});assert.ok(retry.calls.every(c=>c.eraseAll===false));assert.equal(md5hex(retry.memory.subarray(0,pkg.payload.length)),md5hex(pkg.payload));
  const uncertain=await interrupted(pkg,{failErase:true});assert.equal(uncertain.recovery.eraseComplete,false);const stopped=session(uncertain.memory);await assert.rejects(stopped.s.prepare(pkg,{recovery:uncertain.recovery}),/erase was not confirmed/);assert.equal(stopped.calls.length,0);
});

test('every interrupted chunk retry stops for a new explicit session, bounded to three recovery rounds',async()=>{
  const pkg=inspectFirmware('app.bin',image()),first=await interrupted(pkg);let recovery=first.recovery;
  for(let attempt=1;attempt<=3;attempt++){
    const retry=session(first.memory,{failWrite:true});await retry.s.prepare(pkg,{recovery});let error;try{await retry.s.flash(pkg,()=>{},{chunkedRecovery:true});}catch(e){error=e;}assert.equal(error.recovery.attempts,attempt);assert.equal(retry.calls.length,1);assert.equal(retry.signals.length,0);recovery=JSON.parse(JSON.stringify(error.recovery));
  }
  const exhausted=session(first.memory);await assert.rejects(exhausted.s.prepare(pkg,{recovery}),/Three interrupted/);assert.equal(exhausted.calls.length,0);
});
