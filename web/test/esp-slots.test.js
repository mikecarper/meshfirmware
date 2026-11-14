import test from 'node:test';
import assert from 'node:assert/strict';
import {EspSession,espSlotChoices,selectEspWriteSlots,validateEspWriteRecovery} from '../src/esp.js';
import {inspectFirmware,md5hex,crc32,hash} from '../src/firmware.js';

const encode=value=>new TextEncoder().encode(value);
function image({size=64,app=true}={}){
  const bytes=new Uint8Array(size),view=new DataView(bytes.buffer);bytes.set([0xe9,1]);bytes[12]=9;view.setUint32(28,size-48,true);bytes.fill(0x45,32,size-16);if(app)view.setUint32(32,0xabcd5432,true);
  let sum=0xef;for(const byte of bytes.subarray(32,size-16))sum^=byte;bytes[size-1]=sum;return bytes;
}
function table({a=0x10000,b=0x110000,factory=false}={}){
  const entries=factory?[[0,0,a,0x100000,'factory']]:[[1,0,0xe000,0x2000,'otadata'],[0,0x10,a,0x100000,'not-a-name'],[0,0x11,b,0x100000,'not-b-name']];
  const bytes=new Uint8Array(4096).fill(255),view=new DataView(bytes.buffer);
  entries.forEach(([type,subtype,offset,size,label],index)=>{const at=index*32;bytes.fill(0,at,at+32);view.setUint16(at,0x50aa,true);bytes[at+2]=type;bytes[at+3]=subtype;view.setUint32(at+4,offset,true);view.setUint32(at+8,size,true);bytes.set(encode(label),at+12);});return bytes;
}
function ota(sequence){
  const bytes=new Uint8Array(8192).fill(255);if(sequence){const view=new DataView(bytes.buffer);view.setUint32(0,sequence,true);view.setUint32(24,2,true);view.setUint32(28,crc32(bytes.subarray(0,4),0xffffffff),true);}return bytes;
}
function fixture({a=0x10000,b=0x110000,sequence=1,factory=false,memory=null,failWrite=false}={}){
  memory||=new Uint8Array(4<<20).fill(255);if(!memory.some(value=>value!==255)){memory.set(table({a,b,factory}),0x8000);if(!factory)memory.set(ota(sequence),0xe000);}
  const writes=[],reads=[],signals=[],s=new EspSession({getInfo:()=>({}),setSignals:async value=>signals.push(value)},()=>{});s.mac='aa:bb:cc:dd:ee:ff';s.flashBytes=memory.length;s.connectMode='no_reset';
  s.loader={chip:{IMAGE_CHIP_ID:9,CHIP_NAME:'ESP32-S3',readMac:async()=>s.mac},readFlash:async(at,size)=>{reads.push([at,size]);return memory.slice(at,at+size);},getSecurityInfo:async()=>({parsedFlags:{SECURE_BOOT_EN:false,SECURE_DOWNLOAD_ENABLE:false},flashCryptCnt:0}),writeFlash:async options=>{
    writes.push(options);const {address,data}=options.fileArray[0];if(options.eraseAll)memory.fill(255);options.reportProgress?.(0,0,data.length);
    if(failWrite){memory.set(data.subarray(0,Math.min(data.length,16384)),address);throw Error('device disconnected during write');}
    memory.set(data,address);options.reportProgress?.(0,data.length,data.length);
  },flashMd5sum:async(at,size)=>md5hex(memory.subarray(at,at+size))};
  return {s,memory,writes,reads,signals};
}

test('Both remains the exact default and preserves inactive-first, boot-slot-last writes',async()=>{
  const pkg=inspectFirmware('app.bin',image()),f=fixture(),plan=await f.s.prepare(pkg),slots=espSlotChoices(pkg,plan);
  assert.equal(slots.selected,'both');assert.equal(slots.canSelect,true);assert.equal(slots.bootAddress,0x10000);assert.equal(slots.writesBootSlot,true);
  assert.deepEqual(plan.addresses,[0x110000,0x10000]);assert.equal(await f.s.selectSlots(pkg,'both'),plan);
  await f.s.flash(pkg,()=>{});assert.deepEqual(f.writes.map(write=>write.fileArray[0].address),[0x110000,0x10000]);assert.ok(f.writes.every(write=>write.eraseAll===false));
});
test('A and B use physical OTA subtype identities, not partition order, names or write order',async()=>{
  const pkg=inspectFirmware('app.bin',image()),f=fixture({a:0x210000,b:0x10000,sequence:2}),plan=await f.s.prepare(pkg),slots=espSlotChoices(pkg,plan);
  assert.deepEqual(plan.addresses,[0x210000,0x10000]);assert.deepEqual(slots.options.find(option=>option.value==='a').addresses,[0x210000]);assert.deepEqual(slots.options.find(option=>option.value==='b').addresses,[0x10000]);
  assert.equal(slots.options.find(option=>option.value==='a').writesBootSlot,false);assert.equal(slots.options.find(option=>option.value==='b').writesBootSlot,true);
});
test('A-only and B-only write/readback exactly one slot and never alter OTA metadata or the other slot',async()=>{
  for(const selection of ['a','b']){
    const pkg=inspectFirmware('app.bin',image()),f=fixture(),before=f.memory.slice(),plan=await f.s.prepare(pkg),oldProof=plan.revisionProof;
    const selected=await f.s.selectSlots(pkg,selection),at=selection==='a'?0x10000:0x110000,other=selection==='a'?0x110000:0x10000;
    assert.equal(selected.slotSelection,selection);assert.deepEqual(selected.addresses,[at]);assert.equal(selected.writesBootSlot,selection==='a');assert.deepEqual(selected.revisionCheck.images.map(entry=>entry.offset),[at]);if(selection==='a')assert.notEqual(selected.revisionProof,oldProof);
    await f.s.flash(pkg,()=>{});assert.deepEqual(f.writes.map(write=>write.fileArray[0].address),[at]);assert.equal(f.writes[0].eraseAll,false);
    assert.deepEqual(f.memory.subarray(0xe000,0x10000),before.subarray(0xe000,0x10000));assert.deepEqual(f.memory.subarray(other,other+pkg.payload.length),before.subarray(other,other+pkg.payload.length));assert.equal(md5hex(f.memory.subarray(at,at+pkg.payload.length)),md5hex(pkg.payload));
  }
});
test('selection may be changed before writing, restoring the original complete order for Both',async()=>{
  const pkg=inspectFirmware('app.bin',image()),f=fixture(),original=await f.s.prepare(pkg);
  await f.s.selectSlots(pkg,'a');await f.s.selectSlots(pkg,'b');const both=await f.s.selectSlots(pkg,'both');
  assert.deepEqual(both.addresses,original.addresses);assert.deepEqual(both.allSlotAddresses,original.addresses);assert.equal(both.slotSelection,'both');assert.equal(both.writesBootSlot,true);assert.equal(both.revisionProof,original.revisionProof);assert.deepEqual(f.writes,[]);
});
test('factory-only, merged, component and migration plans do not permit partial slot choices',async()=>{
  const pkg=inspectFirmware('app.bin',image()),factory=fixture({factory:true}),plan=await factory.s.prepare(pkg);
  assert.equal(espSlotChoices(pkg,plan).canSelect,false);assert.equal(espSlotChoices(pkg,plan).options[0].label,'Required targets (fixed)');await assert.rejects(factory.s.selectSlots(pkg,'a'),/does not expose exactly/);assert.equal(await factory.s.selectSlots(pkg,'both'),plan);
  for(const patch of [{merged:true},{expert:true},{needed:true},{verified:true},{bridge:[1,2]},{format:'meshcore-usb-partition-expansion-v2'}]){
    const candidate={...plan,...patch},meta=espSlotChoices({...pkg,merged:!!patch.merged,expert:!!patch.expert},candidate);assert.equal(meta.canSelect,false);assert.throws(()=>selectEspWriteSlots({...pkg,merged:!!patch.merged,expert:!!patch.expert},candidate,'a'));
  }
  assert.deepEqual(factory.writes,[]);
});
test('malformed or incomplete capability snapshots do not throw or invent an available A/B option',()=>{
  const pkg={architecture:'esp32',payload:new Uint8Array(64)};
  for(const plan of [null,{}, {addresses:[]}, {parts:[null],addresses:[0]}, {parts:[{type:0,subtype:0x10,offset:0x10000,size:1}],addresses:[0x10000]}]){
    const options=espSlotChoices(pkg,plan);assert.equal(options.canSelect,false);assert.equal(options.options.length,3);assert.ok(options.options.filter(option=>option.value!=='both').every(option=>option.available===false));
  }
});
test('invalid values, missing source identities and arbitrary target addresses are rejected',async()=>{
  const pkg=inspectFirmware('app.bin',image()),f=fixture(),plan=await f.s.prepare(pkg);
  for(const selection of ['A','B','',null,'0x10000','factory'])await assert.rejects(f.s.selectSlots(pkg,selection),/Choose ESP32 slot/);
  assert.equal(espSlotChoices(pkg,{...plan,allSlotAddresses:[0x10000,0x310000]}).canSelect,false);
  assert.throws(()=>selectEspWriteSlots(pkg,{...plan,allSlotAddresses:[0x10000,0x310000]},'b'),/does not expose exactly/);assert.deepEqual(f.writes,[]);
});
test('slot-selection inputs and claims are part of the immutable flash proof',async()=>{
  for(const mutate of [plan=>plan.slotSelection='a',plan=>plan.slotBootAddress=0x110000,plan=>plan.writesBootSlot=false,plan=>plan.allSlotAddresses=[0x10000],plan=>plan.parts=[...plan.parts,{type:0,subtype:0x12,offset:0x210000,size:0x100000}]]){
    const pkg=inspectFirmware('app.bin',image()),f=fixture();await f.s.prepare(pkg);mutate(f.s.plan);await assert.rejects(f.s.flash(pkg,()=>{}),/plan changed/);assert.deepEqual(f.writes,[]);
  }
  const pkg=inspectFirmware('app.bin',image()),f=fixture();const plan=await f.s.prepare(pkg);assert.throws(()=>{plan.parts[1].subtype=0x11;},TypeError);assert.throws(()=>{plan.allSlotAddresses[0]=0x310000;},TypeError);
});
test('changed firmware, chip identity, stale plans and a completed write cannot authorize a new selection',async()=>{
  const pkg=inspectFirmware('app.bin',image()),f=fixture();await f.s.prepare(pkg);pkg.payload[40]^=1;await assert.rejects(f.s.selectSlots(pkg,'a'),/changed before slot/);assert.deepEqual(f.writes,[]);
  const other=fixture(),otherPkg=inspectFirmware('app.bin',image());await other.s.prepare(otherPkg);other.s.loader.chip.readMac=async()=>{other.s.plan={...other.s.plan};return other.s.mac;};await assert.rejects(other.s.selectSlots(otherPkg,'a'),/changed during compatibility/);assert.deepEqual(other.writes,[]);
  const done=fixture();await done.s.prepare(otherPkg);await done.s.flash(otherPkg,()=>{});await assert.rejects(done.s.selectSlots(otherPkg,'b'),/changed before slot/);
});
test('single-slot interrupted recovery retains only its selected slot and cannot silently broaden to Both',async()=>{
  for(const selection of ['a','b']){
    const pkg=inspectFirmware('large.bin',image({size:0xb000})),first=fixture({failWrite:true});await first.s.prepare(pkg);await first.s.selectSlots(pkg,selection);
    let failure;try{await first.s.flash(pkg,()=>{});}catch(error){failure=error;}
    const expected=selection==='a'?0x10000:0x110000;assert.ok(failure?.recovery);validateEspWriteRecovery(failure.recovery);assert.deepEqual(failure.recovery.segments.map(segment=>segment.address),[expected]);
    const retry=fixture({memory:first.memory}),plan=await retry.s.prepare(pkg,{recovery:structuredClone(failure.recovery)}),meta=espSlotChoices(pkg,plan);
    assert.equal(plan.slotSelection,selection);assert.equal(plan.chunkedRecovery,true);assert.equal(meta.canSelect,false);assert.equal(meta.options.find(option=>option.value===selection).available,true);assert.equal(meta.options.find(option=>option.value==='both').available,false);
    await assert.rejects(retry.s.selectSlots(pkg,'both'),/Interrupted-write recovery/);await retry.s.flash(pkg,()=>{},{chunkedRecovery:true});assert.ok(retry.writes.every(write=>write.fileArray[0].address>=expected&&write.fileArray[0].address<expected+pkg.payload.length));assert.ok(retry.writes.every(write=>write.eraseAll===false));assert.equal(md5hex(retry.memory.subarray(expected,expected+pkg.payload.length)),md5hex(pkg.payload));
  }
});
test('single-slot MD5 failure never permits reset or claims a completed write',async()=>{
  const pkg=inspectFirmware('app.bin',image()),f=fixture();await f.s.prepare(pkg);await f.s.selectSlots(pkg,'b');f.s.loader.flashMd5sum=async()=>'0'.repeat(32);
  await assert.rejects(f.s.flash(pkg,()=>{}),/MD5 readback/);await assert.rejects(f.s.finish(false),/verified write/);assert.deepEqual(f.signals,[]);assert.equal(hash(pkg.payload),pkg.payloadHash);
});
test('single-slot recovery cannot broaden its inventory while legacy Both descriptors remain compatible',async()=>{
  const pkg=inspectFirmware('large.bin',image({size:0xb000})),first=fixture({failWrite:true});await first.s.prepare(pkg);await first.s.selectSlots(pkg,'b');let error;
  try{await first.s.flash(pkg,()=>{});}catch(failure){error=failure;}
  assert.equal(error.recovery.slotSelection,'b');const broadened=structuredClone(error.recovery);broadened.segments.push({...broadened.segments[0],address:0x10000});
  await assert.rejects(fixture({memory:first.memory}).s.prepare(pkg,{recovery:broadened}),/different chip, firmware, partition layout or write stage/);
  const both=fixture({failWrite:true});await both.s.prepare(pkg);try{await both.s.flash(pkg,()=>{});}catch(failure){error=failure;}
  const legacy=structuredClone(error.recovery);delete legacy.slotSelection;const retry=fixture({memory:both.memory}),plan=await retry.s.prepare(pkg,{recovery:legacy});assert.equal(plan.slotSelection,'both');assert.equal(plan.chunkedRecovery,true);
});
test('reselecting an OTA target cannot silently adopt changed silicon-revision evidence',async()=>{
  const bytes=image();bytes[14]=1;const pkg=inspectFirmware('constrained.bin',bytes),f=fixture();let major=0;
  f.s.loader.chip.getMajorChipVersion=async()=>major;f.s.loader.chip.getMinorChipVersion=async()=>0;
  const plan=await f.s.prepare(pkg);assert.equal(plan.requiresRevisionOverride,true);major=1;
  await assert.rejects(f.s.selectSlots(pkg,'a'),/Silicon revision evidence changed during slot selection/);assert.equal(f.s.plan,plan);assert.deepEqual(f.writes,[]);
});
