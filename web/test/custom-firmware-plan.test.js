import {test} from 'node:test';
import assert from 'node:assert/strict';
import {EspSession,appWriteOrder} from '../src/esp.js';
import {compatibilityImages} from '../src/esp-compatibility.js';
import {hash,inspectFirmware,md5hex,partitionTable} from '../src/firmware.js';

const encode=value=>new TextEncoder().encode(value);
function image({chip=9,app=true,dataSize=16}={}) {
  const bytes=new Uint8Array(Math.ceil((32+dataSize+1)/16)*16),view=new DataView(bytes.buffer);
  bytes[0]=0xe9;bytes[1]=1;view.setUint16(12,chip,true);view.setUint32(28,dataSize,true);
  if(app)view.setUint32(32,0xabcd5432,true);
  let crc=0xef;for(const byte of bytes.subarray(32,32+dataSize))crc^=byte;bytes[bytes.length-1]=crc;
  return bytes;
}
function table(entries) {
  const bytes=new Uint8Array(4096).fill(255),view=new DataView(bytes.buffer);
  entries.forEach(([type,subtype,offset,size,label],index)=>{
    const at=index*32;bytes.fill(0,at,at+32);view.setUint16(at,0x50aa,true);
    bytes[at+2]=type;bytes[at+3]=subtype;view.setUint32(at+4,offset,true);
    view.setUint32(at+8,size,true);bytes.set(encode(label),at+12);
  });return bytes;
}
const dual=(first=0x10000,second=0x110000)=>table([
  [1,2,0x9000,0x5000,'nvs'],[1,0,0xe000,0x2000,'otadata'],
  [0,0x10,first,0x100000,'app0'],[0,0x11,second,0x100000,'app1'],
]);
function nonzeroMerged() {
  const bootloader=image({chip:0,app:false}),app=image({chip:0}),trailer=encode('EndF-preserve-this-original-app-trailer');
  const bytes=new Uint8Array(0xf000+app.length+trailer.length).fill(255);
  bytes.set(bootloader,0);bytes.set(dual(),0x7000);bytes.set(app,0xf000);bytes.set(trailer,0xf000+app.length);
  return {bytes,bootloader,app,trailer};
}
function session({chip=9,physical=dual()}={}) {
  const writes=[],reads=[],readbacks=[],s=new EspSession({getInfo:()=>({})},()=>{});
  s.mac='aa:bb:cc:dd:ee:ff';s.flashBytes=4<<20;
  s.loader={
    chip:{IMAGE_CHIP_ID:chip,CHIP_NAME:chip===0?'ESP32':'ESP32-S3',readMac:async()=>s.mac},
    readFlash:async(address,length)=>{reads.push([address,length]);return address===0x8000?physical:new Uint8Array(length).fill(255);},
    writeFlash:async options=>{writes.push(options);const data=options.fileArray[0].data;options.reportProgress?.(0,data.length,data.length);},
    flashMd5sum:async(address,length)=>{
      readbacks.push([address,length]);const write=writes.findLast(options=>options.fileArray[0].address===address);
      assert.ok(write,'Readback must follow the matching write');return md5hex(write.fileArray[0].data.subarray(0,length));
    },
  };
  return {s,writes,reads,readbacks};
}
const unused=()=>{throw Error('A merged/fitting custom file must not resolve migration artifacts');};

test('a provider can disable Keymind migration while fitting apps retain actual OTA offsets and readback',async()=>{
  const pkg=inspectFirmware('wadamesh.bin',image()),{s,writes}=session({physical:dual(0x30000,0x130000)});
  const plan=await s.prepare(pkg,{planner:{call:unused},resolveFirmwareName:unused,migrationDisabledReason:'Use the matching Wadamesh merged image.'});
  assert.deepEqual(plan.addresses,appWriteOrder(plan.parts,new Uint8Array(8192).fill(255)));assert.equal(plan.merged,false);
  await s.flash(pkg,()=>{});assert.equal(writes.length,2);assert.ok(writes.every(write=>write.eraseAll===false));
});
test('an oversized standalone app stops without a Keymind bridge or write when migration is disabled',async()=>{
  const pkg=inspectFirmware('wadamesh.bin',image({dataSize:0x100000})),{s,writes}=session();
  await assert.rejects(s.prepare(pkg,{planner:{call:unused},resolveFirmwareName:unused,migrationDisabledReason:'Wadamesh needs its own merged image.'}),/Wadamesh needs its own merged image/);
  assert.deepEqual(writes,[]);assert.equal(s.plan,null);
});

test('nonzero-origin merged writes preserve the entire input, mirror the exact app and erase only once',async()=>{
  const fixture=nonzeroMerged(),before=fixture.bytes.slice(),pkg=inspectFirmware('custom.bin',fixture.bytes);
  const {s,writes,reads,readbacks}=session({chip:0});
  const plan=await s.prepare(pkg,{planner:{call:unused},resolveFirmwareName:unused});
  assert.equal(plan.merged,true);assert.equal(plan.mirroredSlots,1);assert.deepEqual(plan.addresses,[0x1000,0x110000]);
  assert.equal(plan.segments[0].sourceOffset,0);assert.equal(plan.segments[1].sourceOffset,0xf000);
  assert.deepEqual(reads,[],'Merged table and OTA metadata come from the file, not the current layout');
  await s.flash(pkg,()=>{});
  assert.equal(writes.length,2);assert.equal(writes[0].fileArray[0].address,0x1000);
  assert.equal(writes[0].eraseAll,true);assert.equal(writes[1].eraseAll,false);
  assert.deepEqual(writes[0].fileArray[0].data,before);assert.equal(writes[0].fileArray[0].data.length,before.length);
  assert.deepEqual(writes[1].fileArray[0].data,before.subarray(0xf000));
  assert.deepEqual(readbacks,[[0x1000,before.length],[0x110000,before.length-0xf000]]);
  assert.equal(hash(pkg.payload),pkg.payloadHash);assert.equal(pkg.sha256,hash(before));assert.deepEqual(fixture.bytes,before);
});

test('silicon compatibility reads bootloader and app headers at file-relative positions but reports physical offsets',async()=>{
  const fixture=nonzeroMerged(),pkg=inspectFirmware('custom.bin',fixture.bytes),{s}=session({chip:0});
  const plan=await s.prepare(pkg),images=compatibilityImages(pkg,plan);
  assert.deepEqual(images.map(part=>part.offset),[0x1000,0x10000]);
  assert.deepEqual(images.map(part=>part.bootloader),[true,false]);
  assert.deepEqual(images[0].image.subarray(0,fixture.bootloader.length),fixture.bootloader);
  assert.deepEqual(images[1].image.subarray(0,fixture.app.length),fixture.app);
  assert.equal(images[1].image.length,fixture.app.length+fixture.trailer.length);
  assert.ok(images.every(part=>part.requirements.chipId===0));
});

test('a fitting custom app derives nonstandard write offsets from the actual partition and OTA metadata',async()=>{
  const physical=dual(0x30000,0x130000),pkg=inspectFirmware('my-app.bin',image()),{s,writes}=session({physical});
  const plan=await s.prepare(pkg,{resolveFirmwareName:unused});
  assert.equal(plan.merged,false);assert.deepEqual(plan.addresses,[0x130000,0x30000]);
  await s.flash(pkg,()=>{});
  assert.deepEqual(writes.map(write=>write.fileArray[0].address),[0x130000,0x30000]);
  assert.ok(writes.every(write=>write.eraseAll===false));
  assert.ok(writes.every(write=>hash(write.fileArray[0].data)===pkg.payloadHash));
});

test('a fitting custom app retains the shared planner without resolving an expansion release name',async()=>{
  const physical=dual(0x30000,0x130000),pkg=inspectFirmware('my-app.bin',image()),{s}=session({physical});
  let received;
  const planner={call:async(operation,data)=>{
    assert.equal(operation,'plan');received=data;
    return {needed:false,app_offsets:appWriteOrder(partitionTable(data.table),data.ota)};
  }};
  const plan=await s.prepare(pkg,{planner,resolveFirmwareName:unused});
  assert.equal(received.name,pkg.name);assert.equal(received.image,pkg.payload);
  assert.deepEqual(plan.addresses,[0x130000,0x30000]);
});

test('only an oversized custom app resolves a canonical release name and never transforms the application',async()=>{
  const physical=table([[0,0,0x40000,0x1000,'factory']]),pkg=inspectFirmware('my-renamed-app.bin',image({dataSize:8192}));
  const {s,writes}=session({physical}),canonical='Heltec_v3_repeater-full-usb-wifi-ota-v1.18.0.2.bin',source=pkg.payload.slice();
  let resolutions=0,received;
  const planner={call:async(operation,data)=>{
    assert.equal(operation,'plan');received=data;
    const bridge=image();return {needed:true,verified:false,bridge:Array.from(bridge),bridge_sha256:hash(bridge),app_offsets:[0x40000]};
  }};
  const plan=await s.prepare(pkg,{planner,resolveFirmwareName:async selected=>{assert.equal(selected,pkg);resolutions++;return canonical;}});
  assert.equal(resolutions,1);assert.equal(received.name,canonical);assert.equal(received.image,pkg.payload);
  assert.equal(plan.needed,true);assert.equal(pkg.name,'my-renamed-app.bin');assert.deepEqual(pkg.payload,source);
  assert.equal(pkg.payloadHash,hash(source));assert.equal(writes.length,0,'Preparation cannot erase or write');
});

test('an explicitly supplied expansion package skips automatic name resolution and is passed unchanged',async()=>{
  const physical=table([[0,0,0x40000,0x1000,'factory']]),pkg=inspectFirmware('custom.bin',image({dataSize:8192}));
  const {s,writes}=session({physical}),packageBytes=Uint8Array.of(1,2,3),usbSetBytes=Uint8Array.of(4,5,6);let received;
  const planner={call:async(operation,data)=>{
    assert.equal(operation,'plan');received=data;
    const bridge=image();return {needed:true,verified:false,bridge:Array.from(bridge),bridge_sha256:hash(bridge),app_offsets:[0x40000]};
  }};
  await s.prepare(pkg,{planner,packageBytes,usbSetBytes,resolveFirmwareName:unused});
  assert.equal(received.name,pkg.name);assert.equal(received.image,pkg.payload);
  assert.equal(received.package,packageBytes);assert.equal(received.usbSet,usbSetBytes);assert.equal(writes.length,0);
});

test('failed custom-image resolution stops before the planner or any physical write',async()=>{
  const physical=table([[0,0,0x40000,0x1000,'factory']]),pkg=inspectFirmware('custom.bin',image({dataSize:8192}));
  const {s,writes}=session({physical});let plannerCalls=0;
  await assert.rejects(s.prepare(pkg,{planner:{call:async()=>{plannerCalls++;throw Error('Unexpected planner call');}},resolveFirmwareName:async()=>{throw Error('No exact migration release matches the selected bytes');}}),/No exact migration release/);
  assert.equal(plannerCalls,0);assert.equal(writes.length,0);assert.equal(s.plan,null);
});
