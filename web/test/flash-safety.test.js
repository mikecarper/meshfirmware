import {test} from 'node:test';
import assert from 'node:assert/strict';
import {zipSync} from 'fflate';
import {checkedZip,hash,md5hex,crc16,inspectFirmware,nrfPackage,partitionTable,validateUf2,validateEspImage} from '../src/firmware.js';
import {flashNrf,hciPacket,parseAck,slipDecode} from '../src/serial.js';
import {EspSession,assertSecurity,stabilizeS3Jtag} from '../src/esp.js';

const encode=value=>new TextEncoder().encode(value);
const bytesFromHex=value=>Uint8Array.from(value.match(/../g),b=>parseInt(b,16));
function image({chip=9,app=true}={}) {
  const data=new Uint8Array(64),v=new DataView(data.buffer); data[0]=0xe9; data[1]=1; data[12]=chip; v.setUint32(28,16,true); if(app) v.setUint32(32,0xabcd5432,true);
  let checksum=0xef; for(const b of data.subarray(32,48)) checksum^=b; data[63]=checksum; return data;
}
function table({checksum=true}={}) {
  const data=new Uint8Array(4096).fill(255),v=new DataView(data.buffer);
  for(const [i,type,subtype,address,size,name] of [[0,1,2,0x9000,0x5000,'nvs'],[1,1,0,0xe000,0x2000,'otadata'],[2,0,0x10,0x10000,0x100000,'app0'],[3,0,0x11,0x110000,0x100000,'app1']]) {
    const at=i*32; data.fill(0,at,at+32); v.setUint16(at,0x50aa,true); data[at+2]=type; data[at+3]=subtype; v.setUint32(at+4,address,true); v.setUint32(at+8,size,true); data.set(encode(name),at+12);
  }
  if(checksum) { v.setUint16(128,0xebeb,true); data.set(bytesFromHex(md5hex(data.subarray(0,128))),144); } return data;
}
function merged({app=true,chip=9}={}) {
  const bytes=new Uint8Array(0x10000+64).fill(255); bytes.set(image({chip,app:false}),[0,2].includes(chip)?0x1000:0); bytes.set(table(),0x8000); if(app) bytes.set(image({chip}),0x10000); return bytes;
}
function session({chip=9}={}) {
  const calls=[],s=new EspSession({getInfo:()=>({}),setSignals:async signals=>calls.push({signals})},()=>{}); s.mac='aa:bb:cc:dd:ee:ff'; s.flashBytes=4<<20;
  s.loader={chip:{IMAGE_CHIP_ID:chip,readMac:async()=>s.mac},writeFlash:async o=>calls.push(o),flashMd5sum:async(_address,length)=>md5hex(calls.at(-1).fileArray[0].data.subarray(0,length)),after:async mode=>calls.push({reset:mode})}; return {s,calls};
}
function uf2() {
  const data=new Uint8Array(1024),v=new DataView(data.buffer);
  for(let i=0;i<2;i++) { const at=i*512; for(const [offset,value] of [[0,0x0a324655],[4,0x9e5d5157],[8,0x2000],[12,0x26000+i*256],[16,256],[20,i],[24,2],[28,0xada52840],[508,0x0ab16f30]]) v.setUint32(at+offset,value,true); }
  return data;
}
function dfu() {
  const payload=new Uint8Array(256),init=new Uint8Array(12),v=new DataView(init.buffer); v.setUint16(0,0x52,true); v.setUint16(10,crc16(payload),true);
  const files={'manifest.json':encode(JSON.stringify({manifest:{application:{bin_file:'a.bin',dat_file:'a.dat'}}})),'a.bin':payload,'a.dat':init}; return {files,bytes:zipSync(files)};
}
function centralOffset(bytes) { return new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength).getUint32(bytes.length-6,true); }

test('ZIP central/local method, flag, size, CRC and disk mismatches are rejected before extraction',()=>{
  const bytes=zipSync({'file':encode('safe payload')}), central=centralOffset(bytes);
  for(const [offset,byte] of [[8,1],[6,1],[14,1],[18,1],[central+34,1],[central+8,0x10]]) { const changed=bytes.slice(); changed[offset]^=byte; assert.throws(()=>checkedZip(changed)); }
});
test('ZIP unsafe prototype names and unsupported ZIP64 metadata cannot reach decompressor',()=>{
  const unsafe=zipSync({'name00000':encode('bad')}),unsafeCentral=centralOffset(unsafe); unsafe.set(encode('__proto__'),30); unsafe.set(encode('__proto__'),unsafeCentral+46); assert.throws(()=>checkedZip(unsafe),/unsafe/);
  const bytes=zipSync({'file':encode('x')}),central=centralOffset(bytes),v=new DataView(bytes.buffer); v.setUint32(central+24,0xffffffff,true); assert.throws(()=>checkedZip(bytes),/unsupported/);
});
test('ZIP release inventory can be inspected and only the selected bounded file expanded',()=>{
  const bytes=zipSync({'one.bin':new Uint8Array(128).fill(3),'two.bin':new Uint8Array(1024).fill(7)});
  assert.equal(checkedZip(bytes,{directoryOnly:true}).length,2);
  const selected=checkedZip(bytes,{select:name=>name==='one.bin'}); assert.deepEqual(Object.keys(selected),['one.bin']); assert.equal(selected['one.bin'][0],3);
});
test('DFU manifest types, components, and redundant DAT metadata must agree',()=>{
  const {files}=dfu();
  for(const manifest of [{constructor:{}},{application:{bin_file:3,dat_file:'a.dat'}},{application:{bin_file:'a.bin',dat_file:'a.dat',sd_size:0}},{application:{bin_file:'a.bin',dat_file:'a.dat',init_packet_data:{device_type:0xffff}}},{softdevice_bootloader:{bin_file:'a.bin',dat_file:'a.dat',sd_size:0,bl_size:256}}]) { files['manifest.json']=encode(JSON.stringify({manifest})); assert.throws(()=>nrfPackage('bad.zip',zipSync(files))); }
});
test('DFU bytes and component metadata are rechecked before touching serial signals',async()=>{
  for(const mutate of [p=>p.payload[0]^=1,p=>p.mode=2,p=>p.appSize=0]) {
    const pkg=nrfPackage('valid.zip',dfu().bytes); mutate(pkg); let touched=false;
    await assert.rejects(()=>flashNrf({port:{setSignals:async()=>{touched=true}}},pkg,()=>{}),/changed/); assert.equal(touched,false);
  }
});
test('legacy HCI header matches official browser DFU frame and validates length bounds',()=>{
  const packet=slipDecode(hciPacket(Uint8Array.from([3,0,0,0]),1).subarray(1,-1));
  assert.deepEqual([...packet.subarray(0,4)],[0xd1,0x4e,0,0xe1]); assert.throws(()=>hciPacket(new Uint8Array(4096),1),/length/);
  const ack=Uint8Array.from([0x50,0,0,0xb0,0,0]),crc=crc16(ack.subarray(0,4)); ack[4]=crc&255; ack[5]=crc>>>8; assert.equal(parseAck(ack),2); ack[4]^=1; assert.throws(()=>parseAck(ack),/CRC/);
});
test('partition MD5, padding, flags, labels and application alignment mirror the shared validator',()=>{
  assert.equal(partitionTable(table()).length,4);
  for(const mutate of [p=>p[144]^=1,p=>p[160]=0,p=>new DataView(p.buffer).setUint32(28,4,true),p=>p.set(encode('nvs\0'),32+12),p=>new DataView(p.buffer).setUint32(2*32+4,0x11000,true)]) {
    const bad=table({checksum:false}); mutate(bad); assert.throws(()=>partitionTable(bad));
  }
  const badMd5=table(); badMd5[145]^=1; assert.throws(()=>partitionTable(badMd5),/MD5/);
});
test('UF2 requires complete unique blocks, supported flags, one family and nonoverlapping aligned targets',()=>{
  assert.equal(validateUf2(uf2()),0xada52840);
  for(const [offset,value] of [[512+12,0x26000],[12,0xffffffff],[16,255],[512+20,0],[512+28,123],[8,0x6000],[24,3],[12,0x26001]]) { const bad=uf2(); new DataView(bad.buffer).setUint32(offset,value,true); assert.throws(()=>validateUf2(bad)); }
});
test('all registered nRF52 UF2 families require serial DFU ZIP rather than mounted-drive flashing',()=>{
  for(const family of [0x1b57745f,0x621e937a,0xada52840,0x820d9a5f,0x72721d4e,0x6f752678]) {
    const bytes=uf2(),v=new DataView(bytes.buffer);v.setUint32(28,family,true);v.setUint32(512+28,family,true);
    assert.equal(validateUf2(bytes),family);assert.throws(()=>inspectFirmware('nrf52.uf2',bytes),/serial DFU only.*ZIP/);
  }
  const rp2040=uf2(),v=new DataView(rp2040.buffer);v.setUint32(28,0xe48bff56,true);v.setUint32(512+28,0xe48bff56,true);assert.equal(inspectFirmware('pico.uf2',rp2040).architecture,'uf2');
});
test('ESP image appended digest flag and appended digest are validated',()=>{
  const bad=image(); bad[23]=2; assert.throws(()=>validateEspImage(bad),/header/);
  const data=new Uint8Array(96); data.set(image()); data[23]=1; data.set(bytesFromHex(hash(data.subarray(0,64))),64); assert.equal(validateEspImage(data),96); data[70]^=1; assert.throws(()=>validateEspImage(data),/SHA/);
});
test('validated ESP bootloader/component requires an explicit bounded expert offset, never guesses',async()=>{
  const {s}=session(),pkg=inspectFirmware('bootloader.bin',image({app:false})); assert.equal(pkg.expert,true); assert.equal(pkg.destructive,true);
  for(const expertOffset of [undefined,-1,1,4<<20]) await assert.rejects(()=>s.prepare(pkg,{expertOffset}),/explicit/);
  const plan=await s.prepare(pkg,{expertOffset:0}); assert.deepEqual(plan.addresses,[0]); assert.equal(plan.expert,true);
});
test('merged installation requires a valid boot-selected application and correct bootloader offset',async()=>{
  const {s}=session(); await assert.rejects(()=>s.prepare(inspectFirmware('full-merged.bin',merged({app:false}))),/boot-selected/);
  const valid=merged(); await s.prepare(inspectFirmware('full-merged.bin',valid));
  const wrongChip=merged(); wrongChip.set(image({chip:5}),0x10000); await assert.rejects(()=>s.prepare(inspectFirmware('full-merged.bin',wrongChip)),/identity/);
  const classic=merged({chip:0}); classic.set(image({chip:0,app:false}),0); assert.throws(()=>inspectFirmware('bad-merged.bin',classic),/expected offset/);
});
test('ESP write uses unmodified bytes, explicit erase only for merged, independent readback, and one reset',async()=>{
  const {s,calls}=session(),pkg=inspectFirmware('bootloader.bin',image({app:false})); await s.prepare(pkg,{expertOffset:0});
  await assert.rejects(()=>s.finish(false),/verified/); await s.flash(pkg,()=>{});
  assert.equal(calls[0].eraseAll,false); assert.equal(calls[0].flashMode,'keep'); assert.deepEqual(calls[0].fileArray[0].data,pkg.payload);
  await s.finish(false); assert.deepEqual(calls.slice(-2),[{signals:{dataTerminalReady:false,requestToSend:true}},{signals:{dataTerminalReady:false,requestToSend:false}}]); await assert.rejects(()=>s.finish(false),/once/);
  const full=session(); const mergedPkg=inspectFirmware('full-merged.bin',merged()); await full.s.prepare(mergedPkg); await full.s.flash(mergedPkg,()=>{}); assert.equal(full.calls[0].eraseAll,true);
});
test('ESP failed readback blocks reset and changed plan cannot cause a write',async()=>{
  const {s,calls}=session(),pkg=inspectFirmware('bootloader.bin',image({app:false})); await s.prepare(pkg,{expertOffset:0});
  s.plan.addresses=[0x9000]; await assert.rejects(()=>s.flash(pkg,()=>{}),/plan changed/); assert.equal(calls.length,0);
  await s.prepare(pkg,{expertOffset:0}); s.loader.flashMd5sum=async()=> '0'.repeat(32); await assert.rejects(()=>s.flash(pkg,()=>{}),/MD5/); await assert.rejects(()=>s.finish(false),/verified/);
});
test('ESP security responses fail closed when missing and reject secure flags on C6 before stub',async()=>{
  await assert.rejects(()=>assertSecurity({chip:{IMAGE_CHIP_ID:13},getSecurityInfo:async()=>({parsedFlags:{},flashCryptCnt:0})}),/could not be verified/);
  for(const flags of [{SECURE_BOOT_EN:true,SECURE_DOWNLOAD_ENABLE:false},{SECURE_BOOT_EN:false,SECURE_DOWNLOAD_ENABLE:true}]) await assert.rejects(()=>assertSecurity({chip:{IMAGE_CHIP_ID:13},getSecurityInfo:async()=>({parsedFlags:flags,flashCryptCnt:0})}),/Secure boot/);
  let stub=false; const {s}=session({chip:13}); s.loader={detectChip:async()=>{},chip:{IMAGE_CHIP_ID:13},getSecurityInfo:async()=>({parsedFlags:{SECURE_BOOT_EN:true,SECURE_DOWNLOAD_ENABLE:false},flashCryptCnt:0}),runStub:async()=>{stub=true}}; await assert.rejects(()=>s.connect('no_reset'),/Secure boot/); assert.equal(stub,false);
});
function recovery() {
  const {s,calls}=session(),pkg=inspectFirmware('app.bin',image()),bridge=image(),sourceTable=table(),readbacks=[];
  s.connectMode='no_reset'; s.loader.readFlash=async(address,length)=>{assert.equal(address,0x8000);assert.equal(length,4096);return sourceTable;};
  s.loader.flashMd5sum=async(address,length)=>{readbacks.push([address,length]);return md5hex(bridge);};
  const result={format:'meshcore-usb-partition-expansion-v2',needed:true,started:true,completed:false,verified:false,usb_safe:true,device_mac:s.mac.replace(/:/g,'').toUpperCase(),firmware_sha256:pkg.sha256,chip:9,flash_bytes:s.flashBytes,source_table_sha256:hash(sourceTable),bridge_bytes:bridge.length,bridge_sha256:hash(bridge),bridge_offsets:[0x110000,0x10000],bridge:Array.from(bridge)};
  const planner={call:async(op,data)=>{assert.equal(op,'resumeBridge');assert.equal(data.sha256,pkg.sha256);assert.deepEqual(data.image,pkg.payload);return result;}};
  return {s,calls,pkg,result,sourceTable,readbacks,planner};
}
test('recovery grants one bridge start only after exact cached plan, original table and every bridge slot readback',async()=>{
  const {s,calls,pkg,planner,readbacks}=recovery(); const recovered=await s.recoverBridge(pkg,{planner});
  assert.equal(recovered.written,true);assert.equal(recovered.recovered,true);assert.deepEqual(readbacks,[[0x110000,64],[0x10000,64]]);assert.equal(calls.length,0);
  await s.finish(false);assert.equal(calls.length,2);assert.deepEqual(calls[0].signals,{dataTerminalReady:false,requestToSend:true});assert.deepEqual(calls[1].signals,{dataTerminalReady:false,requestToSend:false});await assert.rejects(()=>s.finish(false),/once/);
});
test('bridge recovery refuses changed physical layout, partial readback, altered plan and resetting connect modes',async()=>{
  for(const change of [r=>r.sourceTable[12]^=1,r=>r.s.loader.flashMd5sum=async address=>address===0x10000?'0'.repeat(32):md5hex(Uint8Array.from(r.result.bridge)),r=>r.result.device_mac='000000000000',r=>r.result.completed=true,r=>r.result.bridge_offsets=[0x9000],r=>r.result.bridge[0]^=1,r=>r.s.connectMode='default_reset']) {
    const r=recovery();change(r);await assert.rejects(()=>r.s.recoverBridge(r.pkg,{planner:r.planner}));assert.equal(r.calls.length,0);await assert.rejects(()=>r.s.finish(false),/verified/);
  }
});
test('native S3 final reset uses guarded watchdog sequence and never retries an uncertain reset',async()=>{
  const {s}=session(),pkg=inspectFirmware('bootloader.bin',image({app:false})),writes=[]; await s.prepare(pkg,{expertOffset:0});await s.flash(pkg,()=>{});
  s.loader.writeReg=async(...args)=>{writes.push(args);if(args[0]===0x60008098) throw new Error('USB disconnected during watchdog reset');};
  await assert.rejects(()=>s.finish(true),/USB disconnected/);assert.deepEqual(writes,[[0x6000812c,0,1],[0x600080b0,0x50d83aa1],[0x6000809c,2000],[0x60008098,0xd0000102]]);await assert.rejects(()=>s.finish(true),/once/);assert.equal(writes.length,4);
});
test('S3 flash-session watchdog changes use verified ROM channel, not a shared USB product ID',async()=>{
  const writes=[],loader={chip:{IMAGE_CHIP_ID:9},readReg:async address=>address===0x3fcef14c?4:0x12345678,writeReg:async(...args)=>writes.push(args)};
  await stabilizeS3Jtag(loader);assert.deepEqual(writes,[[0x600080b0,0x50d83aa1],[0x60008098,0],[0x600080b0,0],[0x600080b8,0x8f1d312a],[0x600080b4,0x92345678],[0x600080b8,0]]);
  for(const chip of [0,2,5,13]) await stabilizeS3Jtag({chip:{IMAGE_CHIP_ID:chip},readReg:async()=>{throw new Error('wrong chip register read');}});
  for(const channel of [0,1,2,3]) await stabilizeS3Jtag({chip:{IMAGE_CHIP_ID:9},readReg:async()=>channel,writeReg:async()=>{throw new Error('not JTAG');}});
});
