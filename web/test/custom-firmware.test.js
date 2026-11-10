import {test} from 'node:test';
import assert from 'node:assert/strict';
import {hash,inspectFirmware,partitionTable,validateEspImage} from '../src/firmware.js';

const encode=value=>new TextEncoder().encode(value);
function image({chip=9,app=true,dataSize=16}={}) {
  const bytes=new Uint8Array(Math.ceil((32+dataSize+1)/16)*16),view=new DataView(bytes.buffer);
  bytes[0]=0xe9;bytes[1]=1;bytes[12]=chip;view.setUint32(28,dataSize,true);
  if(app)view.setUint32(32,0xabcd5432,true);
  return checksum(bytes);
}
function checksum(bytes) {
  const size=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength).getUint32(28,true);
  let checksum=0xef;for(const value of bytes.subarray(32,32+size))checksum^=value;
  bytes[Math.ceil((32+size+1)/16)*16-1]=checksum;
  return bytes;
}
function table() {
  const bytes=new Uint8Array(4096).fill(255),view=new DataView(bytes.buffer);
  for(const [index,type,subtype,offset,size,label] of [
    [0,1,2,0x9000,0x5000,'nvs'],[1,1,0,0xe000,0x2000,'otadata'],
    [2,0,0x10,0x10000,0x100000,'app0'],[3,0,0x11,0x110000,0x100000,'app1'],
  ]) {
    const at=index*32;bytes.fill(0,at,at+32);view.setUint16(at,0x50aa,true);
    bytes[at+2]=type;bytes[at+3]=subtype;view.setUint32(at+4,offset,true);
    view.setUint32(at+8,size,true);bytes.set(encode(label),at+12);
  }
  return bytes;
}
function merged({chip=9,origin=0}={}) {
  const app=image({chip}),bytes=new Uint8Array(0x10000+app.length-origin).fill(255);
  bytes.set(image({chip,app:false}),([0,2].includes(chip)?0x1000:0)-origin);
  bytes.set(table(),0x8000-origin);bytes.set(app,0x10000-origin);
  return bytes;
}

test('zero-origin merged images report their actual write and partition-table offsets',()=>{
  for(const chip of [0,2,5,9,13]) {
    const bytes=merged({chip}),before=bytes.slice(),pkg=inspectFirmware('custom.bin',bytes);
    assert.equal(pkg.kind,'Merged install');assert.equal(pkg.merged,true);assert.equal(pkg.expert,false);
    assert.equal(pkg.chipId,chip);assert.equal(pkg.flashOffset,0);assert.equal(pkg.partitionTableOffset,0x8000);
    assert.equal(pkg.payload,bytes);assert.equal(pkg.sha256,hash(before));assert.equal(pkg.payloadHash,hash(before));
    assert.deepEqual(bytes,before);assert.equal(partitionTable(bytes.subarray(pkg.partitionTableOffset,pkg.partitionTableOffset+4096))[2].offset,0x10000);
  }
});

test('classic ESP32 merged exports beginning at 0x1000 preserve original file bytes and hashes',()=>{
  for(const chip of [0,2]) {
    const bytes=merged({chip,origin:0x1000}),backing=new Uint8Array(bytes.length+17);
    backing.set(bytes,7);const selected=backing.subarray(7,7+bytes.length),before=selected.slice();
    const pkg=inspectFirmware('custom.bin',selected);
    assert.equal(pkg.merged,true);assert.equal(pkg.expert,false);assert.equal(pkg.chipId,chip);
    assert.equal(pkg.flashOffset,0x1000);assert.equal(pkg.partitionTableOffset,0x7000);
    assert.equal(pkg.payload,selected);assert.equal(pkg.payload.length,bytes.length);
    assert.equal(pkg.sha256,hash(before));assert.equal(pkg.payloadHash,hash(before));assert.deepEqual(selected,before);
    assert.equal(validateEspImage(pkg.payload.subarray(0x10000-pkg.flashOffset)),64);
  }
});

test('an application descriptor outranks an incidental partition signature inside program data',()=>{
  const bytes=image({dataSize:0xa000});bytes[0x8000]=0xaa;bytes[0x8001]=0x50;checksum(bytes);
  const pkg=inspectFirmware('application.bin',bytes);
  assert.equal(pkg.merged,false);assert.equal(pkg.expert,false);assert.equal(pkg.kind,'Application update');
  assert.equal(pkg.flashOffset,null);assert.equal(pkg.partitionTableOffset,null);assert.equal(pkg.payload,bytes);
});

test('an embedded valid partition-table resource does not turn an ordinary application into a merged install',()=>{
  const bytes=image({dataSize:0xa000});bytes.set(table(),0x8000);checksum(bytes);
  const pkg=inspectFirmware('ordinary.bin',bytes);
  assert.equal(pkg.merged,false);assert.equal(pkg.expert,false);assert.equal(pkg.destructive,false);
});

test('misleading merged and factory filenames never override validated application bytes',()=>{
  for(const name of ['firmware-merged.bin','factory.bin','firmware.factory.bin','full-install.bin']) {
    const bytes=image(),pkg=inspectFirmware(name,bytes);
    assert.equal(pkg.kind,'Application update');assert.equal(pkg.merged,false);assert.equal(pkg.expert,false);
    assert.equal(pkg.flashOffset,null);assert.equal(pkg.destructive,false);assert.equal(pkg.payload,bytes);
    assert.ok(pkg.warnings.some(warning=>/filename.*application-only/i.test(warning)),name);
    assert.ok(!pkg.warnings.some(warning=>/whole-chip erase/i.test(warning)),name);
  }
});

test('descriptor-free valid components remain expert-only without any guessed write offset',()=>{
  for(const chip of [0,2,5,9,13]) {
    const pkg=inspectFirmware('component.bin',image({chip,app:false}));
    assert.equal(pkg.expert,true);assert.equal(pkg.merged,false);assert.equal(pkg.destructive,true);
    assert.equal(pkg.flashOffset,null);assert.equal(pkg.partitionTableOffset,null);
    assert.ok(pkg.warnings.some(warning=>/exact flash offset/i.test(warning)));
  }
});

test('invalid table checksums and table bounds cannot be inferred into a merged write plan',()=>{
  for(const origin of [0,0x1000]) {
    const bytes=merged({chip:0,origin}),offset=0x8000-origin;
    new DataView(bytes.buffer).setUint32(offset+2*32+8,0xffffffff,true);
    assert.throws(()=>inspectFirmware('custom.bin',bytes),/Partition bounds/);
  }
});

test('wrong chip-specific bootloader origins and application images used as merged bootloaders are rejected',()=>{
  const classic=merged({chip:0});classic.set(image({chip:0,app:false}),0);
  assert.throws(()=>inspectFirmware('custom.bin',classic),/expected offset/);
  const notClassic=new Uint8Array(0xf040).fill(255);
  notClassic.set(image({chip:9,app:false}),0);notClassic.set(table(),0x7000);notClassic.set(image({chip:9}),0xf000);
  assert.throws(()=>inspectFirmware('custom.bin',notClassic),/expected offset/);
  const appBoot=merged({chip:0});appBoot.set(image({chip:0}),0x1000);
  assert.throws(()=>inspectFirmware('custom.bin',appBoot),/bootloader.*application descriptor/);
});

test('valid-looking descriptors and partition signatures never bypass image checksum validation',()=>{
  const bytes=image({dataSize:0xa000});bytes.set(table(),0x8000);checksum(bytes);bytes[40]^=1;
  assert.throws(()=>inspectFirmware('factory.bin',bytes),/checksum/);
  const broken=merged({chip:0,origin:0x1000});broken[40]^=1;
  assert.throws(()=>inspectFirmware('custom.bin',broken),/checksum/);
});
