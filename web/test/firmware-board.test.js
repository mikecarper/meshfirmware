import {test} from 'node:test';
import assert from 'node:assert/strict';
import {assessFirmwareBoard} from '../src/firmware-board.js';
import {hash,inspectFirmware} from '../src/firmware.js';

const encode=value=>new TextEncoder().encode(value);
const catalog=(hardware,architecture='nrf52',extra={})=>({project:'MeshCore',hardware,architecture,...extra});
const t1000='Seeed Studio SenseCAP T1000-E',xiao='Seeed Studio Xiao nRF52 WIO';
const v3='Heltec v3',v4='Heltec v4',wsl3='Heltec WSL3';
const rak4631='RAK WisBlock / WisMesh (RAK 4631)',rak3401='RAK WisMesh 1W Booster (3401 + 13302)';
const items=[catalog(t1000),catalog(xiao),catalog(rak4631),catalog(rak3401),catalog('Seeed Studio Wio WM1110'),catalog(v3,'esp32'),catalog(v4,'esp32'),catalog(wsl3,'esp32'),catalog('Heltec v4 R8','esp32')];
const targetFor=value=>Number.parseInt(hash(encode(value)).match(/../g).slice(0,4).reverse().join(''),16);
function body(chip=9){const bytes=new Uint8Array(64),view=new DataView(bytes.buffer);bytes.set([0xe9,1]);bytes[12]=chip;view.setUint32(28,16,true);view.setUint32(32,0xabcd5432,true);let crc=0xef;for(const byte of bytes.subarray(32,48))crc^=byte;bytes[63]=crc;return bytes;}
function endf(hardware,{target=1,chip=9}={}){
  const source=body(chip),bytes=new Uint8Array(source.length+56),view=new DataView(bytes.buffer);bytes.set(source);bytes.set(encode('EndF'),source.length);view.setUint32(source.length+4,source.length,true);bytes.set(Uint8Array.from(hash(source).slice(0,16).match(/../g),byte=>Number.parseInt(byte,16)),source.length+8);view.setUint32(source.length+16,0x01120002,true);view.setUint32(source.length+20,target,true);bytes.set(encode(hardware),source.length+24);return bytes;
}
function nrf(hardware,options={}){const payload=hardware?endf(hardware,options):new Uint8Array(128);return {name:'custom.zip',architecture:'nrf52',kind:'application',mode:4,payload,payloadHash:hash(payload),sha256:hash(payload),appSize:payload.length,sdSize:0,blSize:0};}
const device=(model,architecture='nrf52',extra={})=>({model,architecture,...extra});
function merged(identities){
  const table=new Uint8Array(4096).fill(255),bytes=new Uint8Array(0x20000+120).fill(255),view=new DataView(table.buffer),boot=body();new DataView(boot.buffer).setUint32(32,0,true);let crc=0xef;for(const byte of boot.subarray(32,48))crc^=byte;boot[63]=crc;bytes.set(boot);
  for(const [index,identity]of identities.entries()){const at=index*32,offset=0x10000+index*0x10000;table.fill(0,at,at+32);view.setUint16(at,0x50aa,true);view.setUint32(at+4,offset,true);view.setUint32(at+8,0x10000,true);table.set(encode('app'+index),at+12);table[at+3]=index;bytes.set(endf(identity.hardware,identity),offset);}
  bytes.set(table,0x8000);return inspectFirmware('custom.bin',bytes);
}

test('nRF52 byte identity matches an exact connected board without trusting the ZIP filename',()=>{
  const pkg=nrf('t1000e');pkg.name='wrong-rak3401-name.zip';
  const result=assessFirmwareBoard({pkg,hardware:t1000,device:device('Seeed Tracker T1000-E'),items});
  assert.equal(result.status,'match');assert.equal(result.requiresOverride,false);assert.equal(result.payloadHardware,'t1000e');
});
test('different nRF52 boards require an explicit overridable warning',()=>{
  const result=assessFirmwareBoard({pkg:nrf('t1000e'),hardware:xiao,device:device('Seeed Xiao-nrf52'),items});
  assert.equal(result.status,'mismatch');assert.equal(result.requiresOverride,true);assert.match(result.reason,/firmware identifies/i);
});
test('role changes on the same physical board do not become board mismatches',()=>{
  const pkg=nrf('t1000e');pkg.kind='application';pkg.name='t1000e_repeater.zip';
  assert.equal(assessFirmwareBoard({pkg,hardware:t1000,device:{...device('Seeed Tracker T1000-E'),role:'companion'},items}).status,'match');
});
test('legacy DFU metadata, caller identity metadata and filenames cannot prove a board',()=>{
  const pkg=nrf();pkg.name='t1000e_companion.zip';pkg.firmwareIdentity={hardware:'t1000e',proof:'endf'};pkg.boardIdentity={family:'rak4631',proof:'endf'};pkg.init=Uint8Array.of(0x52,0);
  const result=assessFirmwareBoard({pkg,hardware:t1000,device:device('Seeed Tracker T1000-E'),items});
  assert.equal(result.status,'unknown');assert.equal(result.requiresOverride,true);
});
test('known DFU USB IDs identify the architecture, not an exact nRF52 board',()=>{
  const result=assessFirmwareBoard({pkg:nrf('t1000e'),hardware:t1000,device:{usbInfo:{usbVendorId:0x2886,usbProductId:0x57}},items});
  assert.equal(result.status,'unknown');assert.equal(result.requiresOverride,true);
});
test('processor-family and verified silicon conflicts are reported without suppressing backend gates',()=>{
  const esp=inspectFirmware('custom.bin',endf('Heltec_v4'));
  for(const connected of [{usbInfo:{usbVendorId:0x239a,usbProductId:0x2a}},device('Heltec v4','esp32',{chipId:0})]){
    const result=assessFirmwareBoard({pkg:esp,device:connected,items});assert.equal(result.status,'mismatch');assert.equal(result.requiresOverride,true);
  }
});
test('V4 and V4 R8 remain different physical targets',()=>{
  const pkg=inspectFirmware('custom.bin',endf('Heltec_v4_r8'));
  const result=assessFirmwareBoard({pkg,hardware:v4,device:device('Heltec V4.2 none detected','esp32'),items});
  assert.equal(result.status,'mismatch');assert.equal(result.requiresOverride,true);
});
test('shared hardware tags stay ambiguous even when catalog filtering leaves one board',()=>{
  const pkg=inspectFirmware('custom.bin',endf('Heltec_v3'));
  const result=assessFirmwareBoard({pkg,hardware:v3,device:device('Heltec v3','esp32'),items:[catalog(v3,'esp32')]});
  assert.equal(result.status,'unknown');assert.equal(result.requiresOverride,true);assert.equal(result.payloadCandidates.length,2);
});
test('a byte-verified EndF target can identify an exact published environment without filename guesses',()=>{
  const environment='Heltec_v3_companion_radio_full',pkg=inspectFirmware('renamed.bin',endf('Heltec_v3',{target:targetFor(environment)}));
  const result=assessFirmwareBoard({pkg,hardware:v3,device:device('Heltec v3','esp32'),items:[...items,catalog(v3,'esp32',{releaseNotes:'EXACT TARGET - '+environment+'. Match exact hardware.'})]});
  assert.equal(result.status,'match');assert.equal(result.requiresOverride,false);
});
test('mixed-board merged apps warn even when the first image matches',()=>{
  const pkg=merged([{hardware:'Heltec_v4'},{hardware:'t1000e'}]);
  const result=assessFirmwareBoard({pkg,hardware:v4,device:device('Heltec v4','esp32'),items});
  assert.equal(result.status,'mismatch');assert.equal(result.proof,'conflicting-endf');
});
test('same-tag merged apps with disjoint exact build targets still produce a conflict',()=>{
  const first='Heltec_v3_companion_radio_full',second='Heltec_WSL3_repeater';
  const pkg=merged([{hardware:'Heltec_v3',target:targetFor(first)},{hardware:'Heltec_v3',target:targetFor(second)}]);
  const result=assessFirmwareBoard({pkg,hardware:v3,device:device('Heltec v3','esp32'),items:[...items,catalog(v3,'esp32',{releaseNotes:'EXACT TARGET - '+first+'.'}),catalog(wsl3,'esp32',{releaseNotes:'EXACT TARGET - '+second+'.'})]});
  assert.equal(result.status,'mismatch');assert.equal(result.proof,'conflicting-endf');
});
test('storage-specific RAK firmware is not claimed compatible from the core model alone',()=>{
  const result=assessFirmwareBoard({pkg:nrf('RAK4631_W25Q16'),hardware:rak4631,device:device('RAK 4631'),items});
  assert.equal(result.status,'unknown');assert.equal(result.requiresOverride,true);assert.match(result.reason,/specific storage/);
});
test('standalone manufacturer strings can identify old images, but build-target substrings cannot',()=>{
  const pkg=nrf();pkg.payload.set(encode('Seeed Tracker T1000-E'),4);pkg.payloadHash=hash(pkg.payload);
  assert.equal(assessFirmwareBoard({pkg,hardware:t1000,device:device('Seeed Tracker T1000-E'),items}).status,'match');
  const other=nrf();other.payload.set(encode('prefix_Seeed Tracker T1000-E_suffix'),4);other.payloadHash=hash(other.payload);
  assert.equal(assessFirmwareBoard({pkg:other,hardware:t1000,device:device('Seeed Tracker T1000-E'),items}).status,'unknown');
});
test('a mutated image cannot retain a previous matching assessment',()=>{
  const pkg=nrf('t1000e'),args={pkg,hardware:t1000,device:device('Seeed Tracker T1000-E'),items};
  assert.equal(assessFirmwareBoard(args).status,'match');pkg.payload[40]^=1;
  assert.equal(assessFirmwareBoard(args).status,'mismatch');assert.match(assessFirmwareBoard(args).reason,/changed after inspection/);
});
test('UF2 bootloader-drive processor contradictions warn, but drive labels never prove a match',()=>{
  const payload=new Uint8Array(128),pkg={architecture:'uf2',family:0xe48bff56,payload,payloadHash:hash(payload)};
  assert.equal(assessFirmwareBoard({pkg,plan:{uf2Info:{model:'Seeed T1000-E',boardId:'nRF52840-T1000-E-v1'}}}).status,'mismatch');
  assert.equal(assessFirmwareBoard({pkg,plan:{uf2Info:'UF2 Bootloader 0.9.2\nModel: Seeed T1000-E\nBoard-ID: nRF52840-T1000-E-v1\n'}}).status,'mismatch');
  const same=assessFirmwareBoard({pkg,plan:{uf2Info:{model:'Raspberry Pi Pico',boardId:'RPI-RP2040'}}});
  assert.equal(same.status,'unknown');assert.equal(same.requiresOverride,true);
  assert.equal(assessFirmwareBoard({pkg,plan:{uf2Info:'UF2 Bootloader 1.0.0\nModel: Raspberry Pi Pico\nBoard-ID: RPI-RP2040\n'}}).status,'unknown');
});
