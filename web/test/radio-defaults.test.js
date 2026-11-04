import { test } from 'node:test';
import assert from 'node:assert/strict';
import { zipSync } from 'fflate';
import { checkedZip, crc16, crc32, hash, inspectFirmware, text, validateEspImage } from '../src/firmware.js';
import { endfIdentity } from '../src/board-safety.js';
import { inspectRadioDefaults, customizeRadioDefaults } from '../src/radio-defaults.js';

const encode=value=>new TextEncoder().encode(value),v=bytes=>new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);
const defaults={enabled:true,frequencyHz:910525000,bandwidthHz:250000,spreadingFactor:8,codingRate:5,preambleSymbols:32,txPowerDbm:null};
const disabled={enabled:false,frequencyHz:0,bandwidthHz:0,spreadingFactor:0,codingRate:0,preambleSymbols:0,txPowerDbm:null};
const hex=value=>Uint8Array.from(value.match(/../g),pair=>parseInt(pair,16));
function block(){const bytes=new Uint8Array(64);bytes.set(encode('MCRDEFAULTS0001\0'));v(bytes).setUint16(16,1,true);v(bytes).setUint16(18,64,true);fixBlock(bytes);return bytes;}
function fixBlock(bytes){v(bytes).setUint32(60,crc32(bytes.subarray(0,60)),true);}
function footer(body){const bytes=new Uint8Array(body.length+56),d=v(bytes),at=body.length;bytes.set(body);bytes.set(encode('EndF'),at);d.setUint32(at+4,at,true);bytes.set(hex(hash(body).slice(0,16)),at+8);d.setUint32(at+16,0x01120002,true);d.setUint32(at+20,0x1234,true);bytes.set(encode('RAK_3401'),at+24);return bytes;}
function nrf({kind='application',metadata=true,endf=true,marker=block(),markerAt=128,name='firmware.bin',extra={}}={}){
  let payload=new Uint8Array(512).fill(7);if(marker)payload.set(marker,markerAt);if(endf)payload=footer(payload);
  const init=new Uint8Array(14),d=v(init);d.setUint16(0,0x52,true);d.setUint16(2,0xffff,true);d.setUint32(4,0xffffffff,true);d.setUint16(8,1,true);d.setUint16(10,0x123,true);d.setUint16(12,crc16(payload),true);
  const entry={bin_file:name,dat_file:'firmware.dat',...extra};if(metadata)entry.init_packet_data={device_type:0x52,device_revision:0xffff,application_version:0xffffffff,softdevice_req:[0x123],firmware_crc16:crc16(payload)};
  if(kind==='softdevice_bootloader')Object.assign(entry,{sd_size:256,bl_size:payload.length-256});
  const manifest={manifest:{dfu_version:.5,[kind]:entry}},files={'manifest.json':encode(JSON.stringify(manifest)),[name]:payload,'firmware.dat':init};
  return {bytes:zipSync(files),files,payload,init,manifest,offset:markerAt};
}
function repack(fixture,mutate){const files=checkedZip(fixture.bytes),manifest=JSON.parse(text(files['manifest.json']));mutate(files,manifest);const entry=manifest.manifest[Object.keys(manifest.manifest).find(key=>key!=='dfu_version')],payload=files[entry.bin_file],init=files[entry.dat_file],d=v(init),at=10+d.getUint16(8,true)*2,crc=crc16(payload);d.setUint16(at,crc,true);if(entry.init_packet_data?.firmware_crc16!=null)entry.init_packet_data.firmware_crc16=crc;files['manifest.json']=encode(JSON.stringify(manifest));return zipSync(files);}
function image({marker=block(),markerOffset=64,app=true,sha=true,endf=true,chip=9,split=false,embedded=null}={}){
  const body=new Uint8Array(224).fill(3);if(app)v(body).setUint32(0,0xabcd5432,true);if(marker)body.set(marker,markerOffset);
  if(embedded)body.set(embedded,150);
  const segments=split?[body.subarray(0,96),body.subarray(96)]:[body];let length=24+segments.reduce((n,b)=>n+8+b.length,0),check=Math.ceil((length+1)/16)*16-1;
  let bytes=new Uint8Array(check+1+(sha?32:0)),d=v(bytes);bytes[0]=0xe9;bytes[1]=segments.length;d.setUint16(12,chip,true);bytes[23]=+sha;let at=24,checksum=0xef;
  for(const segment of segments){d.setUint32(at,0x3c000000,true);d.setUint32(at+4,segment.length,true);bytes.set(segment,at+8);for(const byte of segment)checksum^=byte;at+=8+segment.length;}
  bytes[check]=checksum;if(sha)bytes.set(hex(hash(bytes.subarray(0,check+1))),check+1);if(endf)bytes=footer(bytes);return bytes;
}
function table(){const bytes=new Uint8Array(4096).fill(255),d=v(bytes);for(const [index,type,subtype,offset,size,label] of [[0,1,2,0x9000,0x7000,'nvs'],[1,0,0x10,0x10000,0x10000,'app0'],[2,0,0x11,0x20000,0x10000,'app1']]){const at=index*32;d.setUint16(at,0x50aa,true);bytes[at+2]=type;bytes[at+3]=subtype;d.setUint32(at+4,offset,true);d.setUint32(at+8,size,true);bytes.fill(0,at+12,at+32);bytes.set(encode(label),at+12);}return bytes;}
function merged({app=image(),boot=image({app:false,marker:null,endf:false}),pad=0}={}){const bytes=new Uint8Array(0x10000+app.length+pad).fill(255);bytes.set(boot,0);bytes.set(table(),0x8000);bytes[0x9000]=42;bytes.set(app,0x10000);return bytes;}
function unsupported(name,bytes,pattern){const inspected=inspectRadioDefaults(name,bytes);assert.equal(inspected.supported,false);assert.equal(inspected.settings,null);assert.match(inspected.reason,pattern);assert.throws(()=>customizeRadioDefaults(name,bytes,defaults),pattern);}

test('the canonical disabled block matches the firmware ABI initializer byte-for-byte',()=>{
  const bytes=block();assert.equal(bytes.length,64);assert.deepEqual(bytes.subarray(0,16),encode('MCRDEFAULTS0001\0'));assert.deepEqual([...bytes.subarray(16,20)],[1,0,64,0]);assert.ok(bytes.subarray(20,60).every(byte=>byte===0));assert.deepEqual([...bytes.subarray(60)],[0xa6,0x73,0x37,0x89]);
});
test('nRF52 disabled ABI template is inspected and a new full ZIP repairs DAT, manifest, ZIP and EndF integrity without input mutation',()=>{
  const original=nrf(),snapshot=original.bytes.slice(),settings={...defaults,txPowerDbm:-9},settingsBefore={...settings};
  assert.deepEqual(inspectRadioDefaults('RAK_3401_companion_radio_full.zip',original.bytes).settings,disabled);
  const result=customizeRadioDefaults('RAK_3401_companion_radio_full.zip',original.bytes,settings,{expectedSourceSha256:hash(original.bytes)}),pkg=inspectFirmware('RAK_3401_companion_radio_full.zip',result.bytes),files=checkedZip(result.bytes);
  assert.deepEqual(original.bytes,snapshot);assert.deepEqual(settings,settingsBefore);assert.notEqual(result.bytes,original.bytes);assert.notEqual(result.sha256,result.sourceSha256);assert.equal(result.changed,true);assert.equal(result.sourceSha256,hash(snapshot));assert.equal(result.sha256,hash(result.bytes));assert.equal(result.provenance.sourceSha256,result.sourceSha256);assert.deepEqual(inspectRadioDefaults('RAK_3401_companion_radio_full.zip',result.bytes).settings,settings);
  assert.equal(v(files['firmware.dat']).getUint16(12,true),crc16(pkg.payload));assert.equal(JSON.parse(text(files['manifest.json'])).manifest.application.init_packet_data.firmware_crc16,crc16(pkg.payload));
  assert.deepEqual(endfIdentity(pkg.payload),endfIdentity(original.payload));assert.deepEqual(pkg.payload.subarray(0,128),original.payload.subarray(0,128));assert.deepEqual(pkg.payload.subarray(192,-48),original.payload.subarray(192,-48));
  assert.deepEqual(Object.keys(files).sort(),['firmware.bin','firmware.dat','manifest.json']);
});
test('nRF52 minimal manifests without CRC metadata remain minimal and DAT requirements are unchanged',()=>{
  const original=nrf({metadata:false,endf:false}),result=customizeRadioDefaults('app.zip',original.bytes,defaults),files=checkedZip(result.bytes);assert.equal(JSON.parse(text(files['manifest.json'])).manifest.application.init_packet_data,undefined);assert.deepEqual(files['firmware.dat'].subarray(0,12),original.init.subarray(0,12));assert.deepEqual(inspectRadioDefaults('app.zip',result.bytes).settings,defaults);
});
for(const sha of [false,true])test(`ESP32 app BIN with appended SHA=${sha} repairs XOR, SHA, EndF and preserves all other bytes`,()=>{
  const original=image({sha}),snapshot=original.slice(),result=customizeRadioDefaults('app.bin',original,defaults),length=validateEspImage(result.bytes);assert.deepEqual(original,snapshot);assert.equal(length,validateEspImage(original));assert.equal(result.bytes.length,original.length);assert.equal(result.changed,true);assert.deepEqual(endfIdentity(result.bytes),endfIdentity(original));assert.deepEqual(inspectRadioDefaults('app.bin',result.bytes).settings,defaults);assert.equal(inspectFirmware('app.bin',result.bytes).expert,false);assert.deepEqual(result.bytes.subarray(0,96),original.subarray(0,96));
});
test('merged ESP32 BIN changes only one application block and its integrity fields; bootloader, table, other partitions and padding remain exact',()=>{
  const original=merged({pad:128}),snapshot=original.slice(),result=customizeRadioDefaults('board-merged.bin',original,{...defaults,txPowerDbm:40,preambleSymbols:65528});assert.deepEqual(original,snapshot);assert.deepEqual(result.bytes.subarray(0,0x10000),original.subarray(0,0x10000));assert.deepEqual(result.bytes.subarray(-128),original.subarray(-128));assert.equal(inspectFirmware('board-merged.bin',result.bytes).merged,true);assert.deepEqual(endfIdentity(result.bytes.subarray(0x10000,-128)),endfIdentity(image()));assert.equal(inspectRadioDefaults('board-merged.bin',result.bytes).settings.txPowerDbm,40);
});
test('Uint8Array views and Buffer inputs never mutate their shared backing allocation',()=>{
  const original=Buffer.from(image()),before=Uint8Array.from(original);customizeRadioDefaults('app.bin',original,defaults);assert.deepEqual(Uint8Array.from(original),before);
  const raw=image(),backing=new Uint8Array(raw.length+32).fill(99);backing.set(raw,16);const selected=backing.subarray(16,-16),snapshot=backing.slice();customizeRadioDefaults('app.bin',selected,defaults);assert.deepEqual(backing,snapshot);
});
test('no-op and disabling edits return independent full bytes, truthful changed flags, and source provenance',()=>{
  const bytes=image(),noop=customizeRadioDefaults('app.bin',bytes,{enabled:false});assert.equal(noop.changed,false);assert.equal(noop.sha256,noop.sourceSha256);assert.notEqual(noop.bytes,bytes);assert.deepEqual(noop.bytes,bytes);
  const customized=customizeRadioDefaults('app.bin',bytes,defaults),reset=customizeRadioDefaults('app.bin',customized.bytes,{enabled:false});assert.equal(reset.changed,true);assert.deepEqual(reset.bytes,bytes);assert.deepEqual(reset.settings,disabled);
});
test('stale source hashes and invalid editor fields fail before returning a changed image',()=>{
  const bytes=image(),snapshot=bytes.slice();for(const expectedSourceSha256 of ['00'.repeat(32),'bad',null])assert.throws(()=>customizeRadioDefaults('app.bin',bytes,defaults,{expectedSourceSha256}),/source firmware changed/);
  for(const settings of [null,{},[],{...defaults,enabled:1},{...defaults,frequencyHz:149999999},{...defaults,frequencyHz:2500000001},{...defaults,frequencyHz:910525000.5},{...defaults,bandwidthHz:125001},{...defaults,spreadingFactor:4},{...defaults,spreadingFactor:13},{...defaults,codingRate:4},{...defaults,codingRate:9},{...defaults,preambleSymbols:7},{...defaults,preambleSymbols:65529},{...defaults,txPowerDbm:-10},{...defaults,txPowerDbm:41},{...defaults,txPowerDbm:NaN},{...defaults,invented:1},{...defaults,enabled:false}])assert.throws(()=>customizeRadioDefaults('app.bin',bytes,settings));assert.deepEqual(bytes,snapshot);
  for(const frequencyHz of [150000000,2500000000])assert.equal(customizeRadioDefaults('app.bin',bytes,{...defaults,frequencyHz}).settings.frequencyHz,frequencyHz);
  for(const bandwidthHz of [7800,10400,15600,20800,31250,41700,62500,125000,250000,500000])assert.equal(customizeRadioDefaults('app.bin',bytes,{...defaults,bandwidthHz}).settings.bandwidthHz,bandwidthHz);
});
test('no marker, duplicate marker and truncated marker are unsupported without changing normal firmware inspection',()=>{
  const no=nrf({marker:null});assert.equal(inspectFirmware('app.zip',no.bytes).kind,'application');unsupported('app.zip',no.bytes,/no editable defaults block/);
  const oldFooter=repack(no,files=>files['firmware.bin'][files['firmware.bin'].length-48]^=1);unsupported('app.zip',oldFooter,/no editable defaults block/);
  unsupported('app.zip',repack(nrf({endf:false}),(files)=>files['firmware.bin'].set(block(),300)),/Duplicate/);
  const truncated=nrf({endf:false,marker:null});unsupported('app.zip',repack(truncated,files=>files['firmware.bin'].set(encode('MCRDEFAULTS'),500)),/truncated/);
});
test('unknown ABI, noncanonical flags, reserved fields, bad CRC and disabled nonzero data are rejected',()=>{
  const cases=[b=>b[14]=50,b=>v(b).setUint16(16,2,true),b=>v(b).setUint16(18,63,true),b=>v(b).setUint32(20,4,true),b=>v(b).setUint32(20,2,true),b=>b[35]=1,b=>b[40]=1,b=>b[34]=1,b=>v(b).setUint32(24,150000000,true)];
  for(const mutate of cases){const b=block();mutate(b);fixBlock(b);unsupported('app.zip',nrf({marker:b}).bytes,/version|flags|reserved|TX|Disabled/);}
  const b=block();b[63]^=1;unsupported('app.zip',nrf({marker:b}).bytes,/CRC/);
  const enabled=block();v(enabled).setUint32(20,1,true);fixBlock(enabled);unsupported('app.zip',nrf({marker:enabled}).bytes,/frequency/);
});
test('components, signed metadata, destructive utilities and embedded-bootloader wrappers cannot be edited',()=>{
  for(const kind of ['bootloader','softdevice','softdevice_bootloader'])unsupported('app.zip',nrf({kind}).bytes,/ordinary/);
  for(const name of ['with-bootloader-2.4.12-full.zip','R_rak3401.zip','board-erase.zip','board-mota.bin','board-signed.zip','expert.bin'])unsupported(name,name.endsWith('.bin')?image():nrf().bytes,/cannot customize/);
  for(const extra of [{signature:'abc'},{signed:false},{bootloader_version:'2.4.12'}])unsupported('app.zip',nrf({extra}).bytes,/Signed|embedded/);
  unsupported('app.zip',nrf({name:'board-with-bootloader.bin'}).bytes,/Component/);
  unsupported('boot.bin',image({app:false}),/Bootloader|expert/);
});
test('embedded framed mOTA containers refuse renamed nRF52/ESP32 applications independently of filenames and manifest properties',()=>{
  const mota=new Uint8Array(32);mota.set(encode('mOTA'));v(mota).setUint32(4,mota.length,true);mota[8]=3;mota[9]=7;mota.set(encode('vk496'),mota.length-5);
  unsupported('ordinary.zip',repack(nrf({endf:false}),files=>files['firmware.bin'].set(mota,300)),/Embedded mOTA/);
  unsupported('ordinary.bin',image({embedded:mota}),/Embedded mOTA/);
  const unframed=mota.slice();unframed[unframed.length-1]^=1;assert.equal(inspectRadioDefaults('ordinary.bin',image({embedded:unframed})).supported,true);
});
test('corrupt original firmware ZIP/DAT/ESP image and invalid original EndF identities refuse customization',()=>{
  const bad=nrf().bytes.slice();bad[45]^=1;unsupported('app.zip',bad,/ZIP|integrity|invalid|CRC/i);
  const app=image();app[40]^=1;unsupported('app.bin',app,/checksum|SHA/);
  unsupported('app.zip',repack(nrf(),files=>files['firmware.bin'][files['firmware.bin'].length-48]^=1),/EndF/);
  const badFooter=image();badFooter[badFooter.length-48]^=1;unsupported('app.bin',badFooter,/EndF/);
});
test('signed and unexpected ESP trailers are refused; padding-only trailers remain supported',()=>{
  for(const bytes of [new Uint8Array([...image({endf:false}),0xe7,2,3]),new Uint8Array([...image(),0xe7,2,3]),merged({boot:new Uint8Array([...image({app:false,marker:null,endf:false}),0xe7,2])})])unsupported('app.bin',bytes,/Signed|nonpadding/);
  assert.equal(inspectRadioDefaults('app.bin',new Uint8Array([...image(),0,255,0,255])).supported,true);
});
test('ESP marker in bootloader, partition data, padding, split across segments, or duplicate image is never edited',()=>{
  unsupported('board-merged.bin',merged({app:image({marker:null}),boot:image({app:false,endf:false})}),/not inside/);
  const inNvs=merged({app:image({marker:null})});inNvs.set(block(),0x9200);unsupported('board-merged.bin',inNvs,/not inside/);
  const inPadding=new Uint8Array([...image({marker:null,endf:false}),...block()]);unsupported('app.bin',inPadding,/nonpadding/);
  unsupported('app.bin',image({split:true}),/outside/);
  const twice=merged({pad:0x10000});twice.set(image(),0x20000);unsupported('board-merged.bin',twice,/Duplicate/);
});
test('merged application identity mismatch, encrypted app and malformed partition table are refused',()=>{
  unsupported('board-merged.bin',merged({app:image({chip:5})}),/chip identities/);
  const encrypted=merged();v(encrypted).setUint32(0x8000+32+28,1,true);unsupported('board-merged.bin',encrypted,/Encrypted/);
  const damaged=merged();damaged[0x8000+6]^=1;unsupported('board-merged.bin',damaged,/Partition/);
  const other=merged({pad:0x10000});other.set(image({marker:null}),0x20000);unsupported('board-merged.bin',other,/Multiple populated/);
});
