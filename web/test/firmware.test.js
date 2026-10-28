import { test } from 'node:test';
import assert from 'node:assert/strict';
import { zipSync } from 'fflate';
import { crc16, crc32, checkedZip, inspectFirmware, nrfPackage, partitionTable, activeOta, hash, words, validateEspImage } from '../src/firmware.js';
import { slipEncode, slipDecode, hciPacket, parseAck } from '../src/serial.js';
import { sealBackup, verifyBackup, publicFromPrivate } from '../src/meshcore.js';
import { catalogItems, httpsUrl } from '../src/catalog.js';
import { EspSession, assertSecurity } from '../src/esp.js';

const encode = value => new TextEncoder().encode(value);
function nrfZip(kind = 'application') {
  const payload = new Uint8Array(256).fill(7), init = new Uint8Array(12), view = new DataView(init.buffer);
  view.setUint16(0,0x52,true); view.setUint16(10,crc16(payload),true);
  const entry = {bin_file:'firmware.bin',dat_file:'firmware.dat'};
  if (kind === 'softdevice_bootloader') Object.assign(entry,{sd_size:128,bl_size:128});
  return { bytes:zipSync({'manifest.json':encode(JSON.stringify({manifest:{dfu_version:.5,[kind]:entry}})),'firmware.bin':payload,'firmware.dat':init}),payload,init };
}
function espImage(chip = 9) {
  const data = new Uint8Array(80), v = new DataView(data.buffer); data[0] = 0xe9; data[1] = 1; data[12] = chip; v.setUint32(28,16,true); v.setUint32(32,0xabcd5432,true); let crc = .0 + 0xef; for (const b of data.subarray(32,48)) crc ^= b; data[63] = crc; return data.subarray(0,64);
}
function table() {
  const data = new Uint8Array(4096).fill(255), view = new DataView(data.buffer);
  for (const [i,type,subtype,offset,size] of [[0,1,2,0x9000,0x5000],[1,1,0,0xe000,0x2000],[2,0,0x10,0x10000,0x100000],[3,0,0x11,0x110000,0x100000]]) { const at = i * 32; view.setUint16(at,0x50aa,true); data[at+2] = type; data[at+3] = subtype; view.setUint32(at+4,offset,true); view.setUint32(at+8,size,true); data.fill(0,at+12,at+32); data.set(encode(`part${i}`),at+12); }
  return data;
}
test('CRC known vectors and Python zlib CRC initial value',() => { assert.equal(crc16(encode('123456789')),0x29b1); assert.equal(crc32(encode('123456789')),0xcbf43926); assert.equal(crc32(words(1),0xffffffff),0x4743989a); });
test('nRF52 catalog offers only serial DFU ZIPs, never mounted-drive UF2 images',()=>{
  const config={device:[{name:'RAK',type:'nrf52',firmware:[{role:'companion',version:{v1:{files:[{type:'flash',name:'rak.zip'},{type:'download',name:'rak.uf2'}]}}}]}]};
  assert.deepEqual(catalogItems(config).map(item=>item.name),['rak.zip']);
});
for (const kind of ['application','bootloader','softdevice','softdevice_bootloader']) test(`legacy DFU ${kind} validated without transforming bytes`,() => { const fixture = nrfZip(kind), p = nrfPackage('board.zip',fixture.bytes); assert.equal(p.kind,kind); assert.deepEqual(p.payload,fixture.payload); assert.deepEqual(p.init,fixture.init); assert.equal(p.payloadHash,hash(fixture.payload)); });
test('ZIP traversal, duplicate directory, CRC damage, size limits and truncation refused',() => {
  assert.throws(() => checkedZip(zipSync({'../bad':encode('x')})),/unsafe/);
  assert.throws(() => checkedZip(zipSync({'large':new Uint8Array(10000)}),{maxExpanded:100}),/expands/);
  const bytes = nrfZip().bytes; assert.throws(() => checkedZip(bytes.subarray(0,bytes.length-1)),/directory/);
  const damaged = bytes.slice(); damaged[40] ^= 1; assert.throws(() => checkedZip(damaged));
});
test('DFU mismatch and secure/mixed manifests refused',() => {
  const f = nrfZip(), files = checkedZip(f.bytes); files['firmware.bin'][0] ^= 1;
  assert.throws(() => nrfPackage('bad.zip',zipSync(files)),/CRC/);
  files['manifest.json'] = encode(JSON.stringify({manifest:{application:{},bootloader:{}}})); assert.throws(() => nrfPackage('bad.zip',zipSync(files)),/exactly one/);
});
test('SLIP round-trip, HCI header checksum, ACK checksum/CRC bounds',() => {
  const payload = Uint8Array.from([0xc0,0xdb,0,255]); assert.deepEqual(slipDecode(slipEncode(payload).subarray(1,-1)),payload);
  assert.throws(() => slipDecode([0xdb,0]),/escape/);
  const hci = slipDecode(hciPacket(payload,1).subarray(1,-1)); assert.equal((hci[0]+hci[1]+hci[2]+hci[3]) & 255,0); assert.equal(crc16(hci.subarray(0,-2)),hci.at(-2) | hci.at(-1)<<8);
  const ack = Uint8Array.from([16,0,0,240]); assert.equal(parseAck(ack),2); ack[3]++; assert.throws(() => parseAck(ack),/header/);
});
test('ESP image checksum, app descriptor, image kind and immutable digest',() => {
  const data = espImage(); assert.equal(validateEspImage(data),64); assert.equal(inspectFirmware('app.bin',data).chipId,9);
  assert.throws(() => inspectFirmware('app-merged.bin',data),/merged/); const damaged = data.slice(); damaged[35] ^= 1; assert.throws(() => inspectFirmware('app.bin',damaged),/checksum/);
});
test('physical partitions and OTA sequence order follow checked script algorithm',() => {
  const parts = partitionTable(table(),4<<20), ota = new Uint8Array(8192).fill(255); assert.equal(activeOta(parts,ota),0x10000);
  const v = new DataView(ota.buffer); v.setUint32(0,2,true); v.setUint32(24,2,true); v.setUint32(28,crc32(ota.subarray(0,4),0xffffffff),true); assert.equal(activeOta(parts,ota),0x110000);
  ota[28] ^= 1; assert.throws(() => activeOta(parts,ota),/no verified/);
  const bad = table(); new DataView(bad.buffer).setUint32(3*32+4,0x10000,true); assert.throws(() => partitionTable(bad),/overlap/);
});
test('catalog uses exact board pattern and rejects credential/HTTP URLs',() => {
  const config = {device:[{name:'G3',type:'esp32',firmware:[{role:'repeater',github:{type:'repeater',files:{flash:'G3.*\\.bin'}}}]}]};
  const items = catalogItems(config,[{type:'repeater',version:'1',files:[{name:'G3.bin',url:'/a'},{name:'other-G3.bin',url:'/b'}]}]); assert.equal(items.length,1); assert.equal(items[0].url,'https://github.com/a');
  assert.throws(() => httpsUrl('http://example.com/a')); assert.throws(() => httpsUrl('https://user:pass@example.com/a'));
});
test('logical backups are integrity checked, explicitly partial, and never wipe-safe',() => { const a = sealBackup({role:'common-cli',publicKey:'11'.repeat(32),safeForWipe:false,replies:{'get name':'> test'}}); assert.equal(verifyBackup(a).role,'common-cli'); a.payload.replies['get name']='tampered'; assert.throws(() => verifyBackup(a),/SHA/); });
test('MeshCore identity derives scalar public key, not seed-hashed Ed25519',() => { const key = new Uint8Array(64); key[0] = 1; assert.equal(publicFromPrivate(key),'5866666666666666666666666666666666666666666666666666666666666666'); });
test('security stops encrypted/secure devices before uploading any stub',async () => { await assert.rejects(() => assertSecurity({secureDownloadMode:true}),/Secure/); await assert.rejects(() => assertSecurity({chip:{IMAGE_CHIP_ID:9},getSecurityInfo:async()=>({parsedFlags:{SECURE_BOOT_EN:false,SECURE_DOWNLOAD_ENABLE:false},flashCryptCnt:1})}),/encryption/); });
test('ESP write refuses mutated firmware and changed chip MAC before any write',async () => {
  const session = new EspSession({getInfo:()=>({})},()=>{}); let writes=0; session.mac='aa:bb:cc:dd:ee:ff'; session.loader={chip:{readMac:async()=> 'aa:bb:cc:dd:ee:00'},writeFlash:async()=>{writes++}};
  const pkg=inspectFirmware('app.bin',espImage()); session.plan={payloadHash:pkg.payloadHash,sha256:pkg.sha256,addresses:[0x10000]}; await assert.rejects(()=>session.flash(pkg,()=>{}),/MAC changed/); assert.equal(writes,0);
  pkg.payload[40]^=1; await assert.rejects(()=>session.flash(pkg,()=>{}),/changed/); assert.equal(writes,0);
});
