import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {zipSync} from 'fflate';
import {nrfPackage,hash,crc16,checkedZip,inspectFirmware,nrfEraseIntent} from '../src/firmware.js';
import {rakFamily,endfIdentity,payloadBoardIdentity,assessBoard,isKnownDfu} from '../src/board-safety.js';
import {flashNrf,slipDecode,slipEncode} from '../src/serial.js';
const encode = value => new TextEncoder().encode(value);

function zip(payload,name='firmware.bin') {
  const init=new Uint8Array(12),view=new DataView(init.buffer);view.setUint16(0,0x52,true);view.setUint16(10,crc16(payload),true);
  return zipSync({'manifest.json':encode(JSON.stringify({manifest:{dfu_version:0.5,application:{bin_file:name,dat_file:'firmware.dat'}}})),[name]:payload,'firmware.dat':init});
}
function payload(value='',endfHardware=null) {
  const raw=encode(value+'\0'),body=new Uint8Array(Math.max(256,Math.ceil(raw.length/4)*4));body.set(raw);
  if(!endfHardware)return body;
  const result=new Uint8Array(body.length+56),v=new DataView(result.buffer);result.set(body);result.set(encode('EndF'),body.length);v.setUint32(body.length+4,body.length,true);result.set(Uint8Array.from(hash(body).slice(0,16).match(/../g),x=>parseInt(x,16)),body.length+8);v.setUint32(body.length+16,0x01120106,true);v.setUint32(body.length+20,1,true);result.set(encode(endfHardware),body.length+24);return result;
}
const pkg = (value,name='mystery.zip',endf=null) => nrfPackage(name,zip(payload(value,endf)));

test('erase intent is destructive even with an application DFU manifest',()=>{
  for(const name of ['FLASH_ERASE_nrf52_softdevice_v6.zip','flash-wipe.zip','board.erase.zip']){
    const p=pkg('erase firmware',name);assert.equal(p.kind,'application');assert.equal(p.erase,true);assert.equal(p.destructive,true);assert.match(p.warnings.join(' '),/erases stored identity/);
  }
  const inner=nrfPackage('ordinary.zip',zip(payload(), 'flash_erase.bin'));assert.equal(inner.erase,true);
  assert.equal(pkg('ordinary application').erase,false);
});
test('official erase payload hashes survive ZIP renaming and repacking',async t=>{
  for(const version of [6,7]){
    let source;try{source=new Uint8Array(await readFile(new URL(`../../meshcore-dev_MeshCore/downloads/${version===7?'custom/':''}FLASH_ERASE_nrf52_softdevice_v${version}.zip`,import.meta.url)));}catch(error){if(error.code==='ENOENT'){t.diagnostic(`Optional local v${version} reference fixture is absent; canonical hash regression below remains hermetic.`);continue;}throw error;}
    const p=inspectFirmware('renamed.zip',source);assert.equal(p.erase,true);assert.equal(p.destructive,true);assert.match(p.eraseEvidence,/official SoftDevice/);
    const repacked=zipSync(checkedZip(source),{level:0});assert.notEqual(hash(repacked),hash(source));const q=inspectFirmware('renamed-again.zip',repacked);assert.equal(q.erase,true);assert.equal(q.eraseEvidence,p.eraseEvidence);
  }
});
test('known erase hash classification covers both canonical utilities even without local reference downloads',()=>{
  for(const digest of ['f17500b598ce53d4d4183f6bd20e06e9bf2bd3468d9a22ff3af7f148bb0dfc0c','01f8d553e5ce865312fcfe3ddf1eb06f10ed7ca6bd4f34dd81e58b6f8400be8e'])assert.match(nrfEraseIntent('renamed.zip',digest),/official SoftDevice/);
  assert.equal(nrfEraseIntent('ordinary.zip','0'.repeat(64)),null);
});
test('EndF metadata requires exact length, body hash and valid board identity',()=>{
  const bytes=payload('WisCore RAK4631 Board','RAK4631');const identity=endfIdentity(bytes);assert.equal(identity.hardware,'RAK4631');assert.equal(identity.versionText,'v1.18.1.6');assert.deepEqual(identity.versionParts,[1,18,1,6]);
  for(const changed of [b=>b[0]^=1,b=>b[b.length-52]^=1,b=>b[b.length-48]^=1,b=>b[b.length-32]=0xff]){const b=bytes.slice();changed(b);assert.equal(endfIdentity(b),null);}
  assert.equal(endfIdentity(payload()),null);
});
test('payload-owned RAK identity ignores unrelated Full Companion target strings',()=>{
  assert.equal(rakFamily('RAK 3401'),'rak3401');assert.equal(rakFamily('RAK3401 and RAK4631'),'ambiguous');assert.equal(rakFamily('Heltec V4'),'unknown');
  assert.equal(payloadBoardIdentity(payload('WisCore RAK3401 Board\nRAK3401_OTA\nRAK_4631_companion_radio_usb\nRAK_WisMesh_Tag_sensor')).family,'rak3401');
  assert.equal(payloadBoardIdentity(payload('WisCore RAK4631 Board\nWISMESHTAG_OTA\nRAK_3401_companion_radio_usb')).family,'rak4631');
  assert.equal(payloadBoardIdentity(payload('WisCore RAK3401 Board\nWISMESHTAG_OTA')).family,'ambiguous');
  assert.equal(pkg('', 'generic.zip','RAK_4631').boardIdentity.proof,'endf');
});
test('RAK guard uses payload and connected evidence, not a filename bypass',()=>{
  const target=pkg('WisCore RAK4631 Board\nWISMESHTAG_OTA');
  assert.equal(assessBoard(target,{deviceModel:'RAK WisMesh Tag'}).matched,true);
  assert.equal(assessBoard(target,{deviceModel:'WisCore RAK3401 Board'}).token,'rak3401-to-rak4631');
  assert.equal(assessBoard(target,{deviceModel:'GAT562'}).token,'unknown-to-rak4631');
  assert.equal(assessBoard({...target,name:'RAK_3401_mislabelled.zip'},{deviceModel:'RAK4631'}).token,'rak4631-to-ambiguous');
  assert.equal(assessBoard(pkg('Unknown board'),{selectedHardware:'RAK 3401'}).token,'unknown-to-rak3401');
  assert.equal(assessBoard(pkg('Unknown board'),{deviceModel:'RAK4631'}).token,'rak4631-to-unknown');
  assert.equal(assessBoard(target,{deviceModel:'RAK4631',usbText:'WisCore_RAK3401_Board'}).token,'ambiguous-to-rak4631');
  assert.equal(assessBoard(pkg('Unknown board')).requiresOverride,false);
});
test('known DFU mode hints are exact; nearby application and shared ESP IDs are not accepted',()=>{
  for(const [vid,pid] of [[0x2886,0x44],[0x2886,0x57],[0x239a,0x2a],[0x239a,0xb3],[0x239a,0xda]])assert.equal(isKnownDfu({usbVendorId:vid,usbProductId:pid}),true);
  for(const [vid,pid] of [[0x2886,0x8044],[0x239a,0x802a],[0x303a,0x1001],[0x239a,0x1234]])assert.equal(isKnownDfu({usbVendorId:vid,usbProductId:pid}),false);
});
test('DFU safety classification cannot be weakened after package validation',async()=>{
  for(const mutate of [p=>p.name='ordinary.zip',p=>p.destructive=false,p=>p.erase=false,p=>p.boardIdentity={family:'rak3401'},p=>p.firmwareIdentity={version:1}]){
    const p=pkg('WisCore RAK4631 Board','flash_erase.zip');mutate(p);let touched=false;
    await assert.rejects(flashNrf({port:{setSignals:async()=>{touched=true;}}},p,()=>{}),/changed/);assert.equal(touched,false);
  }
});
test('complete serial DFU sends start/init/data/activate and validates each acknowledgement',async()=>{
  const p=pkg('WisCore RAK4631 Board'),sent=[],delays=[],queue=[];let touched=0;
  const link={buffer:[],port:{setSignals:async()=>{touched++;}},write:async packet=>{const frame=slipDecode(packet.subarray(1,-1));sent.push(frame.subarray(4,-2));const ack=((frame[0]&7)+1)&7,h=[ack<<3,0,0,(-(ack<<3))&255];queue.push(slipEncode(h));},read:async()=>queue.shift()||new Uint8Array()};
  const progress=[];await flashNrf(link,p,(value)=>progress.push(value),{delay:async ms=>delays.push(ms)});
  assert.equal(touched,1);assert.deepEqual(sent.map(b=>new DataView(b.buffer,b.byteOffset).getUint32(0,true)),[3,1,4,5]);assert.deepEqual(sent[2].subarray(4),p.payload);assert.equal(progress.at(-1),1);assert.ok(delays.every(n=>n>0));
});
test('stale DFU acknowledgements never authorize init, data or activation',async()=>{
  const p=pkg('ordinary application'),sent=[];let tick=0;
  const link={buffer:[],port:{setSignals:async()=>{}},write:async packet=>sent.push(packet),read:async()=>slipEncode([8,0,0,248])};
  await assert.rejects(flashNrf(link,p,()=>{},{delay:async()=>{},now:()=>tick+=250}),/did not acknowledge/);
  assert.equal(sent.length,3);assert.ok(sent.every(packet=>hash(packet)===hash(sent[0])));
  assert.ok(sent.every(packet=>new DataView(slipDecode(packet.subarray(1,-1)).buffer).getUint32(4,true)===3));
});
