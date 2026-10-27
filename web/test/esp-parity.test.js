import test from 'node:test';
import assert from 'node:assert/strict';
import {EspSession,appWriteOrder} from '../src/esp.js';
import {hash,md5hex,inspectFirmware} from '../src/firmware.js';
const encode=value=>new TextEncoder().encode(value);
function image({app=true}={}){const b=new Uint8Array(64),v=new DataView(b.buffer);b[0]=0xe9;b[1]=1;b[12]=9;v.setUint32(28,16,true);if(app)v.setUint32(32,0xabcd5432,true);let crc=0xef;for(const x of b.subarray(32,48))crc^=x;b[63]=crc;return b;}
function table(entries){const b=new Uint8Array(4096).fill(255),v=new DataView(b.buffer);entries.forEach(([type,subtype,offset,size,name],i)=>{const at=i*32;b.fill(0,at,at+32);v.setUint16(at,0x50aa,true);b[at+2]=type;b[at+3]=subtype;v.setUint32(at+4,offset,true);v.setUint32(at+8,size,true);b.set(encode(name),at+12);});return b;}
const dual=()=>table([[1,2,0x9000,0x5000,'nvs'],[1,0,0xe000,0x2000,'ota'],[0,0x10,0x10000,0x100000,'app0'],[0,0x11,0x110000,0x100000,'app1']]);
function session(parts){const calls=[],s=new EspSession({getInfo:()=>({})},()=>{});s.mac='aa:bb:cc:dd:ee:ff';s.flashBytes=4<<20;s.loader={chip:{IMAGE_CHIP_ID:9,CHIP_NAME:'ESP32-S3',readMac:async()=>s.mac},readFlash:async(at,size)=>{calls.push(['read',at,size]);return at===0x8000?parts:new Uint8Array(size).fill(255);},writeFlash:async options=>calls.push(['write',options]),flashMd5sum:async(_at,length)=>md5hex(calls.filter(row=>row[0]==='write').at(-1)[1].fileArray[0].data.subarray(0,length))};return {s,calls};}
test('factory-only and absent NVS snapshots are allowed before the exact shared planner',async()=>{
  const physical=table([[0,0,0x10000,0x100000,'factory']]),{s,calls}=session(physical),pkg=inspectFirmware('app.bin',image());let received;
  const plan=await s.prepare(pkg,{planner:{call:async(op,data)=>{received=data;assert.equal(op,'plan');return {app_offsets:[0x10000],needed:false};}}});
  assert.equal(received.nvs,null);assert.equal(received.ota,null);assert.deepEqual(plan.addresses,[0x10000]);assert.deepEqual(calls,[['read',0x8000,4096],['read',0x8000,4096]]);
});
test('larger OTA partitions read only the required 8192-byte metadata snapshot',async()=>{
  const physical=table([[1,2,0x9000,0x5000,'nvs'],[1,0,0xe000,0x3000,'ota'],[0,0x10,0x20000,0x100000,'app0'],[0,0x11,0x120000,0x100000,'app1']]),{s,calls}=session(physical);let received;
  await s.prepare(inspectFirmware('app.bin',image()),{planner:{call:async(_op,data)=>{received=data;return {app_offsets:[0x120000,0x20000],needed:false};}}});
  assert.equal(received.ota.length,8192);assert.ok(calls.some(row=>row[0]==='read'&&row[1]===0xe000&&row[2]===8192));
});
test('factory write order has no fake OTA requirement but rejects unsupported layouts',()=>{
  assert.deepEqual(appWriteOrder([{type:0,subtype:0,offset:0x10000}]),[0x10000]);
  assert.throws(()=>appWriteOrder([{type:0,subtype:2,offset:0x10000}]),/unsupported/);
  assert.throws(()=>appWriteOrder([{type:0,subtype:0x10,offset:0x10000}]),/Actual OTA/);
});
test('merged install mirrors the exact embedded app and verifies each secondary slot',async()=>{
  const bytes=new Uint8Array(0x10000+64+56).fill(255);bytes.set(image({app:false}),0);bytes.set(dual(),0x8000);bytes.set(image(),0x10000);bytes.set(encode('EndF-preserve-the-exact-trailer'),0x10000+64);
  const pkg=inspectFirmware('full-merged.bin',bytes),{s,calls}=session();const plan=await s.prepare(pkg);
  assert.equal(plan.mirroredSlots,1);assert.deepEqual(plan.addresses,[0,0x110000]);await s.flash(pkg,()=>{});
  const writes=calls.filter(row=>row[0]==='write').map(row=>row[1]);assert.equal(writes.length,2);assert.equal(writes[0].eraseAll,true);assert.equal(writes[1].eraseAll,false);assert.deepEqual(writes[1].fileArray[0].data,bytes.subarray(0x10000));
  assert.equal(hash(writes[1].fileArray[0].data),plan.segments[1].payloadHash);
});
test('merged mirroring refuses guessing past the primary boundary and refuses modified segment proof',async()=>{
  const bytes=new Uint8Array(0x10000+64).fill(255);bytes.set(image({app:false}),0);bytes.set(dual(),0x8000);bytes.set(image(),0x10000);const pkg=inspectFirmware('full-merged.bin',bytes),{s,calls}=session();await s.prepare(pkg);
  s.plan.segments=[{address:0,sourceOffset:0,length:bytes.length,payloadHash:hash(bytes)}];await assert.rejects(s.flash(pkg,()=>{}),/plan changed/);assert.equal(calls.filter(row=>row[0]==='write').length,0);
  const oversized=new Uint8Array(0x110000+1).fill(255);oversized.set(bytes);const other=session();await assert.rejects(other.s.prepare(inspectFirmware('full-merged.bin',oversized)),/boundary/);
});
test('actual WASM shared validator accepts factory/no-NVS and larger OTA metadata layouts',async()=>{
  const {loadPyodide}=await import('pyodide'),{fileURLToPath}=await import('node:url'),{readFile}=await import('node:fs/promises'),{createPlannerService}=await import('../src/planner-runtime.js');
  const sources={};for(const name of ['meshcore_partition_expansion.py','meshcore_backup.py'])sources[name]=new Uint8Array(await readFile(new URL('../../tools/'+name,import.meta.url)));
  const manifest=JSON.stringify(Object.fromEntries(Object.entries(sources).map(([name,b])=>[name,hash(b)])));
  const service=createPlannerService({persistent:false,loadRuntime:()=>loadPyodide({indexURL:fileURLToPath(new URL('../node_modules/pyodide/',import.meta.url)),stdout:()=>{},stderr:()=>{}}),readValidator:async name=>name==='integrity.json'?manifest:sources[name]});
  const common={name:'app.bin',image:image(),mac:'aa:bb:cc:dd:ee:ff',chip:'ESP32-S3',flashBytes:4<<20,nvs:null,ota:null};
  const factory=await service.call('plan',{...common,table:table([[0,0,0x10000,0x100000,'factory']])});assert.deepEqual(factory.app_offsets,[0x10000]);assert.equal(factory.needed,false);
  const ota=await service.call('plan',{...common,table:table([[1,0,0xe000,0x3000,'ota'],[0,0x10,0x20000,0x100000,'app0'],[0,0x11,0x120000,0x100000,'app1']]),ota:new Uint8Array(8192).fill(255)});assert.deepEqual(ota.app_offsets,[0x120000,0x20000]);assert.equal(ota.needed,false);
});
