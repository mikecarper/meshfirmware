// Actual unchanged Python planning/verification in WebAssembly, with only the
// physical ESP transport mocked. These fixtures never open a serial device.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { loadPyodide } from 'pyodide';
import { EspSession } from '../src/esp.js';
import { hash, md5hex } from '../src/firmware.js';
import { createPlannerService } from '../src/planner-runtime.js';

async function fixture(){
  const sources={};for(const name of ['meshcore_partition_expansion.py','meshcore_backup.py'])sources[name]=new Uint8Array(await readFile(new URL('../../tools/'+name,import.meta.url)));
  const manifest=JSON.stringify(Object.fromEntries(Object.entries(sources).map(([name,bytes])=>[name,hash(bytes)])));let py;
  const service=createPlannerService({persistent:false,loadRuntime:async()=>py=await loadPyodide({indexURL:fileURLToPath(new URL('../node_modules/pyodide/',import.meta.url)),stdout(){},stderr(){}}),readValidator:async name=>name==='integrity.json'?manifest:sources[name]});
  await assert.rejects(service.call('validateBackup',{text:'{}'}));py.FS.mkdirTree('/repo/tests');py.FS.mkdirTree('/repo/tools');py.FS.writeFile('/repo/tests/test_meshcore_partition_expansion.py',await readFile(new URL('../../tests/test_meshcore_partition_expansion.py',import.meta.url)));py.FS.writeFile('/repo/tools/meshcore_partition_expansion.py',sources['meshcore_partition_expansion.py']);
  const fixture=JSON.parse(await py.runPythonAsync(`
import importlib.util
spec=importlib.util.spec_from_file_location('retry_fixtures','/repo/tests/test_meshcore_partition_expansion.py')
f=importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
_image=f.esp_image(0x140100)
json.dumps({'image':list(_image),'table':list(f.table(f.legacy_entries())),'expanded':list(m.canonical_table(16<<20)),'nvs':list(b'\\xff'*0x5000),'unfinished':list(f.finished_nvs(restored=0)),'finished':list(f.finished_nvs()),'package':list(f.migration_archive(_image))})
`));
  const data=Object.fromEntries(Object.entries(fixture).map(([key,value])=>[key,new Uint8Array(value)])),pkg={name:'heltec_v4_repeater-v1.17.1.9-halo-keymind-cascade-dev-88c85108.bin',architecture:'esp32',chipId:9,payload:data.image,payloadHash:hash(data.image),sha256:hash(data.image)};
  const memory=new Uint8Array(16<<20).fill(255);memory.set(data.table,0x8000);memory.set(data.nvs,0x9000);
  return {service,data,pkg,memory};
}
function session(memory,{failWrite=false,mac='aa:bb:cc:dd:ee:55'}={}){
  const calls=[],s=new EspSession({getInfo:()=>({})},()=>{});s.mac=mac;s.flashBytes=memory.length;s.connectMode='no_reset';
  s.loader={chip:{IMAGE_CHIP_ID:9,CHIP_NAME:'ESP32-S3',readMac:async()=>s.mac},readFlash:async(at,length)=>memory.slice(at,at+length),getSecurityInfo:async()=>({parsedFlags:{SECURE_BOOT_EN:false,SECURE_DOWNLOAD_ENABLE:false},flashCryptCnt:0}),flashMd5sum:async(at,length)=>md5hex(memory.subarray(at,at+length)),writeFlash:async options=>{calls.push(options);const {data,address}=options.fileArray[0];options.reportProgress?.(0,0,data.length);if(failWrite){memory.set(data.subarray(0,256),address);throw Error('device disconnected during bridge write');}memory.set(data,address);}};
  return {s,calls};
}

test('partial bridge retries on exact source table; target proof selects final app; failed final app retries after cached completion',async()=>{
  const {service,data,pkg,memory}=await fixture(),initial=session(memory,{failWrite:true}),args={planner:service,packageBytes:data.package};
  const planned=await initial.s.prepare(pkg,args);assert.equal(planned.needed,true);let interrupted;try{await initial.s.flash(pkg,()=>{});}catch(error){interrupted=error;}assert.equal(interrupted.recovery.stage,'bridge');assert.equal(initial.calls.length,1);await assert.rejects(initial.s.finish(false),/verified/);
  // The old UI path forced verify() here and rejected the unchanged table.
  const retry=session(memory),replanned=await retry.s.prepare(pkg,{...args,resume:true,recovery:interrupted.recovery});assert.equal(replanned.resume,false);assert.equal(replanned.chunkedRecovery,true);assert.equal(replanned.verified,false);
  await retry.s.flash(pkg,()=>{},{chunkedRecovery:true});assert.deepEqual(retry.calls.map(c=>c.fileArray[0].address),[0x150000,0x10000]);assert.ok(retry.calls.every(c=>!c.eraseAll));
  // Simulate only the reviewed bridge's completed table/settings restoration.
  memory.set(data.expanded,0x8000);memory.set(data.finished,0x9000);
  const final=session(memory,{failWrite:true}),verified=await final.s.prepare(pkg,{...args,resume:true,recovery:interrupted.recovery});assert.equal(verified.verified,true);assert.equal(verified.recoveryResolved,true);assert.equal(verified.chunkedRecovery,undefined);assert.deepEqual(verified.addresses,[0x650000,0x10000]);
  let finalError;try{await final.s.flash(pkg,()=>{});}catch(error){finalError=error;}assert.equal(finalError.recovery.stage,'application');
  // verify_plan marks the cache completed before the app write. A later
  // plan() returns fits/needed:false, so verify must rediscover its exact plan.
  const appRetry=session(memory),appPlan=await appRetry.s.prepare(pkg,{...args,resume:true,recovery:finalError.recovery});assert.equal(appPlan.verified,true);assert.equal(appPlan.chunkedRecovery,true);await appRetry.s.flash(pkg,()=>{},{chunkedRecovery:true});assert.ok(appRetry.calls.every(c=>c.fileArray[0].data.length<=16384&&!c.eraseAll));assert.equal(md5hex(memory.subarray(0x10000,0x10000+pkg.payload.length)),md5hex(pkg.payload));
});

test('target-table restoration proof is mandatory even when UI migration state was lost',async()=>{
  const {service,data,pkg,memory}=await fixture(),s=session(memory),args={planner:service,packageBytes:data.package};await s.s.prepare(pkg,args);await s.s.flash(pkg,()=>{});
  memory.set(data.expanded,0x8000);memory.set(data.unfinished,0x9000);const incomplete=session(memory);await assert.rejects(incomplete.s.prepare(pkg,args),/identity\/configuration restoration/);assert.equal(incomplete.calls.length,0);
  memory.set(data.finished,0x9000);const complete=session(memory),plan=await complete.s.prepare(pkg,args);assert.equal(plan.verified,true);assert.deepEqual(plan.addresses,[0x650000,0x10000]);
});
