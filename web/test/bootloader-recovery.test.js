import test from 'node:test';
import assert from 'node:assert/strict';
import {zipSync,unzipSync} from 'fflate';
import {hash,inspectFirmware} from '../src/firmware.js';
import {createRecoveryCatalog,recoveryBundleAsset,recoveryPackage,validateRecoveryCatalog} from '../src/bootloader-recovery.js';
import {recoveryFixture} from './fixtures/recovery-bundle.js';

const when='2026-10-27T12:00:00Z',encode=value=>new TextEncoder().encode(JSON.stringify(value));
const snapshot=f=>createRecoveryCatalog(f.release,f.bundle,when);

test('recovery exports only exact serial DFU ZIP profiles, never HEX/UF2 or identity-based automatic selection',()=>{
  const f=recoveryFixture(),catalog=snapshot(f);assert.equal(catalog.cached,false);assert.equal(catalog.profiles.length,2);assert.ok(catalog.profiles.every(p=>p.name.startsWith('R_')&&p.name.endsWith('.zip')));assert.equal(catalog.profiles[0].installedIdentity,catalog.profiles[1].installedIdentity);
  for(const profile of catalog.profiles){const selected=recoveryPackage(catalog,profile.id,f.bundle);assert.equal(selected.name,profile.name);assert.equal(hash(selected.bytes),profile.sha256);assert.equal(inspectFirmware(selected.name,selected.bytes).kind,'softdevice_bootloader');assert.deepEqual(selected.bytes,f.inner[profile.id]);}
  for(const id of ['',undefined,'XIAO_DFU','unknown','../xiao_nrf52840_ble'])assert.throws(()=>recoveryPackage(catalog,id,f.bundle),/profile/);
});

test('bundle API proof requires exact stable release URL, canonical bundle name, size and digest',()=>{
  const f=recoveryFixture();assert.deepEqual(recoveryBundleAsset(f.release),f.asset);
  for(const mutate of [r=>r.draft=true,r=>r.prerelease=true,r=>r.tag_name='R_0.11.0-OTAFIX2.4.12',r=>r.html_url='https://example.test/release',r=>r.assets.push({...r.assets[0]}),r=>r.assets[0].browser_download_url=r.assets[0].browser_download_url.replace('github.com','example.test'),r=>r.assets[0].digest=null,r=>r.assets[0].size=(32<<20)+1,r=>r.assets[0].name='R_wrong.zip']){const release=structuredClone(f.release);mutate(release);assert.throws(()=>recoveryBundleAsset(release));}
});

test('outer SHA-256 and size are checked before attempting to parse a malformed ZIP',()=>{
  const f=recoveryFixture(),bad=f.bundle.slice();bad[0]^=255;assert.throws(()=>createRecoveryCatalog(f.release,bad,when),/size or SHA-256/);assert.throws(()=>createRecoveryCatalog(f.release,bad.subarray(1),when),/size or SHA-256/);
  const release=structuredClone(f.release);release.assets[0].digest='sha256:'+hash(bad);assert.throws(()=>createRecoveryCatalog(release,bad,when),/ZIP/);
});

test('root manifest must prove recovery-only tag, packed stable version and exact unique board inventory',()=>{
  for(const mutate of [m=>m.tag='v0.11.0-OTAFIX2.4.11',m=>m.recovery_only=false,m=>m.packed_bootloader_version='0x02040C00',m=>m.board_count++,m=>m.boards.push({...m.boards[0]}),m=>m.boards[1].board=m.boards[0].board,m=>m.boards[0].board='../unsafe',m=>m.boards[0].device_name='',m=>m.boards[0].bootloader_manifest_crc32='bad',m=>m.boards[0].bootloader_sha256='bad'])assert.throws(()=>snapshot(recoveryFixture({mutateManifest:mutate})));
  assert.throws(()=>createRecoveryCatalog(recoveryFixture().release,recoveryFixture().bundle,'yesterday'),/checkedAt/);
});

test('each profile has exactly one declared R_ ZIP under its own exact directory',()=>{
  for(const mutateManifest of [m=>{const b=m.boards[0];b.files['another.zip']='a'.repeat(64);},m=>{const b=m.boards[0],name=Object.keys(b.files).find(n=>n.endsWith('.zip'));b.files[name.replace(/^R_/,'')]=b.files[name];delete b.files[name];},m=>{const b=m.boards[0],name=Object.keys(b.files).find(n=>n.endsWith('.zip'));b.files[name.replace('7.3.0','7.3')]=b.files[name];delete b.files[name];}])assert.throws(()=>snapshot(recoveryFixture({mutateManifest})));
  assert.throws(()=>snapshot(recoveryFixture({mutateFiles:files=>{const name=Object.keys(files).find(n=>n.endsWith('.zip'));files[name.replace('/xiao_nrf52840_ble/','/wrong_board/')]=files[name];delete files[name];}})),/missing/);
  assert.throws(()=>snapshot(recoveryFixture({mutateFiles:files=>{files['undeclared.zip']=new Uint8Array([1,2,3]);}})),/undeclared/);
});

test('declared inner hash and raw bootloader hash are both verified before a profile is usable',()=>{
  assert.throws(()=>snapshot(recoveryFixture({mutateManifest:m=>{const b=m.boards[0],name=Object.keys(b.files).find(n=>n.endsWith('.zip'));b.files[name]='0'.repeat(64);}})),/ZIP hash/);
  assert.throws(()=>snapshot(recoveryFixture({mutateManifest:m=>m.boards[0].bootloader_sha256='0'.repeat(64)})),/declared combined/);
  assert.throws(()=>snapshot(recoveryFixture({kind:'application'})),/declared combined/);
});

test('inner DFU DAT CRC and combined sizes are independently validated even with recomputed outer/inner hashes',()=>{
  for(const alter of [files=>files['sd_bl.dat'][10]^=1,files=>{const m=JSON.parse(new TextDecoder().decode(files['manifest.json']));m.manifest.softdevice_bootloader.sd_size=60;files['manifest.json']=encode(m);}]){
    const f=recoveryFixture({mutateFiles:files=>{const path=Object.keys(files).find(n=>n.endsWith('.zip')),inner=unzipSync(files[path]);alter(inner);files[path]=zipSync(inner);const manifest=JSON.parse(new TextDecoder().decode(files['manifest.json']));manifest.boards[0].files[path.split('/').pop()]=hash(files[path]);files['manifest.json']=encode(manifest);}});
    assert.throws(()=>snapshot(f),/CRC|component sizes/);
  }
});

test('cached snapshot validation cannot authorize a changed profile without rechecking the raw bundle',()=>{
  const f=recoveryFixture(),catalog=snapshot(f),cached=validateRecoveryCatalog({...catalog,cached:true});assert.equal(cached.cached,true);assert.equal(recoveryPackage(cached,cached.profiles[0].id,f.bundle).name,cached.profiles[0].name);
  for(const mutate of [c=>c.bundle.sha256='0'.repeat(64),c=>c.bundle.url='https://example.test/bundle.zip',c=>c.tag='OTAFIX2.4.11',c=>c.profiles.push({...c.profiles[0]}),c=>c.profiles[0].entry=c.profiles[1].entry]){const changed=structuredClone(catalog);mutate(changed);assert.throws(()=>recoveryPackage(changed,catalog.profiles[0].id,f.bundle));}
  const changed=structuredClone(catalog);changed.profiles[0].installedIdentity='FORGED_DFU';validateRecoveryCatalog(changed);assert.throws(()=>recoveryPackage(changed,changed.profiles[0].id,f.bundle),/verified raw bundle/);
  const changedPayload=f.bundle.slice();changedPayload[20]^=1;assert.throws(()=>recoveryPackage(catalog,catalog.profiles[0].id,changedPayload),/SHA-256/);
});
