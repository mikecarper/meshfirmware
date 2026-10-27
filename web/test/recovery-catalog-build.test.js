import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {buildCatalog} from '../scripts/catalog-build.mjs';
import {bytes,json} from '../scripts/catalog.mjs';
import {BOOTLOADER_LATEST_URL,BOOTLOADER_REPOSITORY} from '../src/bootloader-catalog.js';
import {createRecoveryCatalog} from '../src/bootloader-recovery.js';
import {recoveryFixture} from './fixtures/recovery-bundle.js';

const checkedAt='2026-10-27T18:00:00.000Z';
const application={project:'MeshCore',provider:'MeshCore',architecture:'nrf52',hardware:'Seeed Studio Xiao nRF52 WIO',role:'companionFull',version:'v1.18',name:'Xiao_nrf52_companion_radio_full-v1.18.zip',url:'https://example.test/application.zip',erase:[],bootloader:[]};
const previous=extra=>({generatedAt:checkedAt,warnings:[],items:[application],...extra});
function normalMetadata(release){
  const tag=release.tag_name,version=tag.split('OTAFIX')[1],base=`https://github.com/${BOOTLOADER_REPOSITORY}/releases/download/${tag}/`,name=`xiao_nrf52840_ble_bootloader-${tag}_s140_7.3.0.zip`,file={name,url:base+name,size:192834,sha256:'b'.repeat(64)},manifest={schemaVersion:1,repository:BOOTLOADER_REPOSITORY,tag,version,releaseUrl:release.html_url,prerelease:false,profiles:[{id:'xiao_nrf52840_ble',label:'XIAO BLE',meshcoreHardware:['Xiao_nrf52'],deviceName:'XIAO_DFU',storage:'qspi',files:{zip:file}}],unavailableProfiles:[]};
  return {manifest,url:base+'bootloader-manifest.json',release:{...release,assets:[...release.assets,{name:'bootloader-manifest.json',browser_download_url:base+'bootloader-manifest.json',size:100,digest:'sha256:'+'a'.repeat(64)},{name,browser_download_url:file.url,size:file.size,digest:'sha256:'+file.sha256}]}};
}

test('recovery build reuses latest API response and remains available when the normal manifest fails',async()=>{
  const fixture=recoveryFixture(),seen=[],loads=[];
  const result=await buildCatalog({now:()=>checkedAt,previous:async()=>previous(),readJson:async url=>{seen.push(url);if(url===BOOTLOADER_LATEST_URL)return fixture.release;throw Error('metadata offline');},readBytes:async(url,options)=>{loads.push([url,options]);return fixture.bundle;}});
  assert.equal(seen.filter(url=>url===BOOTLOADER_LATEST_URL).length,1);assert.equal(result.bootloaderCatalog,null);assert.equal(result.recoveryCatalog.version,'2.4.12');assert.equal(result.recoveryCatalog.profiles.length,2);assert.equal(result.recoveryCatalog.cached,false);
  assert.deepEqual(loads,[[fixture.asset.browser_download_url,{sha256:fixture.asset.digest.slice(7),size:fixture.asset.size}]]);
  assert.equal(result.items[0].url,application.url);assert.deepEqual(result.items[0].bootloader,[]);
});

test('recovery failure does not poison normal bootloader or application metadata',async()=>{
  const fixture=recoveryFixture(),normal=normalMetadata(fixture.release);
  const result=await buildCatalog({now:()=>checkedAt,previous:async()=>previous(),readJson:async url=>{if(url===BOOTLOADER_LATEST_URL)return normal.release;if(url===normal.url)return normal.manifest;throw Error('provider offline');},readBytes:async()=>{throw Error('bundle download failed');}});
  assert.equal(result.recoveryCatalog,null);assert.equal(result.bootloaderCatalog.manifest.version,'2.4.12');assert.equal(result.items[0].bootloaderInfo.version,'2.4.12');assert.equal(result.items[0].url,application.url);assert.ok(result.warnings.some(w=>w.includes('bundle download failed')));
});

test('only a validated cached recovery catalog survives an outage with an explicit last-known warning',async()=>{
  const fixture=recoveryFixture(),snapshot=createRecoveryCatalog(fixture.release,fixture.bundle,checkedAt),raw=previous({recoveryCatalog:snapshot});
  const result=await buildCatalog({previous:async()=>raw,readJson:async()=>{throw Error('offline');},readBytes:async()=>{throw Error('must not fetch after failed release lookup');}});
  assert.equal(result.recoveryCatalog.cached,true);assert.equal(result.recoveryCatalog.bundle.sha256,snapshot.bundle.sha256);assert.ok(result.warnings.some(w=>w.includes('last verified public recovery')&&w.includes('latest recovery bundle could not be checked')));assert.equal(result.items[0].url,application.url);
  const invalid=structuredClone(raw);invalid.recoveryCatalog.bundle.sha256='f'.repeat(64);
  const rejected=await buildCatalog({previous:async()=>invalid,readJson:async()=>{throw Error('offline');},readBytes:async()=>{throw Error('offline');}});
  assert.equal(rejected.recoveryCatalog,null);assert.equal(rejected.items[0].url,application.url);assert.ok(rejected.warnings.some(w=>w.includes('recovery')));
});

test('legacy byte-loader absence declines recovery without implicit fetches or disabling normal selection',async()=>{
  const fixture=recoveryFixture(),normal=normalMetadata(fixture.release),seen=[];
  const result=await buildCatalog({previous:async()=>previous(),readJson:async url=>{seen.push(url);if(url===BOOTLOADER_LATEST_URL)return normal.release;if(url===normal.url)return normal.manifest;throw Error('provider offline');}});
  assert.equal(result.recoveryCatalog,null);assert.equal(result.items[0].bootloaderInfo.version,'2.4.12');assert.ok(result.warnings.some(w=>w.includes('No verified recovery-bundle byte loader')));assert.ok(!seen.includes(fixture.asset.browser_download_url));assert.equal(seen.filter(url=>url===BOOTLOADER_LATEST_URL).length,1);
});

test('production raw-byte loader enforces release size and SHA before returning binary data',async()=>{
  const payload=Uint8Array.from([0,255,12,99]),sha256=createHash('sha256').update(payload).digest('hex'),url='https://example.test/public-recovery.zip',fetchImpl=async()=>new Response(payload);
  assert.deepEqual(await bytes(url,{sha256,size:payload.length,fetchImpl}),payload);
  await assert.rejects(()=>bytes(url,{sha256:'a'.repeat(64),size:payload.length,fetchImpl}),/SHA-256/);
  await assert.rejects(()=>bytes(url,{sha256,size:payload.length-1,fetchImpl}),/exceeds/);
  await assert.rejects(()=>bytes(url,{sha256,size:payload.length+1,fetchImpl}),/size or SHA-256/);
  let fetched=false;const unexpected=async()=>{fetched=true;throw Error('must not fetch');};
  await assert.rejects(()=>bytes(url,{sha256,size:(32<<20)+1,fetchImpl:unexpected}),/bounds/);assert.equal(fetched,false);
  await assert.rejects(()=>json(url,{sha256,size:(1<<20)+1,fetchImpl:unexpected}),/bounds/);assert.equal(fetched,false);
});
