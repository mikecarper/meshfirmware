import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {BOOTLOADER_REPOSITORY,BOOTLOADER_LATEST_URL,bootloaderManifestAsset,validateBootloaderSnapshot,applyBootloaderCatalog} from '../src/bootloader-catalog.js';
import {buildCatalog} from '../scripts/catalog-build.mjs';
import {json} from '../scripts/catalog.mjs';
import {getCatalog} from '../src/catalog.js';

const tag='v0.11.0-OTAFIX2.4.12',root=`https://github.com/${BOOTLOADER_REPOSITORY}`,download=`${root}/releases/download/${tag}/`,checkedAt='2026-10-27T05:00:00.000Z';
const clone=value=>structuredClone(value);
function fixture(){
  const profiles=[['t1000_e','t1000e','T1KE_DFU'],['heltec_mesh_tower_v2_sdcard','Heltec_tower_v2_sdcard','TOWER_V2_OTA']].map(([id,hardware,deviceName])=>({id,label:id,meshcoreHardware:[hardware],deviceName,storage:'internal',files:{zip:{name:`${id}_bootloader-${tag}_s140_7.3.0.zip`,url:`${download}${id}_bootloader-${tag}_s140_7.3.0.zip`,size:192834,sha256:'b'.repeat(64)},uf2:{name:'unused.uf2'},hex:{name:'unused.hex'}}}));
  const manifest={schemaVersion:1,repository:BOOTLOADER_REPOSITORY,tag,version:'2.4.12',releaseUrl:`${root}/releases/tag/${tag}`,prerelease:false,profiles,unavailableProfiles:[{id:'heltec_mesh_tower_v2',label:'Historical internal-only Tower',meshcoreHardware:['Heltec_tower_v2'],reason:'Retired profile: local migration required.'},{id:'thinknode_m4',label:'ThinkNode M4',meshcoreHardware:['ThinkNode_M4'],reason:'No qualified board-specific bootloader is available.'}]};
  const release={tag_name:tag,html_url:manifest.releaseUrl,draft:false,prerelease:false,assets:[{name:'bootloader-manifest.json',browser_download_url:download+'bootloader-manifest.json',size:12345,digest:'sha256:'+'a'.repeat(64)},...profiles.map(p=>({name:p.files.zip.name,browser_download_url:p.files.zip.url,size:p.files.zip.size,digest:'sha256:'+p.files.zip.sha256})),{name:'OTAFIX-2.4.12-R_recovery.zip',browser_download_url:download+'OTAFIX-2.4.12-R_recovery.zip',size:100,digest:'sha256:'+'c'.repeat(64)}]};
  return {schemaVersion:1,checkedAt,release,manifest};
}
const item=(hardwareId='t1000e',extra={})=>({project:'MeshCore',provider:'Keymind Cascade',architecture:'nrf52',hardware:'Friendly physical board',role:'companionFull',version:'application-version-unchanged',name:`${hardwareId}_companion_radio_full-v1.18.zip`,url:'https://example.test/application.zip',bootloader:['https://flasher.meshcore.io/firmware/old-2.2.zip'],erase:['https://example.test/erase.zip'],releaseNotes:`SETUP - https://mikecarper.github.io/MeshCore/firmware_picker/?hardware=${hardwareId}`,...extra});

test('stable release and manifest retain only exact API-matched normal serial DFU ZIPs',()=>{
  const input=fixture(),before=JSON.stringify(input),checked=validateBootloaderSnapshot(input);
  assert.equal(JSON.stringify(input),before);assert.equal(checked.checkedAt,checkedAt);assert.equal(checked.cached,false);assert.equal(checked.manifest.version,'2.4.12');
  for(const p of checked.manifest.profiles)assert.deepEqual(Object.keys(p.files),['zip']);
  assert.ok(!checked.release.assets.some(a=>/R_recovery|\.uf2$|\.hex$/.test(a.name)));
  assert.equal(bootloaderManifestAsset(checked.release).name,'bootloader-manifest.json');
  assert.deepEqual(validateBootloaderSnapshot(checked),checked);
});

test('release/manifest identity, unique aliases, sizes, digests and exact ZIP names fail closed',()=>{
  for(const change of [
    s=>s.checkedAt='yesterday',s=>s.release.draft=true,s=>s.release.prerelease=true,s=>s.release.tag_name='R_'+tag,
    s=>s.manifest.repository='someone/other',s=>s.manifest.tag='old',s=>s.manifest.version='2.2',s=>s.manifest.prerelease=true,
    s=>s.manifest.profiles[1].meshcoreHardware=['t1000e'],s=>s.manifest.unavailableProfiles[0].meshcoreHardware=['t1000e'],
    s=>s.manifest.profiles[0].files.zip.name='R_'+s.manifest.profiles[0].files.zip.name,
    s=>s.manifest.profiles[0].files.zip.name=s.manifest.profiles[0].files.zip.name.replace('.zip','.uf2'),
    s=>s.manifest.profiles[0].files.zip.url='https://elsewhere.test/image.zip',s=>s.manifest.profiles[0].files.zip.size++,
    s=>s.manifest.profiles[0].files.zip.sha256='d'.repeat(64),s=>s.release.assets.push(clone(s.release.assets[1])),
    s=>s.release.assets[0].digest=null,s=>s.release.assets.push(clone(s.release.assets[0])),s=>s.manifest.unavailableProfiles[0].files={zip:{}}
  ]){const s=fixture();change(s);assert.throws(()=>validateBootloaderSnapshot(s));}
});

test('exact trusted setup and role-boundary filename evidence map items without friendly-name guesses',()=>{
  const s=fixture(),source=item(),[mapped]=applyBootloaderCatalog([source],s);
  assert.equal(mapped.url,source.url);assert.equal(mapped.role,source.role);assert.equal(mapped.version,source.version);assert.deepEqual(mapped.erase,source.erase);
  assert.equal(mapped.bootloader.length,1);assert.equal(mapped.bootloaderInfo.profile,'t1000_e');assert.equal(mapped.bootloaderInfo.hardwareId,'t1000e');assert.equal(mapped.bootloaderInfo.sha256,'b'.repeat(64));assert.equal(mapped.bootloaderInfo.version,'2.4.12');
  assert.equal(applyBootloaderCatalog([item('t1000e',{provider:'MeshCore',releaseNotes:''})],s)[0].bootloaderInfo.profile,'t1000_e');
  for(const source of [item('unknown',{hardware:'Seeed Studio SenseCAP T1000-E'}),item('unknown',{name:'t1000e_companionish.zip',releaseNotes:''}),item('unknown',{name:'t1000e_companion_radio_full.zip',releaseNotes:'SETUP - https://mikecarper.github.io/MeshCore/firmware_picker/?hardware=Heltec_tower_v2_sdcard'}),item('unknown',{name:'unknown.zip',releaseNotes:'SETUP - https://attacker.test/MeshCore/firmware_picker/?hardware=t1000e'})]){
    const [blocked]=applyBootloaderCatalog([source],s);assert.deepEqual(blocked.bootloader,[]);assert.ok(blocked.bootloaderUnavailable);assert.equal(blocked.bootloaderInfo,undefined);
  }
});

test('Tower profiles stay artifact-specific and unavailable profiles clear stale wrong-board recommendations',()=>{
  const sameFriendly={hardware:'Heltec MeshTower V2'},[retired,normal,pending]=applyBootloaderCatalog([item('Heltec_tower_v2',sameFriendly),item('Heltec_tower_v2_sdcard',sameFriendly),item('ThinkNode_M4')],fixture());
  assert.deepEqual(retired.bootloader,[]);assert.match(retired.bootloaderUnavailable,/Retired/);assert.equal(normal.bootloaderInfo.profile,'heltec_mesh_tower_v2_sdcard');assert.deepEqual(pending.bootloader,[]);assert.match(pending.bootloaderUnavailable,/qualified/);
});

test('unverified releases disable automatic nRF52 links and old embedded notices, not firmware or other chips',()=>{
  const source=item('t1000e',{notice:'Install https://flasher.meshcore.io/firmware/old-2.2.zip first',bootloaderInfo:{version:'2.2'}}),esp={...source,architecture:'esp32'},[blocked,same]=applyBootloaderCatalog([source,esp]);
  assert.deepEqual(blocked.bootloader,[]);assert.equal(blocked.bootloaderInfo,undefined);assert.ok(!blocked.notice.includes('old-2.2'));assert.equal(blocked.url,source.url);assert.equal(same,esp);
  const [fresh]=applyBootloaderCatalog([source],fixture());assert.ok(fresh.notice.includes(fresh.bootloaderInfo.url));assert.ok(!fresh.notice.includes('old-2.2'));
  const [restored]=applyBootloaderCatalog([blocked],fixture());assert.ok(restored.notice.includes(restored.bootloaderInfo.url));
});

test('build fetches latest manifest with explicit asset digest/size and caches only verified fork data',async()=>{
  const s=fixture(),seen=[],config={device:[{name:'T1000-E',type:'nrf52',firmware:[{role:'companionFull',version:{v1:{notes:item().releaseNotes,files:[{name:item().name,url:item().url,type:'flash'}]}}}]}]};
  const result=await buildCatalog({now:()=>checkedAt,readJson:async(url,options)=>{seen.push([url,options]);if(url===BOOTLOADER_LATEST_URL)return s.release;if(url===download+'bootloader-manifest.json')return s.manifest;if(url.includes('/git/trees/'))return{tree:[]};if(url.includes('raw.githubusercontent.com/'))return config;throw Error('official offline');}});
  assert.equal(result.bootloaderCatalog.manifest.version,'2.4.12');assert.ok(result.items.every(i=>i.bootloaderInfo?.profile==='t1000_e'));
  assert.deepEqual(seen.find(([url])=>url===download+'bootloader-manifest.json')[1],{sha256:'a'.repeat(64),size:12345});
  const cached=await buildCatalog({previous:async()=>result,readJson:async()=>{throw Error('all offline');}});
  assert.equal(cached.bootloaderCatalog.cached,true);assert.ok(cached.items.every(i=>i.bootloaderInfo?.cached===true));assert.ok(cached.warnings.some(w=>w.includes('last verified')&&w.includes('latest release could not be checked')));
});

test('a failed latest check without verified cache never restores legacy upstream bootloader recommendations',async()=>{
  const previous={generatedAt:checkedAt,warnings:[],items:[item('t1000e',{provider:'MeshCore'})]},result=await buildCatalog({previous:async()=>previous,readJson:async()=>{throw Error('offline');}});
  assert.equal(result.bootloaderCatalog,null);assert.equal(result.items.length,1);assert.deepEqual(result.items[0].bootloader,[]);assert.ok(result.items[0].bootloaderUnavailable);assert.equal(result.items[0].url,previous.items[0].url);
});

test('offline browser cache marks verified bootloaders last-known and rejects invalid release snapshots',async()=>{
  const raw={generatedAt:checkedAt,warnings:[],bootloaderCatalog:{...fixture(),cached:false},items:[item()]},offline=async()=>{throw Error('offline');};
  const cached=await getCatalog({fetchImpl:offline,storage:{getItem:()=>JSON.stringify(raw)}});
  assert.equal(cached.cached,true);assert.equal(cached.bootloaderCatalog.cached,true);assert.equal(cached.items[0].bootloaderInfo.cached,true);
  assert.equal(cached.items[0].bootloaderInfo.version,'2.4.12');assert.deepEqual(cached.items[0].bootloader,[raw.bootloaderCatalog.manifest.profiles[0].files.zip.url]);
  assert.ok(!JSON.stringify(cached).includes('old-2.2.zip'));assert.equal(raw.bootloaderCatalog.cached,false);
  const invalid=clone(raw);invalid.bootloaderCatalog.manifest.profiles[0].files.zip.sha256='e'.repeat(64);
  await assert.rejects(()=>getCatalog({fetchImpl:offline,storage:{getItem:()=>JSON.stringify(invalid)}}),/Choose a local firmware file/);
});

test('production JSON fetch checks raw bytes and exact asset size before parsing',async()=>{
  const bytes=new TextEncoder().encode('{ "value": 1 }\n'),sha256=createHash('sha256').update(bytes).digest('hex'),url=download+'bootloader-manifest.json',fetchImpl=async()=>new Response(bytes);
  assert.deepEqual(await json(url,{sha256,size:bytes.length,fetchImpl}),{value:1});
  await assert.rejects(()=>json(url,{sha256:'a'.repeat(64),size:bytes.length,fetchImpl}),/SHA-256/);
  await assert.rejects(()=>json(url,{sha256,size:bytes.length-1,fetchImpl}),/exceeds/);
  await assert.rejects(()=>json(url,{sha256,size:bytes.length+1,fetchImpl}),/size or SHA-256/);
  await assert.rejects(()=>json(url,{sha256,size:0,fetchImpl}),/bounds/);
});
