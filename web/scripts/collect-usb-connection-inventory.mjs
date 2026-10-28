// Public source/build provenance only. Does not run PlatformIO or access USB.
import {readFile,writeFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

export const repository='https://github.com/mikecarper/MeshCore';
const releaseVersion='v1.18.0.1-halo-keymind-cascade-dev-03214a16';
export const manifestTags=Object.freeze(['','lora-ota-','lora-ota-2-','lora-ota-3-','full-profiles-'].map(prefix=>prefix+releaseVersion));
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const sourcePattern=/^SOURCE - https:\/\/github\.com\/mikecarper\/MeshCore\/tree\/([a-f0-9]{40})\s*$/m;
const exactPattern=/^EXACT TARGET - ([A-Za-z0-9_.+-]+)\. Match/m;
const publicSource={repository,revision:'03214a16df2bd09d3272dfb001d2d322c6740f60'};
// Exact bytes were size/SHA-256 checked against GitHub release metadata, then
// the embedded literal was read from firmware.bin (DFU) or the raw app image.
// These samples verify both canonical conventions alongside the pinned builder;
// they are not claims that arbitrary environment overrides are impossible.
export const runtimeEvidence=Object.freeze([
  {runtimeVersion:releaseVersion,url:repository+'/releases/download/lora-ota-3-'+releaseVersion+'/t1000e_sensor_lora_ota_no_external_sensors-full-ota-'+releaseVersion+'.zip',size:427599,sha256:'3249786bf8b829c3228819979aeed75e2432cc3838a4a5e7e11eca4e51cfeb6c',component:'firmware.bin',container:'legacy-nrf52-dfu-zip',scope:'verified embedded literal sample plus pinned release builder'},
  {runtimeVersion:'v1.18.0.1-halo-keymind-cascade-dev-observer-03214a16',url:repository+'/releases/download/full-profiles-'+releaseVersion+'/LilyGo_TLora_V2_1_1_6_repeater_observer_mqtt_-full-usb-wifi-ota-'+releaseVersion+'.bin',size:1881720,sha256:'31a1b21502676ddb3e6fe9270a9305a6c09a51414fe5a01554e656c9bc40a5c7',component:'application image',container:'esp32-application-bin',scope:'verified embedded literal sample plus pinned release builder'}
]);

export function verifyManifest(bytes,metadata){
  if(!Number.isSafeInteger(metadata?.size)||metadata.size<=0||metadata.size>(2<<20)||!/^[a-f0-9]{64}$/.test(metadata.sha256||''))throw Error('Invalid public manifest bounds');
  if(bytes.length!==metadata.size||hash(bytes)!==metadata.sha256)throw Error('Public manifest size/SHA-256 mismatch');
  const records=JSON.parse(Buffer.from(bytes).toString('utf8'));
  if(!Array.isArray(records)||records.length>2000)throw Error('Invalid public target manifest');
  for(const record of records)if(!record||record.source_commit!==publicSource.revision||typeof record.target!=='string'||typeof record.artifact_target!=='string'||typeof record.platformio_env!=='string'||!Array.isArray(record.files))throw Error('Public target manifest has incomplete provenance');
  return records;
}

// Stock build.sh places this same value in both filenames and FIRMWARE_VERSION.
export function stockRuntimeVersion(filename,buildScript){
  if(!buildScript.includes('FIRMWARE_VERSION_STRING="${FIRMWARE_VERSION}-${COMMIT_HASH}"')||!buildScript.includes('FIRMWARE_FILENAME="$1-${FIRMWARE_VERSION_STRING}"')||!buildScript.includes('-DFIRMWARE_VERSION='))return null;
  const stem=filename.replace(/\.(?:bin|zip|uf2)$/i,'').replace(/-merged$/,'');
  return stem.match(/-(v?\d+(?:\.\d+){2,3}[^/]*-[a-f0-9]{7,40})$/i)?.[1]||null;
}

export function keymindRuntimeVersion(version,record,buildScript){
  // Only this exact published release's normal/observer conventions have byte
  // evidence above. Do not synthesize a runtime suffix for other/custom builds.
  if(version!==releaseVersion||record.source_commit!==publicSource.revision||!buildScript.includes('get_firmware_version_string()')||!buildScript.includes('channel_tag="-observer${OTA_CHANNEL_TAG:+-${OTA_CHANNEL_TAG}}"')||!buildScript.includes('"${version}${build_suffix}${channel_tag}-${commit_hash}"'))return null;
  const suffix='-'+record.source_commit.slice(0,8);
  if(!version.endsWith(suffix))return null;
  return record.platformio_env.includes('observer')?version.slice(0,-suffix.length)+'-observer'+suffix:version;
}

function identity(item){return {provider:item.provider,hardware:item.hardware,architecture:item.architecture,role:item.role,version:item.version,artifact:item.name};}

/** Injected inputs make the collector testable without network or a checkout. */
export function buildInventory({catalog,manifests,resolveRevision,sourceText,sourceEnvironments,previews=[]}){
  if(!Array.isArray(catalog?.items)||!Array.isArray(manifests))throw Error('Invalid inventory inputs');
  const items=[],unresolved=[],files=new Map(),sourceCache=new Map(),envCache=new Map();
  const text=(revision,file)=>{const key=revision+':'+file;if(!sourceCache.has(key))sourceCache.set(key,sourceText(revision,file));return sourceCache.get(key);};
  const envs=revision=>{if(!envCache.has(revision))envCache.set(revision,new Set(sourceEnvironments(revision)));return envCache.get(revision);};
  for(const manifest of manifests)for(const record of manifest.records){
    if(record.source_commit!==publicSource.revision)throw Error('Manifest source does not match the pinned release');
    if(!envs(record.source_commit).has(record.platformio_env))throw Error('Manifest environment is not in its source revision');
    for(const artifact of record.files){
      const prior=files.get(artifact);
      if(prior&&JSON.stringify(prior.record)!==JSON.stringify(record))throw Error('Conflicting published artifact provenance');
      files.set(artifact,{record,manifest});
    }
  }
  for(const item of catalog.items){
    const base=identity(item);
    if(item.provider==='Keymind Cascade'){
      const entry=files.get(item.name),declared=item.releaseNotes?.match(sourcePattern)?.[1],target=item.releaseNotes?.match(exactPattern)?.[1];
      if(!entry||declared!==entry.record.source_commit||target!==entry.record.target){unresolved.push({...base,reason:'No exact published manifest/source/target join'});continue;}
      const {record,manifest}=entry;
      items.push({...base,runtimeVersion:keymindRuntimeVersion(item.version,record,text(record.source_commit,'build_legacy.sh')),source:{...publicSource},target:record.target,environment:record.platformio_env,profile:record.build_profile,manifestSha256:manifest.sha256});
    }else if(item.provider==='MeshCore'){
      const stem=item.name.replace(/\.(?:bin|zip|uf2)$/i,'').replace(/-merged$/,''),match=stem.match(/^(.*?)-(v?\d+(?:\.\d+){2,3}[^/]*-([a-f0-9]{7,40}))$/i);
      if(!match){unresolved.push({...base,reason:'Artifact has no published source-commit suffix'});continue;}
      let revision;try{revision=resolveRevision(match[3]);}catch{}
      if(!/^[a-f0-9]{40}$/.test(revision||'')||!revision.startsWith(match[3])||!envs(revision).has(match[1])){unresolved.push({...base,reason:'Source revision or exact environment could not be proven'});continue;}
      items.push({...base,runtimeVersion:stockRuntimeVersion(item.name,text(revision,'build.sh')),source:{repository:'https://github.com/meshcore-dev/MeshCore',revision},target:match[1],environment:match[1],profile:'standard'});
    }else unresolved.push({...base,reason:'Provider source publication is not reviewed'});
  }
  for(const preview of previews){
    if(!envs(preview.source.revision).has(preview.environment))throw Error('Preview environment missing from exact public source');
    items.push({...preview,artifact:null});
  }
  items.sort((a,b)=>a.provider.localeCompare(b.provider)||a.version.localeCompare(b.version)||a.hardware.localeCompare(b.hardware)||a.artifact?.localeCompare(b.artifact||'')||0);
  return {schemaVersion:1,runtimeEvidence:runtimeEvidence.map(item=>({...item})),catalogGeneratedAt:catalog.generatedAt,items,unresolved,manifests:manifests.map(({url,size,sha256})=>({url,size,sha256}))};
}

export function checkoutReader(checkout){
  const git=(...args)=>execFileSync('git',['-C',checkout,...args],{encoding:'utf8',maxBuffer:16<<20}).trim();
  const revisions=new Map();
  return {resolveRevision:prefix=>{if(!revisions.has(prefix))revisions.set(prefix,git('rev-parse','--verify',prefix+'^{commit}'));return revisions.get(prefix);},sourceText:(revision,file)=>git('show',revision+':'+file),sourceEnvironments:revision=>[...git('grep','-h','-E','^\\[env:',revision,'--','*.ini').matchAll(/^\[env:([^\]]+)\]/gm)].map(match=>match[1])};
}

export async function collectInventory({catalogPath=new URL('../public/catalog.json',import.meta.url),checkout='C:/git/MeshCore',fetchImpl=fetch,includePreviews=true}={}){
  const catalog=JSON.parse(await readFile(catalogPath,'utf8')),reader=checkoutReader(checkout);
  const manifests=await Promise.all(manifestTags.map(async tag=>{
    const release=JSON.parse(execFileSync('gh',['release','view',tag,'--repo','mikecarper/MeshCore','--json','assets'],{encoding:'utf8',maxBuffer:8<<20}));
    const asset=release.assets.find(asset=>asset.name==='TARGET-MANIFEST.json');if(!asset)throw Error('Missing pinned public target manifest');
    const metadata={url:asset.url,size:asset.size,sha256:String(asset.digest).replace(/^sha256:/,'')},response=await fetchImpl(metadata.url,{signal:AbortSignal.timeout(30000)});if(!response.ok)throw Error('Manifest download HTTP '+response.status);
    return {...metadata,records:verifyManifest(new Uint8Array(await response.arrayBuffer()),metadata)};
  }));
  const previews=[];
  if(includePreviews){
    const revision='eab29a12cd65adb89be36ccdf15441cb74a497ed',proof=JSON.parse(execFileSync('gh',['api','repos/mikecarper/MeshCore/commits/'+revision,'--jq','{sha,html_url}'],{encoding:'utf8'}));
    if(proof.sha!==revision)throw Error('Public preview source not verified');
    // Exact runtime/model evidence was captured in the browser's read-only V4
    // session before this inventory; no additional models or roles are inferred.
    previews.push({provider:'Keymind Cascade',hardware:'Heltec v4',architecture:'esp32',role:'repeater',version:'v1.18.0.2-halo-keymind-cascade-dev-observer-eab29a12',runtimeVersion:'v1.18.0.2-halo-keymind-cascade-dev-observer-eab29a12',source:{repository,revision},target:'heltec_v4_repeater_observer_mqtt',environment:'heltec_v4_repeater_observer_mqtt',profile:'full',evidence:{sourceUrl:proof.html_url,runtime:'Read-only Heltec V4.2 none detected browser report; Build: 27-Oct-2026',publication:'public source; observed preview, not a published release asset'}});
  }
  return buildInventory({catalog,manifests,...reader,previews});
}

if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  const args=process.argv.slice(2),output=args.find(arg=>arg.startsWith('--output='))?.slice(9),checkout=args.find(arg=>arg.startsWith('--checkout='))?.slice(11)||'C:/git/MeshCore';
  const inventory=await collectInventory({checkout});
  if(output){await writeFile(output,JSON.stringify(inventory,null,2)+'\n');console.log(`Inventory: ${inventory.items.length} proven input rows; ${inventory.unresolved.length} unresolved; ${inventory.manifests.length} verified public manifests.`);}
  else process.stdout.write(JSON.stringify(inventory,null,2)+'\n');
}
