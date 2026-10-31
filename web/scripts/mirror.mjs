// Build-time PUBLIC firmware mirror. Never enumerate device files or backups.
import {mkdir,readFile,writeFile,readdir,lstat,unlink,rename} from 'node:fs/promises';
import {resolve,basename,dirname,join} from 'node:path';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {gzipSync,gunzipSync} from 'node:zlib';
import {matchesCatalogInstallMode} from '../src/automatic.js';
import {catalogProvider,compareVersions} from '../src/catalog.js';
import {validateMirrorIndex,mirrorParts,MAX_MIRROR_INDEX_BYTES} from '../src/downloads.js';
import {publicEraseUtility} from '../src/public-erase-utilities.js';
import {migrationMetadataSource,isMigrationArchive} from '../src/migration-sources.js';
import {inspectFirmware} from '../src/firmware.js';
import {splitMigrationArchive} from './migration-parts.mjs';

export const MIRROR_MAX_ASSET_BYTES=64<<20;
export const MIRROR_MAX_BYTES=850<<20;
const MAX_SOURCES=4096,MAX_RELEASES=128,MAX_METADATA_BYTES=16<<20;
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const sha=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
// Current archives and their discovery metadata are required together. The
// separate older USB set is a fallback for legacy packages, not a dependency
// of every current (embedded-USB) archive; retain its existing availability
// warning when that independent old release is absent.
const requiredMigration=source=>['migration','migration-metadata'].includes(source.kind);
class Unavailable extends Error {}
class IntegrityError extends Error {}
const invariant=(condition,message)=>{if(!condition)throw new IntegrityError(message);};

// Public GitHub release routes use authoritative repository/release metadata.
// Only the separate exact, pinned erase registry permits a static-host asset.
// No arbitrary origin, query, userinfo, local path or private download qualifies.
export function githubAsset(value){
  let url;try{url=new URL(value);}catch{return null;}
  if(url.protocol!=='https:'||url.hostname!=='github.com'||url.port||url.username||url.password||url.search||url.hash)return null;
  const match=/^\/([A-Za-z0-9_.-]{1,100})\/([A-Za-z0-9_.-]{1,100})\/releases\/download\/([^/]+)\/([^/]+)$/.exec(url.pathname);
  if(!match)return null;
  let tag,name;try{tag=decodeURIComponent(match[3]);name=decodeURIComponent(match[4]);}catch{return null;}
  if(!tag||tag.length>256||!name||name.length>256||/[\x00-\x1f\x7f\\]/.test(tag)||/[\x00-\x1f\x7f\\/]/.test(name)||['.','..'].includes(name)||match[1]==='.'||match[1]==='..'||match[2]==='.'||match[2]==='..')return null;
  return {url:url.href,owner:match[1],repository:match[2],tag,name};
}
function profileKey(item){
  // Strip only this entry's explicitly declared version and its publication
  // hash. Display/radio/storage/full/reduced and merged suffixes remain exact.
  const at=item.name.lastIndexOf(item.version);
  const name=at<0?item.name:item.name.slice(0,at)+'{version}'+item.name.slice(at+item.version.length).replace(/^-[a-f0-9]{7,40}(?=(?:-merged)?\.[^.]+$)/i,'');
  return JSON.stringify([catalogProvider(item.provider),item.hardware,item.architecture,item.role,item.action,name]);
}
function reference(value,kind,priority,evidence={}){
  const utility=kind==='erase'?publicEraseUtility(value):null,asset=githubAsset(value)||utility;if(!asset)return null;
  if(evidence.sha256!==undefined&&!sha(evidence.sha256))throw new IntegrityError('Catalog public asset has an invalid SHA-256.');
  if(evidence.size!==undefined&&(!Number.isSafeInteger(evidence.size)||evidence.size<1||evidence.size>MIRROR_MAX_ASSET_BYTES))throw new IntegrityError('Catalog public asset has an invalid size.');
  if(utility){
    invariant(!evidence.sha256||evidence.sha256===utility.sha256,'Catalog SHA-256 conflicts with the pinned erase utility.');
    invariant(!evidence.size||evidence.size===utility.size,'Catalog size conflicts with the pinned erase utility.');
    return {...utility,kind,priority};
  }
  return {...asset,kind,priority,...(evidence.sha256?{sha256:evidence.sha256}:{}),...(evidence.size?{size:evidence.size}:{})};
}
function verifyPinnedEraseBytes(source,raw){
  const utility=source.kind==='erase'?publicEraseUtility(source.url):null;if(!utility)return;
  invariant(source.sha256===utility.sha256&&source.size===utility.size,'Erase utility metadata differs from its exact registry pin.');
  let pkg;try{pkg=inspectFirmware(utility.name,new Uint8Array(raw));}catch{throw new IntegrityError('Pinned erase ZIP failed firmware validation.');}
  invariant(pkg.architecture==='nrf52'&&pkg.kind==='application'&&pkg.erase&&pkg.payloadHash===utility.payloadHash&&/^official (?:SoftDevice v[67] erase payload|QSPI formatter payload\b)/.test(pkg.eraseEvidence||''),'Pinned erase ZIP does not contain its reviewed application utility.');
}
export function selectMirrorSources(catalog){
  invariant(catalog&&Array.isArray(catalog.items)&&catalog.items.length<=50000,'Invalid public mirror catalog.');
  const newest=new Map();
  for(const item of catalog.items){
    if(!matchesCatalogInstallMode(item,'update')&&!matchesCatalogInstallMode(item,'install'))continue;
    const key=profileKey(item),previous=newest.get(key),order=previous?compareVersions(item.version,previous[0].version):-1;
    if(!previous||order<0)newest.set(key,[item]);else if(order===0)previous.push(item);
  }
  const selected=[...newest.values()].flat(),sources=new Map(),utilityReleases=new Map();
  function add(source){
    if(!source)return;
    const previous=sources.get(source.url);
    if(previous){
      invariant(!previous.sha256||!source.sha256||previous.sha256===source.sha256,'Conflicting catalog SHA-256 for one public URL.');
      invariant(!previous.size||!source.size||previous.size===source.size,'Conflicting catalog size for one public URL.');
      sources.set(source.url,{...previous,...source,priority:Math.min(previous.priority,source.priority),sha256:previous.sha256||source.sha256,size:previous.size||source.size});
    }else sources.set(source.url,source);
    invariant(sources.size<=MAX_SOURCES,'Public mirror source limit exceeded.');
  }
  for(const item of selected){
    const keymind=catalogProvider(item.provider)==='Keymind Cascade',merged=item.action==='flash-wipe',priority=1;
    add(reference(item.url,merged?'merged-install':'application',priority,{sha256:item.sha256}));
    for(const url of item.erase||[])add(reference(url,'erase',0));
    for(const url of item.bootloader||[])add(reference(url,'bootloader',0,item.bootloaderInfo?.url===url?item.bootloaderInfo:{}));
    const own=githubAsset(item.url);
    if(keymind&&own?.owner==='mikecarper'&&own.repository==='MeshCore'&&/^v\d+(?:\.\d+){2,3}(?:-[A-Za-z0-9._-]+)?$/.test(item.version)){
      const tag='utility-'+item.version;utilityReleases.set(tag,{owner:own.owner,repository:own.repository,tag,priority:0});
    }
  }
  const bundle=catalog.recoveryCatalog?.bundle;if(bundle)add(reference(bundle.url,'recovery',0,bundle));
  // This exact shared set is needed by reviewed older migration archives.
  if(utilityReleases.size)add(reference('https://github.com/mikecarper/MeshCore/releases/download/utility-usb-partition-v1-3d3d5827/meshcore-usb-partition-bridges.zip','usb-bridge',0,{sha256:'187cac4f3f716d5df50e123a03ba51da637356874a434a72a60d9eb99d988ed8'}));
  return {sources:[...sources.values()].sort((a,b)=>a.priority-b.priority||a.url.localeCompare(b.url)),utilityReleases:[...utilityReleases.values()].sort((a,b)=>a.tag.localeCompare(b.tag)),selectedApplications:selected.length};
}
async function bodyBytes(response,limit,expected){
  if(!response?.ok){try{await response?.body?.cancel?.();}catch{}throw Object.assign(new Unavailable(`HTTP ${response?.status||'unavailable'}`),{status:response?.status});}
  const length=response.headers?.get('content-length');
  if(length!==null&&length!==undefined&&/^\d+$/.test(length)&&Number(length)>limit){try{await response.body?.cancel?.();}catch{}throw new IntegrityError('Public asset response exceeds its byte bound.');}
  invariant(response.body&&typeof response.body.getReader==='function','Public asset has no readable body.');
  const reader=response.body.getReader(),chunks=[];let total=0;
  try{for(;;){const {value,done}=await reader.read();if(done)break;invariant(value instanceof Uint8Array,'Public response contains invalid bytes.');total+=value.length;invariant(total<=limit,'Public asset stream exceeds its byte bound.');chunks.push(value);}}
  catch(error){if(error instanceof IntegrityError)throw error;throw new Unavailable('Network response stream unavailable');}
  finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
  invariant(expected===undefined||total===expected,'Public asset size differs from its verified source.');
  return Buffer.concat(chunks,total);
}
async function outputDirectory(value){
  const output=resolve(value);invariant(basename(output)==='firmware'&&dirname(output)!==output,'Mirror output must be a dedicated firmware directory.');
  await mkdir(output,{recursive:true});
  invariant(!(await lstat(output)).isSymbolicLink(),'Mirror output cannot be a symlink.');
  const files=await readdir(output,{withFileTypes:true});
  for(const file of files)invariant(file.isFile()&&!file.isSymbolicLink()&&/^(?:index\.json|[a-f0-9]{64}\.gz)$/.test(file.name),'Unexpected file in generated firmware directory. Preserve it and repair only this generated mirror directory.');
  let previous=null;
  if(files.some(file=>file.name==='index.json')){
    const target=join(output,'index.json'),stat=await lstat(target);invariant(stat.isFile()&&!stat.isSymbolicLink()&&stat.size>0&&stat.size<=MAX_MIRROR_INDEX_BYTES,'Previous generated mirror index exceeds its safe size.');
    try{previous=validateMirrorIndex(JSON.parse(await readFile(target,'utf8')));}catch{throw new IntegrityError('Previous generated mirror index is invalid; existing files were preserved.');}
  }
  const owned=new Map((previous?.entries||[]).flatMap(entry=>mirrorParts(entry).map(piece=>[piece.path,piece])));
  for(const file of files)if(file.name!=='index.json')invariant(owned.has(file.name),'Unowned hash file in generated firmware directory; existing files were preserved.');
  return {output,owned,previous:new Map((previous?.entries||[]).map(entry=>[entry.url,entry]))};
}
async function cachedGzip(target,source,metadata){
  let stat;try{stat=await lstat(target);}catch(error){if(error.code==='ENOENT')return null;throw error;}
  invariant(stat.isFile()&&!stat.isSymbolicLink()&&stat.size>=20&&stat.size<=MIRROR_MAX_ASSET_BYTES,'Cached public mirror file is not a bounded regular file.');
  if(metadata)invariant(stat.size===metadata.gzipSize,'Cached public mirror size differs from its owned index.');
  const cached=await readFile(target);
  invariant(cached.length===stat.size&&cached[0]===31&&cached[1]===139&&cached[2]===8&&cached[3]===0&&cached.readUInt32LE(cached.length-4)===source.size,'Cached public mirror gzip header or size is invalid.');
  if(metadata)invariant(digest(cached)===metadata.gzipSha256,'Cached public mirror gzip SHA-256 differs from its owned index.');
  let raw;try{raw=gunzipSync(cached,{maxOutputLength:source.size});}catch{throw new IntegrityError('Cached public mirror gzip is corrupt or exceeds its bound.');}
  invariant(raw.length===source.size&&digest(raw)===source.sha256,'Cached public mirror differs from its authoritative source SHA-256.');
  verifyPinnedEraseBytes(source,raw);
  return cached;
}

export async function buildMirror({catalog,outputDir,fetchImpl=fetch,token,maxBytes=MIRROR_MAX_BYTES,concurrency=4,now=()=>new Date().toISOString(),onProgress=()=>{},minimumApplicationRatio=0,requireApplications=false}={}){
  invariant(Number.isSafeInteger(maxBytes)&&maxBytes>0&&maxBytes<=MIRROR_MAX_BYTES,'Mirror budget must be within 850 MiB.');
  invariant(Number.isInteger(concurrency)&&concurrency>=1&&concurrency<=8,'Mirror concurrency must be 1–8.');
  invariant(typeof outputDir==='string'&&typeof fetchImpl==='function'&&typeof onProgress==='function','Missing mirror output or fetch implementation.');
  invariant(token===undefined||typeof token==='string','Invalid API authorization configuration.');
  invariant(typeof minimumApplicationRatio==='number'&&Number.isFinite(minimumApplicationRatio)&&minimumApplicationRatio>=0&&minimumApplicationRatio<=1&&typeof requireApplications==='boolean','Invalid minimum public application coverage.');
  const chosen=selectMirrorSources(catalog),{output,owned,previous}=await outputDirectory(outputDir),warnings=[],releases=new Map(),releaseBytes=new Map(),repositories=new Map();
  const warn=message=>{if(warnings.length<256)warnings.push(message.slice(0,500));};
  async function fetchResponse(url,api=false,exactUtility=false){
    try{const response=await fetchImpl(url,{signal:AbortSignal.timeout(api?45000:120000),credentials:'omit',...(api||exactUtility?{redirect:'error'}:{}),headers:{'User-Agent':'meshfirmware-pages-mirror',...(api&&token?{Authorization:`Bearer ${token}`}:{})}});if(api&&response.url&&response.url!==url)throw new IntegrityError('Authoritative GitHub API metadata redirected away from its exact URL.');if(exactUtility&&response.url&&response.url!==url)throw new IntegrityError('Pinned erase utility redirected away from its exact URL.');return response;}
    catch(error){if(error instanceof IntegrityError)throw error;throw new Unavailable('Network request unavailable');}
  }
  async function publicRepository(source){
    const name=`${source.owner}/${source.repository}`,key=name.toLowerCase();
    if(!repositories.has(key)){
      if(repositories.size>=MAX_RELEASES)throw new Unavailable('Repository metadata request limit reached');
      const url=`https://api.github.com/repos/${source.owner}/${source.repository}`;
      repositories.set(key,(async()=>{
        const raw=await bodyBytes(await fetchResponse(url,true),1<<20);let value;
        try{value=JSON.parse(raw.toString('utf8'));}catch{throw new IntegrityError('GitHub repository metadata is not JSON.');}
        invariant(value&&value.private===false&&value.visibility==='public'&&typeof value.full_name==='string'&&value.full_name.toLowerCase()===key,'Public mirror source repository is private or its public identity is unverified.');
        return true;
      })());
    }
    return repositories.get(key);
  }
  async function release(source){
    await publicRepository(source);
    const key=JSON.stringify([source.owner,source.repository,source.tag]);
    if(!releases.has(key)){
      if(releases.size>=MAX_RELEASES)throw new Unavailable('Release metadata request limit reached');
      const url=`https://api.github.com/repos/${source.owner}/${source.repository}/releases/tags/${encodeURIComponent(source.tag)}`;
      releases.set(key,(async()=>{
        const raw=await bodyBytes(await fetchResponse(url,true),MAX_METADATA_BYTES);let value;
        try{value=JSON.parse(raw.toString('utf8'));}catch{throw new IntegrityError('GitHub release metadata is not JSON.');}
        invariant(value&&value.tag_name===source.tag&&value.draft===false&&Array.isArray(value.assets)&&value.assets.length<=20000,'GitHub release identity or asset inventory is invalid.');
        releaseBytes.set(url,raw);
        return value;
      })());
    }
    return releases.get(key);
  }
  // Utility discovery uses only the native planner's exact release tag; no
  // similarly named board, release or Wi-Fi-only replacement is guessed.
  const candidates=new Map(chosen.sources.map(source=>[source.url,source]));
  for(const utility of chosen.utilityReleases){
    try{
      const value=await release(utility);
      const metadata=migrationMetadataSource(`https://api.github.com/repos/${utility.owner}/${utility.repository}/releases/tags/${utility.tag}`);
      invariant(metadata,'Invalid exact migration metadata source.');
      const raw=releaseBytes.get(metadata.url);
      candidates.set(metadata.url,{...metadata,kind:'migration-metadata',priority:0,sha256:digest(raw),size:raw.length,bytes:raw});
      for(const asset of value.assets){
        if(typeof asset.name!=='string'||!(/-migration\.zip$/i.test(asset.name)||/^meshcore-usb-partition-bridges\.zip$/i.test(asset.name)))continue;
        const source=reference(asset.browser_download_url,'migration',utility.priority);
        invariant(source&&isMigrationArchive(source.url)&&source.owner===utility.owner&&source.repository===utility.repository&&source.tag===utility.tag&&source.name===asset.name,'Utility asset escaped its exact release.');
        candidates.set(source.url,source);
      }
    }catch(error){if(!(error instanceof Unavailable))throw error;invariant(error.status===404,`Partition migration discovery for ${utility.tag} is unavailable: ${error.message}. Keep the existing deployment.`);warn(`Utility release ${utility.tag}: ${error.message}.`);}
  }
  invariant(candidates.size<=MAX_SOURCES,'Public mirror source limit exceeded.');
  const sources=[...candidates.values()].sort((a,b)=>a.priority-b.priority||a.url.localeCompare(b.url)),resolved=[];
  for(const source of sources){
    try{
      const utility=source.kind==='erase'?publicEraseUtility(source.url):null;
      if(source.kind==='migration-metadata'){resolved.push(source);continue;}
      if(utility){
        invariant(source.name===utility.name&&source.sha256===utility.sha256&&source.size===utility.size,'Erase utility source differs from its exact registry pin.');
        resolved.push(source);continue;
      }
      const value=await release(source),matches=value.assets.filter(asset=>asset.name===source.name);
      if(matches.length!==1)throw new Unavailable('Exact release asset is missing or ambiguous');
      const asset=matches[0],actual=githubAsset(asset.browser_download_url);
      invariant(actual?.url===source.url&&actual.owner===source.owner&&actual.repository===source.repository&&actual.tag===source.tag&&actual.name===source.name,'GitHub asset URL differs from its catalog source.');
      if(!/^sha256:[a-f0-9]{64}$/.test(asset.digest||''))throw new Unavailable('GitHub does not expose a SHA-256 digest for this asset');
      invariant(Number.isSafeInteger(asset.size)&&asset.size>0&&asset.size<=MIRROR_MAX_ASSET_BYTES,'GitHub public asset size is invalid or exceeds 64 MiB.');
      const actualHash=asset.digest.slice(7);
      invariant(!source.sha256||source.sha256===actualHash,'Catalog SHA-256 differs from the GitHub release asset.');
      invariant(!source.size||source.size===asset.size,'Catalog size differs from the GitHub release asset.');
      resolved.push({...source,size:asset.size,sha256:actualHash});
    }catch(error){if(!(error instanceof Unavailable))throw error;invariant(!requiredMigration(source),`Required partition migration asset ${source.name} is unavailable: ${error.message}.`);warn(`${source.owner}/${source.repository}: ${source.name}: ${error.message}.`);}
  }
  const applicationUrls=new Set(chosen.sources.filter(source=>['application','merged-install'].includes(source.kind)).map(source=>source.url)),appRequested=applicationUrls.size,appResolved=resolved.filter(source=>applicationUrls.has(source.url)).length;
  invariant(!requireApplications||appRequested>0&&appResolved>0,'No verified public application assets are available; existing deployment must be retained.');
  invariant(!appRequested||appResolved/appRequested>=minimumApplicationRatio,'Verified application metadata coverage is below the required deployment threshold.');
  async function download(source){
    try{
      let raw=source.bytes;
      const prior=previous.get(source.url);
      if(!raw&&prior?.sha256===source.sha256&&prior.size===source.size){
        const pieces=[];
        for(const piece of mirrorParts(prior)){
          const cached=await cachedGzip(join(output,piece.path),piece,owned.get(piece.path));
          if(!cached)throw new IntegrityError('Owned public mirror cache is incomplete.');
          pieces.push(gunzipSync(cached,{maxOutputLength:piece.size}));
        }
        raw=Buffer.concat(pieces,source.size);
      }
      if(!raw){
        const utility=source.kind==='erase'?publicEraseUtility(source.url):null,response=await fetchResponse(source.url,false,!!utility);
        if(response.url&&!utility){const final=new URL(response.url);invariant(!final.username&&!final.password&&['https://github.com','https://release-assets.githubusercontent.com','https://objects.githubusercontent.com'].includes(final.origin),'GitHub asset redirected to an unapproved origin.');}
        raw=await bodyBytes(response,source.size,source.size);
      }
      invariant(digest(raw)===source.sha256,'Public asset SHA-256 differs from its verified source.');
      verifyPinnedEraseBytes(source,raw);
      // Keep original bytes: share ZIP_STORED members (including .mota's
      // duplicate app bytes) and the unchanged app after a merged prefix.
      // The browser must reassemble and verify the complete GitHub digest.
      const rawParts=source.kind==='migration'?splitMigrationArchive(raw):source.kind==='merged-install'&&raw.length>0x10000?[raw.subarray(0,0x10000),raw.subarray(0x10000)]:[raw];
      const parts=rawParts.map(bytes=>{const gzip=gzipSync(bytes,{level:9,mtime:0});invariant(gzip.length<=MIRROR_MAX_ASSET_BYTES,'Compressed public asset exceeds 64 MiB.');return {sha256:digest(bytes),size:bytes.length,gzip,gzipSha256:digest(gzip),gzipSize:gzip.length};});
      return {source,parts};
    }catch(error){if(!(error instanceof Unavailable))throw error;return {source,unavailable:error.message};}
  }
  // Bounded look-ahead keeps results deterministic in priority order without
  // holding the entire catalog's uncompressed assets in memory.
  const pending=new Map(),entries=[],files=new Map();let scheduled=0,total=0,skipped=0;
  const schedule=()=>{while(scheduled<resolved.length&&pending.size<concurrency){const index=scheduled++;pending.set(index,download(resolved[index]).then(result=>({result}),error=>({error})));}};
  schedule();
  for(let index=0;index<resolved.length;index++){
    const settled=await pending.get(index);pending.delete(index);if(settled.error)throw settled.error;const result=settled.result;schedule();
    onProgress({completed:index+1,total:resolved.length,entries:entries.length,bytes:total});
    if(result.unavailable){invariant(!publicEraseUtility(result.source.url),`Required pinned erase utility ${result.source.name} is unavailable: ${result.unavailable}.`);invariant(!requiredMigration(result.source),`Required partition migration asset ${result.source.name} is unavailable: ${result.unavailable}.`);warn(`${result.source.name}: ${result.unavailable}.`);continue;}
    const {source,parts}=result,unique=new Map(parts.map(piece=>[piece.sha256+'.gz',piece]));
    const extra=[...unique].reduce((sum,[path,piece])=>sum+(files.has(path)?0:piece.gzipSize),0);
    if(total+extra>maxBytes){invariant(!publicEraseUtility(source.url),'Required pinned erase utility exceeds the public mirror budget.');invariant(!requiredMigration(source)&&source.kind!=='usb-bridge','Required partition migration asset exceeds the public mirror budget.');skipped++;continue;}
    for(const [path,piece] of unique){
      const {gzip,gzipSha256,gzipSize,size}=piece,prior=files.get(path);
      if(prior){invariant(prior.gzipSha256===gzipSha256&&prior.gzipSize===gzipSize&&prior.size===size,'One content hash produced inconsistent mirror bytes.');continue;}
      const target=join(output,path);invariant(dirname(target)===output,'Mirror asset escaped its output directory.');
      const existing=owned.has(path)?await cachedGzip(target,piece,owned.get(path)):null;
      if(existing)invariant(digest(existing)===gzipSha256,'Existing generated firmware asset is corrupt.');else await writeFile(target,gzip,{flag:'wx'});
      total+=gzipSize;files.set(path,{gzipSha256,gzipSize,size});
    }
    const references=parts.map(({sha256,size,gzipSha256,gzipSize})=>({sha256,size,gzipSha256,gzipSize,path:sha256+'.gz'}));
    entries.push({url:source.url,sha256:source.sha256,size:source.size,...(parts.length===1?references[0]:{parts:references})});
  }
  const appMirrored=entries.filter(entry=>applicationUrls.has(entry.url)).length;
  invariant(!requireApplications||appMirrored>0,'No verified public application payloads were mirrored; existing deployment must be retained.');
  invariant(!appRequested||appMirrored/appRequested>=minimumApplicationRatio,'Mirrored application coverage is below the required deployment threshold.');
  if(skipped)warn(`${skipped} optional public assets did not fit the ${maxBytes} byte mirror budget; direct/manual download remains available for those exact files.`);
  invariant(entries.length<=MAX_SOURCES,'Public mirror index entry limit exceeded.');
  const index={schemaVersion:1,generatedAt:now(),entries,warnings};
  invariant(typeof index.generatedAt==='string'&&Number.isFinite(Date.parse(index.generatedAt)),'Invalid mirror generation timestamp.');
  validateMirrorIndex(index);const serialized=JSON.stringify(index);invariant(Buffer.byteLength(serialized)<=MAX_MIRROR_INDEX_BYTES,'Generated public mirror index exceeds its byte bound.');
  // Remove only checked, content-addressed generated files, never recurse and
  // never use user paths/globs. Unknown files and symlinks were refused above.
  for(const [file,entry] of owned)if(!files.has(file)){const target=join(output,file);invariant(dirname(target)===output,'Unsafe stale mirror asset.');const exists=await cachedGzip(target,{size:entry.size,sha256:entry.sha256},entry);if(exists)await unlink(target);}
  const temporary=join(output,'index.json.pending');
  try{await writeFile(temporary,serialized,{flag:'wx'});await rename(temporary,join(output,'index.json'));}
  finally{try{await unlink(temporary);}catch(error){if(error.code!=='ENOENT')throw error;}}
  return {index,bytes:total,files:files.size,selectedApplications:chosen.selectedApplications,requestedSources:sources.length,skipped,appRequested,appResolved,appMirrored};
}

if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  const catalog=JSON.parse(await readFile(new URL('../public/catalog.json',import.meta.url),'utf8'));
  const result=await buildMirror({catalog,outputDir:fileURLToPath(new URL('../public/firmware/',import.meta.url)),token:process.env.GITHUB_TOKEN,requireApplications:true,minimumApplicationRatio:0.9,onProgress:({completed,total,bytes})=>{if(completed%25===0||completed===total)console.log(`Mirroring public assets: ${completed}/${total}; ${(bytes/(1<<20)).toFixed(1)} MiB.`);}});
  console.log(`Public firmware mirror: ${result.index.entries.length} URLs, ${result.files} hash-addressed files, ${(result.bytes/(1<<20)).toFixed(1)} MiB; applications ${result.appMirrored}/${result.appRequested}; ${result.index.warnings.length} warnings.`);
  for(const warning of result.index.warnings.slice(0,12))console.warn(warning);
}
