import {Gunzip} from 'fflate';
import {hash} from './firmware.js';
import {publicEraseUtility} from './public-erase-utilities.js';

export const MAX_FIRMWARE_BYTES=64<<20;
export const MAX_MIRROR_INDEX_BYTES=4<<20;
const MAX_MIRROR_ENTRIES=10000;
// Keep this as a runtime directory URL. Vite rewrites a literal directory URL
// to a public asset path without its trailing slash, breaking project Pages.
const mirrorDirectory='../firmware/';
const defaultMirrorBase=new URL(mirrorDirectory,import.meta.url);
const indexCaches=new WeakMap();
const digest=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const size=value=>Number.isSafeInteger(value)&&value>0&&value<=MAX_FIRMWARE_BYTES;
const error=(message,downloadKind='mirror')=>Object.assign(new Error(message),{downloadKind});

function https(value){
  if(typeof value!=='string'||value.length>4096)throw error('Invalid firmware download URL.','url');
  let url;try{url=new URL(value);}catch{throw error('Invalid firmware download URL.','url');}
  if(url.protocol!=='https:'||url.username||url.password)throw error('Firmware URLs must use HTTPS without credentials.','url');
  return url;
}
function releaseUrl(value){
  if(publicEraseUtility(value))return value;
  const url=https(value);
  if(url.origin!=='https://github.com'||url.search||url.hash||!/^\/[^/]+\/[^/]+\/releases\/download\/[^/]+\/[^/]+$/.test(url.pathname)||url.href!==value)throw error('Mirror entry is not an exact public release asset or pinned erase utility URL.');
  return url.href;
}
function mirrorBaseUrl(value,pageOrigin){
  let url;try{url=new URL(value);}catch{throw error('Invalid same-origin firmware mirror directory.');}
  const localHttp=url.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(url.hostname);
  if((url.protocol!=='https:'&&!localHttp)||url.username||url.password||url.search||url.hash||!url.pathname.endsWith('/firmware/'))throw error('Invalid same-origin firmware mirror directory.');
  if(pageOrigin&&url.origin!==pageOrigin)throw error('The firmware mirror must use this page’s origin.');
  return url;
}

// Both the browser and the public-artifact boundary check use this validator.
// A URL identifies the source; only a digest can identify a local mirror file.
export function validateMirrorIndex(value,{mirrorBase}={}){
  if(!value||value.schemaVersion!==1||!Array.isArray(value.entries)||value.entries.length>MAX_MIRROR_ENTRIES||!Array.isArray(value.warnings)||value.warnings.length>MAX_MIRROR_ENTRIES||value.warnings.some(w=>typeof w!=='string'||w.length>4096))throw error('Invalid firmware mirror index.');
  if(value.generatedAt!==undefined&&(typeof value.generatedAt!=='string'||value.generatedAt.length>64||!Number.isFinite(Date.parse(value.generatedAt))))throw error('Invalid firmware mirror timestamp.');
  const base=mirrorBase===undefined?null:mirrorBaseUrl(mirrorBase),urls=new Set(),paths=new Map();
  const entries=value.entries.map(entry=>{
    if(!entry||!digest(entry.sha256)||!digest(entry.gzipSha256)||!size(entry.size)||!size(entry.gzipSize)||entry.gzipSize<20||entry.path!==`${entry.sha256}.gz`)throw error('Invalid firmware mirror entry size, hash or path.');
    const url=releaseUrl(entry.url),utility=publicEraseUtility(url);
    if(utility&&(entry.sha256!==utility.sha256||entry.size!==utility.size))throw error('Public erase utility differs from its pinned ZIP size or SHA-256.');
    if(urls.has(url))throw error('Ambiguous duplicate URL in firmware mirror index.');urls.add(url);
    const result={url,sha256:entry.sha256,size:entry.size,gzipSha256:entry.gzipSha256,gzipSize:entry.gzipSize,path:entry.path};
    const identity=JSON.stringify([result.sha256,result.size,result.gzipSha256,result.gzipSize]);
    if(paths.has(result.path)&&paths.get(result.path)!==identity)throw error('Conflicting content-addressed firmware mirror entries.');paths.set(result.path,identity);
    if(base){const target=new URL(result.path,base);if(target.origin!==base.origin||target.pathname!==base.pathname+result.path)throw error('Firmware mirror path escapes its directory.');}
    return Object.freeze(result);
  });
  return Object.freeze({schemaVersion:1,...(value.generatedAt===undefined?{}:{generatedAt:value.generatedAt}),entries:Object.freeze(entries),warnings:Object.freeze([...value.warnings])});
}

async function boundedDownload(url,{fetchImpl,maxBytes=MAX_FIRMWARE_BYTES,expectedSize,sameOrigin=false,timeoutMs=120000,cache,decodedGzipSize}={}){
  const response=await fetchImpl(url,{credentials:'omit',signal:AbortSignal.timeout(timeoutMs),...(sameOrigin?{mode:'same-origin'}:{}),...(cache?{cache}:{})});
  let httpGzip=false,bodySize=expectedSize,bodyLimit=maxBytes;
  try{
    if(!response.ok)throw error(`Download host returned HTTP ${response.status}.`,'http');
    if(sameOrigin&&response.url){let finalUrl;try{finalUrl=new URL(response.url).href;}catch{throw error('Invalid firmware mirror response URL.');}if(finalUrl!==url)throw error('The firmware mirror redirected away from its exact same-origin asset.');}
    const declared=response.headers.get('Content-Length');
    if(declared!==null&&(!/^\d+$/.test(declared)||!Number.isSafeInteger(Number(declared))||Number(declared)>maxBytes))throw error('Firmware download exceeds its permitted size.','size');
    if(expectedSize!==undefined&&declared!==null&&Number(declared)!==expectedSize)throw error('Firmware mirror Content-Length does not match its verified size.');
    if(decodedGzipSize!==undefined){
      const encoding=(response.headers.get('Content-Encoding')||'identity').trim().toLowerCase();
      if(!['identity','gzip'].includes(encoding))throw error('Firmware mirror uses an unsupported HTTP content encoding.');
      if(encoding==='gzip'){
        // Fetch exposes decoded bytes but Content-Length still describes the
        // encoded transfer. Keep that header bound above and bound the exposed
        // body separately by the two exact, already validated sizes.
        httpGzip=true;bodySize=undefined;bodyLimit=Math.max(maxBytes,decodedGzipSize);
      }
    }
    if(!response.body?.getReader)throw error('Download has no readable response body.','body');
  }catch(cause){try{await response.body?.cancel?.();}catch{/* Preserve the primary size/HTTP/integrity error. */}throw cause;}
  const reader=response.body.getReader(),chunks=bodySize===undefined?[]:null,result=bodySize===undefined?null:new Uint8Array(bodySize);let total=0;
  try{
    for(;;){
      const {value,done}=await reader.read();if(done)break;
      if(!(value instanceof Uint8Array))throw error('Download has an invalid response stream.','body');
      if(total+value.length>bodyLimit||(bodySize!==undefined&&total+value.length>bodySize))throw error('Firmware download exceeds its permitted size.','size');
      if(result)result.set(value,total);else chunks.push(value);total+=value.length;
    }
  }finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
  let bytes=result;
  if(bodySize!==undefined){if(total!==bodySize)throw error('Firmware mirror download length does not match its verified size.');}
  else {bytes=new Uint8Array(total);let at=0;for(const chunk of chunks){bytes.set(chunk,at);at+=chunk.length;}}
  return decodedGzipSize===undefined?bytes:{bytes,httpGzip};
}

async function loadIndex(base,fetchImpl){
  let cache=indexCaches.get(fetchImpl);if(!cache){cache=new Map();indexCaches.set(fetchImpl,cache);}
  const key=base.href;if(cache.has(key))return cache.get(key);
  const pending=(async()=>{
    let bytes;
    try{bytes=await boundedDownload(new URL('index.json',base).href,{fetchImpl,maxBytes:MAX_MIRROR_INDEX_BYTES,sameOrigin:true,timeoutMs:45000,cache:'no-cache'});}
    catch(cause){if(!cause.downloadKind||cause.downloadKind==='http')cause.mirrorUnavailable=true;throw cause;}
    let parsed;try{parsed=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{throw error('Firmware mirror index is not valid UTF-8 JSON.');}
    const index=validateMirrorIndex(parsed,{mirrorBase:base});return new Map(index.entries.map(entry=>[entry.url,entry]));
  })();
  cache.set(key,pending);
  try{return await pending;}catch(cause){if(cache.get(key)===pending)cache.delete(key);throw cause;}
}

function unpackMirror(gzip,entry){
  if(hash(gzip)!==entry.gzipSha256)throw error('Firmware mirror compressed SHA-256 does not match its verified index.');
  // The build emits one ordinary gzip member with no optional filename/header
  // data. Check its declared output size before allocating or decompressing.
  if(gzip.length<20||gzip[0]!==31||gzip[1]!==139||gzip[2]!==8||gzip[3]!==0||new DataView(gzip.buffer,gzip.byteOffset,gzip.byteLength).getUint32(gzip.length-4,true)!==entry.size)throw error('Firmware mirror gzip header or output size is invalid.');
  const result=new Uint8Array(entry.size);let total=0,finished=false;
  try{
    const gunzip=new Gunzip((chunk,final)=>{
      if(total+chunk.length>entry.size||total+chunk.length>MAX_FIRMWARE_BYTES)throw error('Firmware mirror decompression exceeds its verified size.');
      result.set(chunk,total);total+=chunk.length;finished ||= final;
    });
    // Tiny compressed chunks limit temporary inflater allocations even when
    // a malicious stream greatly exceeds its declared output size.
    for(let at=0;at<gzip.length;at+=1024)gunzip.push(gzip.subarray(at,Math.min(at+1024,gzip.length)),at+1024>=gzip.length);
  }catch(cause){if(cause.downloadKind)throw cause;throw error('Firmware mirror gzip data could not be decompressed.');}
  if(!finished||total!==entry.size||hash(result)!==entry.sha256)throw error('Firmware mirror raw size or SHA-256 does not match the selected release asset.');
  return result;
}

// Mirrored bytes still pass through the ordinary firmware/container/board
// validators. This helper never opens USB, authorizes a write or uses a proxy.
export async function fetchFirmwareBytes(url,{expectedSha256='',fetchImpl=fetch,mirrorBase=defaultMirrorBase,pageOrigin=globalThis.location?.origin}={}){
  const source=https(url).href,utility=publicEraseUtility(source);
  if(typeof fetchImpl!=='function')throw error('A firmware download fetch function is required.','url');
  if(typeof expectedSha256!=='string'||expectedSha256&&!/^[a-f0-9]{64}$/i.test(expectedSha256))throw error('Invalid expected firmware SHA-256.','hash');
  if(utility&&expectedSha256&&expectedSha256.toLowerCase()!==utility.sha256)throw error('Selected erase utility SHA-256 differs from its pinned public ZIP.','hash');
  const expected=utility?.sha256||expectedSha256.toLowerCase(),base=mirrorBaseUrl(mirrorBase,pageOrigin);let index;
  try{index=await loadIndex(base,fetchImpl);}catch(cause){if(!cause.mirrorUnavailable)throw cause;}
  const entry=index?.get(source);
  if(entry){
    if(expected&&entry.sha256!==expected)throw error('Firmware mirror SHA-256 differs from the selected catalog release.');
    const {bytes,httpGzip}=await boundedDownload(new URL(entry.path,base).href,{fetchImpl,maxBytes:entry.gzipSize,expectedSize:entry.gzipSize,decodedGzipSize:entry.size,sameOrigin:true});
    // A static host can serve the .gz file with Content-Encoding:gzip, which
    // makes the browser decode it before JavaScript can inspect compressed
    // bytes. The authoritative raw GitHub digest and exact size ALWAYS apply.
    // If encoded bytes remain exposed (including an extra HTTP gzip wrapper),
    // their exact compressed digest must still pass before our own inflater.
    if(httpGzip&&bytes.length===entry.size&&hash(bytes)===entry.sha256)return bytes;
    if(httpGzip&&(bytes.length!==entry.gzipSize||hash(bytes)!==entry.gzipSha256))throw error('HTTP-decoded firmware mirror raw size or SHA-256 does not match the selected release asset.');
    return unpackMirror(bytes,entry);
  }
  const bytes=await boundedDownload(source,{fetchImpl,...(utility?{maxBytes:utility.size,expectedSize:utility.size}:{})});
  if(expected&&hash(bytes)!==expected)throw error('Published SHA-256 does not match the downloaded firmware.','hash');
  return bytes;
}
