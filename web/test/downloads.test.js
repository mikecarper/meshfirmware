import test from 'node:test';
import assert from 'node:assert/strict';
import {gzipSync} from 'node:zlib';
import {readFile,mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,dirname,basename} from 'node:path';
import {createServer,build} from 'vite';
import {hash} from '../src/firmware.js';
import {fetchFirmwareBytes,validateMirrorIndex,MAX_FIRMWARE_BYTES,MAX_MIRROR_INDEX_BYTES} from '../src/downloads.js';

const base=new URL('https://flasher.test/meshfirmware/firmware/');
const source='https://github.com/mikecarper/MeshCore/releases/download/full-v1.18.0/board_repeater-v1.18.0.zip';
const alternate='https://github.com/meshcore-dev/MeshCore/releases/download/repeater-v1.17.1/second.zip';
const clone=value=>structuredClone(value);
function fixture(raw=new TextEncoder().encode('verified public firmware\0\xc0\xdb')){
  const gzip=new Uint8Array(gzipSync(raw,{level:9})),sha256=hash(raw),entry={url:source,sha256,size:raw.length,gzipSha256:hash(gzip),gzipSize:gzip.length,path:sha256+'.gz'};
  return {raw,gzip,entry,index:{schemaVersion:1,generatedAt:'2026-10-27T12:00:00.000Z',entries:[entry],warnings:[]}};
}
function response(bytes,{status=200,url='',headers={},chunkSize=bytes.length||1,streamError=null}={}){
  let at=0;const calls={cancel:0,release:0,read:0,bodyCancel:0};
  return {ok:status>=200&&status<300,status,url,headers:{get:key=>Object.entries(headers).find(([name])=>name.toLowerCase()===key.toLowerCase())?.[1]??null},calls,body:{
    async cancel(){calls.bodyCancel++;},
    getReader(){return {async read(){calls.read++;if(streamError)throw streamError;if(at>=bytes.length)return {done:true};const value=bytes.subarray(at,at+chunkSize);at+=value.length;return {value,done:false};},async cancel(){calls.cancel++;},releaseLock(){calls.release++;}};}
  }};
}
const jsonResponse=(value,options)=>response(new TextEncoder().encode(JSON.stringify(value)),options);
function workbench(f=fixture(),{index=f.index,asset=f.gzip,direct=f.raw,indexResponse=null,assetResponse=null}={}){
  const calls=[];
  const fetchImpl=async(url,options)=>{
    calls.push({url:String(url),options});
    if(String(url)===new URL('index.json',base).href)return typeof indexResponse==='function'?indexResponse():indexResponse||jsonResponse(index);
    if(String(url)===new URL(f.entry.path,base).href)return typeof assetResponse==='function'?assetResponse():assetResponse||response(asset);
    return response(direct);
  };
  return {calls,fetchImpl,get:(url=source,extra={})=>fetchFirmwareBytes(url,{fetchImpl,mirrorBase:base,pageOrigin:base.origin,...extra})};
}

test('verified same-origin mirror bytes download automatically with no direct GitHub request',async()=>{
  const f=fixture(),w=workbench(f);const result=await w.get(source,{expectedSha256:f.entry.sha256});
  assert.deepEqual(result,f.raw);assert.deepEqual(w.calls.map(call=>call.url),[new URL('index.json',base).href,new URL(f.entry.path,base).href]);
  for(const call of w.calls){assert.equal(call.options.credentials,'omit');assert.equal(call.options.mode,'same-origin');assert.ok(call.options.signal instanceof AbortSignal);assert.ok(!('headers' in call.options));}
});

function multipartFixture(){
  const a=fixture(new TextEncoder().encode('public migration prefix')),b=fixture(new Uint8Array(2048).fill(17)),raw=new Uint8Array([...a.raw,...b.raw,...a.raw]);
  const {url,...prefix}=a.entry,{url:unused,...payload}=b.entry;
  const entry={url:source,sha256:hash(raw),size:raw.length,parts:[prefix,payload,prefix]};
  return {raw,entry,index:{schemaVersion:1,entries:[entry],warnings:[]},parts:new Map([[prefix.path,a],[payload.path,b]])};
}

test('multipart firmware reconstructs the exact original ZIP using only verified same-origin parts',async()=>{
  const f=multipartFixture(),calls=[];
  const fetchImpl=async(url,options)=>{calls.push({url,options});if(url.endsWith('/index.json'))return jsonResponse(f.index);return response(f.parts.get(url.split('/').at(-1)).gzip);};
  assert.deepEqual(await fetchFirmwareBytes(source,{fetchImpl,mirrorBase:base,pageOrigin:base.origin,expectedSha256:f.entry.sha256}),f.raw);
  assert.equal(calls.length,4);assert.ok(calls.every(call=>call.url.startsWith(base.href)&&call.options.mode==='same-origin'&&call.options.credentials==='omit'));
  const index=validateMirrorIndex(f.index);assert.ok(Object.isFrozen(index.entries[0].parts));assert.ok(Object.isFrozen(index.entries[0].parts[0]));
});

test('multipart boundaries, part corruption and final release digest cannot weaken download validation',async()=>{
  for(const change of [entry=>entry.parts=[],entry=>entry.parts=[entry.parts[0]],entry=>entry.parts=Array(129).fill(entry.parts[0]),entry=>entry.parts[0].path='../other.gz',entry=>entry.parts[0].size++,entry=>entry.path='a'.repeat(64)+'.gz']){
    const f=multipartFixture();change(f.entry);assert.throws(()=>validateMirrorIndex(f.index),/mirror/i);
  }
  for(const failure of ['part','aggregate','order']){
    const f=multipartFixture();if(failure==='aggregate')f.entry.sha256='a'.repeat(64);if(failure==='order')f.entry.parts.reverse(),[f.entry.parts[0],f.entry.parts[1]]=[f.entry.parts[1],f.entry.parts[0]];
    const calls=[],fetchImpl=async url=>{calls.push(url);if(url.endsWith('/index.json'))return jsonResponse(f.index);const data=f.parts.get(url.split('/').at(-1)).gzip.slice();if(failure==='part')data[12]^=1;return response(data);};
    await assert.rejects(fetchFirmwareBytes(source,{fetchImpl,mirrorBase:base,pageOrigin:base.origin}),/SHA-256/);assert.ok(calls.every(url=>url.startsWith(base.href)),'Never fall back to unverified direct bytes');
  }
});

test('exact migration discovery metadata downloads from the same public mirror without GitHub API access',async()=>{
  const f=fixture(new TextEncoder().encode(JSON.stringify({tag_name:'utility-v1.18.0',assets:[]}))),metadata='https://api.github.com/repos/mikecarper/MeshCore/releases/tags/utility-v1.18.0';
  f.entry.url=metadata;const w=workbench(f);assert.deepEqual(await w.get(metadata),f.raw);assert.equal(w.calls.length,2);assert.ok(w.calls.every(call=>call.url.startsWith(base.href)));
  for(const url of [metadata+'?token=secret',metadata.replace('mikecarper','someone'),metadata.replace('/utility-v','/v')]){const invalid=clone(f.index);invalid.entries[0].url=url;assert.throws(()=>validateMirrorIndex(invalid),/mirror/i);}
});

test('mirror lookup binds the complete original URL, never another board or a similar filename',async()=>{
  const f=fixture(),w=workbench(f);await w.get(alternate,{expectedSha256:hash(f.raw)});await w.get(source);
  assert.deepEqual(w.calls.map(call=>call.url),[new URL('index.json',base).href,alternate,new URL(f.entry.path,base).href]);
  assert.equal(w.calls[1].options.credentials,'omit');assert.equal(w.calls[1].options.mode,undefined);
  const sameName=source.replace('/mikecarper/MeshCore/','/other/repository/');const next=workbench(f);await next.get(sameName);assert.equal(next.calls.at(-1).url,sameName);
});

test('successful index loading is shared across simultaneous requests and exact source aliases',async()=>{
  const f=fixture();f.index.entries.push({...f.entry,url:alternate});const w=workbench(f);
  const [a,b]=await Promise.all([w.get(),w.get(alternate)]);assert.deepEqual(a,f.raw);assert.deepEqual(b,f.raw);
  assert.equal(w.calls.filter(call=>call.url.endsWith('/index.json')).length,1);assert.equal(w.calls.filter(call=>call.url.endsWith('.gz')).length,2);
});

test('each page revalidates the mutable index while content-addressed gzip assets keep ordinary caching',async()=>{
  const f=fixture(),w=workbench(f);await w.get();await w.get();
  const indexes=w.calls.filter(call=>call.url.endsWith('/index.json')),assets=w.calls.filter(call=>call.url.endsWith('.gz'));
  assert.equal(indexes.length,1,'The in-memory promise still shares the index for this page');assert.equal(indexes[0].options.cache,'no-cache');
  for(const asset of assets){assert.equal(asset.options.cache,undefined);assert.equal(asset.options.credentials,'omit');assert.equal(asset.options.mode,'same-origin');}
  const nextPage=workbench(f);await nextPage.get();assert.equal(nextPage.calls[0].options.cache,'no-cache');
});

test('Vite dev and production preserve the project-relative firmware directory and its trailing slash',async()=>{
  const sourceText=await readFile(new URL('../src/downloads.js',import.meta.url),'utf8');
  const snippet=sourceText.slice(0,sourceText.indexOf('const indexCaches')).replace(/^import .*;\r?\n/gm,'').replace('const defaultMirrorBase=','export const defaultMirrorBase=');
  const directory=/const mirrorDirectory\s*=\s*(['"])(.*?)\1/.exec(snippet)?.[2];assert.equal(directory,'../firmware/');
  const root=await mkdtemp(join(tmpdir(),'meshfirmware-download-bundle-'));let server;
  try{
    await mkdir(join(root,'src'));await mkdir(join(root,'public','firmware'),{recursive:true});
    await writeFile(join(root,'public','firmware','index.json'),'{}');await writeFile(join(root,'src','downloads.js'),snippet);
    server=await createServer({configFile:false,root,logLevel:'silent',server:{middlewareMode:true,watch:null},optimizeDeps:{noDiscovery:true,include:[]}});
    const dev=await server.transformRequest('/src/downloads.js');assert.match(dev.code,/new URL\(mirrorDirectory,\s*import\.meta\.url\)/);
    const output=await build({configFile:false,root,logLevel:'silent',base:'./',build:{write:false,minify:false,rollupOptions:{input:join(root,'src','downloads.js'),preserveEntrySignatures:'strict'}}});
    const chunk=output.output.find(item=>item.type==='chunk');assert.match(chunk.code,/new URL\((?:mirrorDirectory|["']\.\.\/firmware\/["']),\s*import\.meta\.url\)/);
    for(const location of ['https://example.test/meshfirmware/assets/app.js','https://example.test/meshfirmware/src/downloads.js'])assert.equal(new URL(directory,location).href,'https://example.test/meshfirmware/firmware/');
  }finally{
    await server?.close();
    assert.equal(dirname(resolve(root)),resolve(tmpdir()));assert.ok(basename(root).startsWith('meshfirmware-download-bundle-'));
    await rm(root,{recursive:true,force:true});
  }
});

test('standard HTTP gzip decoding still verifies the exact authoritative raw asset size and SHA',async()=>{
  const f=fixture(new Uint8Array(4096).fill(17));assert.ok(f.gzip.length<f.raw.length,'This covers the larger browser-decoded body');
  for(const withLength of [true,false]){
    const asset=response(f.raw,{chunkSize:33,headers:{'Content-Encoding':'gzip',...(withLength?{'Content-Length':String(f.entry.gzipSize)}:{})}}),w=workbench(f,{assetResponse:asset});
    assert.deepEqual(await w.get(source,{expectedSha256:f.entry.sha256}),f.raw);assert.equal(w.calls.length,2);assert.equal(asset.calls.cancel,1);assert.equal(asset.calls.release,1);
  }
  const rawBad=f.raw.slice();rawBad[0]^=1;const wrong=workbench(f,{assetResponse:response(rawBad,{headers:{'Content-Encoding':'gzip','Content-Length':String(f.entry.gzipSize)}})});
  await assert.rejects(wrong.get(),/HTTP-decoded.*SHA-256/);assert.equal(wrong.calls.length,2);
});

test('HTTP gzip preserves encoded header bounds, raw body bounds and compressed proof when exposed',async()=>{
  const f=fixture(new Uint8Array(4096).fill(17));
  const badLength=response(f.raw,{headers:{'Content-Encoding':'gzip','Content-Length':String(f.entry.gzipSize+1)}}),header=workbench(f,{assetResponse:badLength});
  await assert.rejects(header.get(),/size|Content-Length/);assert.equal(badLength.calls.bodyCancel,1);assert.equal(header.calls.length,2);
  const short=workbench(f,{assetResponse:response(f.raw.subarray(1),{headers:{'Content-Encoding':'gzip'}})});await assert.rejects(short.get(),/HTTP-decoded.*size or SHA-256/);assert.equal(short.calls.length,2);
  const over=response(new Uint8Array(f.raw.length+1),{headers:{'Content-Encoding':'gzip'},chunkSize:31}),oversize=workbench(f,{assetResponse:over});await assert.rejects(oversize.get(),error=>error.downloadKind==='size');assert.equal(over.calls.cancel,1);assert.equal(over.calls.release,1);
  // An additional HTTP gzip layer can expose the approved gzip file itself.
  const encoded=workbench(f,{assetResponse:response(f.gzip,{headers:{'Content-Encoding':'gzip','Content-Length':String(f.entry.gzipSize)}})});assert.deepEqual(await encoded.get(),f.raw);
  const crcCorrupt=f.gzip.slice();crcCorrupt[crcCorrupt.length-8]^=1;
  for(const headers of [{},{'Content-Encoding':'gzip'}]){
    const corrupt=workbench(f,{assetResponse:response(crcCorrupt,{headers})});await assert.rejects(corrupt.get(),/SHA-256/);assert.equal(corrupt.calls.length,2,'Corruption never falls back to an unverified source');
  }
  // Without an HTTP decoding header, raw bytes cannot bypass compressed proof.
  const undeclared=workbench(f,{assetResponse:response(f.raw)});await assert.rejects(undeclared.get(),/size|compressed SHA-256/);
});

test('unsupported HTTP encodings and native gzip-decoder errors fail closed',async()=>{
  const f=fixture();
  for(const encoding of ['br','deflate','gzip, gzip','compress']){
    const asset=response(f.raw,{headers:{'Content-Encoding':encoding}}),w=workbench(f,{assetResponse:asset});await assert.rejects(w.get(),/unsupported HTTP content encoding/);assert.equal(asset.calls.bodyCancel,1);assert.equal(asset.calls.read,0);assert.equal(w.calls.length,2);
  }
  const asset=response(f.raw,{headers:{'Content-Encoding':'gzip'},streamError:new TypeError('Native HTTP gzip decoder rejected CRC')}),w=workbench(f,{assetResponse:asset});
  await assert.rejects(w.get(),/rejected CRC/);assert.equal(asset.calls.cancel,1);assert.equal(asset.calls.release,1);assert.equal(w.calls.length,2);
});

test('missing or unavailable mirror indexes fall back to the original HTTPS source and can be retried',async()=>{
  for(const unavailable of [()=>response(new Uint8Array(),{status:404}),()=>response(new Uint8Array(),{status:503}),()=>{throw new TypeError('Network unavailable');}]){
    const f=fixture(),w=workbench(f,{indexResponse:unavailable});assert.deepEqual(await w.get(),f.raw);assert.deepEqual(await w.get(),f.raw);
    assert.deepEqual(w.calls.map(call=>call.url),[new URL('index.json',base).href,source,new URL('index.json',base).href,source]);
  }
});

test('index and asset paths cannot be redirected to another origin or unrelated same-origin endpoint',async()=>{
  const f=fixture();
  for(const url of ['https://evil.test/index.json','https://flasher.test/another/index.json']){
    const w=workbench(f,{indexResponse:jsonResponse(f.index,{url})});await assert.rejects(w.get(),/mirror redirected/);assert.equal(w.calls.length,1);
  }
  const w=workbench(f,{assetResponse:response(f.gzip,{url:'https://evil.test/firmware.gz'})});await assert.rejects(w.get(),/mirror redirected/);assert.equal(w.calls.length,2);
});

test('pure index validation returns immutable normalized public metadata and permits consistent digest aliases',()=>{
  const f=fixture();f.index.entries.push({...f.entry,url:alternate});f.index.buildStats={ignored:true};
  const before=JSON.stringify(f.index),index=validateMirrorIndex(f.index,{mirrorBase:base});assert.equal(JSON.stringify(f.index),before);assert.equal(index.entries.length,2);
  assert.ok(Object.isFrozen(index));assert.ok(Object.isFrozen(index.entries));assert.ok(Object.isFrozen(index.entries[0]));assert.deepEqual(index.warnings,[]);assert.equal(index.buildStats,undefined);
  assert.throws(()=>{index.entries[0].path='untrusted.zip';},TypeError);
});

test('malformed mirror indexes, paths, source URLs, ambiguous entries and unbounded sizes fail closed',()=>{
  const f=fixture();
  const mutations=[
    index=>index.schemaVersion=2,index=>index.entries={},index=>index.warnings='warning',index=>index.warnings=[null],index=>index.generatedAt='not a date',
    index=>index.entries[0].path='../private.json',index=>index.entries[0].path='https://evil.test/file.gz',index=>index.entries[0].path='other.gz',
    index=>index.entries[0].sha256='A'.repeat(64),index=>index.entries[0].gzipSha256='invalid',index=>index.entries[0].size=0,index=>index.entries[0].size=MAX_FIRMWARE_BYTES+1,index=>index.entries[0].size=1.5,
    index=>index.entries[0].gzipSize=19,index=>index.entries[0].gzipSize=MAX_FIRMWARE_BYTES+1,index=>index.entries[0].url='http://github.com/a/b/releases/download/v1/file.zip',
    index=>index.entries[0].url='https://u:p@github.com/a/b/releases/download/v1/file.zip',index=>index.entries[0].url='https://elsewhere.test/a.zip',index=>index.entries[0].url=source+'?token=not-allowed',index=>index.entries[0].url=source+'#not-allowed',
    index=>index.entries[0].url='https://github.com/releases/download/v1/board.zip',index=>index.entries.push({...index.entries[0]}),
    index=>index.entries.push({...index.entries[0],url:alternate,gzipSha256:'a'.repeat(64)}),index=>index.entries=Array(10001).fill(index.entries[0])
  ];
  for(const mutate of mutations){const input=clone(f.index);mutate(input);assert.throws(()=>validateMirrorIndex(input),/mirror|HTTPS/i);}
});

test('present invalid JSON or metadata never silently falls back to direct download; failed caches can recover',async()=>{
  const f=fixture();let valid=false;
  const w=workbench(f,{indexResponse:()=>valid?jsonResponse(f.index):response(new TextEncoder().encode('{malformed'))});
  await assert.rejects(w.get(),error=>error.downloadKind==='mirror'&&/valid UTF-8 JSON/.test(error.message));assert.equal(w.calls.length,1);
  valid=true;assert.deepEqual(await w.get(),f.raw);assert.equal(w.calls.length,3);
  const bad=clone(f.index);bad.entries[0].path='../escape.gz';const broken=workbench(f,{index:bad});await assert.rejects(broken.get(),/Invalid firmware mirror entry/);assert.equal(broken.calls.length,1);
});

test('mirror manifests are bounded by both declared and actual stream lengths',async()=>{
  const f=fixture();
  const declared=response(new Uint8Array(),{headers:{'Content-Length':String(MAX_MIRROR_INDEX_BYTES+1)}}),a=workbench(f,{indexResponse:declared});
  await assert.rejects(a.get(),error=>error.downloadKind==='size');assert.equal(declared.calls.bodyCancel,1);assert.equal(a.calls.length,1);
  const actual=response(new Uint8Array(MAX_MIRROR_INDEX_BYTES+1),{chunkSize:65536}),b=workbench(f,{indexResponse:actual});
  await assert.rejects(b.get(),error=>error.downloadKind==='size');assert.equal(actual.calls.cancel,1);assert.equal(actual.calls.release,1);assert.equal(b.calls.length,1);
});

test('a selected published digest must agree with the mirror before any binary download',async()=>{
  const f=fixture(),w=workbench(f);await assert.rejects(w.get(source,{expectedSha256:'a'.repeat(64)}),/differs from the selected catalog/);assert.equal(w.calls.length,1);
  const uppercase=workbench(f);assert.deepEqual(await uppercase.get(source,{expectedSha256:f.entry.sha256.toUpperCase()}),f.raw);
});

test('compressed and raw SHA-256 mismatches fail closed without trying another source',async()=>{
  const f=fixture(),bad=f.gzip.slice();bad[10]^=1;
  const a=workbench(f,{asset:bad});await assert.rejects(a.get(),/compressed SHA-256/);assert.equal(a.calls.length,2);
  const index=clone(f.index);index.entries[0].sha256='b'.repeat(64);index.entries[0].path='b'.repeat(64)+'.gz';
  const changed={...f,entry:index.entries[0]},b=workbench(changed,{index});await assert.rejects(b.get(),/raw size or SHA-256/);assert.equal(b.calls.length,2);
});

test('mirror response lengths and malformed gzip cannot weaken the verified output bounds',async()=>{
  const f=fixture();
  for(const asset of [f.gzip.subarray(0,f.gzip.length-1),new Uint8Array([...f.gzip,0])]){
    const w=workbench(f,{asset});await assert.rejects(w.get(),/length|size/);assert.equal(w.calls.length,2);
  }
  const lengthMismatch=response(f.gzip,{headers:{'Content-Length':String(f.gzip.length-1)}}),a=workbench(f,{assetResponse:lengthMismatch});await assert.rejects(a.get(),/Content-Length/);assert.equal(lengthMismatch.calls.bodyCancel,1);
  for(const mutate of [gzip=>gzip[0]=0,gzip=>gzip[2]=0,gzip=>gzip[3]=8,gzip=>gzip[gzip.length-4]^=1]){
    const gzip=f.gzip.slice();mutate(gzip);const index=clone(f.index);index.entries[0].gzipSha256=hash(gzip);const w=workbench(f,{index,asset:gzip});await assert.rejects(w.get(),/gzip header or output size/);assert.equal(w.calls.length,2);
  }
});

test('a forged small gzip output size cannot cause an unbounded decompression',async()=>{
  const f=fixture(new Uint8Array(1<<20)),gzip=f.gzip.slice(),index=clone(f.index);const declared=16;
  new DataView(gzip.buffer).setUint32(gzip.length-4,declared,true);index.entries[0].size=declared;index.entries[0].gzipSha256=hash(gzip);
  const w=workbench(f,{index,asset:gzip});await assert.rejects(w.get(),/decompression exceeds its verified size/);assert.equal(w.calls.length,2);
});

test('original direct downloads retain HTTP, byte-limit, missing-body and SHA checks',async()=>{
  const f=fixture(),index={...f.index,entries:[]};
  for(const [direct,kind]of [[response(new Uint8Array(),{status:404}),'http'],[response(new Uint8Array(),{headers:{'Content-Length':String(MAX_FIRMWARE_BYTES+1)}}),'size'],[{ok:true,status:200,headers:{get:()=>null},body:null},'body']]){
    const calls=[],fetchImpl=async(url,opts)=>{calls.push({url,opts});return String(url).endsWith('/index.json')?jsonResponse(index):direct;};
    await assert.rejects(fetchFirmwareBytes(source,{fetchImpl,mirrorBase:base}),error=>error.downloadKind===kind);assert.equal(calls.length,2);assert.equal(calls[1].opts.credentials,'omit');
  }
  const w=workbench(f,{index});await assert.rejects(w.get(source,{expectedSha256:'a'.repeat(64)}),error=>error.downloadKind==='hash');assert.equal(w.calls.length,2);
});

test('stream failures release readers and never turn a present mirror into another download',async()=>{
  const f=fixture(),asset=response(f.gzip,{streamError:new TypeError('Disconnected')}),w=workbench(f,{assetResponse:asset});
  await assert.rejects(w.get(),/Disconnected/);assert.equal(asset.calls.cancel,1);assert.equal(asset.calls.release,1);assert.equal(w.calls.length,2);
});

test('the mirror directory must be same-origin and cannot carry credentials, a query or another protocol',async()=>{
  const f=fixture();
  for(const mirrorBase of ['https://evil.test/firmware/','https://u:p@flasher.test/meshfirmware/firmware/','https://flasher.test/meshfirmware/firmware/?token=x','https://flasher.test/meshfirmware/firmware/#x','file:///tmp/firmware/','http://untrusted.test/firmware/','https://flasher.test/other/']){
    const w=workbench(f);await assert.rejects(w.get(source,{mirrorBase,pageOrigin:base.origin}),/same-origin|origin/);assert.equal(w.calls.length,0);
  }
});

test('only HTTPS original sources and well-formed expected hashes are accepted before any request',async()=>{
  for(const [url,expectedSha256]of [['http://example.test/x.zip',''],['https://u:p@example.test/x.zip',''],['file:///x.zip',''],[source,'invalid'],[source,null]]){
    const w=workbench();await assert.rejects(w.get(url,{expectedSha256}),/HTTPS|SHA-256/);assert.equal(w.calls.length,0);
  }
});
