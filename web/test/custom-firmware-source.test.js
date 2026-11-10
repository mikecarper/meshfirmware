import test from 'node:test';
import assert from 'node:assert/strict';
import {hash} from '../src/firmware.js';
import {findFirmwareSources} from '../src/downloads.js';
import {resolveCustomFirmwareName} from '../src/custom-firmware.js';

const base=new URL('https://flasher.test/meshfirmware/firmware/');
const version='v1.18.0.1-halo-keymind-cascade-dev',commit='03214a16';
const name=`heltec_v4_repeater-full-usb-wifi-ota-${version}-${commit}.bin`;
const release=name=>`https://github.com/mikecarper/MeshCore/releases/download/full-profiles-${version}-${commit}/${name}`;
function fixture(){
  const payload=new Uint8Array(512),at=payload.length-56,v=new DataView(payload.buffer);
  payload[0]=0xe9;payload[12]=9;payload.set(new TextEncoder().encode('EndF'),at);v.setUint32(at+4,at,true);
  payload.set(Uint8Array.from(hash(payload.subarray(0,at)).slice(0,16).match(/../g),b=>parseInt(b,16)),at+8);
  v.setUint32(at+16,0x01120001,true);v.setUint32(at+20,0x12345678,true);payload.set(new TextEncoder().encode('Heltec_v4'),at+24);
  const sha256=hash(payload),pkg={name:'my-renamed-firmware.bin',architecture:'esp32',chipId:9,merged:false,expert:false,payload,sha256,payloadHash:sha256};
  const source={url:release(name),sha256,size:payload.length};
  const item={...source,name,project:'MeshCore',provider:'Keymind Cascade',architecture:'esp32',action:'flash-update',role:'repeater'};
  return {pkg,source,item};
}
function mirror(entries){
  return {schemaVersion:1,entries:entries.map(entry=>({...entry,path:entry.sha256+'.gz',gzipSha256:'a'.repeat(64),gzipSize:32})),warnings:[]};
}
function indexReader(index,options={}){
  const calls=[];
  const fetchImpl=async(url,request)=>{
    calls.push({url,request});
    if(options.reject)throw options.reject;
    const response=new Response(JSON.stringify(index),{status:options.status||200,headers:{'Content-Type':'application/json'}});
    if(options.redirect)Object.defineProperty(response,'url',{value:options.redirect});
    return response;
  };
  return {calls,options:{fetchImpl,mirrorBase:base,pageOrigin:base.origin}};
}

test('local source lookup sends only one bounded same-origin index GET and never uploads the hash or image',async()=>{
  const {source}=fixture(),other={...source,url:source.url.replace(name,'other.bin'),sha256:'b'.repeat(64)},reader=indexReader(mirror([source,other]));
  const results=await findFirmwareSources({sha256:source.sha256.toUpperCase(),size:source.size},reader.options);
  assert.deepEqual(results,[source]);assert.ok(Object.isFrozen(results));assert.ok(Object.isFrozen(results[0]));
  assert.equal(reader.calls.length,1);assert.equal(reader.calls[0].url,new URL('index.json',base).href);
  const request=reader.calls[0].request;
  assert.equal(request.credentials,'omit');assert.equal(request.mode,'same-origin');assert.equal(request.cache,'no-cache');
  assert.ok(request.signal instanceof AbortSignal);assert.equal(request.body,undefined);
  assert.equal(request.headers,undefined);assert.ok(!reader.calls[0].url.includes(source.sha256));
});

test('source lookup requires exact whole-asset size/hash and cannot match a chunk inside a merged image',async()=>{
  const {source}=fixture(),part={sha256:source.sha256,size:source.size,path:source.sha256+'.gz',gzipSha256:'a'.repeat(64),gzipSize:32};
  const index={schemaVersion:1,entries:[{url:source.url,sha256:'b'.repeat(64),size:source.size*2,parts:[part,part]}],warnings:[]};
  const reader=indexReader(index);
  assert.deepEqual(await findFirmwareSources({sha256:source.sha256,size:source.size},reader.options),[]);
  const wrongSize=indexReader(mirror([source]));
  assert.deepEqual(await findFirmwareSources({sha256:source.sha256,size:source.size+1},wrongSize.options),[]);
});

test('invalid index, off-origin redirect and invalid request never become trusted provenance',async()=>{
  const {source}=fixture();
  for(const [value,options,pattern] of [[{schemaVersion:1,entries:[],warnings:[null]}, {}, /index/],
    [mirror([source]),{redirect:'https://other.test/firmware/index.json'},/redirect/],
    [mirror([source]),{status:503},/HTTP 503/]]){
    const reader=indexReader(value,options);
    await assert.rejects(findFirmwareSources(source,reader.options),pattern);
  }
  const reader=indexReader(mirror([source]));
  for(const input of [{sha256:'bad',size:source.size},{sha256:source.sha256,size:0},{sha256:source.sha256,size:65<<20}])
    await assert.rejects(findFirmwareSources(input,reader.options),/SHA-256 or size/);
  await assert.rejects(findFirmwareSources(source,{...reader.options,pageOrigin:'https://different.test'}),/page’s origin/);
  assert.equal(reader.calls.length,0);
});

test('renamed byte-identical published app resolves without changing original display filename or bytes',async()=>{
  const {pkg,item}=fixture(),snapshot=pkg.payload.slice();let fetched=false;
  const result=await resolveCustomFirmwareName(pkg,[item],{findSources:async()=>{fetched=true;return[];}});
  assert.equal(result.name,name);assert.equal(result.url,item.url);assert.equal(result.source,'catalog-sha256');
  assert.equal(result.firmwareVersion,version);assert.equal(result.sourceCommit,commit);
  assert.ok(Object.isFrozen(result));assert.equal(fetched,false);
  assert.equal(pkg.name,'my-renamed-firmware.bin');assert.deepEqual(pkg.payload,snapshot);
  assert.equal(pkg.sha256,hash(snapshot));
});

test('when the catalog lacks a digest, provenance uses the validated same-origin mirror index',async()=>{
  const {pkg,source,item}=fixture(),reader=indexReader(mirror([source]));
  const result=await resolveCustomFirmwareName(pkg,[{...item,sha256:undefined}],reader.options);
  assert.equal(result.name,name);assert.equal(result.source,'same-origin-mirror-sha256');
  assert.equal(reader.calls.length,1);assert.ok(reader.calls.every(call=>call.url===new URL('index.json',base).href));
});

test('name/model alone and a renamed modified image cannot grant publication provenance',async()=>{
  const {pkg,item,source}=fixture();
  const sameName={...pkg,name};
  assert.equal(await resolveCustomFirmwareName(sameName,[{...item,sha256:undefined}],{findSources:async()=>[]}),null);
  const modified={...pkg,payload:pkg.payload.slice()};modified.payload[100]^=1;
  await assert.rejects(resolveCustomFirmwareName(modified,[item]),/immutable SHA-256/);
  const updated={...pkg,payload:pkg.payload.slice()};updated.payload[100]^=1;
  updated.sha256=updated.payloadHash=hash(updated.payload);
  let called=false;
  assert.equal(await resolveCustomFirmwareName(updated,[item],{findSources:async()=>{called=true;return[source];}}),null);
  assert.equal(called,false,'A corrupt EndF cannot trigger network provenance lookup');
});

test('merged, expert, non-ESP and missing EndF images cannot use application migration provenance',async()=>{
  const {pkg,item}=fixture();let calls=0;const options={findSources:async()=>{calls++;return[];}};
  for(const candidate of [{...pkg,merged:true},{...pkg,expert:true},{...pkg,architecture:'nrf52'},{...pkg,architecture:'uf2'}])
    assert.equal(await resolveCustomFirmwareName(candidate,[item],options),null);
  const plain={...pkg,payload:new Uint8Array(256)};plain.sha256=plain.payloadHash=hash(plain.payload);
  assert.equal(await resolveCustomFirmwareName(plain,[item],options),null);assert.equal(calls,0);
});

test('foreign repositories, components, unsafe paths and filename versions conflicting with EndF are ignored',async()=>{
  const {pkg,source}=fixture();
  const urls=[source.url.replace('/mikecarper/','/somebody/'),source.url+'?key=secret',source.url+'#hint',
    source.url.replace(name,encodeURIComponent('../'+name)),source.url.replace(name,name.replace('repeater','companion_radio_full')),
    source.url.replace(name,name.replace('.bin','-merged.bin')),source.url.replace(name,name.replace('.bin','-factory.bin')),
    source.url.replace(name,name.replace('1.18.0.1','1.17.1.9')),source.url.replace(name,'bootloader-'+name)];
  for(const url of urls)assert.equal(await resolveCustomFirmwareName(pkg,[],{findSources:async()=>[{...source,url}]}),null,url);
});

test('matching aliases must agree on release identity and hardware-role before deterministic selection',async()=>{
  const {pkg,source,item}=fixture(),aliasName=name.replace('full-usb-wifi','full-logging'),alias={...source,url:release(aliasName)};
  const result=await resolveCustomFirmwareName(pkg,[],{findSources:async()=>[source,alias]});
  assert.equal(result.name,[name,aliasName].sort((a,b)=>a.localeCompare(b))[0]);
  for(const otherName of [name.replace(commit,'abcdef12'),name.replace('heltec_v4','Station_G2'),name.replace('repeater','sensor')])
    await assert.rejects(resolveCustomFirmwareName(pkg,[],{findSources:async()=>[source,{...source,url:release(otherName)}]}),/ambiguous/);
  await assert.rejects(resolveCustomFirmwareName(pkg,[item,{...item,name:name.replace('repeater','sensor'),role:'sensor',url:release(name.replace('repeater','sensor'))}]),/ambiguous/);
});

test('network or integrity errors propagate without fallback downloads of arbitrary firmware',async()=>{
  const {pkg}=fixture(),reader=indexReader(null,{reject:new Error('offline')});
  await assert.rejects(resolveCustomFirmwareName(pkg,[],reader.options),/offline/);
  assert.equal(reader.calls.length,1);assert.equal(reader.calls[0].url,new URL('index.json',base).href);
});
