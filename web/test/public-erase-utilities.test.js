import test from 'node:test';
import assert from 'node:assert/strict';
import {publicEraseUtilities,publicEraseUtility} from '../src/public-erase-utilities.js';
import {nrfEraseIntent} from '../src/firmware.js';
import {validateMirrorIndex,fetchFirmwareBytes} from '../src/downloads.js';

const entry=utility=>({url:utility.url,sha256:utility.sha256,size:utility.size,path:utility.sha256+'.gz',gzipSha256:'a'.repeat(64),gzipSize:100});
const index=entries=>({schemaVersion:1,entries,warnings:[]});
const mirrorBase='https://flasher.test/meshfirmware/firmware/';

test('only seven exact official erase/formatter URLs have immutable ZIP and canonical payload pins',()=>{
  assert.equal(publicEraseUtilities.length,7);assert.ok(Object.isFrozen(publicEraseUtilities));assert.equal(new Set(publicEraseUtilities.map(u=>u.url)).size,7);
  for(const utility of publicEraseUtilities){
    assert.ok(Object.isFrozen(utility));assert.equal(publicEraseUtility(utility.url),utility);assert.equal(utility.url,'https://flasher.meshcore.io/firmware/'+utility.name);assert.ok(utility.size>0&&utility.size<4<<20);assert.match(utility.sha256,/^[a-f0-9]{64}$/);assert.match(nrfEraseIntent(utility.name,utility.payloadHash),/^official /);
    for(const url of [utility.url+'?download=1',utility.url+'#file',utility.url.replace('https:','http:'),utility.url.replace('/firmware/','/private/'),utility.url.replace('https://','https://user:pass@'),utility.url.replace('.io/','.io:444/')])assert.equal(publicEraseUtility(url),null);
  }
  for(const url of [null,undefined,{},'https://flasher.meshcore.io/firmware/unknown.zip'])assert.equal(publicEraseUtility(url),null);
  assert.throws(()=>{publicEraseUtilities[0].sha256='b'.repeat(64);},TypeError);
});

test('static utility mirror metadata must match the exact pinned ZIP, not just a trusted hostname',()=>{
  for(const utility of publicEraseUtilities){
    const valid=entry(utility);assert.equal(validateMirrorIndex(index([valid])).entries[0].url,utility.url);
    for(const patch of [{sha256:'b'.repeat(64),path:'b'.repeat(64)+'.gz'},{size:utility.size+1},{url:utility.url+'?x=1'},{url:utility.url.replace('/firmware/','/other/')},{url:'https://flasher.meshcore.io/firmware/custom_erase.zip'}])assert.throws(()=>validateMirrorIndex(index([{...valid,...patch}])),/pinned|public GitHub|mirror/i);
  }
});

test('a known utility cannot bypass its raw ZIP pin when the mirror is unavailable',async()=>{
  const utility=publicEraseUtilities[0],requests=[],fetchImpl=async(url,options)=>{requests.push({url,options});return url===mirrorBase+'index.json'?new Response('',{status:404}):new Response(new Uint8Array(utility.size));};
  await assert.rejects(fetchFirmwareBytes(utility.url,{mirrorBase,pageOrigin:'https://flasher.test',fetchImpl}),/SHA-256/);assert.deepEqual(requests.map(r=>r.url),[mirrorBase+'index.json',utility.url]);assert.ok(requests.every(r=>r.options.credentials==='omit'));assert.ok(requests.every(r=>!r.options.headers));
  const noRequests=async()=>{assert.fail('Conflicting expected hash must stop before any download');};await assert.rejects(fetchFirmwareBytes(utility.url,{mirrorBase,pageOrigin:'https://flasher.test',fetchImpl:noRequests,expectedSha256:'b'.repeat(64)}),/pinned/);
});

test('a pinned static mirror never retries an unverified original after corrupt mirrored bytes',async()=>{
  const utility=publicEraseUtilities[0],requests=[],fetchImpl=async url=>{requests.push(url);if(url===mirrorBase+'index.json')return Response.json(index([entry(utility)]));if(url===mirrorBase+utility.sha256+'.gz')return new Response(new Uint8Array(100));assert.fail('No direct retry after mirror integrity failure');};
  await assert.rejects(fetchFirmwareBytes(utility.url,{mirrorBase,pageOrigin:'https://flasher.test',fetchImpl}),/SHA-256/);assert.equal(requests.length,2);
});
