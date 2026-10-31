import test from 'node:test';
import assert from 'node:assert/strict';
import {zipSync} from 'fflate';
import {createHash} from 'node:crypto';
import {splitMigrationArchive} from '../scripts/migration-parts.mjs';

const bytes=value=>new TextEncoder().encode(value),hash=value=>createHash('sha256').update(value).digest('hex');
const fixture=(options={level:0})=>{
  const app=Uint8Array.from({length:4096},(_,at)=>at%251),bridge=Uint8Array.from({length:2048},(_,at)=>at%233),mota=Buffer.concat([bytes('MOTA public metadata\0'),app,bytes('MOTA trailing metadata')]);
  return {app,bridge,mota,raw:zipSync({'README.md':bytes('PUBLIC MIGRATION ARTIFACT'),'full-application.bin':app,'full-application.mota':mota,'wifi-bridge.bin':bridge,'lora-bridge.mota':Buffer.concat([bytes('OTHER MOTA\0'),bridge]),'target-partitions.bin':bytes('a public table'),'manifest.json':bytes('{}')},options)};
};

test('stored migration archives preserve every original byte and expose identical complete payloads for deduplication',()=>{
  const {raw,app,bridge}=fixture(),original=raw.slice(),parts=splitMigrationArchive(raw);
  assert.ok(parts.length>1&&parts.length<=128);assert.deepEqual(Buffer.concat(parts),Buffer.from(raw));assert.equal(hash(Buffer.concat(parts)),hash(raw));assert.deepEqual(raw,original);
  assert.equal(parts.filter(part=>hash(part)===hash(app)).length,2);assert.equal(parts.filter(part=>hash(part)===hash(bridge)).length,2);
  assert.ok(parts.every(part=>part.buffer===raw.buffer&&part.length>0),'Parts are bounded views, not rewritten ZIP entries');
});

test('identical overlapping binary candidates never duplicate or omit archive ranges',()=>{
  const app=new Uint8Array(4096).fill(5),sub=app.subarray(0,2048),raw=zipSync({'app.bin':app,'sub.bin':sub,'app.mota':Buffer.concat([bytes('prefix'),app,bytes('suffix')])},{level:0});
  assert.deepEqual(Buffer.concat(splitMigrationArchive(raw)),Buffer.from(raw));
});

test('bounded long public license names remain metadata without blocking safe payload deduplication',()=>{
  const app=new Uint8Array(1024).fill(7),raw=zipSync({['Station_G3_'+ 'public'.repeat(20)+'.meshtext-license.txt']:bytes('Public font license'),'full-application.bin':app},{level:0}),parts=splitMigrationArchive(raw);
  assert.ok(parts.length>1);assert.deepEqual(Buffer.concat(parts),Buffer.from(raw));
});

test('compressed, truncated, descriptor, encrypted, unknown and unsafe ZIP layouts remain one exact opaque part',()=>{
  const compressed=fixture({level:6}).raw,raw=fixture().raw;
  const cases=[compressed,bytes('not a ZIP'),raw.subarray(0,raw.length-1),zipSync({'../private.bin':bytes('x')},{level:0}),zipSync({'empty.bin':new Uint8Array()},{level:0}),zipSync(Object.fromEntries(Array.from({length:33},(_,at)=>['file'+at+'.bin',bytes('x')])) ,{level:0})];
  for(const patch of [data=>{data[6]=8;},data=>{data[6]=1;},data=>{new DataView(data.buffer).setUint32(18,0xffffffff,true);},data=>{data[data.length-6]^=1;},data=>{const at=data.findIndex((_,i)=>data[i]===0x50&&data[i+1]===0x4b&&data[i+2]===1&&data[i+3]===2);data[at+42]^=1;}]){const data=raw.slice();patch(data);cases.push(data);}
  for(const value of cases){const parts=splitMigrationArchive(value);assert.equal(parts.length,1);assert.equal(parts[0],value);}
});

test('invalid or oversized inputs cannot bypass the migration archive memory bound',()=>{
  for(const value of [null,[],new Uint8Array(),new Uint8Array((32<<20)+1)])assert.throws(()=>splitMigrationArchive(value),/bounded public bytes/);
});

test('highly repeated MOTA payloads cannot create an unbounded part inventory',()=>{
  const app=new Uint8Array(1024).fill(3),raw=zipSync({'app.bin':app,'app.mota':Buffer.concat(Array.from({length:100},()=>app))},{level:0});
  const parts=splitMigrationArchive(raw);assert.equal(parts.length,1);assert.equal(parts[0],raw);
});
