import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {gzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {verifyMirrorDirectory} from '../scripts/mirror-boundary.mjs';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
async function fixture(run){
  const root=await mkdtemp(join(tmpdir(),'mesh-public-mirror-')),raw=Buffer.from('PUBLIC RELEASE FIRMWARE ONLY'),gz=gzipSync(raw),digest=sha(raw);
  const entry={url:'https://github.com/example/radio/releases/download/v1/board.bin',sha256:digest,size:raw.length,gzipSha256:sha(gz),gzipSize:gz.length,path:digest+'.gz'},index={schemaVersion:1,entries:[entry],warnings:[]};
  const save=async()=>{await writeFile(join(root,'index.json'),JSON.stringify(index));await writeFile(join(root,entry.path),gz);};
  try{await save();await run({root,raw,gz,entry,index,save});}finally{await rm(root,{recursive:true,force:true});}
}
test('public mirror boundary verifies both hashes, exact source mapping and deduplicated file budget',async()=>fixture(async({root,entry,index,save})=>{
  index.entries.push({...entry,url:'https://github.com/example/radio/releases/download/v2/board.bin'});await save();
  const result=await verifyMirrorDirectory(root);assert.equal(result.files,1);assert.equal(result.entries,2);assert.ok(result.bytes>entry.gzipSize);
  await assert.rejects(verifyMirrorDirectory(root,{maxBytes:1}),/budget/);
}));
test('mirror boundary refuses unknown/private output, subdirectories and unreferenced blobs',async()=>{
  for(const name of ['mc.config_backup.node.json','extra.txt','a'.repeat(64)+'.gz'])await fixture(async({root})=>{await writeFile(join(root,name),'not a published asset');await assert.rejects(verifyMirrorDirectory(root),/Unreferenced|unexpected/);});
  await fixture(async({root})=>{await mkdir(join(root,'other'));await assert.rejects(verifyMirrorDirectory(root),/Unreferenced|unexpected/);});
});
test('mirror boundary refuses changed bytes, raw proof and malformed or unsafe source metadata',async()=>{
  await fixture(async({root,entry,gz})=>{const changed=Buffer.from(gz);changed[12]^=1;await writeFile(join(root,entry.path),changed);await assert.rejects(verifyMirrorDirectory(root),/SHA-256/);});
  await fixture(async({root,index,save})=>{index.entries[0].size++;await save();await assert.rejects(verifyMirrorDirectory(root),/length|buffer/);});
  await fixture(async({root,index,save})=>{index.entries[0].url='https://github.com/example/radio/releases/download/v1/mc.config_backup.zip';await save();await assert.rejects(verifyMirrorDirectory(root),/Unapproved source/);});
  await fixture(async({root,index,save})=>{index.entries[0].path='../outside.gz';await save();await assert.rejects(verifyMirrorDirectory(root),/path/);});
});

test('Pages creates the verified public mirror after refreshing its catalog and before the static build',async()=>{
  const workflow=await readFile(new URL('../../.github/workflows/web-flasher.yml',import.meta.url),'utf8');
  const catalog=workflow.indexOf('run: node scripts/catalog.mjs'),mirror=workflow.indexOf('run: node scripts/mirror.mjs'),build=workflow.indexOf('run: pnpm build');
  assert.ok(catalog>=0&&mirror>catalog&&build>mirror,'The deployed app must include the exact refreshed catalog’s mirror.');
  assert.match(workflow.slice(mirror,build),/GITHUB_TOKEN:\s*\$\{\{ github\.token \}\}/,'Metadata authorization stays within the configured CI token.');
});
