import {readdir,readFile,lstat} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import assert from 'node:assert/strict';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {validateMirrorIndex,mirrorParts,MAX_MIRROR_INDEX_BYTES} from '../src/downloads.js';
import {migrationMetadataSource} from '../src/migration-sources.js';

export const MAX_PUBLIC_MIRROR_BYTES=850<<20;
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');

// Only build-generated, content-addressed PUBLIC assets are allowed: verified
// release assets and the exact hash-pinned official erase/format utilities.
// No input path is taken from a board backup, local download or private archive.
export async function verifyMirrorDirectory(directory,{maxBytes=MAX_PUBLIC_MIRROR_BYTES}={}){
  const root=directory instanceof URL?directory:pathToFileURL(resolve(directory)+'/');
  let info;try{info=await lstat(root);}catch(error){if(error.code==='ENOENT')return {entries:0,files:0,bytes:0};throw error;}
  assert.ok(info.isDirectory()&&!info.isSymbolicLink(),'Invalid public firmware mirror directory.');
  const indexPath=new URL('index.json',root),indexInfo=await lstat(indexPath);
  assert.ok(indexInfo.isFile()&&!indexInfo.isSymbolicLink()&&indexInfo.size<=MAX_MIRROR_INDEX_BYTES,'Invalid public firmware mirror index file.');
  const index=validateMirrorIndex(JSON.parse(await readFile(indexPath,'utf8'))),files=new Map();
  for(const entry of index.entries){
    const name=decodeURIComponent(new URL(entry.url).pathname.split('/').pop());
    assert.ok((/\.(?:bin|zip|uf2)$/i.test(name)||migrationMetadataSource(entry.url))&&!/[\\/]|config_backup|\.env|\.key(?:\.|$)/i.test(name),'Unapproved source in public firmware mirror.');
    for(const piece of mirrorParts(entry))files.set(piece.path,piece);
  }
  const names=await readdir(root);
  assert.deepEqual([...names].sort(),['index.json',...files.keys()].sort(),'Unreferenced or unexpected file in public firmware mirror.');
  let bytes=indexInfo.size,compressedBytes=0;
  for(const [name,entry]of files){
    const path=new URL(name,root),stat=await lstat(path);
    assert.ok(stat.isFile()&&!stat.isSymbolicLink(),'Symlink or non-file in public firmware mirror.');
    assert.equal(stat.size,entry.gzipSize,'Public firmware mirror size differs from its index.');
    bytes+=stat.size;compressedBytes+=stat.size;assert.ok(compressedBytes<=maxBytes,'Public firmware mirror exceeds its deployment budget.');
    const compressed=await readFile(path);
    assert.equal(digest(compressed),entry.gzipSha256,'Public firmware compressed SHA-256 differs from its index.');
    const raw=gunzipSync(compressed,{maxOutputLength:entry.size});
    assert.equal(raw.length,entry.size,'Public firmware raw length differs from its index.');
    assert.equal(digest(raw),entry.sha256,'Public firmware raw SHA-256 differs from its release digest.');
  }
  // Parts are shared only as exact public byte ranges. Check the original
  // release digest as well: valid parts in a different order are not that ZIP.
  // Re-read one bounded part at a time, never retain all decoded mirror files.
  for(const entry of index.entries.filter(entry=>entry.parts)){
    const aggregate=createHash('sha256');let length=0;
    for(const piece of mirrorParts(entry)){
      const raw=gunzipSync(await readFile(new URL(piece.path,root)),{maxOutputLength:piece.size});
      assert.equal(raw.length,piece.size,'Public firmware part length differs from its index.');
      length+=raw.length;assert.ok(length<=entry.size,'Public multipart firmware exceeds its release length.');aggregate.update(raw);
    }
    assert.equal(length,entry.size,'Public multipart firmware length differs from its release.');
    assert.equal(aggregate.digest('hex'),entry.sha256,'Public multipart firmware SHA-256 differs from its release digest.');
  }
  return {entries:index.entries.length,files:files.size,bytes};
}
