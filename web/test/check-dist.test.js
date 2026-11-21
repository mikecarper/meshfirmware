import test from 'node:test';
import assert from 'node:assert/strict';
import {copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, sep} from 'node:path';
import {pathToFileURL} from 'node:url';
import {verifyPublicArtifact} from '../scripts/check-dist.mjs';

async function fixture(t) {
  const dir=await mkdtemp(join(tmpdir(),'mesh-public-artifact-'));
  t.after(()=>rm(dir,{force:true,recursive:true}));
  const root=pathToFileURL(dir+sep), guides=new URL('reader/field-guides.json',root);
  await mkdir(new URL('reader/',root));
  await mkdir(new URL('validators/',root));
  await copyFile(new URL('../public/reader/field-guides.json',import.meta.url),guides);
  await writeFile(new URL('index.html',root),'<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">');
  await writeFile(new URL('validators/integrity.json',root),'{"meshcore_backup.py":"","meshcore_partition_expansion.py":""}');
  return {root,guides};
}

test('artifact check accepts the exact bundled Reader field guides',async t=>{
  const {root}=await fixture(t);
  assert.equal((await verifyPublicArtifact(root)).count,3);
});

test('artifact check rejects unexpected public files, including books beside the guides',async t=>{
  for(const name of ['my-book.json','reader/my-book.json']) {
    const {root}=await fixture(t);
    await writeFile(new URL(name,root),'Private book');
    await assert.rejects(verifyPublicArtifact(root),/Unapproved public (?:Reader )?output/);
  }
});

test('artifact check requires the original field-guide bytes',async t=>{
  const {root,guides}=await fixture(t), changed=await readFile(guides);
  changed[0]^=1;
  await writeFile(guides,changed);
  await assert.rejects(verifyPublicArtifact(root),/field guides differ/);
  await rm(guides);
  await assert.rejects(verifyPublicArtifact(root),/Missing bundled Reader field guides/);
  await mkdir(guides);
  await assert.rejects(verifyPublicArtifact(root),/Unapproved public Reader output/);
});

test('artifact check rejects a symlink in place of the guides', {skip:process.platform==='win32'}, async t=>{
  const {root,guides}=await fixture(t);
  await rm(guides);
  await symlink('../index.html',guides);
  await assert.rejects(verifyPublicArtifact(root),/Symlink in artifact/);
});
