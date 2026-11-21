import { readdir, readFile, lstat } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
import {verifyMirrorDirectory} from './mirror-boundary.mjs';
const allowedRoot=new Set(['index.html','catalog.json','assets','python','validators','licenses','firmware','reader','THIRD_PARTY_NOTICES.txt']);
const fieldGuides='reader/field-guides.json';

export async function verifyPublicArtifact(root=new URL('../dist/',import.meta.url)) {
  let count=0,totalBytes=0,readerGuideFound=false;
  async function walk(url,path='') {
    for(const entry of await readdir(url,{withFileTypes:true})) {
      const name=path+entry.name, target=new URL(encodeURIComponent(entry.name),url), info=await lstat(target);
      assert.ok(!info.isSymbolicLink(),`Symlink in artifact: ${name}`);
      if(!path) assert.ok(allowedRoot.has(entry.name),`Unapproved public output: ${name}`);
      assert.ok(!/config_backup|\.env(?:\.|$)|(?:^|\/)\.git(?:\/|$)|\.pem$|\.p12$|\.pfx$|\.key$|\.map$/i.test(name),`Private/development file in artifact: ${name}`);
      if(name==='reader') assert.ok(info.isDirectory(),'Reader output must be a directory.');
      if(path.startsWith('reader/')) {
        assert.ok(name===fieldGuides&&info.isFile(),`Unapproved public Reader output: ${name}`);
        const source=await readFile(new URL('../public/'+fieldGuides,import.meta.url));
        assert.ok(info.size===source.length&&source.equals(await readFile(target)),'Published field guides differ from the bundled source.');
        readerGuideFound=true;
      }
      if(info.isDirectory()) await walk(new URL(target.href+'/'),name+'/');
      else {count++;totalBytes+=info.size;assert.ok(totalBytes<=950000000,'Published site exceeds its safe Pages size budget.');}
    }
  }
  await walk(root);
  assert.ok(readerGuideFound,'Missing bundled Reader field guides.');
  const mirror=await verifyMirrorDirectory(new URL('firmware/',root));
  const html=await readFile(new URL('index.html',root),'utf8');
  assert.ok(!html.includes('localhost')&&!html.includes('127.0.0.1'),'Published app must not call a local helper.');
  assert.ok(/Content-Security-Policy/.test(html),'Missing CSP.');
  const expected=JSON.parse(await readFile(new URL('validators/integrity.json',root),'utf8'));
  assert.deepEqual(Object.keys(expected).sort(),['meshcore_backup.py','meshcore_partition_expansion.py']);
  return {count,mirror};
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) {
  const {count,mirror}=await verifyPublicArtifact();
  console.log(`Public artifact boundary verified: ${count} whitelisted static files; no device backups. ${mirror.files} verified public firmware files (${mirror.entries} exact public source URLs).`);
}
