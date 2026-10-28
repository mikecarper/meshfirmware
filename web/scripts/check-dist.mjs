import { readdir, readFile, lstat } from 'node:fs/promises';
import assert from 'node:assert/strict';
import {verifyMirrorDirectory} from './mirror-boundary.mjs';
const root=new URL('../dist/',import.meta.url);
const allowedRoot=new Set(['index.html','catalog.json','assets','python','validators','licenses','firmware','THIRD_PARTY_NOTICES.txt']);
let count=0,totalBytes=0;
async function walk(url,path='') {
  for(const entry of await readdir(url,{withFileTypes:true})) {
    const name=path+entry.name, target=new URL(encodeURIComponent(entry.name)+(entry.isDirectory()?'/':''),url);
    assert.ok(!(await lstat(target)).isSymbolicLink(),`Symlink in artifact: ${name}`);
    if(!path) assert.ok(allowedRoot.has(entry.name),`Unapproved public output: ${name}`);
    assert.ok(!/config_backup|\.env(?:\.|$)|(?:^|\/)\.git(?:\/|$)|\.pem$|\.p12$|\.pfx$|\.key$|\.map$/i.test(name),`Private/development file in artifact: ${name}`);
    if(entry.isDirectory()) await walk(target,name+'/'); else {count++;totalBytes+=(await lstat(target)).size;assert.ok(totalBytes<=950000000,'Published site exceeds its safe Pages size budget.');}
  }
}
await walk(root);
const mirror=await verifyMirrorDirectory(new URL('firmware/',root));
const html=await readFile(new URL('index.html',root),'utf8');
assert.ok(!html.includes('localhost')&&!html.includes('127.0.0.1'),'Published app must not call a local helper.');
assert.ok(/Content-Security-Policy/.test(html),'Missing CSP.');
const expected=JSON.parse(await readFile(new URL('validators/integrity.json',root),'utf8'));
assert.deepEqual(Object.keys(expected).sort(),['meshcore_backup.py','meshcore_partition_expansion.py']);
console.log(`Public artifact boundary verified: ${count} whitelisted static files; no device backups. ${mirror.files} verified public firmware files (${mirror.entries} exact release URLs).`);
