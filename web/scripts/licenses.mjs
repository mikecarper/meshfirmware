import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
const out=new URL('../public/licenses/',import.meta.url);
await mkdir(out,{recursive:true});
const visited=new Set(), records=[], ids=new Set(['LGPL-2.1-only','MIT','Apache-2.0','MPL-2.0','Python-2.0']);
async function visit(name,from) {
  const require=createRequire(from); let entry;
  try {entry=require.resolve(name+'/package.json');}
  catch {entry=require.resolve(name);while(JSON.parse(await readFile(join(dirname(entry),'package.json'),'utf8').catch(()=>'{}')).name!==name) {const next=dirname(dirname(entry));if(next===dirname(entry))throw new Error('Cannot resolve license '+name);entry=join(next,'index.js');}entry=join(dirname(entry),'package.json');}
  const pkg=JSON.parse(await readFile(entry,'utf8')), key=pkg.name+'@'+pkg.version;
  if(visited.has(key))return;visited.add(key);
  records.push(`${key}: ${pkg.license || 'see package source'} — ${typeof pkg.repository==='object'?pkg.repository.url:pkg.repository||''}`);
  const licenses=(pkg.license||'').match(/[A-Za-z][A-Za-z0-9.+-]*/g)||[];
  for(const id of licenses) if(!['AND','OR','WITH'].includes(id))ids.add(id);
  for(const file of await readdir(dirname(entry))) if(/^(?:LICENSE|LICENCE|COPYING|NOTICE)(?:[.-].*)?$/i.test(file)) {
    try {await writeFile(new URL(encodeURIComponent(key.replace(/\//g,'_')+'-'+file),out),await readFile(join(dirname(entry),file)));}catch(error){if(error.code!=='EISDIR')throw error;}
  }
  for(const dep of Object.keys(pkg.dependencies||{}))await visit(dep,entry);
}
const pkg=JSON.parse(await readFile(new URL('../package.json',import.meta.url),'utf8'));
for(const name of Object.keys(pkg.dependencies)) await visit(name,new URL('../package.json',import.meta.url));
for(const raw of ids) {
  const id=['GPL-3.0','GPLV3'].includes(raw)?'GPL-3.0-only':raw==='GPL-2.0'?'GPL-2.0-only':raw;
  const response=await fetch(`https://raw.githubusercontent.com/spdx/license-list-data/main/text/${id}.txt`,{signal:AbortSignal.timeout(30000)});
  if(!response.ok)throw new Error(`License text unavailable: ${id}`);
  await writeFile(new URL(encodeURIComponent(id+'.txt'),out),await response.text());
}
await writeFile(new URL('packages.txt',out),records.sort().join('\n')+'\n');
await writeFile(new URL('../public/THIRD_PARTY_NOTICES.txt',import.meta.url),await readFile(new URL('../THIRD_PARTY_NOTICES.txt',import.meta.url)));
console.log(`Runtime licenses prepared for ${visited.size} packages.`);
