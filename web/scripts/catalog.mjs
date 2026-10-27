// Build-time public metadata only. Never reads the repository's device backups.
import { mkdir, writeFile,readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { buildCatalog } from './catalog-build.mjs';

export async function json(url,{sha256,size,fetchImpl=fetch}={}) {
  const response = await fetchImpl(url, { signal: AbortSignal.timeout(45000), headers: { 'User-Agent': 'meshfirmware-pages-catalog', ...(process.env.GITHUB_TOKEN && url.startsWith('https://api.github.com/') ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}) } });
  if (!response.ok) throw new Error(`${new URL(url).hostname}: HTTP ${response.status}`);
  if(sha256!==undefined||size!==undefined){
    if(typeof sha256!=='string'||!/^[a-f0-9]{64}$/.test(sha256)||!Number.isInteger(size)||size<=0||size>(1<<20)||!response.body)throw new Error('Invalid verified public-manifest fetch bounds.');
    const reader=response.body.getReader(),bytes=new Uint8Array(size);let total=0;
    try{for(;;){const {value,done}=await reader.read();if(done)break;if(total+value.length>size)throw new Error('Public manifest exceeds its release asset size.');bytes.set(value,total);total+=value.length;}}
    finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
    if(total!==size||createHash('sha256').update(bytes).digest('hex')!==sha256)throw new Error('Public manifest release size or SHA-256 verification failed.');
    return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
  }
  return response.json();
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  const catalog=await buildCatalog({readJson:json,previous:async()=>{try{return JSON.parse(await readFile(new URL('../public/catalog.json',import.meta.url),'utf8'));}catch{return json('https://mikecarper.github.io/meshfirmware/catalog.json');}}});
  await mkdir(new URL('../public',import.meta.url),{recursive:true});
  await writeFile(new URL('../public/catalog.json',import.meta.url),JSON.stringify(catalog));
  console.log(`Catalog: ${catalog.items.length} public artifacts; ${catalog.warnings.length} provider warnings.`);
}
