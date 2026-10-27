// Build-time public metadata only. Never reads the repository's device backups.
import { mkdir, writeFile,readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { buildCatalog } from './catalog-build.mjs';

async function responseFor(url,fetchImpl) {
  const response = await fetchImpl(url, { signal: AbortSignal.timeout(45000), headers: { 'User-Agent': 'meshfirmware-pages-catalog', ...(process.env.GITHUB_TOKEN && url.startsWith('https://api.github.com/') ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}) } });
  if (!response.ok) throw new Error(`${new URL(url).hostname}: HTTP ${response.status}`);
  return response;
}
export async function bytes(url,{sha256,size,fetchImpl=fetch}={}) {
  if(typeof sha256!=='string'||!/^[a-f0-9]{64}$/.test(sha256)||!Number.isInteger(size)||size<=0||size>(32<<20))throw new Error('Invalid verified public-asset fetch bounds.');
  const response=await responseFor(url,fetchImpl);
  if(!response.body)throw new Error('Verified public asset has no response body.');
  const reader=response.body.getReader(),payload=new Uint8Array(size);let total=0;
  try{for(;;){const {value,done}=await reader.read();if(done)break;if(total+value.length>size)throw new Error('Public asset exceeds its release asset size.');payload.set(value,total);total+=value.length;}}
  finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
  if(total!==size||createHash('sha256').update(payload).digest('hex')!==sha256)throw new Error('Public asset release size or SHA-256 verification failed.');
  return payload;
}
export async function json(url,{sha256,size,fetchImpl=fetch}={}) {
  if(sha256!==undefined||size!==undefined){
    if(!Number.isInteger(size)||size>(1<<20))throw new Error('Invalid verified public-manifest fetch bounds.');
    return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await bytes(url,{sha256,size,fetchImpl})));
  }
  return (await responseFor(url,fetchImpl)).json();
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  const catalog=await buildCatalog({readJson:json,readBytes:bytes,previous:async()=>{try{return JSON.parse(await readFile(new URL('../public/catalog.json',import.meta.url),'utf8'));}catch{return json('https://mikecarper.github.io/meshfirmware/catalog.json');}}});
  await mkdir(new URL('../public',import.meta.url),{recursive:true});
  await writeFile(new URL('../public/catalog.json',import.meta.url),JSON.stringify(catalog));
  console.log(`Catalog: ${catalog.items.length} public artifacts; ${catalog.warnings.length} provider warnings.`);
}
