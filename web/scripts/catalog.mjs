// Build-time public metadata only. Never reads the repository's device backups.
import { mkdir, writeFile,readFile } from 'node:fs/promises';
import { buildCatalog } from './catalog-build.mjs';

async function json(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(45000), headers: { 'User-Agent': 'meshfirmware-pages-catalog', ...(process.env.GITHUB_TOKEN && url.startsWith('https://api.github.com/') ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}) } });
  if (!response.ok) throw new Error(`${new URL(url).hostname}: HTTP ${response.status}`);
  return response.json();
}
const catalog=await buildCatalog({readJson:json,previous:async()=>{try{return JSON.parse(await readFile(new URL('../public/catalog.json',import.meta.url),'utf8'));}catch{return json('https://mikecarper.github.io/meshfirmware/catalog.json');}}});
await mkdir(new URL('../public',import.meta.url),{recursive:true});
await writeFile(new URL('../public/catalog.json',import.meta.url),JSON.stringify(catalog));
console.log(`Catalog: ${catalog.items.length} public artifacts; ${catalog.warnings.length} provider warnings.`);
