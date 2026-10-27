// Build-time public metadata only. Never reads the repository's device backups.
import { mkdir, writeFile } from 'node:fs/promises';
import { catalogItems } from '../src/catalog.js';

async function json(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(45000), headers: { 'User-Agent': 'meshfirmware-pages-catalog', ...(process.env.GITHUB_TOKEN && url.startsWith('https://api.github.com/') ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}) } });
  if (!response.ok) throw new Error(`${new URL(url).hostname}: HTTP ${response.status}`);
  return response.json();
}
const [config,releases] = await Promise.all([json('https://flasher.meshcore.io/config.json'),json('https://flasher.meshcore.io/releases')]);
const items = catalogItems(config,releases), warnings = [];
for (const [provider,path] of [['Keymind Cascade','mesh-america/keymind-cascade-v1.16.0-provider.json'],['Keymind Cascade Logging','mesh-america/keymind-cascade-logging-v1.16.0-provider.json']]) {
  try { items.push(...catalogItems(await json(`https://raw.githubusercontent.com/mikecarper/MeshCore/keymindCascade/${path}`),[],provider)); }
  catch (error) { warnings.push(`${provider}: ${error.message}`); }
}
await mkdir(new URL('../public',import.meta.url),{recursive:true});
await writeFile(new URL('../public/catalog.json',import.meta.url),JSON.stringify({generatedAt:new Date().toISOString(),items,warnings}));
console.log(`Catalog: ${items.length} public artifacts; ${warnings.length} provider warnings.`);
