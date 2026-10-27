import { mkdir,copyFile,readFile,writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
const publicDir = new URL('../public/',import.meta.url);
await mkdir(new URL('python/',publicDir),{recursive:true});
for (const name of ['pyodide.mjs','pyodide.asm.js','pyodide.asm.wasm','python_stdlib.zip','pyodide-lock.json']) await copyFile(new URL(`../node_modules/pyodide/${name}`,import.meta.url),new URL(`python/${name}`,publicDir));
await mkdir(new URL('validators/',publicDir),{recursive:true});
const integrity = {};
for (const name of ['meshcore_partition_expansion.py','meshcore_backup.py']) {
  const bytes = await readFile(new URL(`../../tools/${name}`,import.meta.url));
  integrity[name] = createHash('sha256').update(bytes).digest('hex');
  await writeFile(new URL(`validators/${name}`,publicDir),bytes);
}
await writeFile(new URL('validators/integrity.json',publicDir),JSON.stringify(integrity));
console.log('Prepared browser-local WebAssembly runtime and exact shared partition validator. No device backups included.');
