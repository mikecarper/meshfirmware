import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {createServer} from 'vite';
import {localRuntimeUrls} from '../src/local-runtime-urls.js';

for(const [label,moduleUrl,root] of [
  ['root Vite development','http://127.0.0.1:5183/src/planner-runtime.js','http://127.0.0.1:5183/'],
  ['subdirectory Vite development','http://127.0.0.1:5183/meshfirmware/src/planner-runtime.js?t=123','http://127.0.0.1:5183/meshfirmware/'],
  ['root built worker','https://example.test/assets/planner-worker-abc.js','https://example.test/'],
  ['GitHub Pages built worker','https://mikecarper.github.io/meshfirmware/assets/planner-worker-abc.js','https://mikecarper.github.io/meshfirmware/'],
  ['GitHub Pages built main thread','https://mikecarper.github.io/meshfirmware/assets/planner-runtime-abc.js?version=2#fragment','https://mikecarper.github.io/meshfirmware/'],
])test(`local Python/validator URLs remain correct for ${label}`,()=>{
  const urls=localRuntimeUrls(moduleUrl);
  assert.deepEqual(urls,{
    moduleURL:root+'python/pyodide.mjs',
    indexURL:root+'python/',
    validatorsURL:root+'validators/',
  });
  for(const name of ['pyodide.asm.js','pyodide.asm.wasm','python_stdlib.zip','pyodide-lock.json']){
    const resource=new URL(name,urls.indexURL);
    assert.equal(resource.href,root+'python/'+name);
    assert.equal(resource.origin,new URL(moduleUrl).origin);
  }
  for(const name of ['integrity.json','meshcore_backup.py','meshcore_partition_expansion.py']){
    const resource=new URL(name,urls.validatorsURL);
    assert.equal(resource.href,root+'validators/'+name);
    assert.equal(resource.origin,new URL(moduleUrl).origin);
  }
  assert.doesNotMatch(urls.moduleURL,/pythonpyodide/);
});

test('planner loads runtime and validators through the shared file-based resolver, never directory string concatenation',async()=>{
  const source=await readFile(new URL('../src/planner-runtime.js',import.meta.url),'utf8');
  assert.match(source,/localRuntimeUrls\(import\.meta\.url\)/);
  assert.match(source,/import\(\/\* @vite-ignore \*\/ localUrls\.moduleURL\)/);
  assert.match(source,/loadPyodide\(\{ indexURL: localUrls\.indexURL \}\)/);
  assert.doesNotMatch(source,/new URL\(['"]\.\.\/python\/['"],\s*import\.meta\.url\)/);
  assert.doesNotMatch(source,/indexURL\s*\+\s*['"]pyodide\.mjs/);
  assert.equal((source.match(/localUrls\.validatorsURL/g)||[]).length,2);
});

test('Vite development transformation preserves the local runtime filename and trailing-slash directory',async()=>{
  // Exercise the transformation that caused /python + pyodide.mjs to lose
  // its separating slash. No HTTP listener, browser or USB access is needed.
  const server=await createServer({
    configFile:false,root:fileURLToPath(new URL('..',import.meta.url)),base:'./',
    server:{middlewareMode:true},appType:'custom',logLevel:'silent',
    optimizeDeps:{noDiscovery:true,include:[]},
  });
  try{
    const transformed=await server.transformRequest('/src/local-runtime-urls.js');
    assert.ok(transformed?.code);
    const {localRuntimeUrls:transformedResolver}=await import('data:text/javascript,'+encodeURIComponent(transformed.code));
    const urls=transformedResolver('http://127.0.0.1:5183/src/planner-runtime.js');
    assert.equal(urls.moduleURL,'http://127.0.0.1:5183/python/pyodide.mjs');
    assert.equal(urls.indexURL,'http://127.0.0.1:5183/python/');
    assert.equal(urls.validatorsURL,'http://127.0.0.1:5183/validators/');
  }finally{await server.close();}
});
