import test from 'node:test';
import assert from 'node:assert/strict';
import {catalogItems,compareVersions,getCatalog} from '../src/catalog.js';
import {buildCatalog,keymindProviderPaths} from '../scripts/catalog-build.mjs';
const config=(name='Board')=>({staticPath:'/firmware',device:[{name,type:'nrf52',erase:'erase.zip',bootloader:['boot.uf2','boot.zip'],firmware:[{role:'repeater',title:'Repeater',subTitle:'Full USB + OTA',notice:'Check <b>bootloader</b>',version:{'v1.18.0':{notes:'release detail',files:[{name:'app.zip',type:'flash',digest:'sha256:'+'a'.repeat(64)}]}}}]}]});
test('catalog retains erase, bootloader, variant and release context without HTML injection',()=>{
  const item=catalogItems(config())[0];assert.deepEqual(item.erase,['https://flasher.meshcore.io/firmware/erase.zip']);assert.deepEqual(item.bootloader,['https://flasher.meshcore.io/firmware/boot.zip']);assert.equal(item.title,'Repeater');assert.equal(item.subtitle,'Full USB + OTA');assert.equal(item.notice,'Check bootloader');assert.equal(item.releaseNotes,'release detail');assert.equal(item.sha256,'a'.repeat(64));
});
test('versions and Keymind manifests sort numerically newest first',()=>{
  assert.deepEqual(['v1.9.0','v1.18.0','v1.18.0.1','v1.18.0-rc1'].sort(compareVersions),['v1.18.0.1','v1.18.0','v1.18.0-rc1','v1.9.0']);
  const tree={tree:['1.9.0','1.18.0','1.20.1'].map(version=>({type:'blob',path:`mesh-america/keymind-cascade-v${version}-provider.json`}))};assert.match(keymindProviderPaths(tree,'cascade')[0],/v1.20.1/);assert.equal(keymindProviderPaths(tree,'logging').length,1);
});
test('official outage does not prevent fresh Keymind catalog and uses validated old official entries',async()=>{
  const old={generatedAt:'2026-01-01T00:00:00Z',warnings:[],items:catalogItems(config('Old Official'))};
  const result=await buildCatalog({previous:async()=>old,readJson:async url=>{if(url.includes('trees/'))return {tree:[{type:'blob',path:'mesh-america/keymind-cascade-v1.20.0-provider.json'}]};if(url.includes('raw.githubusercontent'))return config('Fresh Keymind');throw new Error('offline');}});
  assert.ok(result.items.some(item=>item.hardware==='Old Official'));assert.ok(result.items.some(item=>item.hardware==='Fresh Keymind'));assert.ok(result.warnings.some(w=>w.includes('retained last known')));
});
test('official primary failure uses Mesh America proxy while Keymind failures remain isolated',async()=>{
  const seen=[];const result=await buildCatalog({readJson:async url=>{seen.push(url);if(url.includes('meshamerica')&&url.endsWith('config.json'))return config();if(url.includes('meshamerica')&&url.endsWith('releases'))return [{type:'repeater',files:[]}];throw new Error('offline');}});
  assert.equal(result.items[0].provider,'MeshCore');assert.ok(seen.some(url=>url.includes('meshamerica')));assert.ok(result.warnings.length);
});
test('browser catalog remembers only public metadata and uses validated last-known snapshot on failure',async()=>{
  const memory=new Map(),storage={setItem:(k,v)=>memory.set(k,v),getItem:k=>memory.get(k)},snapshot={generatedAt:'2026-01-01T00:00:00Z',warnings:[],items:catalogItems(config())};
  await getCatalog({storage,fetchImpl:async()=>({ok:true,json:async()=>snapshot})});const cached=await getCatalog({storage,fetchImpl:async()=>{throw new Error('offline');}});assert.equal(cached.cached,true);assert.equal(cached.items.length,1);assert.ok(cached.warnings[0].includes('cached'));
  memory.set('meshfirmware.publicCatalog.v1',JSON.stringify({...snapshot,items:[{...snapshot.items[0],url:'http://bad'}]}));await assert.rejects(getCatalog({storage,fetchImpl:async()=>{throw new Error('offline');}}),/local firmware/);
});
