import test from 'node:test';
import assert from 'node:assert/strict';
import {catalogItems,catalogProvider,combineProviderItems,compareVersions,getCatalog,validateCatalog} from '../src/catalog.js';
import {buildCatalog,keymindProviderPaths} from '../scripts/catalog-build.mjs';
const config=(name='Board')=>({staticPath:'/firmware',device:[{name,type:'nrf52',erase:'erase.zip',bootloader:['boot.uf2','boot.zip'],firmware:[{role:'repeater',title:'Repeater',subTitle:'Full USB + OTA',notice:'Check <b>bootloader</b>',version:{'v1.18.0':{notes:'release detail',files:[{name:'app.zip',type:'flash',digest:'sha256:'+'a'.repeat(64)}]}}}]}]});
const snapshot=items=>({generatedAt:'2026-01-01T00:00:00Z',warnings:[],items});
const legacyConfig=()=>{
  const value=config(),firmware=value.device[0].firmware[0];
  firmware.subTitle='Legacy USB logging profile';
  firmware.version={'v1.17.1':{notes:'Older distinct logging image; follow its exact profile requirements.',files:[{name:'app-usb-logging-v1.17.1.zip',type:'flash'}]}};
  return value;
};
const publicSources=(normal,logging)=>async url=>{
  if(url.includes('/git/trees/'))return {tree:[]};
  if(url.includes('raw.githubusercontent.com/')){
    const value=url.includes('keymind-cascade-logging-')?logging:normal;
    if(value)return value;
  }
  throw new Error('source offline');
};
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

test('legacy provider labels collapse only identical artifacts, regardless of object key order',()=>{
  const item={...catalogItems(config(),[],'Keymind Cascade')[0],requirements:{bootloader:'exact-board',migration:{supported:false,eraseAllowed:false}}};
  const duplicate=Object.fromEntries(Object.entries({...item,provider:'Keymind Cascade Logging',requirements:{migration:{eraseAllowed:false,supported:false},bootloader:'exact-board'}}).reverse());
  const safetyVariant={...duplicate,notice:'Different safety requirement: board-specific recovery required.'};
  const urlVariant={...duplicate,url:'https://example.com/legacy-usb-logging.zip'};
  const input=[item,duplicate,safetyVariant,urlVariant],before=structuredClone(input);
  assert.equal(catalogProvider('Keymind Cascade Logging'),'Keymind Cascade');
  assert.equal(catalogProvider('MeshCore'),'MeshCore');
  assert.equal(catalogItems(config(),[],'Keymind Cascade Logging')[0].provider,'Keymind Cascade');
  const result=combineProviderItems(input);
  assert.equal(result.length,3);
  assert.ok(result.every(entry=>entry.provider==='Keymind Cascade'));
  assert.ok(result.some(entry=>entry.notice===safetyVariant.notice));
  assert.ok(result.some(entry=>entry.url===urlVariant.url));
  assert.deepEqual(input,before);
});

test('fresh normal and logging manifests expose one Keymind copy of identical artifacts',async()=>{
  const result=await buildCatalog({readJson:publicSources(config(),config())});
  assert.equal(result.items.length,1);
  assert.equal(result.items[0].provider,'Keymind Cascade');
  assert.equal(result.items[0].name,'app.zip');
});

test('consolidation preserves distinct older logging files and their profile requirements',async()=>{
  const result=await buildCatalog({readJson:publicSources(config(),legacyConfig())});
  assert.equal(result.items.length,2);
  assert.ok(result.items.every(item=>item.provider==='Keymind Cascade'));
  const legacy=result.items.find(item=>item.name==='app-usb-logging-v1.17.1.zip');
  assert.equal(legacy.version,'v1.17.1');
  assert.equal(legacy.subtitle,'Legacy USB logging profile');
  assert.match(legacy.releaseNotes,/exact profile requirements/);
  assert.equal(legacy.url,'https://flasher.meshcore.io/firmware/app-usb-logging-v1.17.1.zip');
});

test('all-offline fallback retains a legacy Logging-only snapshot under the combined provider',async()=>{
  const old=snapshot(catalogItems(legacyConfig()).map(item=>({...item,provider:'Keymind Cascade Logging'}))),before=structuredClone(old);
  const result=await buildCatalog({previous:async()=>old,readJson:async()=>{throw new Error('all offline');}});
  assert.equal(result.items.length,1);
  assert.equal(result.items[0].provider,'Keymind Cascade');
  assert.equal(result.items[0].name,'app-usb-logging-v1.17.1.zip');
  assert.ok(result.warnings.some(warning=>warning.includes('retained last known')));
  assert.deepEqual(old,before);
});

test('a logging-source outage retains cached distinct profiles beside the fresh normal manifest',async()=>{
  const old=snapshot(catalogItems(legacyConfig()).map(item=>({...item,provider:'Keymind Cascade Logging'})));
  const result=await buildCatalog({previous:async()=>old,readJson:publicSources(config(),null)});
  assert.equal(result.items.length,2);
  assert.deepEqual(result.items.map(item=>item.name).sort(),['app-usb-logging-v1.17.1.zip','app.zip']);
  assert.ok(result.items.every(item=>item.provider==='Keymind Cascade'));
  assert.ok(result.warnings.some(warning=>warning.includes('retained last known')));
});

test('partial source outage removes fresh and cached duplicates after utility metadata enrichment',async()=>{
  const previous=await buildCatalog({readJson:publicSources(config(),config())});
  assert.equal(previous.items.length,1);
  assert.ok(previous.items[0].bootloaderUnavailable);
  const before=structuredClone(previous);
  const result=await buildCatalog({previous:async()=>previous,readJson:publicSources(config(),null)});
  assert.equal(result.items.length,1);
  assert.deepEqual(result.items[0],previous.items[0]);
  assert.ok(result.warnings.some(warning=>warning.includes('retained last known')));
  assert.deepEqual(previous,before);
});

test('fresh and cached catalog validation merges aliases without mutating snapshots or losing safety variants',async()=>{
  const item=catalogItems(config(),[],'Keymind Cascade')[0];
  const duplicate=Object.fromEntries(Object.entries({...item,provider:'Keymind Cascade Logging'}).reverse());
  const variant={...duplicate,notice:'Requires a different recovery procedure.'};
  const source=snapshot([item,duplicate,variant]),before=structuredClone(source);
  const checked=validateCatalog(source);
  assert.equal(checked.items.length,2);
  assert.ok(checked.items.every(entry=>entry.provider==='Keymind Cascade'));
  assert.ok(checked.items.some(entry=>entry.notice===variant.notice));
  const memory=new Map(),storage={setItem:(key,value)=>memory.set(key,value),getItem:key=>memory.get(key)};
  const fresh=await getCatalog({storage,fetchImpl:async()=>({ok:true,json:async()=>source})});
  assert.equal(fresh.items.length,2);
  memory.set('meshfirmware.publicCatalog.v1',JSON.stringify(source));
  const cached=await getCatalog({storage,fetchImpl:async()=>{throw new Error('offline');}});
  assert.equal(cached.cached,true);
  assert.equal(cached.items.length,2);
  assert.ok(cached.items.every(entry=>entry.provider==='Keymind Cascade'));
  assert.ok(cached.items.some(entry=>entry.notice===variant.notice));
  assert.deepEqual(source,before);
});
