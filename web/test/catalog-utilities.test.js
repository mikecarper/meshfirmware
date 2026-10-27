import test from 'node:test';
import assert from 'node:assert/strict';
import {inheritOfficialUtilities,validateCatalog,getCatalog} from '../src/catalog.js';
import {buildCatalog} from '../scripts/catalog-build.mjs';

const erase='https://flasher.meshcore.io/firmware/FLASH_ERASE_nrf52_softdevice_v7.zip';
const boot='https://flasher.meshcore.io/firmware/t1000_e_bootloader-0.9.2-OTAFIX2.2.zip';
const official={project:'MeshCore',provider:'MeshCore',hardware:'Seeed Studio SenseCAP T1000-E',architecture:'nrf52',role:'companionBle',name:'official.zip',url:'https://example.test/official.zip',erase:[erase],bootloader:[boot]};
const provider={...official,provider:'Keymind Cascade',role:'companionFull',version:'v1.18.0.1',name:'keymind.zip',url:'https://example.test/keymind.zip',erase:[],bootloader:[]};
const snapshot=items=>({generatedAt:'2026-10-27T00:00:00Z',items,warnings:[]});

test('missing provider utilities inherit only exact official board/architecture matches without replacing firmware metadata',()=>{
  const before=JSON.stringify(provider),items=inheritOfficialUtilities([official,{...official,role:'repeater'},provider]);
  assert.deepEqual(items[2],{...provider,erase:[erase],bootloader:[boot]});assert.equal(JSON.stringify(provider),before);
  for(const mismatch of [{hardware:'Seeed Studio SenseCAP T1000-E alternative'},{architecture:'esp32'},{hardwareVersion:'v2'}]){
    const source={...official,hardwareVersion:'v1'},target={...provider,...mismatch};
    assert.equal(inheritOfficialUtilities([source,target])[1],target);
  }
  for(const missing of [{hardware:''},{architecture:undefined},{architecture:'unknown'}]){
    const target={...provider,...missing};assert.equal(inheritOfficialUtilities([{...official,...missing},target])[1],target);
  }
  const own={...provider,erase:['https://example.test/own-erase.zip']};
  assert.deepEqual(inheritOfficialUtilities([official,own])[1],{...own,bootloader:[boot]});
});

test('conflicting official hints are not guessed and unrelated providers cannot become utility sources',()=>{
  const conflict={...official,erase:['https://example.test/different-erase.zip']};
  const item=inheritOfficialUtilities([official,conflict,provider])[2];
  assert.deepEqual(item.erase,[]);assert.deepEqual(item.bootloader,[boot]);
  const other={...official,provider:'Other firmware provider'};
  assert.equal(inheritOfficialUtilities([other,provider])[1],provider);
  const multiple={...official,bootloader:[boot,'https://example.test/second.zip']};
  assert.deepEqual(inheritOfficialUtilities([multiple,{...multiple,bootloader:[...multiple.bootloader].reverse()},provider])[2].bootloader,[...multiple.bootloader].sort());
});

test('old browser snapshots and offline caches receive the same exact-board fallback without mutation',async()=>{
  const raw=snapshot([official,provider]),before=JSON.stringify(raw),fixed=validateCatalog(raw);
  assert.deepEqual(fixed.items[1].erase,[erase]);assert.deepEqual(fixed.items[1].bootloader,[boot]);assert.equal(JSON.stringify(raw),before);
  const cached=await getCatalog({fetchImpl:async()=>{throw Error('offline');},storage:{getItem:()=>JSON.stringify(raw)}});
  assert.equal(cached.cached,true);assert.deepEqual(cached.items[1].erase,[erase]);assert.deepEqual(cached.items[1].bootloader,[boot]);
});

test('fresh provider firmware can use validated cached official metadata during official outage',async()=>{
  const config={device:[{name:provider.hardware,type:'nrf52',firmware:[{role:'companionFull',version:{v1:{files:[{name:'keymind.zip',url:provider.url,type:'flash'}]}}}]}]};
  const result=await buildCatalog({previous:async()=>snapshot([official]),readJson:async url=>{if(url.includes('/git/trees/'))return{tree:[]};if(url.includes('raw.githubusercontent.com/'))return config;throw Error('official outage');}});
  for(const item of result.items.filter(item=>item.provider!=='MeshCore')){
    assert.deepEqual(item.erase,[erase]);assert.deepEqual(item.bootloader,[boot]);assert.equal(item.url,provider.url);assert.equal(item.role,'companionFull');
  }
  assert.equal(result.items.filter(item=>item.provider!=='MeshCore').length,2);
});

test('fully cached provider firmware also gains the official utility fallback at build time',async()=>{
  const result=await buildCatalog({previous:async()=>snapshot([official,provider]),readJson:async()=>{throw Error('offline');}});
  const item=result.items.find(item=>item.provider==='Keymind Cascade');assert.deepEqual(item.erase,[erase]);assert.deepEqual(item.bootloader,[boot]);
});
