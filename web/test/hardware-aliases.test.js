import test from 'node:test';
import assert from 'node:assert/strict';
import {canonicalHardware} from '../src/hardware-aliases.js';
import {catalogItems,catalogItemKey,combineProviderItems,validateCatalog,getCatalog,inheritOfficialUtilities} from '../src/catalog.js';
import {detectMeshtasticBoard} from '../src/meshtastic-boards.js';
import {chooseFirmware} from '../src/automatic.js';

const aliases=[
  ['Seeed Studio Wio Tracker L1 EINK','Seeed Studio Wio Tracker L1 E-Ink',100],
  ['Seeed Studio SenseCAP MeshTracker X1','Seeed SenseCAP MeshTracker X1',128],
  ['Seeed Studio SenseCAP Solar Node P1','Seeed Studio SenseCAP Solar',95],
  ['Heltec Heltec Wireless Paper','Heltec Wireless Paper',49,'esp32'],
];
const item=(hardware,more={})=>({project:'MeshCore',provider:'MeshCore',hardware,architecture:'nrf52',role:'companionFull',action:'flash',version:'v1.18.0',name:'board-v1.18.0.zip',url:'https://example.test/board-v1.18.0.zip',...more});
const snapshot=items=>({generatedAt:'2026-10-30T00:00:00Z',warnings:[],items});

test('only reviewed equivalent hardware display names are canonicalized',()=>{
  for(const [legacy,canonical] of aliases){assert.equal(canonicalHardware(legacy),canonical);assert.equal(canonicalHardware(canonical),canonical);}
  for(const value of [undefined,null,{},'','Seeed Studio Wio Tracker L1 Pro','Seeed WioTracker L1 1W','Heltec v4 R8','Heltec v4 + Expansion Kit (Touch)','Seeed Studio SenseCAP Solar Node P1 alternative','Seeed Studio Xiao S3'])assert.equal(canonicalHardware(value),value);
});

test('fresh provider manifests and cached snapshots normalize labels without changing provider, version or firmware evidence',()=>{
  for(const [legacy,canonical] of aliases){
    const source=item(legacy,{provider:'Keymind Cascade',releaseNotes:'Exact target evidence',sha256:'a'.repeat(64)}),raw=snapshot([source]),before=structuredClone(raw);
    const result=validateCatalog(raw).items[0];assert.equal(result.hardware,canonical);assert.equal(result.provider,source.provider);assert.equal(result.version,source.version);assert.equal(result.url,source.url);assert.equal(result.releaseNotes,source.releaseNotes);assert.equal(result.sha256,source.sha256);assert.deepEqual(raw,before);
    const config={device:[{name:legacy,type:'nrf52',firmware:[{role:'companionFull',version:{'v1.18.0':{files:[{name:source.name,url:source.url,type:'flash'}]}}}]}]};
    assert.equal(catalogItems(config)[0].hardware,canonical);
  }
});

test('catalog dedupe merges only same-provider identical aliases and preserves safety, variant and provider boundaries',()=>{
  const legacy=item(aliases[0][0]),canonical={...legacy,hardware:aliases[0][1]},variants=[{...canonical,provider:'Keymind Cascade'},{...canonical,version:'v1.17.0'},{...canonical,notice:'Different profile requirement'},{...canonical,url:'https://example.test/different.zip'},{...canonical,hardware:'Seeed Studio Wio Tracker L1 Pro'}];
  assert.equal(catalogItemKey(legacy),catalogItemKey(canonical));
  const input=[legacy,canonical,...variants],before=structuredClone(input),result=combineProviderItems(input);
  assert.equal(result.length,6);assert.equal(result.filter(entry=>entry.hardware===canonical.hardware).length,5);assert.deepEqual(input,before);
  assert.ok(result.some(entry=>entry.provider==='Keymind Cascade'));assert.ok(result.some(entry=>entry.notice==='Different profile requirement'));
});

test('both providers remain selectable after alias collapse and no false board ambiguity remains',()=>{
  for(const [legacy,canonical,hwModel,architecture='nrf52'] of aliases){
    const base=architecture==='esp32'?{architecture,action:'flash-update',name:'board-v1.18.0.bin',url:'https://example.test/board-v1.18.0.bin'}:{};
    const items=validateCatalog(snapshot([item(legacy,base),item(canonical,{...base,provider:'Keymind Cascade'})])).items;
    const board=detectMeshtasticBoard({items,hwModel});assert.equal(board.hardware,canonical);
    for(const provider of ['MeshCore','Keymind Cascade']){
      const result=chooseFirmware({items,device:{firmwareFamily:'meshtastic',role:'meshtastic',meshtasticRole:0},hardware:board.hardware,provider});
      assert.notEqual(result.artifactIndex,null);assert.equal(items[result.artifactIndex].provider,provider);assert.equal(result.selections.hardware,canonical);
    }
  }
});

test('offline and live catalog reads use the same canonical labels without losing equivalent utility inheritance',async()=>{
  const [legacy,canonical]=aliases[2],erase='https://example.test/exact-erase.zip';
  const official=item(legacy,{erase:[erase]}),provider=item(canonical,{provider:'Keymind Cascade',erase:[]}),raw=snapshot([official,provider]);
  assert.deepEqual(inheritOfficialUtilities([official,provider])[1].erase,[erase]);
  const memory=new Map(),storage={getItem:key=>memory.get(key),setItem:(key,value)=>memory.set(key,value)};
  const live=await getCatalog({storage,fetchImpl:async()=>({ok:true,json:async()=>raw})}),offline=await getCatalog({storage,fetchImpl:async()=>{throw Error('offline');}});
  for(const result of [live,offline]){assert.ok(result.items.every(entry=>entry.hardware===canonical));assert.deepEqual(result.items[1].erase,[erase]);assert.equal(result.items[1].provider,'Keymind Cascade');}
  assert.equal(raw.items[0].hardware,legacy);assert.equal(offline.cached,true);
});
