import test from 'node:test';
import assert from 'node:assert/strict';
import {PAGER_VARIANTS_KEY,rememberPagerVariant,recallPagerVariant,forgetPagerVariant} from '../src/remembered-pager.js';

const sx='LilyGo T-Lora Pager (SX1262)',lr='LilyGo T-Lora Pager (LR1121)';
const device={firmwareFamily:'meshcore',role:'companion',version:'wadamesh-tak beta_1',model:'LilyGo T-LoRa Pager',publicKey:'ab'.repeat(32)};
const catalog=[{project:'MeshCore',provider:'Wadamesh TAK',architecture:'esp32',role:'gui',hardware:sx,wadameshBuild:'tlora-pager-sx1262'},
  {project:'MeshCore',provider:'Wadamesh TAK',architecture:'esp32',role:'gui',hardware:lr,wadameshBuild:'tlora-pager-lr1121'}];
function storage(initial=null){const map=new Map(initial===null?[]:[[PAGER_VARIANTS_KEY,initial]]);return {getItem:key=>map.get(key)??null,setItem:(key,value)=>map.set(key,value),map};}

test('remembers only an explicitly selected reviewed variant for the same full identity',()=>{
  const store=storage();assert.equal(recallPagerVariant({storage:store,device,items:catalog}),null);
  assert.equal(rememberPagerVariant({storage:store,device,hardware:sx,items:catalog}),true);
  assert.equal(recallPagerVariant({storage:store,device,items:catalog}),sx);
  assert.equal(recallPagerVariant({storage:store,device:{...device,publicKey:'AB'.repeat(32)},items:catalog}),sx);
  assert.equal(recallPagerVariant({storage:store,device:{...device,publicKey:'cd'.repeat(32)},items:catalog}),null);
  assert.equal(rememberPagerVariant({storage:store,device,hardware:lr,items:catalog}),true);
  assert.equal(recallPagerVariant({storage:store,device,items:catalog}),lr);
  const value=JSON.parse(store.map.get(PAGER_VARIANTS_KEY));assert.deepEqual(value,{version:1,entries:[{key:device.publicKey,hardware:lr}]});
});

test('unrecognized firmware, different hardware, malformed keys and unavailable variants never use a remembered choice',()=>{
  const store=storage();assert.equal(rememberPagerVariant({storage:store,device,hardware:sx,items:catalog}),true);
  for(const bad of [{...device,version:'MeshCore'}, {...device,firmwareFamily:'bootloader'}, {...device,role:'common-cli'}, {...device,model:'LilyGo T-Deck'}, {...device,model:'LilyGo T-LoRa Pager (SX1262)'}, {...device,publicKey:'ab'.repeat(6)}, {...device,publicKey:'0'.repeat(64)}]){
    assert.equal(recallPagerVariant({storage:store,device:bad,items:catalog}),null);
    assert.equal(rememberPagerVariant({storage:store,device:bad,hardware:lr,items:catalog}),false);
  }
  assert.equal(recallPagerVariant({storage:store,device,items:[catalog[1]]}),null);
  assert.equal(rememberPagerVariant({storage:store,device,hardware:'LilyGo T-Deck',items:catalog}),false);
  assert.equal(rememberPagerVariant({storage:store,device,hardware:sx,items:[{...catalog[0],wadameshBuild:'tlora-pager-lr1121'}]}),false);
});

test('malformed or untrusted saved preferences do not select any variant',()=>{
  for(const data of ['{',JSON.stringify({version:2,entries:[{key:device.publicKey,hardware:sx}]}),JSON.stringify({version:1,entries:[{key:device.publicKey,hardware:'LilyGo T-Deck'}]}),JSON.stringify({version:1,entries:[{key:device.publicKey,hardware:sx},{key:device.publicKey,hardware:lr}]}),JSON.stringify({version:1,entries:[{key:device.publicKey,hardware:sx,extra:'bad'}]}),'x'.repeat(8193)]){
    assert.equal(recallPagerVariant({storage:storage(data),device,items:catalog}),null);
  }
  assert.equal(recallPagerVariant({storage:{getItem(){throw Error('denied');}},device,items:catalog}),null);
  assert.equal(rememberPagerVariant({storage:{getItem(){return null;},setItem(){throw Error('denied');}},device,hardware:sx,items:catalog}),false);
});

test('stores a bounded list without retaining other device fields',()=>{
  const store=storage();
  for(let i=1;i<=33;i++){
    const d={...device,publicKey:i.toString(16).padStart(64,'0'),name:'private name',secret:'not stored'};
    assert.equal(rememberPagerVariant({storage:store,device:d,hardware:sx,items:catalog}),true);
  }
  const raw=store.map.get(PAGER_VARIANTS_KEY),saved=JSON.parse(raw);
  assert.equal(saved.entries.length,32);assert.equal(saved.entries[0].key,'2'.padStart(64,'0'));assert.ok(!raw.includes('private name'));assert.ok(!raw.includes('not stored'));
});

test('forgetting a preference affects only the explicitly identified pager',()=>{
  const store=storage(),other={...device,publicKey:'cd'.repeat(32)};
  assert.equal(rememberPagerVariant({storage:store,device,hardware:sx,items:catalog}),true);
  assert.equal(rememberPagerVariant({storage:store,device:other,hardware:lr,items:catalog}),true);
  assert.equal(forgetPagerVariant({storage:store,device}),true);
  assert.equal(recallPagerVariant({storage:store,device,items:catalog}),null);
  assert.equal(recallPagerVariant({storage:store,device:other,items:catalog}),lr);
  assert.equal(forgetPagerVariant({storage:store,device}),false);
  assert.equal(forgetPagerVariant({storage:store,device:{...other,version:'MeshCore'}}),false);
  assert.equal(recallPagerVariant({storage:store,device:other,items:catalog}),lr);
  assert.equal(forgetPagerVariant({storage:{getItem:()=>JSON.stringify({version:1,entries:[{key:other.publicKey,hardware:lr}]}),setItem(){throw Error('denied');}},device:other}),false);
});
