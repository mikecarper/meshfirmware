import test from 'node:test';
import assert from 'node:assert/strict';
import { checkCatalogRoutes } from '../scripts/check-catalog.mjs';
import { validateCatalog } from '../src/catalog.js';
const route='/releases/download/companion-v1.18.0/board.zip';
const item={project:'MeshCore',provider:'MeshCore',hardware:'Board',architecture:'nrf52',name:'board.zip',url:'https://github.com/meshcore-dev/MeshCore'+route,erase:['https://flasher.meshcore.io/firmware/erase.zip']};
const snapshot=value=>({generatedAt:'2026-10-27T00:00:00Z',warnings:[],items:[value]});
test('publication refuses malformed raw official links even when browser cache recovery can repair them',()=>{
  const raw=snapshot({...item,url:'https://github.com'+route}),original=JSON.stringify(raw);
  assert.equal(validateCatalog(raw).items[0].url,item.url);
  assert.throws(()=>checkCatalogRoutes(raw),/owner\/repository/);
  assert.equal(JSON.stringify(raw),original);
});
test('publication checks every raw artifact and utility reference, not only a repaired first item',()=>{
  assert.deepEqual(checkCatalogRoutes(snapshot(item)),{artifacts:1,utilities:1,officialReleases:1});
  assert.throws(()=>checkCatalogRoutes({...snapshot(item),items:[item,{...item,url:'https://github.com'+route}]}),/owner\/repository/);
  assert.throws(()=>checkCatalogRoutes(snapshot({...item,erase:['https://github.com'+route]})),/owner\/repository/);
});

test('publication cannot retain old or unverified bootloader recommendations that the browser would disable',()=>{
  const legacy={...item,bootloader:['https://flasher.meshcore.io/firmware/old-2.2.zip']};
  assert.deepEqual(validateCatalog(snapshot(legacy)).items[0].bootloader,[]);
  assert.throws(()=>checkCatalogRoutes(snapshot(legacy)),/verified fork manifest/);
});

test('invalid optional recovery metadata cannot be published and cannot poison otherwise valid application entries',()=>{
  const raw={...snapshot(item),recoveryCatalog:{schemaVersion:1}},checked=validateCatalog(raw);
  assert.equal(checked.items[0].url,item.url);assert.equal(checked.recoveryCatalog,null);assert.ok(checked.warnings.some(w=>w.includes('Recovery catalog could not be verified')));
  assert.throws(()=>checkCatalogRoutes(raw),/verified stable-release bundle/);
});
