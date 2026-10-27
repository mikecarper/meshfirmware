import test from 'node:test';
import assert from 'node:assert/strict';
import {catalogItems,githubReleaseUrl,validateCatalog,validateFirmwareUrl,getCatalog} from '../src/catalog.js';
import {buildCatalog} from '../scripts/catalog-build.mjs';

const route='/releases/download/companion-v1.18.0/ThinkNode_M1_companion_radio_ble-v1.18.0-81dbae5.zip';
const correct='https://github.com/meshcore-dev/MeshCore'+route;
const bad='https://github.com'+route;
const config={device:[{name:'Elecrow ThinkNode M1',type:'nrf52',firmware:[{role:'companionBle',github:{type:'companion',files:{flash:'ThinkNode_M1_companion_radio_ble-v1\\.18\\.0-81dbae5\\.zip'}}}]}]};
const releases=[{type:'companion',version:'v1.18.0',files:[{name:route.split('/').at(-1),url:route}]}];
const snapshot=item=>({generatedAt:'2026-01-01T00:00:00Z',warnings:[],items:[item]});

test('actual upstream repository-relative routes preserve owner/repository instead of URL-origin resolution',()=>{
  assert.equal(catalogItems(config,releases)[0].url,correct);
  assert.equal(githubReleaseUrl(route),correct);
  assert.equal(githubReleaseUrl(route.slice(1)),correct);
  assert.equal(githubReleaseUrl('https://github.com/mikecarper/MeshCore/releases/download/keymind/file.zip'),'https://github.com/mikecarper/MeshCore/releases/download/keymind/file.zip');
  assert.throws(()=>githubReleaseUrl(route,'https://github.com/meshcore-dev'),/repository base/);
  assert.throws(()=>githubReleaseUrl('http://example.test/app.zip'),/HTTPS/);
});
test('static paths, absolute assets and repository-relative utility paths remain distinct',()=>{
  const device={name:'test',type:'nrf52',erase:'releases/download/utility/erase.zip',bootloader:'/firmware/boot.zip',firmware:[{role:'repeater',version:{v1:{files:[{name:'local.zip',type:'flash'},{name:'named.zip',url:route,type:'flash'}]}}}]};
  const items=catalogItems({staticPath:'/firmware',device:[device]});
  assert.equal(items[0].url,'https://flasher.meshcore.io/firmware/local.zip');assert.equal(items[1].url,correct);
  assert.deepEqual(items[0].erase,['https://github.com/meshcore-dev/MeshCore/releases/download/utility/erase.zip']);assert.deepEqual(items[0].bootloader,['https://flasher.meshcore.io/firmware/boot.zip']);
});
test('legacy official cached links are repaired, never preserved; ambiguous provider bad links are rejected',async()=>{
  const item={...catalogItems(config,releases)[0],url:bad},old=snapshot(item),fixed=validateCatalog(old);
  assert.equal(fixed.items[0].url,correct);assert.equal(old.items[0].url,bad);assert.ok(fixed.warnings.some(w=>w.includes('Repaired 1')));
  assert.throws(()=>validateFirmwareUrl(bad),/owner\/repository/);
  assert.throws(()=>validateCatalog(snapshot({...item,provider:'Keymind Cascade'})),/owner\/repository/);
  const storage={getItem:()=>JSON.stringify(old),setItem(){}};
  const cached=await getCatalog({storage,fetchImpl:async()=>{throw new Error('offline');}});assert.equal(cached.items[0].url,correct);
  const build=await buildCatalog({readJson:async()=>{throw new Error('offline');},previous:async()=>old});assert.equal(build.items[0].url,correct);
});
