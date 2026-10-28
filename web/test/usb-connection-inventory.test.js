import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {buildInventory,verifyManifest,keymindRuntimeVersion,stockRuntimeVersion,runtimeEvidence} from '../scripts/collect-usb-connection-inventory.mjs';

const revision='03214a16df2bd09d3272dfb001d2d322c6740f60',repo='https://github.com/mikecarper/MeshCore';
const builder='get_firmware_version_string() channel_tag="-observer${OTA_CHANNEL_TAG:+-${OTA_CHANNEL_TAG}}" "${version}${build_suffix}${channel_tag}-${commit_hash}"';
const stockBuilder='FIRMWARE_VERSION_STRING="${FIRMWARE_VERSION}-${COMMIT_HASH}" FIRMWARE_FILENAME="$1-${FIRMWARE_VERSION_STRING}" -DFIRMWARE_VERSION=';
const record={source_commit:revision,target:'board_repeater',artifact_target:'board_repeater-full-ota',platformio_env:'board_repeater_observer_mqtt',build_profile:'full',files:['board_repeater-full-ota-v1.18.0.1-halo-keymind-cascade-dev-03214a16.bin']};
const item={provider:'Keymind Cascade',hardware:'Board',architecture:'esp32',role:'repeater',version:'v1.18.0.1-halo-keymind-cascade-dev-03214a16',name:record.files[0],releaseNotes:`EXACT TARGET - board_repeater. Match the exact board.\nSOURCE - ${repo}/tree/${revision}`};
const inputs={catalog:{generatedAt:'2026-10-28T00:00:00Z',items:[item]},manifests:[{url:repo+'/releases/download/tag/TARGET-MANIFEST.json',size:1,sha256:'a'.repeat(64),records:[record]}],sourceEnvironments:()=>[record.platformio_env],sourceText:()=>builder,resolveRevision:()=>revision};

test('public target manifests require exact size, SHA and full pinned source',()=>{
  const bytes=Buffer.from(JSON.stringify([record])),metadata={size:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')};
  assert.deepEqual(verifyManifest(bytes,metadata),[record]);assert.throws(()=>verifyManifest(bytes,{...metadata,size:bytes.length+1}),/mismatch/);assert.throws(()=>verifyManifest(bytes,{...metadata,sha256:'b'.repeat(64)}),/mismatch/);
  const bad=Buffer.from(JSON.stringify([{...record,source_commit:'0'.repeat(40)}]));assert.throws(()=>verifyManifest(bad,{size:bad.length,sha256:createHash('sha256').update(bad).digest('hex')}),/provenance/);
});
test('inventory joins exact filenames and canonical target to real source env, not artifact naming guesses',()=>{
  const inventory=buildInventory(inputs);assert.equal(inventory.items.length,1);assert.equal(inventory.unresolved.length,0);assert.equal(inventory.items[0].target,'board_repeater');assert.equal(inventory.items[0].environment,record.platformio_env);assert.equal(inventory.items[0].runtimeVersion,'v1.18.0.1-halo-keymind-cascade-dev-observer-03214a16');assert.equal(inventory.items[0].manifestSha256,'a'.repeat(64));
  assert.throws(()=>buildInventory({...inputs,sourceEnvironments:()=>[]}),/environment/);
  assert.equal(buildInventory({...inputs,catalog:{items:[{...item,name:'similar.bin'}]}}).unresolved.length,1);
  assert.equal(buildInventory({...inputs,catalog:{items:[{...item,releaseNotes:item.releaseNotes.replace('board_repeater.','other.')} ]}}).unresolved.length,1);
});
test('runtime values are retained only when the exact source builder convention is known',()=>{
  assert.equal(keymindRuntimeVersion(item.version,record,builder),'v1.18.0.1-halo-keymind-cascade-dev-observer-03214a16');
  assert.equal(keymindRuntimeVersion(item.version,{...record,platformio_env:'board_repeater'},builder),item.version);
  assert.equal(keymindRuntimeVersion(item.version,record,''),null);assert.equal(keymindRuntimeVersion('v1.18.0.1-halo-keym',record,builder),null);
  assert.equal(keymindRuntimeVersion('v1.18.0.2-halo-keymind-cascade-dev-03214a16',record,builder),null,'A different/custom version must not inherit sampled runtime conventions');
  assert.equal(stockRuntimeVersion('board-v1.17.1-d929643-merged.bin',stockBuilder),'v1.17.1-d929643');assert.equal(stockRuntimeVersion('board-v1.17.1-d929643.bin',''),null);
});
test('stock hashes require a full matching source commit and an exact source environment',()=>{
  const s={...item,provider:'MeshCore',name:'board_repeater-v1.17.1-d929643.bin',version:'v1.17.1'},sha='d92964352441e53b93e8667b802e04f6e072b39e',i={...inputs,catalog:{items:[s]},manifests:[],resolveRevision:()=>sha,sourceEnvironments:()=>['board_repeater'],sourceText:()=>stockBuilder};
  const result=buildInventory(i);assert.equal(result.items[0].source.revision,sha);assert.equal(result.items[0].runtimeVersion,'v1.17.1-d929643');assert.equal(result.items[0].environment,'board_repeater');
  assert.equal(buildInventory({...i,resolveRevision:()=>revision}).unresolved.length,1);assert.equal(buildInventory({...i,sourceEnvironments:()=>[]}).unresolved.length,1);
  assert.equal(buildInventory({...i,catalog:{items:[{...s,name:'Ultra-v11.0.bin'}]}}).unresolved[0].reason,'Artifact has no published source-commit suffix');
});
test('committed inventory retains public provenance and explicit unresolved rows without private node data',async()=>{
  const inventory=JSON.parse(await readFile(new URL('../scripts/usb-connection-inventory.json',import.meta.url),'utf8'));assert.equal(inventory.schemaVersion,1);assert.ok(inventory.items.length>=3678);assert.equal(inventory.manifests.length,5);assert.equal(inventory.unresolved.length,24);
  for(const item of inventory.items){assert.match(item.source.revision,/^[a-f0-9]{40}$/);assert.ok(item.environment&&item.target);assert.ok(item.runtimeVersion===null||typeof item.runtimeVersion==='string');assert.ok(!Object.hasOwn(item,'publicKey')&&!Object.hasOwn(item,'serialNumber')&&!Object.hasOwn(item,'nodeName'));}
  for(const manifest of inventory.manifests){assert.ok(manifest.url.startsWith(repo+'/releases/download/'));assert.match(manifest.sha256,/^[a-f0-9]{64}$/);assert.ok(manifest.size>0);}
  assert.deepEqual(inventory.runtimeEvidence,runtimeEvidence);assert.equal(inventory.runtimeEvidence.length,2);
  assert.deepEqual(inventory.runtimeEvidence.map(row=>row.size),[427599,1881720]);
  for(const row of inventory.runtimeEvidence){assert.ok(row.url.startsWith(repo+'/releases/download/'));assert.match(row.sha256,/^[a-f0-9]{64}$/);assert.match(row.scope,/sample plus pinned release builder/);assert.ok(row.component&&row.container);}
});
