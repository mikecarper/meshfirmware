import test from 'node:test';
import assert from 'node:assert/strict';
import {chooseFirmware} from '../src/automatic.js';

const hardware='RAK WisMesh 1W Booster (3401 + 13302)';
const unified='RAK_3401_repeater_unified_lora_ota';
const version='v1.18.0.1-halo-keymind-cascade-dev-03214a16';
const item=(target=unified,profile='full-ota',more={})=>{
  const name=`${target}-${profile}-${more.version||version}.zip`;
  return {project:'MeshCore',provider:'Keymind Cascade',hardware,architecture:'nrf52',role:'repeater',action:'flash',version,name,url:`https://example.test/${name}`,releaseNotes:`EXACT TARGET - ${target}. Match the exact build.`,...more};
};
const device={firmwareFamily:'meshtastic',role:'meshtastic',meshtasticHardware:117,meshtasticRole:2,model:'RAK3401',version:'2.7.15',catalogRole:null,publicKey:null};
const choose=(items,more={})=>chooseFirmware({items,device,hardware,...more});
const variants=()=>[
  item('RAK_3401_repeater_bridge_rs232_serial1'),
  item(unified,'reduced-ota'),
  item('RAK_3401_repeater_rak13302_w25q16_lora_ota'),
  item('RAK_3401_repeater_lora_ota_no_external_sensors'),
  item(),
];

test('RAK3401 selects the universal Full OTA repeater independently of variant order',()=>{
  const items=variants();
  for(let rotation=0;rotation<items.length;rotation++)for(const reversed of [false,true]){
    let inventory=[...items.slice(rotation),...items.slice(0,rotation)];if(reversed)inventory.reverse();
    for(const installMode of ['update','install']){
      const result=choose(inventory,{installMode});assert.equal(inventory[result.artifactIndex].name,item().name);assert.equal(result.selections.role,'repeater');assert.equal(result.selections.provider,'Keymind Cascade');assert.equal(result.selections.version,version);assert.match(result.reason,/Universal RAK3401 Full OTA profile selected/);assert.equal(result.warning,'');
    }
  }
});

test('a missing or non-unique universal Full build keeps ambiguous RAK3401 feature choices manual',()=>{
  const noDefault=variants().filter(candidate=>candidate.name!==item().name);
  for(const inventory of [noDefault,[...noDefault,item(unified,'full-ota',{releaseNotes:'EXACT TARGET - different_target.'})],[...variants(),item(unified,'full-ota',{url:'https://example.test/different-payload.zip'})],[item('RAK_3401_future_repeater'),item('RAK_3401_other_future_repeater')]]){
    const result=choose(inventory);assert.equal(result.artifactIndex,null);assert.match(result.reason,/Multiple exact-board builds remain/);
  }
  const duplicate=choose([...variants(),item()]);assert.equal([...variants(),item()][duplicate.artifactIndex].name,item().name,'identical catalog duplicates are still collapsed');
});

test('a RAK3401 canonical default never defeats explicit target, version, provider or role selections',()=>{
  const alternate=item('RAK_3401_repeater_rak13302_w25q16_lora_ota');
  const exact=choose([...variants()],{device:{...device,exactTarget:'RAK_3401_repeater_rak13302_w25q16_lora_ota'}});assert.equal(variants()[exact.artifactIndex].name,alternate.name);
  const conflicting=choose(variants(),{device:{...device,exactTarget:'missing_target'}});assert.equal(conflicting.artifactIndex,null);assert.match(conflicting.reason,/exact build target/);
  const profileStillExplicit=choose(variants(),{device:{...device,exactTarget:unified}});assert.equal(profileStillExplicit.artifactIndex,null,'an explicitly reported exact target does not authorize a different profile choice');
  const old=item(unified,'full-ota',{version:'v1.17.0'}),oldReduced=item(unified,'reduced-ota',{version:'v1.17.0'}),inventory=[...variants(),old,oldReduced];
  const selectedOld=choose(inventory,{version:'v1.17.0'});assert.equal(inventory[selectedOld.artifactIndex].name,old.name);assert.equal(selectedOld.selections.version,'v1.17.0');
  const stock=choose(variants().map(candidate=>({...candidate,provider:'MeshCore'})),{provider:'MeshCore'});assert.equal(stock.artifactIndex,null,'the Keymind preference must not guess a stock feature variant');
  const companion=item('RAK_3401_companion_radio_full','full',{role:'companionFull'}),selectedCompanion=choose([...variants(),companion],{role:'companionFull'});assert.equal([...variants(),companion][selectedCompanion.artifactIndex].name,companion.name);assert.equal(selectedCompanion.selections.role,'companionFull');
  assert.equal(choose(variants(),{role:'roomServer'}).artifactIndex,null);
});

test('the universal preference cannot cross board identity or use a stale release to resolve a newer ambiguity',()=>{
  const wrongBoard=choose(variants().map(candidate=>({...candidate,hardware:'RAK WisBlock / WisMesh (RAK 4631)'})),{hardware:'RAK WisBlock / WisMesh (RAK 4631)'});assert.equal(wrongBoard.artifactIndex,null,'RAK4631 cannot inherit a RAK3401 filename preference');
  const noHardware=choose(variants(),{hardware:''});assert.equal(noHardware.artifactIndex,null);
  const future=[item('RAK_3401_future_repeater','full-ota',{version:'v1.19.0'}),item('RAK_3401_other_future_repeater','full-ota',{version:'v1.19.0'}),item()];
  const result=choose(future);assert.equal(result.selections.version,'v1.19.0');assert.equal(result.artifactIndex,null);
  const conflictingHardware=choose(variants(),{device:{...device,hardwareId:'another_hardware_id'}});assert.equal(conflictingHardware.artifactIndex,null);assert.match(conflictingHardware.reason,/hardware ID/);
});

test('RAK4631 also defaults to its own universal Full OTA build without crossing feature, provider or target choices',()=>{
  const hardware='RAK WisBlock / WisMesh (RAK 4631)',target='RAK_4631_repeater_unified_lora_ota';
  const full=item(target,'full-ota',{hardware}),reduced=item(target,'reduced-ota',{hardware}),bridge=item('RAK_4631_repeater_bridge_rs232','full-ota',{hardware}),inventory=[bridge,reduced,full];
  for(const items of [inventory,inventory.toReversed()]){
    const result=choose(items,{hardware,device:{...device,meshtasticHardware:9,model:'RAK4631'}});assert.equal(items[result.artifactIndex].name,full.name);assert.match(result.reason,/Universal RAK4631 Full OTA/);
    const explicit=choose(items,{hardware,device:{...device,exactTarget:'RAK_4631_repeater_bridge_rs232'}});assert.equal(items[explicit.artifactIndex].name,bridge.name);
  }
  assert.equal(choose([bridge,reduced],{hardware}).artifactIndex,null);
  assert.equal(choose(inventory.map(i=>({...i,provider:'MeshCore'})),{hardware,provider:'MeshCore'}).artifactIndex,null);
});

test('embedded bootloaders and recovery/erase utilities cannot supply the RAK3401 universal default',()=>{
  const alternatives=variants().filter(candidate=>candidate.name!==item().name);
  const excluded=[
    item(unified,'with-bootloader-2.4.12-full-ota'),
    item(unified,'full-ota',{includesBootloader:true}),
    item(unified,'full-ota',{includesSoftdevice:true}),
    item('R_wiscore_rak3401_auto'),item('RAK_3401_erase'),
    item(unified,'full-ota',{architecture:'esp32',action:'flash-wipe',name:'RAK_3401_repeater_unified_lora_ota-merged.bin'}),
  ];
  for(const candidate of excluded){const result=choose([...alternatives,candidate]);assert.equal(result.artifactIndex,null);assert.match(result.reason,/Multiple exact-board builds remain/);}
});

test('RAK3401 defaults are display-only suggestions and never mutate catalog or role evidence',()=>{
  const items=variants(),original=structuredClone(items),originalDevice=structuredClone(device);
  for(const candidate of items)Object.freeze(candidate);Object.freeze(items);Object.freeze(device);
  const result=choose(items);assert.equal(result.artifactIndex,4);assert.deepEqual(items,original);assert.deepEqual(device,originalDevice);assert.equal(Object.hasOwn(result,'erase'),false);assert.equal(Object.hasOwn(result,'approved'),false);
});
