import test from 'node:test';
import assert from 'node:assert/strict';
import {firmwareChoices,firmwareChoiceLabel} from '../src/catalog-choices.js';
import {rakCatalogItems,rakUnified,rakLegacy} from './fixtures/rak-catalog.js';

test('published RAK4631 choices prefer unified Full/Reduced and Ethernet Full only',()=>{
  const items=rakCatalogItems(),before=structuredClone(items);
  const choices=firmwareChoices(items);
  assert.equal(choices.olderCount,11);
  assert.equal(choices.items.length,3);
  assert(choices.items.every(item=>/repeater_(unified_lora_ota|ethernet)-/.test(item.name)));
  assert.equal(choices.items.filter(item=>item.name.includes('-full-ota-')).length,2);
  assert.equal(choices.items.filter(item=>item.name.includes('-reduced-ota-')).length,1);
  assert.deepEqual(items,before,'presentation must preserve the complete catalog');
  assert(choices.items.every(item=>items.includes(item)),'original indices remain valid');
  assert.deepEqual(new Set(choices.items.map(firmwareChoiceLabel)),new Set([
    'Repeater / Unified - Full sensors + LoRa OTA',
    '(PICK THIS) Repeater / Unified - Reduced optional sensors + LoRa OTA',
    'Repeater / Ethernet - Full sensors + LoRa OTA',
  ]));
});

test('older builds, exact installed UART1 targets and shared filenames stay available',()=>{
  const items=rakCatalogItems();
  assert.deepEqual(firmwareChoices(items,{showOlder:true}).items,items);
  const exact=firmwareChoices(items,{installedTarget:rakLegacy});
  assert.equal(exact.items.length,5);
  assert(exact.items.includes(items[0])&&exact.items.includes(items[1]));
  const linked=firmwareChoices(items,{keepNames:[items[0].name]});
  assert.equal(linked.items.length,4);assert(linked.items.includes(items[0]));
  assert.equal(firmwareChoices(items,{keepNames:['unknown.zip']}).items.length,3);
});

test('an installed Ethernet target uses Full while explicit Reduced files stay available',()=>{
  const items=rakCatalogItems(),reduced=items.find(item=>item.name.startsWith('RAK_4631_repeater_ethernet-reduced-'));
  const installed=firmwareChoices(items,{installedTarget:'RAK_4631_repeater_ethernet'});
  assert.equal(installed.items.length,3);
  assert(!installed.items.includes(reduced));
  assert(firmwareChoices(items,{showOlder:true}).items.includes(reduced));
  assert(firmwareChoices(items,{keepNames:[reduced.name]}).items.includes(reduced));
});

test('Ethernet retains its Reduced fallback without one matching published Full build',()=>{
  const items=rakCatalogItems(),full=items.find(item=>item.name.startsWith('RAK_4631_repeater_ethernet-full-'));
  const reduced=items.find(item=>item.name.startsWith('RAK_4631_repeater_ethernet-reduced-'));
  const withoutFull=items.filter(item=>item!==full);
  const mismatches=[{provider:'MeshCore'},{hardware:'Different board'},{releaseNotes:''},
    {version:'v1.18.0.1-halo-keymind-cascade-dev-03214a16'},
    {name:full.name.replace('a723af94','bbbbbbbb')}];
  for(const choices of [withoutFull,...mismatches.map(changes=>[...withoutFull,{...full,...changes}]),
    [...items,{...full,url:full.url+'?different-payload'}]]){
    assert(firmwareChoices(choices).items.includes(reduced));
  }
});

test('every reduced-sensor label is recommended across boards, roles and bundled bootloaders',()=>{
  const base=rakCatalogItems()[0];
  for(const [hardware,role,name] of [
    ['Heltec v4','repeater','heltec_v4_repeater-reduced-ota-v1.18.0.2.bin'],
    ['Heltec T114','roomServer','Heltec_t114_room_server-with-bootloader-2.4.12-reduced-ota-v1.18.0.2.zip'],
    ['RAK WisBlock / WisMesh (RAK 4631)','repeater',rakUnified+'-reduced-ota-v1.18.0.2.zip'],
  ]){
    const item={...base,hardware,role,name};
    assert(firmwareChoiceLabel(item).startsWith('(PICK THIS) '));
    assert(!firmwareChoiceLabel({...item,name:name.replace('-reduced-','-full-')}).includes('(PICK THIS)'));
  }
});

test('unfiltered choices identify their hardware and release without exposing raw target names',()=>{
  const item=rakCatalogItems().find(item=>item.name.startsWith(rakUnified+'-full-'));
  const label=firmwareChoiceLabel(item,{showHardware:true,showVersion:true});
  assert(label.startsWith(item.hardware+' / Repeater / Unified - Full sensors'));
  assert(label.endsWith(' - '+item.version));
  assert(!label.includes('RAK_4631_repeater_'));
});

test('a missing unified sensor profile retains every exact fallback for that policy',()=>{
  for(const sensors of ['full','reduced']){
    const items=rakCatalogItems().filter(item=>!item.name.startsWith(`${rakUnified}-${sensors}-`));
    const result=firmwareChoices(items);
    assert.equal(result.items.length,7);
    assert(result.items.includes(items.find(item=>item.name.startsWith(`${rakLegacy}-${sensors}-`))));
  }
  const legacy=rakCatalogItems().filter(item=>!item.name.startsWith(rakUnified+'-'));
  assert.deepEqual(firmwareChoices(legacy).items,legacy.filter(item=>!item.name.startsWith('RAK_4631_repeater_ethernet-reduced-')));
});

test('a replacement must match board, provider, role, action, release source and target declaration',()=>{
  for(const changes of [{provider:'MeshCore'},{hardware:'Different board'},
    {architecture:'esp32'},{role:'companionFull'},{action:'download'},
    {version:'v1.18.0.1-halo-keymind-cascade-dev-03214a16'},
    {releaseNotes:'EXACT TARGET - different_target.'},{releaseNotes:''}]){
    const items=rakCatalogItems().map(item=>item.name.startsWith(rakUnified+'-')?{...item,...changes}:item);
    assert.equal(firmwareChoices(items).items.length,13,JSON.stringify(changes));
  }
  const mixed=rakCatalogItems().map(item=>item.name.startsWith(rakUnified+'-')?
    {...item,name:item.name.replace('a723af94','bbbbbbbb')}:item);
  assert.equal(firmwareChoices(mixed).items.length,13);
});

test('historical storage releases keep all choices without a same-release unified replacement',()=>{
  const items=rakCatalogItems();
  const old=items.filter(item=>!item.name.startsWith(rakUnified+'-')).map(item=>({
    ...item,version:item.version.replace('1.18.0.2','1.18.0.1'),
    name:item.name.replace('1.18.0.2','1.18.0.1'),
  }));
  const result=firmwareChoices([...items,...old]);
  assert(old.filter(item=>!item.name.startsWith('RAK_4631_repeater_ethernet-reduced-')).every(item=>result.items.includes(item)));
  assert.equal(result.items.length,14);
});

test('conflicting published replacements do not retire the affected exact fallbacks',()=>{
  const items=rakCatalogItems(),full=items.find(item=>item.name.startsWith(rakUnified+'-full-'));
  const result=firmwareChoices([...items,{...full,url:full.url+'?different-payload'}]);
  assert(result.items.includes(items[0]));
  assert(!result.items.includes(items[1]),'the independent Reduced replacement still matches');
});

test('bundled bootloaders and unrelated RAK roles are outside ordinary application consolidation',()=>{
  const items=rakCatalogItems(),bundled=items.map(item=>({...item,
    name:item.name.replace('-full-ota-','-with-bootloader-2.4.12-full-ota-')
      .replace('-reduced-ota-','-with-bootloader-2.4.12-reduced-ota-')}));
  assert.deepEqual(firmwareChoices(bundled).items,bundled);
  for(const role of ['roomServer','companionFull','sensor']){
    const other=items.map(item=>({...item,role}));
    assert.deepEqual(firmwareChoices(other).items,other);
  }
});

test('RAK3401 consolidates only its matching storage targets',()=>{
  const items=rakCatalogItems().filter(item=>/repeater_(unified_lora_ota|lora_ota_no_external_sensors|w25q16_lora_ota)-/.test(item.name))
    .map(item=>JSON.parse(JSON.stringify(item).replaceAll('RAK_4631','RAK_3401')))
    .map(item=>({...item,hardware:'RAK WisMesh 1W Booster (3401 + 13302)'}));
  const result=firmwareChoices(items);
  assert.equal(result.items.length,2);
  assert(result.items.every(item=>item.name.startsWith('RAK_3401_repeater_unified_lora_ota-')));
});
