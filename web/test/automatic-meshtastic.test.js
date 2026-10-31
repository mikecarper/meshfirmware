import test from 'node:test';
import assert from 'node:assert/strict';
import {chooseFirmware} from '../src/automatic.js';
import {detectMeshtasticBoard} from '../src/meshtastic-boards.js';
const item=(more={})=>({project:'MeshCore',hardware:'Heltec T114',architecture:'nrf52',provider:'Keymind Cascade',role:'companionFull',action:'flash',version:'v1.18.0',name:'Heltec_t114_companion_radio_full-v1.18.0.zip',url:'https://example.test/t114.zip',...more});
const device={firmwareFamily:'meshtastic',role:'meshtastic',meshtasticHardware:69,version:'2.7.13',catalogRole:null,publicKey:null};
const choose=(items,more={})=>chooseFirmware({items,device,hardware:'Heltec T114',...more});

test('Meshtastic T114 maps to nRF52 and automatically selects the Keymind Full Companion ZIP, never Heltec ESP32 V2',()=>{
  const items=[item(),item({provider:'MeshCore',role:'companionBle'}),item({hardware:'Heltec v2',architecture:'esp32',action:'flash-update',name:'Heltec_v2_companion_radio_full-v1.18.0.bin'})],board=detectMeshtasticBoard({items,hwModel:device.meshtasticHardware});
  assert.equal(board.hardware,'Heltec T114');const result=choose(items,{hardware:board.hardware});assert.equal(result.artifactIndex,0);assert.deepEqual(result.selections,{provider:'Keymind Cascade',hardware:'Heltec T114',role:'companionFull',version:'v1.18.0'});assert.equal(result.warning,'');assert.equal(result.downgrade,false);assert.match(result.reason,/Meshtastic detected/);
});

test('Meshtastic Router, Router Late and Client Base default to Repeater; every other role defaults to Full Companion',()=>{
  const items=['companionUsb','repeater','companionBle','companionFull'].map(role=>item({role,name:`t114_${role}-v1.18.0.zip`,url:`https://example.test/${role}.zip`}));
  // Official Config.DeviceConfig.Role values, including deprecated roles.
  const roles=['CLIENT','CLIENT_MUTE','ROUTER','ROUTER_CLIENT','REPEATER','TRACKER','SENSOR','TAK','CLIENT_HIDDEN','LOST_AND_FOUND','TAK_TRACKER','ROUTER_LATE','CLIENT_BASE'];
  for(const [meshtasticRole,name] of roles.entries()){
    const result=choose(items,{device:{...device,meshtasticRole}}),expected=[2,11,12].includes(meshtasticRole)?'repeater':'companionFull';
    assert.equal(result.selections.role,expected,name);assert.equal(items[result.artifactIndex].role,expected,name);assert.equal(result.warning,'',name);assert.equal(result.downgrade,false,name);
  }
});

test('missing, unknown or invalid Meshtastic roles use Full Companion without reading names or firmware text',()=>{
  const items=[item(),item({role:'repeater',name:'t114_repeater-v1.18.0.zip'})];
  for(const meshtasticRole of [undefined,null,13,999,-1,2.5,'2','ROUTER','ROUTER_LATE','CLIENT_BASE',{},NaN]){
    const result=choose(items,{device:{...device,meshtasticRole,name:'ROUTER',model:'Client Base',meshtasticRoleName:'ROUTER_LATE',catalogRole:'repeater',version:'Meshtastic repeater v2.7.13'}});
    assert.equal(result.selections.role,'companionFull',String(meshtasticRole));assert.equal(result.artifactIndex,0,String(meshtasticRole));
  }
});

test('Meshtastic defaults never replace an explicitly selected MeshCore role',()=>{
  const items=[item(),item({role:'repeater',name:'t114_repeater-v1.18.0.zip'}),item({role:'companionUsb',name:'t114_companion_usb-v1.18.0.zip'})];
  for(const meshtasticRole of [0,2,11,12])for(const [index,role] of ['companionFull','repeater','companionUsb'].entries()){
    const result=choose(items,{device:{...device,meshtasticRole},role});assert.equal(result.selections.role,role);assert.equal(result.artifactIndex,index);
  }
});

test('an unavailable Meshtastic default remains selected and requires an explicit different role rather than BLE or USB substitution',()=>{
  for(const meshtasticRole of [undefined,0,2,11,12]){
    const expected=[2,11,12].includes(meshtasticRole)?'repeater':'companionFull';
    const items=['companionBle','companionUsb',expected==='repeater'?'companionFull':'repeater'].map(role=>item({role,name:`t114_${role}-v1.18.0.zip`,url:`https://example.test/${role}.zip`}));
    for(const installMode of ['update','install']){
      const result=choose(items,{device:{...device,meshtasticRole},installMode});assert.equal(result.selections.role,expected);assert.equal(result.artifactIndex,null);assert.match(result.reason,/Meshtastic-based.*default.*no alternative role was substituted/);
    }
  }
});

test('stock can fill an absent automatic Keymind provider but an explicit provider is never replaced',()=>{
  const stock=item({provider:'MeshCore'});assert.equal(choose([stock]).artifactIndex,0);assert.equal(choose([stock]).selections.provider,'MeshCore');assert.equal(choose([stock],{provider:'Keymind Cascade'}).artifactIndex,null);
  assert.equal(choose([item(),stock],{provider:'MeshCore'}).artifactIndex,1);assert.equal(choose([item(),stock],{role:'companionUsb'}).artifactIndex,null);
  const stockRepeater=item({provider:'MeshCore',role:'repeater',name:'t114_repeater-v1.18.0.zip'});assert.equal(choose([stockRepeater],{device:{...device,meshtasticRole:2}}).artifactIndex,0);
  assert.equal(choose([stockRepeater],{device:{...device,meshtasticRole:2},provider:'Keymind Cascade'}).artifactIndex,null);
  const bleOnly=choose([item({provider:'MeshCore',role:'companionBle'})]);assert.equal(bleOnly.selections.role,'companionFull');assert.equal(bleOnly.artifactIndex,null);assert.match(bleOnly.reason,/Full Companion default/);
});

test('Meshtastic role and version are never interpreted as a MeshCore role or a downgrade',()=>{
  const items=[item(),item({role:'repeater',name:'t114_repeater-v1.18.0.zip'})],result=choose(items,{device:{...device,catalogRole:'repeater',version:'Meshtastic repeater v2.7.13'}});assert.equal(result.selections.role,'companionFull');assert.equal(result.artifactIndex,0);assert.equal(result.warning,'');
  assert.equal(choose(items,{role:'repeater'}).artifactIndex,1);
});

test('no Companion build, unknown board, or ambiguous exact-board variants remain an explicit manual choice',()=>{
  const repeater=item({role:'repeater'});assert.equal(choose([repeater]).artifactIndex,null);assert.equal(choose([repeater]).selections.role,'companionFull');assert.equal(choose([item()],{hardware:''}).artifactIndex,null);
  const variants=[item(),item({name:'t114_other_display-v1.18.0.zip',url:'https://example.test/other.zip'})];assert.equal(choose(variants).artifactIndex,null);assert.equal(choose([repeater],{role:'repeater'}).artifactIndex,0);
});

test('the pure firmware chooser respects the supplied mode and never substitutes a bootloader or another version',()=>{
  const full=item(),boot=item({name:'Heltec_t114_companion_radio_full-with-bootloader-v1.18.0.zip'}),merged=item({architecture:'esp32',action:'flash-wipe',name:'t114-v1.18.0-merged.bin'}),old=item({version:'v1.17.0',name:'t114-v1.17.0.zip',url:'https://example.test/old.zip'});
  assert.equal(choose([boot,merged,full]).artifactIndex,2);assert.equal(choose([full,old],{version:'v1.17.0'}).artifactIndex,1);assert.equal(choose([merged]).artifactIndex,null);
});
