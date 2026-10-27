import test from 'node:test';
import assert from 'node:assert/strict';
import {chooseFirmware} from '../src/automatic.js';
const app=(more={})=>({project:'MeshCore',hardware:'Heltec v4',provider:'MeshCore',architecture:'esp32',role:'repeater',version:'v1.18.0',action:'flash-update',name:'heltec_v4_repeater-v1.18.0.bin',url:'https://example.test/heltec_v4_repeater-v1.18.0.bin',...more});
const choose=(items,more={})=>chooseFirmware({items,hardware:'Heltec v4',device:{catalogRole:'repeater'},...more});

test('newest exact-board write-only application is selected, never merged install',()=>{
  const items=[app({version:'v1.9.0'}),app({action:'flash-wipe',name:'heltec_v4_repeater-v1.19.0-merged.bin',version:'v1.19.0'}),app(),app({hardware:'Heltec v4 R8',version:'v2.0.0'})];
  const result=choose(items);assert.equal(result.artifactIndex,2);assert.equal(result.selections.version,'v1.18.0');assert.equal(result.selections.provider,'MeshCore');assert.equal(result.selections.role,'repeater');
});
test('clear Keymind provider markers select same fork, runtime logging state does not switch build provider',()=>{
  const items=[app(),app({provider:'Keymind Cascade'}),app({provider:'Keymind Cascade Logging'})];
  assert.equal(choose(items,{device:{catalogRole:'repeater',version:'v1.17.1-halo-keymind-cascade-dev-abcdef'}}).artifactIndex,1);
  assert.equal(choose(items,{device:{catalogRole:'repeater',version:'v1.17.1-keymind-cascade-logging'}}).artifactIndex,2);
  assert.equal(choose(items,{device:{catalogRole:'repeater',version:'v1.17.1',logging:true}}).artifactIndex,0);
});
test('explicit provider, role and version are honored, never silently changed if unsupported',()=>{
  const items=[app(),app({provider:'Keymind Cascade',role:'sensor',version:'v1.17.0'})];
  assert.equal(choose(items,{provider:'Keymind Cascade',role:'sensor',version:'v1.17.0'}).artifactIndex,1);
  for(const overrides of [{provider:'Unknown'},{role:'roomServer'},{version:'v0.0.1'}])assert.equal(choose(items,overrides).artifactIndex,null);
});
test('generic CommonCLI role does not guess repeater versus room or sensor',()=>{
  const result=choose([app(),app({role:'roomServer'}),app({role:'sensor'})],{device:{role:'common-cli'}});assert.equal(result.artifactIndex,null);assert.equal(result.selections.role,'');assert.match(result.reason,/running role/);
});
test('generic companion does not choose BLE versus USB; exact role evidence disambiguates',()=>{
  const items=[app({role:'companionBle'}),app({role:'companionUsb'})];
  assert.equal(choose(items,{device:{role:'companion'}}).artifactIndex,null);
  assert.equal(choose(items,{device:{role:'companion',catalogRole:'companionUsb'}}).artifactIndex,1);
  assert.equal(choose(items,{device:{role:'companion',version:'MeshCore companion_radio_ble v1.17.1'}}).artifactIndex,0);
});
test('a sole matching protocol role can be selected without switching to an unrelated interface role',()=>{
  const items=[app(),app({role:'companionFull'})];
  assert.equal(choose(items,{device:{role:'companion'}}).artifactIndex,1);
  assert.equal(choose(items,{device:{role:'common-cli'}}).artifactIndex,0);
});
test('same friendly hardware Full builds with TFT versus base remain manual without target evidence',()=>{
  const base=app({provider:'Keymind Cascade',role:'companionFull',name:'heltec_v4_2_v4_3_companion_radio_full_femon-v1.18.0.bin',releaseNotes:'EXACT TARGET - heltec_v4_2_v4_3_companion_radio_full_femon. Match exact hardware.\nSETUP - https://mikecarper.github.io/MeshCore/firmware_picker/?hardware=heltec_v4_2_v4_3'}),tft={...base,name:'heltec_v4_tft_companion_radio_full_femon-v1.18.0.bin',url:'https://example.test/tft.bin',releaseNotes:'EXACT TARGET - heltec_v4_tft_companion_radio_full_femon. Match exact hardware.\nSETUP - https://mikecarper.github.io/MeshCore/firmware_picker/?hardware=heltec_v4_tft'};
  const input={provider:'Keymind Cascade',device:{catalogRole:'companionFull'}};
  assert.equal(choose([base,tft],input).artifactIndex,null);
  assert.equal(choose([base,tft],{...input,device:{...input.device,hardwareId:'heltec_v4_tft'}}).artifactIndex,1);
  assert.equal(choose([base,tft],{...input,device:{...input.device,firmwareTarget:'heltec_v4_2_v4_3_companion_radio_full_femon'}}).artifactIndex,0);
  assert.equal(choose([base,tft],{...input,device:{...input.device,firmwareTarget:'heltec_v4'}}).artifactIndex,null);
});

// Exact current release targets/profiles and SETUP IDs, including the Full
// target's intentionally different environment name vs its heltec_v4 SETUP ID.
const keymindV4=(role='repeater',tft=false)=>{
  const target=role==='companionFull'?tft?'heltec_v4_tft_companion_radio_full_femon':'heltec_v4_2_v4_3_companion_radio_full_femon':`heltec_v4${tft?'_tft':''}_${role==='roomServer'?'room_server':role}`;
  const profile=role==='companionFull'?'':!tft&&['repeater','roomServer'].includes(role)?'-full-usb-wifi-ota':'-full-logging-ota';
  return app({provider:'Keymind Cascade',role,version:'v1.18.0.1-halo-keymind-cascade-dev-03214a16',
    name:`${target}${profile}-v1.18.0.1-halo-keymind-cascade-dev-03214a16.bin`,url:`https://example.test/${role}-${tft?'tft':'oled'}.bin`,
    releaseNotes:`EXACT TARGET - ${target}. Match the exact board, radio, screen, and storage hardware.\nSETUP - https://mikecarper.github.io/MeshCore/firmware_picker/?hardware=heltec_v4${tft?'_tft':''}`});
};
test('exact reviewed V4 OLED models choose the fork OLED application rather than its same-name TFT variant',()=>{
  for(const role of ['repeater','roomServer','sensor','companionFull'])for(const model of ['Heltec V4 OLED','Heltec V4.2 OLED','Heltec V4.3 OLED']){
    const result=choose([keymindV4(role),keymindV4(role,true)],{device:{model,catalogRole:role,version:'v1.18.0.1-halo-keymind-cascade-dev-03214a16'}});
    assert.equal(result.artifactIndex,0,`${model} ${role}`);assert.equal(result.selections.provider,'Keymind Cascade');
  }
  const logging=[keymindV4(),keymindV4('repeater',true)].map(item=>({...item,provider:'Keymind Cascade Logging'}));
  assert.equal(choose(logging,{provider:'Keymind Cascade Logging',device:{model:'Heltec V4.3 OLED',catalogRole:'repeater'}}).artifactIndex,0);
  const oldSetup={...keymindV4('companionFull'),releaseNotes:'SETUP - https://mikecarper.github.io/MeshCore/firmware_picker/?hardware=heltec_v4_2_v4_3'};
  assert.equal(choose([oldSetup],{provider:'Keymind Cascade',device:{model:'Heltec V4.3 OLED',catalogRole:'companionFull'}}).artifactIndex,null); // Never guess unsupported older metadata aliases.
});

test('unknown, TFT, truncated or different V4 models do not gain an inferred OLED build hint',()=>{
  for(const model of ['Heltec V4','Heltec V4 TFT','Heltec V4.3 TFT','Heltec V4.3 OLE','Heltec V4.3 OLED extra','Heltec V4 R8 OLED','Heltec V4.4 OLED'])assert.equal(choose([keymindV4(),keymindV4('repeater',true)],{provider:'Keymind Cascade',device:{model,catalogRole:'repeater'}}).artifactIndex,null,model);
  assert.equal(choose([app()],{device:{model:'Heltec V4.3 OLED',catalogRole:'repeater'}}).artifactIndex,0); // Official metadata has no SETUP ID.
  assert.equal(choose([keymindV4(),keymindV4('repeater',true)],{hardware:'Heltec v4 R8',provider:'Keymind Cascade',device:{model:'Heltec V4.3 OLED',catalogRole:'repeater'}}).artifactIndex,null);
});

test('explicit device hardware and exact target hints override reviewed OLED model convenience',()=>{
  const items=[keymindV4(),keymindV4('repeater',true)],device={model:'Heltec V4.3 OLED',catalogRole:'repeater'};
  assert.equal(choose(items,{provider:'Keymind Cascade',device:{...device,hardwareId:'heltec_v4_tft'}}).artifactIndex,1);
  assert.equal(choose(items,{provider:'Keymind Cascade',device:{...device,firmwareTarget:'heltec_v4_tft_repeater'}}).artifactIndex,1);
  assert.equal(choose(items,{provider:'Keymind Cascade',device:{...device,hardwareId:'unreviewed'}}).artifactIndex,null);
  assert.equal(choose(items,{provider:'Keymind Cascade',device:{...device,firmwareTarget:'unreviewed'}}).artifactIndex,null);
});
test('explicit target metadata is not bypassed by a conflicting filename or secondary hardware hint',()=>{
  const misleading=app({name:'wanted_repeater-v1.18.0.bin',releaseNotes:'EXACT TARGET - other_repeater. Match exact hardware.'});
  assert.equal(choose([misleading],{device:{catalogRole:'repeater',firmwareTarget:'wanted_repeater'}}).artifactIndex,null);
  const conflict=app({releaseNotes:'SETUP - https://mikecarper.github.io/MeshCore/firmware_picker/?hardware=other',bootloaderInfo:{hardwareId:'wanted'}});
  assert.equal(choose([conflict],{device:{catalogRole:'repeater',hardwareId:'wanted'}}).artifactIndex,null);
});
test('automatic selection never downgrades numerically; explicit requested versions remain usable',()=>{
  assert.equal(choose([app()],{device:{catalogRole:'repeater',version:'v1.19.0'}}).artifactIndex,null);
  assert.equal(choose([app()],{device:{catalogRole:'repeater',version:'v1.19.0'},version:'v1.18.0'}).artifactIndex,0);
  assert.equal(choose([app({version:'v1.18.0.1-keymind-cascade-dev-new'})],{device:{catalogRole:'repeater',version:'v1.18.0.1-keymind-cascade-dev-old'},provider:'MeshCore'}).artifactIndex,0);
});
test('nRF52 serial application ZIP can be suggested, but erased/bootloader/SoftDevice/utilities never are',()=>{
  const nrf=app({architecture:'nrf52',action:'flash',name:'board_repeater-v1.18.0.zip'});
  assert.equal(choose([nrf]).artifactIndex,0);
  for(const name of ['board_bootloader-v1.18.0.zip','softdevice.zip','FLASH_ERASE.zip','R_board_bootloader.zip','QSPIFlash_Format.zip'])assert.equal(choose([{...nrf,name}]).artifactIndex,null);
  for(const action of ['flash-wipe','download','erase'])assert.equal(choose([{...nrf,action}]).artifactIndex,null);
});
test('duplicate equivalent entries are harmless, conflicting URLs or digests remain ambiguous',()=>{
  assert.equal(choose([app(),app()]).artifactIndex,0);
  assert.equal(choose([app(),app({url:'https://other.test/app.bin'})]).artifactIndex,null);
  assert.equal(choose([app(),app({sha256:'a'.repeat(64)})]).artifactIndex,null);
});
test('missing exact hardware and unsupported architectures do not select firmware',()=>{
  assert.equal(choose([app()],{hardware:''}).artifactIndex,null);
  assert.equal(choose([app({architecture:'noflash',action:'download'})]).artifactIndex,null);
  assert.equal(choose([null,{project:'Meshtastic'},app({role:'bootloader'})]).artifactIndex,null);
});
