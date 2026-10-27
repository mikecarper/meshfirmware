import test from 'node:test';
import assert from 'node:assert/strict';
import {chooseFirmware,firmwareVersionWarning,matchesInstallMode,matchesCatalogInstallMode} from '../src/automatic.js';
const app=(more={})=>({project:'MeshCore',hardware:'Heltec v4',provider:'MeshCore',architecture:'esp32',role:'repeater',version:'v1.18.0',action:'flash-update',name:'heltec_v4_repeater-v1.18.0.bin',url:'https://example.test/heltec_v4_repeater-v1.18.0.bin',...more});
const choose=(items,more={})=>chooseFirmware({items,hardware:'Heltec v4',provider:'MeshCore',device:{catalogRole:'repeater'},...more});

test('newest exact-board write-only application is selected, never merged install',()=>{
  const items=[app({version:'v1.9.0'}),app({action:'flash-wipe',name:'heltec_v4_repeater-v1.19.0-merged.bin',version:'v1.19.0'}),app(),app({hardware:'Heltec v4 R8',version:'v2.0.0'})];
  const result=choose(items);assert.equal(result.artifactIndex,2);assert.equal(result.selections.version,'v1.18.0');assert.equal(result.selections.provider,'MeshCore');assert.equal(result.selections.role,'repeater');
});
test('Keymind and historical logging markers select the same fork, not a separate logging provider',()=>{
  const items=[app(),app({provider:'Keymind Cascade'}),app({provider:'Keymind Cascade Logging'})];
  assert.equal(choose(items,{provider:'',device:{catalogRole:'repeater',version:'v1.17.1-halo-keymind-cascade-dev-abcdef'}}).artifactIndex,1);
  const legacy=choose(items,{provider:'',device:{catalogRole:'repeater',version:'v1.17.1-keymind-cascade-logging'}});
  assert.equal(legacy.artifactIndex,1);assert.equal(legacy.selections.provider,'Keymind Cascade');
  assert.equal(choose(items,{provider:'Keymind Cascade Logging'}).artifactIndex,1);
  assert.equal(choose(items,{device:{catalogRole:'repeater',version:'v1.17.1',logging:true}}).artifactIndex,0);
});
test('Keymind is the default even for stock firmware and unavailable Keymind builds never fall back to stock',()=>{
  const stock=app(),keymind=app({provider:'Keymind Cascade'});
  for(const device of [{},{version:'v1.18.0'},{version:'v1.18.0-keymind-cascade'},{version:'v1.17.1',logging:true}]){
    const result=choose([stock,keymind],{provider:'',device:{...device,catalogRole:'repeater'}});
    assert.equal(result.selections.provider,'Keymind Cascade');assert.equal(result.artifactIndex,1);
  }
  const missing=choose([stock],{provider:''});assert.equal(missing.selections.provider,'Keymind Cascade');assert.equal(missing.artifactIndex,null);
  assert.equal(choose([stock,keymind],{provider:'MeshCore'}).artifactIndex,0);
});
test('distinct historical logging images stay manual when they share a board role and version',()=>{
  const legacy=app({provider:'Keymind Cascade Logging',name:'heltec_v4_repeater-usb-logging-v1.18.0.bin',url:'https://example.test/usb-logging.bin'});
  const result=choose([app({provider:'Keymind Cascade'}),legacy],{provider:'Keymind Cascade'});
  assert.equal(result.artifactIndex,null);assert.match(result.reason,/Multiple exact-board builds/);assert.deepEqual(result.candidates,[0,1]);
  assert.equal(choose([legacy],{provider:'Keymind Cascade Logging'}).artifactIndex,0);
});
test('merged provider entries with differing profile or safety metadata stay manual even for the same download',()=>{
  const item=app({provider:'Keymind Cascade'});
  for(const metadata of [{notice:'Different exact-board recovery requirements'},{subtitle:'Legacy USB logging profile'},{erase:['https://example.test/board-specific-erase.zip']},{bootloaderInfo:{hardwareId:'heltec_v4'}}]){
    const result=choose([item,{...item,provider:'Keymind Cascade Logging',...metadata}],{provider:'Keymind Cascade'});
    assert.equal(result.artifactIndex,null);assert.match(result.reason,/Multiple exact-board builds/);assert.deepEqual(result.candidates,[0,1]);
  }
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
    const result=choose([keymindV4(role),keymindV4(role,true)],{provider:'',device:{model,catalogRole:role,version:'v1.18.0.1-halo-keymind-cascade-dev-03214a16'}});
    assert.equal(result.artifactIndex,0,`${model} ${role}`);assert.equal(result.selections.provider,'Keymind Cascade');
  }
  const logging=[keymindV4(),keymindV4('repeater',true)].map(item=>({...item,provider:'Keymind Cascade Logging'}));
  assert.equal(choose(logging,{provider:'Keymind Cascade Logging',device:{model:'Heltec V4.3 OLED',catalogRole:'repeater'}}).artifactIndex,0);
  const oldSetup={...keymindV4('companionFull'),releaseNotes:'SETUP - https://mikecarper.github.io/MeshCore/firmware_picker/?hardware=heltec_v4_2_v4_3'};
  assert.equal(choose([oldSetup],{provider:'Keymind Cascade',device:{model:'Heltec V4.3 OLED',catalogRole:'companionFull'}}).artifactIndex,null); // Never guess unsupported older metadata aliases.
});

test('exact headless V4 revisions choose the reviewed base application for every supported role',()=>{
  for(const role of ['repeater','roomServer','sensor','companionFull'])for(const model of ['Heltec V4.2 none detected','Heltec V4.3 none detected']){
    const result=choose([keymindV4(role,true),keymindV4(role)],{provider:'',device:{model,catalogRole:role,version:'v1.18.0.1-halo-keymind-cascade-dev-03214a16'}});
    assert.equal(result.artifactIndex,1,`${model} ${role}`);assert.equal(result.selections.provider,'Keymind Cascade');
  }
  const logging=[keymindV4('repeater',true),keymindV4()].map(item=>({...item,provider:'Keymind Cascade Logging'}));
  assert.equal(choose(logging,{provider:'Keymind Cascade Logging',device:{model:'Heltec V4.2 none detected',catalogRole:'repeater'}}).artifactIndex,1);
});

test('headless convenience preserves exact target checks and warns when its compatible catalog build is older',()=>{
  const items=[keymindV4(),keymindV4('repeater',true)],device={model:'Heltec V4.2 none detected',catalogRole:'repeater'};
  assert.equal(choose(items,{provider:'Keymind Cascade',device:{...device,hardwareId:'heltec_v4_tft'}}).artifactIndex,1);
  assert.equal(choose(items,{provider:'Keymind Cascade',device:{...device,firmwareTarget:'heltec_v4_tft_repeater'}}).artifactIndex,1);
  for(const model of ['Heltec V4 none detected','Heltec V4.4 none detected','Heltec V4.2 none','Heltec V4.2 none detected R8','Heltec V4.2 off','Heltec V4.2 display initialization failed']){
    assert.equal(choose(items,{provider:'Keymind Cascade',device:{...device,model}}).artifactIndex,null,model);
  }
  const result=choose(items,{provider:'',device:{...device,version:'v1.18.0.2-halo-keymind-cascade-dev-observer-eab29a12'}});
  assert.equal(result.selections.hardware,'Heltec v4');assert.equal(result.selections.provider,'Keymind Cascade');assert.equal(result.selections.role,'repeater');
  assert.equal(result.artifactIndex,0);assert.equal(result.downgrade,true);assert.match(result.warning,/Downgrade warning/);assert.match(result.warning,/v1\.18\.0\.2/);assert.match(result.warning,/v1\.18\.0\.1/);
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
test('automatic and explicit older versions remain selectable with an advisory warning',()=>{
  for(const explicit of [false,true]){
    const result=choose([app()],{device:{catalogRole:'repeater',version:'v1.19.0'},...(explicit?{version:'v1.18.0'}:{})});
    assert.equal(result.artifactIndex,0);assert.equal(result.selections.version,'v1.18.0');assert.equal(result.downgrade,true);
    assert.match(result.warning,/v1\.18\.0/);assert.match(result.warning,/v1\.19\.0/);assert.match(result.warning,/backup/);assert.match(result.warning,/confirmation/);
  }
  const equalNumeric=choose([app({version:'v1.18.0.1-keymind-cascade-dev-new'})],{device:{catalogRole:'repeater',version:'v1.18.0.1-keymind-cascade-dev-old'},provider:'MeshCore'});
  assert.equal(equalNumeric.artifactIndex,0);assert.equal(equalNumeric.downgrade,false);assert.equal(equalNumeric.warning,'');
});

test('newest compatible version is still preferred and downgrade permission never chooses an incompatible utility or role',()=>{
  const result=choose([app({version:'v1.9.0'}),app({version:'v1.20.0'}),app({version:'v1.10.0'})],{device:{catalogRole:'repeater',version:'v1.19.0'}});
  assert.equal(result.artifactIndex,1);assert.equal(result.downgrade,false);assert.equal(result.warning,'');
  const nrf=app({architecture:'nrf52',action:'flash',name:'board_repeater-v1.17.1.zip',version:'v1.17.1'});
  assert.equal(choose([nrf],{device:{catalogRole:'repeater',version:'v1.18.0.2'}}).downgrade,true);
  for(const item of [app({role:'sensor'}),app({hardware:'Heltec v4 R8'}),app({action:'flash-wipe',name:'heltec-v4-merged.bin'}),{...nrf,name:'board_bootloader-v1.17.1.zip'}]){
    const refused=choose([item],{device:{catalogRole:'repeater',version:'v1.19.0'}});
    assert.equal(refused.artifactIndex,null);assert.equal(refused.warning,'');assert.equal(refused.downgrade,false);
  }
});

test('version warning compares numeric components and does not guess commit or build-date order',()=>{
  for(const [running,selected] of [['v1.18.0.2-preview','v1.18.0.1-release'],['v1.18.0.2','v1.18.0'],['v1.10.0','v1.9.0'],['v2.0','v1.99.99']])assert.match(firmwareVersionWarning(running,selected),/Downgrade warning/);
  for(const [running,selected] of [['v1.18.0.1-oldhash','v1.18.0.1-newhash'],['v1.18.0 (Build: 27-Oct-2026)','v1.18.0 (Build: 26-Oct-2026)'],['v1.9.0','v1.10.0'],['v1.18','v1.18.0'],['unknown','v1.18.0'],['v1.18.0','unknown'],[null,'v1.18.0'],['v1.18.0',undefined]])assert.equal(firmwareVersionWarning(running,selected),'');
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

const mergedInstall=(more={})=>app({action:'flash-wipe',name:'heltec_v4_repeater-v1.18.0-merged.bin',url:'https://example.test/heltec_v4_repeater-v1.18.0-merged.bin',...more});
test('install-mode matching separates application updates from explicit merged installs',()=>{
  const update=app(),merged=mergedInstall();
  assert.equal(matchesInstallMode(update),true);assert.equal(matchesInstallMode(merged),false);
  assert.equal(matchesInstallMode(update,'update'),true);assert.equal(matchesInstallMode(merged,'update'),false);
  assert.equal(matchesInstallMode(update,'install'),false);assert.equal(matchesInstallMode(merged,'install'),true);
  for(const mode of ['update','install'])for(const item of [
    null,{project:'Meshtastic'},mergedInstall({role:'bootloader'}),mergedInstall({name:'bootloader-merged.bin'}),
    mergedInstall({name:'FLASH_ERASE-merged.bin'}),mergedInstall({name:'softdevice-merged.bin'}),mergedInstall({name:'R_board-merged.bin'}),
    mergedInstall({name:'QSPIFlash_Format-merged.bin'}),mergedInstall({architecture:'uf2'})
  ])assert.equal(matchesInstallMode(item,mode),false,`${mode}: ${item?.name}`);
  for(const item of [mergedInstall({name:'application.bin'}),mergedInstall({name:'board-merged-component.bin'}),mergedInstall({action:'flash-update'}),mergedInstall({action:'download'})])assert.equal(matchesInstallMode(item,'install'),false,item.name);
});

test('only explicit install mode selects a merged image and neither mode falls back to the other',()=>{
  const update=app(),merged=mergedInstall();
  for(const mode of [undefined,'update'])assert.equal(choose([merged,update],mode===undefined?{}:{installMode:mode}).artifactIndex,1);
  const result=choose([update,merged],{installMode:'install'});
  assert.equal(result.artifactIndex,1);assert.match(result.reason,/erase\/new install/);assert.match(result.reason,/nothing has been loaded or written/);
  assert.equal(result.downgrade,false);assert.equal(result.warning,'');
  assert.equal(choose([update],{installMode:'install'}).artifactIndex,null);
  assert.equal(choose([merged]).artifactIndex,null);
  for(const mode of ['',null,'erase','wipe','unknown']){
    assert.equal(matchesInstallMode(merged,mode),false);assert.equal(matchesInstallMode(update,mode),false);
    const refused=choose([update,merged],{installMode:mode});assert.equal(refused.artifactIndex,null);assert.match(refused.reason,/unsupported install mode/);
  }
});

test('explicit installs retain exact role hardware version and newest-build selection',()=>{
  const current=mergedInstall(),newer=mergedInstall({version:'v1.19.0',name:'heltec_v4_repeater-v1.19.0-merged.bin',url:'https://example.test/new-merged.bin'}),otherBoard=mergedInstall({hardware:'Heltec v4 R8',version:'v9.0.0'}),sensor=mergedInstall({role:'sensor',version:'v8.0.0'});
  const items=[current,newer,otherBoard,sensor,app({version:'v10.0.0'})];
  assert.equal(choose(items,{installMode:'install'}).artifactIndex,1);
  assert.equal(choose(items,{installMode:'install',version:current.version}).artifactIndex,0);
  assert.equal(choose(items,{installMode:'install',role:'sensor'}).artifactIndex,3);
  for(const overrides of [{provider:'Unknown'},{role:'roomServer'},{version:'v0.1.0'},{hardware:''}])assert.equal(choose(items,{installMode:'install',...overrides}).artifactIndex,null);
  assert.equal(choose([current,mergedInstall({role:'roomServer'})],{installMode:'install',device:{role:'common-cli'}}).artifactIndex,null);
});

test('erase/new install retains reviewed V4 target and display distinctions plus downgrade warnings',()=>{
  const convert=item=>({...item,action:'flash-wipe',name:item.name.replace(/\.bin$/,'-merged.bin'),url:item.url.replace(/\.bin$/,'-merged.bin')}),items=[convert(keymindV4('repeater',true)),convert(keymindV4())];
  const device={model:'Heltec V4.2 none detected',catalogRole:'repeater',version:'v1.18.0.2-keymind-cascade'};
  const result=choose(items,{provider:'Keymind Cascade',device,installMode:'install'});
  assert.equal(result.artifactIndex,1);assert.equal(result.downgrade,true);assert.match(result.warning,/v1\.18\.0\.2/);assert.match(result.warning,/v1\.18\.0\.1/);
  assert.equal(choose(items,{provider:'Keymind Cascade',device:{...device,firmwareTarget:'heltec_v4_tft_repeater'},installMode:'install'}).artifactIndex,0);
  assert.equal(choose(items,{provider:'Keymind Cascade',device:{...device,hardwareId:'heltec_v4_tft'},installMode:'install'}).artifactIndex,0);
  for(const hints of [{firmwareTarget:'unknown_target'},{hardwareId:'unknown_board'},{model:'Heltec V4.4 none detected'}])assert.equal(choose(items,{provider:'Keymind Cascade',device:{...device,...hints},installMode:'install'}).artifactIndex,null);
});

test('same-download install entries with different safety or profile metadata remain manual',()=>{
  const item=mergedInstall();
  for(const difference of [{notice:'Requires different recovery'},{subtitle:'Alternate storage profile'},{sha256:'a'.repeat(64)},{url:'https://elsewhere.test/merged.bin'}]){
    const result=choose([item,{...item,...difference}],{installMode:'install'});
    assert.equal(result.artifactIndex,null);assert.match(result.reason,/Multiple exact-board builds/);assert.deepEqual(result.candidates,[0,1]);
  }
  assert.equal(choose([item,{...item}],{installMode:'install'}).artifactIndex,0);
});

test('nRF52 uses the same ordinary application DFU ZIP for either mode without choosing an erase or bootloader ZIP',()=>{
  const nrf=app({architecture:'nrf52',action:'flash',name:'board_repeater-v1.18.0.zip'});
  for(const mode of ['update','install']){
    assert.equal(matchesInstallMode(nrf,mode),true);assert.equal(choose([nrf],{installMode:mode}).artifactIndex,0);
    for(const name of ['board_bootloader-v1.18.0.zip','softdevice.zip','FLASH_ERASE.zip','R_board_bootloader.zip','QSPIFlash_Format.zip','board-merged.zip']){
      assert.equal(matchesInstallMode({...nrf,name},mode),false);assert.equal(choose([{...nrf,name}],{installMode:mode}).artifactIndex,null);
    }
    for(const action of ['flash-update','flash-wipe','erase','download'])assert.equal(matchesInstallMode({...nrf,action},mode),false);
  }
});

test('catalog retains qualified embedded-bootloader application bundles without auto-suggesting them',()=>{
  const embedded=app({architecture:'nrf52',action:'flash',name:'board_repeater-with-bootloader-2.4.12-full-ota-v1.18.0.zip'});
  for(const mode of ['update','install']){
    assert.equal(matchesCatalogInstallMode(embedded,mode),true);
    assert.equal(matchesInstallMode(embedded,mode),false);assert.equal(choose([embedded],{installMode:mode}).artifactIndex,null);
    for(const name of ['board_bootloader-v2.4.12.zip','board_repeater-with-bootloader-latest-full-v1.18.0.zip','board_repeater-with-bootloader-2.4.12-FLASH_ERASE.zip','board_repeater-with-bootloader-2.4.12-with-bootloader-2.4.12-full-v1.18.0.zip'])assert.equal(matchesCatalogInstallMode({...embedded,name},mode),false,name);
    for(const difference of [{role:'bootloader'},{architecture:'esp32'},{action:'download'},{project:'Meshtastic'}])assert.equal(matchesCatalogInstallMode({...embedded,...difference},mode),false);
  }
});

test('manual legacy catalog entries remain in Update only and are never automatic suggestions',()=>{
  const entries=[
    app({architecture:'noflash',action:'download',name:'board_companion-v1.18.0.bin'}),
    app({architecture:'noflash',action:'download',name:'board_companion-v1.18.0.uf2'}),
    app({architecture:'noflash',action:'download',name:'board_repeater-v1.18.0.zip'}),
    app({architecture:'esp32',action:'flash',name:'board_repeater-v1.18.0.zip'}),
    app({architecture:'esp32',action:'download',name:'board_repeater-v1.18.0.uf2'})
  ];
  for(const entry of entries){
    assert.equal(matchesCatalogInstallMode(entry),true);assert.equal(matchesCatalogInstallMode(entry,'update'),true);
    assert.equal(matchesCatalogInstallMode(entry,'install'),false);assert.equal(matchesInstallMode(entry),false);
    assert.equal(choose([entry]).artifactIndex,null);assert.equal(choose([entry],{installMode:'install'}).artifactIndex,null);
    for(const difference of [{role:'bootloader'},{name:'board_bootloader-v1.18.0.uf2'},{name:'FLASH_ERASE.zip'},{name:'board-merged.zip'},{name:'R_board.zip'},{project:'Meshtastic'},{version:''},{url:''}])assert.equal(matchesCatalogInstallMode({...entry,...difference}),false);
  }
  assert.equal(matchesCatalogInstallMode(app({architecture:'noflash',action:'download',name:'board.hex'})),false);
  assert.equal(matchesCatalogInstallMode(app({architecture:'noflash',action:'flash',name:'board.uf2'})),false);
  for(const mode of [null,'','unknown'])for(const item of [entries[0],mergedInstall()])assert.equal(matchesCatalogInstallMode(item,mode),false);
});
