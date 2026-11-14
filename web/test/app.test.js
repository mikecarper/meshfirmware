// DOM wiring unit tests, not browser/hardware automation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {xiaoBootloaderSnapshot} from './fixtures/xiao-bootloader.js';
import vm from 'node:vm';
import {detectBoard,detectRecoveryProfile} from '../src/board-detection.js';
import {detectMeshtasticBoard} from '../src/meshtastic-boards.js';
import {detectMeshtastic} from '../src/meshtastic.js';
import {canonicalHardware} from '../src/hardware-aliases.js';
import {nrfDfuUsbIds} from '../src/nrf-usb-ids.js';
import {nrfBoardCandidates} from '../src/nrf-board-candidates.js';
import {espBoardCandidates} from '../src/esp-board-candidates.js';
import {parseBootloaderInfo,detectBootloaderBoard} from '../src/bootloader-info.js';
import {xiaoInstalledStatus,xiaoInfoProfile,xiaoBootloaderItem} from '../src/xiao-bootloader.js';
import {chooseFirmware,defaultFirmwareProvider,firmwareVersionWarning,matchesInstallMode,matchesCatalogInstallMode} from '../src/automatic.js';
import {chooseConnection,parseUsbMode} from '../src/connection-choice.js';
import {lookupUsbConnectionMap} from '../src/usb-connection-map.js';
import {createNextStepScroller} from '../src/next-step-scroll.js';
import {tryNativeUsbFallback,xiaoS3ManualBootAdvice} from '../src/connection-fallback.js';
import {catalogProvider,catalogItemKey} from '../src/catalog.js';
import {hash as firmwareHash,md5hex,partitionTable as parsePartitionTable,crc32,inspectFirmware as inspectFirmwareBytes} from '../src/firmware.js';
import {assessFirmwareBoard} from '../src/firmware-board.js';
import {espSlotChoices,selectEspWriteSlots} from '../src/esp-slots.js';
import {isWadamesh,wadameshDisplayAssessment,WADAMESH_STARTUP_NOTICE} from '../src/wadamesh.js';
import {inspectRadioDefaults,customizeRadioDefaults} from '../src/radio-defaults.js';
import {createPostFlashSettingsPlan,applyPostFlashSettings} from '../src/post-flash-settings.js';
import {createPostFlashCompanionRequest} from '../src/post-flash-companion.js';
import {MigrationApproval} from '../src/migration-approval.js';
import {cleanCliReply} from '../src/meshcore.js';
import {assessBootloaderVersion} from '../src/bootloader-version.js';
import {fetchFirmwareBytes as verifiedDownload} from '../src/downloads.js';
import {firmwareFilesLinks} from '../src/firmware-links.js';
import {selectionLink} from '../src/selection-link.js';
import {backupCoverage} from '../src/backup-coverage.js';
import {quickSettingPlan,quickHotspotUrl} from '../src/quick-settings.js';
import {commonCliReplyState} from '../src/common-cli.js';
import {postFlashBleAdvice} from '../src/post-flash-advice.js';
import {gzipSync} from 'node:zlib';
const html=await readFile(new URL('../index.html',import.meta.url),'utf8');
const source=(await readFile(new URL('../src/app.js',import.meta.url),'utf8')).replace(/^import .*;\r?$/gm,'');
const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);
function uiElement(id=''){
  const classes=new Set(),attributes=new Map(),listeners=new Map();
  return {id,value:'',disabled:false,hidden:false,textContent:'',files:[],options:[],checked:false,classList:{toggle(name,force){const enabled=force===undefined?!classes.has(name):force;if(enabled)classes.add(name);else classes.delete(name);return enabled;},contains:name=>classes.has(name)},replaceChildren(...options){this.options=options;this.value=options[0]?.value||'';},removeAttribute:name=>attributes.delete(name),setAttribute:(name,value)=>attributes.set(name,String(value)),getAttribute:name=>attributes.get(name)??null,addEventListener(type,handler){listeners.set(type,handler);},emit(type,event){listeners.get(type)?.(event);},showModal(){this.open=true;},close(){this.open=false;},scrollHeight:0};
}
function workbench({pending=null,recovery=null,espRecovery=null,verification=null,catalogPromise=null,productionDefaults=false,search='',performanceApi,savedSelections=null}={}) {
  const calls=[],elements=new Map(),serialEvents={},windowEvents={};
  class Option {constructor(text,value){this.text=text;this.value=value;}}
  for(const id of ids)elements.set(id,uiElement(id));
  elements.get('project').value='MeshCore';elements.get('transport-mode').value='no_reset';elements.get('backup-role').value='companion';
  if(productionDefaults){for(const id of ['auto-detect-board','auto-backup','auto-finish'])elements.get(id).checked=true;elements.get('transport-mode').value='auto';elements.get('backup-role').value='auto';}
  const port={getInfo:()=>({usbVendorId:0x303a,usbProductId:0x1001})};
  const storage=new Map(pending?[['meshfirmware.pendingMigration',JSON.stringify(pending)]]:[]);
  if(savedSelections!==null)storage.set('meshfirmware.selections',JSON.stringify(savedSelections));
  if(recovery)storage.set('meshfirmware.nrfRecovery',JSON.stringify(recovery));
  if(espRecovery)storage.set('meshfirmware.espRecovery',JSON.stringify(espRecovery));
  if(verification)storage.set('meshfirmware.verifyApplication',JSON.stringify(verification));
  const context=vm.createContext({quickSettingPlan,commonCliReplyState,canonicalHardware,nrfDfuUsbIds,lookupUsbConnectionMap,usbConnectionMap:{schemaVersion:1,builds:[]},document:{getElementById:id=>{assert.ok(elements.has(id),`Missing HTML id ${id}`);return elements.get(id);},querySelectorAll:()=>[...elements.values()]},navigator:{serial:{requestPort:async()=>{calls.push('chooser');return port;},getPorts(){throw new Error('must not enumerate automatically');},addEventListener(type,handler){serialEvents[type]=handler;}}},window:{performance:performanceApi,location:{search},addEventListener(type,handler){windowEvents[type]=handler;}},localStorage:{getItem:k=>storage.get(k),setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},Option,URL,URLSearchParams,Blob,Uint8Array,TextEncoder,TextDecoder,console,setTimeout,clearTimeout,AbortSignal,Date,
    fail(message){throw new Error(message);},text:b=>new TextDecoder().decode(b),hash:()=>'',getCatalog:async()=>catalogPromise||({items:[],warnings:[],generatedAt:new Date().toISOString()}),catalogProvider,catalogItemKey,httpsUrl:value=>value,compareVersions:(a,b)=>b.localeCompare(a),detectBoard,detectRecoveryProfile,chooseFirmware,firmwareVersionWarning,matchesInstallMode,matchesCatalogInstallMode,chooseConnection,parseUsbMode,MigrationApproval,cleanCliReply,assessBootloaderVersion,firmwareFilesLinks,fetch:async()=>{throw Error('Unexpected network request');},fetchFirmwareBytes:(url,options)=>verifiedDownload(url,{...options,mirrorBase:'https://mirror.example.test/firmware/',pageOrigin:'https://mirror.example.test',fetchImpl:(target,init)=>target==='https://mirror.example.test/firmware/index.json'?Promise.resolve({ok:false,status:404}):options.fetchImpl(target,init)}),assessBoard:()=>({requiresOverride:false,payloadFamily:'unknown'}),endfIdentity:()=>null,rakFamily:value=>/rak4631/i.test(value)?'rak4631':'unknown',detectMeshCore(){},exportNativeBackup(){},backupSummary:()=>({complete:true,privateIdentity:true,reasons:[]}),commonCliRestorePreview:()=>({operations:[],skipped:[],warnings:[]}),restoreCommonCli:async()=>{throw Error('Unexpected CommonCLI restore');},
    backupCoverage,createNextStepScroller,tryNativeUsbFallback,xiaoS3ManualBootAdvice,SerialLink:class{constructor(){calls.push('serial');throw new Error('Unexpected serial open');}},EspSession:class{constructor(){calls.push('rom');throw new Error('Unexpected ROM session');}},validateEspWriteRecovery:value=>value,MeshCore:class{},BrowserPlanner:class{},inspectFirmware(){throw new Error('Bad image');},checkedZip(){return [];},recoveryPackage(){throw new Error('No verified recovery package');},verifyBackup(){},parseBackup(){},enterCompanionBinary(){},backupCommonCli(){},touch1200(){},flashNrf(){},waitForMigration(){}
  });
  context.assessFirmwareBoard=()=>({status:'match',requiresOverride:false,reason:'Test board identity.'});context.espSlotChoices=espSlotChoices;
  context.quickHotspotUrl=quickHotspotUrl;context.postFlashBleAdvice=postFlashBleAdvice;context.createNrfActivationCheck=()=>null;
  context.inspectRadioDefaults=inspectRadioDefaults;context.customizeRadioDefaults=customizeRadioDefaults;
  context.createPostFlashSettingsPlan=createPostFlashSettingsPlan;context.applyPostFlashSettings=applyPostFlashSettings;context.createPostFlashCompanionRequest=createPostFlashCompanionRequest;context.loadRadioPresets=async()=>({presets:[],source:'bundled',warning:'Test preset inventory.'});
  context.detectApplication=(...args)=>context.detectMeshCore(...args);context.detectMeshtasticBoard=detectMeshtasticBoard;
  context.parseBootloaderInfo=parseBootloaderInfo;context.detectBootloaderBoard=detectBootloaderBoard;context.xiaoInstalledStatus=xiaoInstalledStatus;context.xiaoInfoProfile=xiaoInfoProfile;context.xiaoBootloaderItem=xiaoBootloaderItem;context.chooseBootloaderInfoFile=async()=>{calls.push('file-picker');throw Error('Unexpected file chooser');};
  context.selectionLink=selectionLink;context.nrfBoardCandidates=nrfBoardCandidates;context.espBoardCandidates=espBoardCandidates;context.isWadamesh=isWadamesh;context.wadameshDisplayAssessment=wadameshDisplayAssessment;context.WADAMESH_STARTUP_NOTICE=WADAMESH_STARTUP_NOTICE;context.defaultFirmwareProvider=defaultFirmwareProvider;
  vm.runInContext(source,context);
  return {context,elements,calls,port,serialEvents,windowEvents,evaluate:code=>vm.runInContext(code,context)};
}

async function espSlotWorkbench({selection='both',boot=0x210000}={}){
  const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;
  ui.context.pkg=fakePackage({name:'slots.bin',architecture:'esp32'});
  ui.context.slotPlan={sha256:ui.context.pkg.sha256,addresses:[0x10000,0x210000],parts:[{type:0,subtype:0x10,offset:0x10000,size:0x200000,label:'app0'},{type:0,subtype:0x11,offset:0x210000,size:0x200000,label:'app1'}],slotSelection:'both',slotBootAddress:boot,writesBootSlot:true};
  if(selection!=='both')ui.context.slotPlan=selectEspWriteSlots(ui.context.pkg,ui.context.slotPlan,selection);
  ui.evaluate('state.port=selectedPort;state.pkg=pkg;state.plan={...slotPlan,generation:state.generation,port:state.port,installMode:state.installMode};');
  ui.context.openSlots=()=>ui.evaluate('flashSlotControls(state.pkg,state.plan,state.radioDefaults?.postFlashPlan)');
  return ui;
}
function pickModalSlot(ui,value){for(const choice of ['a','b','both'])ui.elements.get('confirm-esp-slot-'+choice).checked=choice===value;ui.elements.get('confirm-esp-slot-'+value).onchange();}
function closeConfirm(ui,value='confirm'){const dialog=ui.elements.get('confirm-dialog');dialog.returnValue=value;dialog.emit('close');}

test('ESP32 final modal defaults to both real OTA slots and holds edits until confirmation',async()=>{
  const ui=await espSlotWorkbench();ui.context.slotControls=ui.context.openSlots();
  const pending=ui.evaluate('confirm("Write this firmware?","file","warning","FLASH",{espSlots:slotControls})');
  assert.equal(ui.elements.get('confirm-esp-slots').hidden,false);assert.equal(ui.elements.get('confirm-esp-slot-both').checked,true);
  assert.match(ui.elements.get('confirm-esp-slot-a-label').textContent,/Slot A.*0x10000/);assert.match(ui.elements.get('confirm-esp-slot-b-label').textContent,/Slot B.*0x210000/);
  pickModalSlot(ui,'a');assert.match(ui.elements.get('confirm-esp-slot-summary').textContent,/0x10000.*does not update the boot-selected application.*verification.*will not run/);
  assert.equal(ui.evaluate('state.plan.slotSelection'),'both');assert.equal(ui.context.slotControls.selection,'both');
  closeConfirm(ui);assert.equal(await pending,true);assert.equal(ui.context.slotControls.selection,'a');assert.equal(ui.evaluate('state.plan.slotSelection'),'both');assert.equal(ui.elements.get('confirm-esp-slots').hidden,true);assert.deepEqual(ui.calls,[]);
});

test('cancel, stale scope and forged radio combinations cannot approve a slot change',async()=>{
  for(const outcome of ['cancel','generation','image','plan','multiple','none']){
    const ui=await espSlotWorkbench();ui.context.slotControls=ui.context.openSlots();const pending=ui.evaluate('confirm("Write","file","warning","FLASH",{espSlots:slotControls})');pickModalSlot(ui,'b');
    if(outcome==='generation')ui.evaluate('state.generation++');if(outcome==='image')ui.evaluate('state.pkg={...state.pkg}');if(outcome==='plan')ui.evaluate('state.plan={...state.plan}');
    if(outcome==='multiple')ui.elements.get('confirm-esp-slot-a').checked=true;if(outcome==='none')ui.elements.get('confirm-esp-slot-b').checked=false;
    closeConfirm(ui,outcome==='cancel'?'cancel':'confirm');assert.equal(await pending,false,outcome);assert.equal(ui.context.slotControls.selection,'both',outcome);assert.deepEqual(ui.calls,[]);
  }
});

test('slot controls reset for each ordinary final approval and stay hidden in unrelated confirmations',async()=>{
  const ui=await espSlotWorkbench({selection:'a'});ui.context.slotControls=ui.context.openSlots();assert.equal(ui.context.slotControls.selection,'both');
  const pending=ui.evaluate('confirm("Write","file","warning","FLASH",{espSlots:slotControls})');assert.equal(ui.elements.get('confirm-esp-slot-both').checked,true);closeConfirm(ui,'cancel');await pending;
  const other=ui.evaluate('confirm("Board warning","file","warning","FLASH UNVERIFIED BOARD")');assert.equal(ui.elements.get('confirm-esp-slots').hidden,true);closeConfirm(ui,'cancel');await other;
  ui.evaluate('state.pkg={...state.pkg,architecture:"nrf52"}');assert.equal(ui.context.openSlots(),null);assert.deepEqual(ui.calls,[]);
});

test('merged, migration and interrupted writes retain their fixed approved targets',async()=>{
  for(const locked of ['merged','migration','approval','recovery','verified']){
    const ui=await espSlotWorkbench({selection:locked==='recovery'?'a':'both'});
    if(locked==='merged')ui.evaluate('state.pkg={...state.pkg,merged:true}');if(locked==='migration')ui.evaluate('state.migration={mac:"test"}');if(locked==='approval')ui.evaluate('state.migrationApproval={}');if(locked==='recovery')ui.evaluate('state.espRecovery={};state.plan.chunkedRecovery=true');if(locked==='verified')ui.evaluate('state.plan.verified=true');
    ui.context.slotControls=ui.context.openSlots();assert.equal(ui.context.slotControls.canSelect,false,locked);const expected=locked==='recovery'?'a':'both';assert.equal(ui.context.slotControls.selection,expected,locked);
    const pending=ui.evaluate('confirm("Write","file","warning","FLASH",{espSlots:slotControls})');assert.equal(ui.elements.get('confirm-esp-slot-'+expected).disabled,true);assert.equal(ui.elements.get('confirm-esp-slot-'+expected).checked,true);closeConfirm(ui);assert.equal(await pending,true,locked);assert.deepEqual(ui.calls,[]);
  }
});

test('queued post-flash settings prevent approving an inactive-only write, even with a forged checked input',async()=>{
  const ui=await espSlotWorkbench();ui.evaluate('state.radioDefaults={postFlashPlan:{mediaMesh:{preset:"off"}}}');ui.context.slotControls=ui.context.openSlots();
  const pending=ui.evaluate('confirm("Write","file","warning","FLASH",{espSlots:slotControls})');assert.equal(ui.elements.get('confirm-esp-slot-a').disabled,true);assert.equal(ui.elements.get('confirm-esp-slot-b').disabled,false);assert.match(ui.elements.get('confirm-esp-slot-reason').textContent,/Queued USB settings/);
  pickModalSlot(ui,'a');closeConfirm(ui);assert.equal(await pending,false);assert.equal(ui.context.slotControls.selection,'both');assert.deepEqual(ui.calls,[]);
});

test('final ESP32 approval reseals the chosen slot before writing and queues startup only for boot-slot writes',async()=>{
  for(const selection of ['a','b','both']){
    const ui=await espSlotWorkbench();ui.context.confirm=async(title,_detail,_warning,_action,options)=>{assert.equal(title,'Write this firmware?');assert.ok(options.espSlots);options.espSlots.selection=selection;ui.calls.push('approve');return true;};
    ui.evaluate('state.esp={selectSlots:async()=>{throw Error("replace")},flash:async()=>{}}');
    ui.evaluate('state.esp').selectSlots=async(pkg,choice)=>{ui.calls.push('select:'+choice);return selectEspWriteSlots(pkg,ui.evaluate('state.plan'),choice);};
    ui.evaluate('state.esp').flash=async()=>{ui.calls.push('write');assert.deepEqual(Array.from(ui.evaluate('state.plan.addresses')),selection==='a'?[0x10000]:selection==='b'?[0x210000]:[0x10000,0x210000]);assert.equal(ui.evaluate('state.plan.port'),ui.port);};
    await ui.evaluate('flashPreparedFirmware()');assert.deepEqual(ui.calls,selection==='both'?['approve','write']:['approve','select:'+selection,'write']);
    assert.equal(ui.evaluate('state.plan.written'),true);assert.equal(!!ui.evaluate('state.verification'),selection!=='a');assert.equal(ui.elements.get('flash-progress-dialog').open,true);
    if(selection==='a')assert.match(ui.elements.get('flash-progress-advice').textContent,/Only slot A.*boot.*not changed/i);
  }
});

test('backend slot-reselection failures or changed context never reach a write',async()=>{
  for(const outcome of ['failure','generation','session','settings']){
    const ui=await espSlotWorkbench();ui.context.confirm=async(_title,_detail,_warning,_action,options)=>{options.espSlots.selection='a';if(outcome==='settings')ui.evaluate('state.radioDefaults={postFlashPlan:{mediaMesh:{preset:"off"}}}');return true;};
    ui.evaluate('state.esp={}');ui.evaluate('state.esp').selectSlots=async()=>{ui.calls.push('select');if(outcome==='failure')throw Error('Identity changed');if(outcome==='generation')ui.evaluate('state.generation++');if(outcome==='session')ui.evaluate('state.esp={}');return selectEspWriteSlots(ui.context.pkg,ui.evaluate('state.plan'),'a');};
    ui.evaluate('state.esp').flash=async()=>ui.calls.push('write');await assert.rejects(ui.evaluate('flashPreparedFirmware()'),/Identity changed|evidence changed|session changed|settings changed/);assert.equal(ui.calls.includes('write'),false,outcome);
  }
});

test('finishing an inactive-only ESP32 write does not verify or configure the old application',async()=>{
  const ui=await espSlotWorkbench({selection:'a'});ui.evaluate('state.plan.written=true;state.verification={name:"old"};state.esp={port:state.port,finish:async()=>{},close:async()=>{}}');
  ui.context.detectMeshCore=()=>{throw Error('Must not query old application')};ui.context.applyPostFlashSettings=()=>{throw Error('Must not configure old application')};
  await ui.evaluate('finishVerifiedEsp()');assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.evaluate('state.finishedFirmware.verified'),false);assert.match(ui.evaluate('state.finishedFirmware.startupAdvice'),/Only slot A.*not verified/);assert.match(ui.elements.get('notice').textContent,/No MeshCore startup check or settings commands/);assert.deepEqual(ui.calls,[]);
});

const t114MeshtasticItem=(more={})=>({project:'MeshCore',provider:'Keymind Cascade',hardware:'Heltec T114',architecture:'nrf52',role:'companionFull',version:'v1.18.0.1',name:'Heltec_t114_companion_radio_full-v1.18.0.1.zip',action:'flash',url:'https://example.test/t114.zip',...more});
function radioDefaultsImage(){
  const bytes=new Uint8Array(240),view=new DataView(bytes.buffer);bytes[0]=0xe9;bytes[1]=1;bytes[12]=9;view.setUint32(28,192,true);view.setUint32(32,0xabcd5432,true);
  const block=bytes.subarray(96,160),fields=new DataView(block.buffer,block.byteOffset,64);block.set(new TextEncoder().encode('MCRDEFAULTS0001\0'));fields.setUint16(16,1,true);fields.setUint16(18,64,true);fields.setUint32(60,crc32(block.subarray(0,60)),true);
  bytes[239]=bytes.subarray(32,224).reduce((checksum,byte)=>checksum^byte,0xef);return bytes;
}
async function radioDefaultsWorkbench(){
  const ui=workbench();await Promise.resolve();ui.context.hash=firmwareHash;ui.context.inspectFirmware=inspectFirmwareBytes;ui.context.originalImage=radioDefaultsImage();ui.context.originalItem={hardware:'Heltec v4',architecture:'esp32',role:'companionFull',name:'board.bin',sha256:firmwareHash(ui.context.originalImage)};
  ui.elements.get('expected-sha').value=ui.context.originalItem.sha256;await ui.evaluate('loadFirmware("board.bin",originalImage,originalItem)');await ui.elements.get('radio-defaults-load').onclick();return ui;
}
function chooseRadioDefaults(ui){
  ui.elements.get('radio-defaults-enabled').checked=true;
  for(const [id,value]of [['frequency','910.525'],['bandwidth','125000'],['sf','6'],['cr','5'],['preamble','32'],['power','']])ui.elements.get('radio-defaults-'+id).value=value;
  ui.elements.get('radio-defaults-frequency').oninput();
}
test('editable firmware defaults are inspected without opening USB or changing the validated source',async()=>{
  const ui=await radioDefaultsWorkbench();assert.equal(ui.elements.get('radio-defaults-editor').hidden,false);assert.equal(ui.elements.get('radio-defaults-enabled').checked,false);
  assert.equal(ui.evaluate('state.radioDefaults.sourceSha256'),firmwareHash(ui.context.originalImage));assert.equal(ui.evaluate('state.pkg.sha256'),firmwareHash(ui.context.originalImage));assert.deepEqual(ui.calls,[]);assert.match(ui.elements.get('radio-defaults-status').textContent,/supports editable/);
});
test('applying defaults derives a new fully checked image with separate source provenance and invalidates earlier approvals',async()=>{
  const ui=await radioDefaultsWorkbench(),source=ui.context.originalImage.slice();ui.evaluate('state.plan={sha256:state.pkg.sha256};state.backupApproved={sha256:state.pkg.sha256};');chooseRadioDefaults(ui);
  assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.backupApproved'),null);assert.equal(ui.elements.get('prepare').disabled,true);assert.equal(ui.elements.get('flash').disabled,true);assert.equal(ui.evaluate('nextFlasherControl()'),'radio-defaults-apply');
  await ui.elements.get('radio-defaults-apply').onclick();const pkg=ui.evaluate('state.pkg'),inspection=inspectRadioDefaults('board.bin',pkg.payload);
  assert.notEqual(pkg.sha256,firmwareHash(source));assert.equal(inspection.settings.frequencyHz,910525000);assert.equal(inspection.settings.spreadingFactor,6);assert.equal(inspection.settings.preambleSymbols,32);assert.equal(inspection.settings.txPowerDbm,null);
  assert.equal(ui.elements.get('expected-sha').value,pkg.sha256);assert.equal(ui.evaluate('state.item.sha256'),firmwareHash(source));assert.equal(ui.evaluate('state.radioDefaults.sourceSha256'),firmwareHash(source));assert.equal(ui.evaluate('state.radioDefaults.dirty'),false);assert.deepEqual(ui.context.originalImage,source);
  assert.match(ui.elements.get('radio-defaults-provenance').textContent,new RegExp(firmwareHash(source)));assert.match(ui.evaluate('radioDefaultsSummary()'),/910.525 MHz.*125 kHz.*SF6.*saved settings/);assert.deepEqual(ui.calls,[]);
});
test('turning customization off restores exact original bytes and their hash without another download',async()=>{
  const ui=await radioDefaultsWorkbench();chooseRadioDefaults(ui);await ui.elements.get('radio-defaults-apply').onclick();ui.elements.get('radio-defaults-enabled').checked=false;ui.elements.get('radio-defaults-enabled').onchange();await ui.elements.get('radio-defaults-apply').onclick();
  assert.deepEqual(ui.evaluate('state.pkg.payload'),ui.context.originalImage);assert.equal(ui.elements.get('expected-sha').value,firmwareHash(ui.context.originalImage));assert.equal(ui.evaluate('state.radioDefaults.provenance'),null);assert.equal(ui.elements.get('radio-defaults-provenance').hidden,true);assert.deepEqual(ui.calls,[]);
});
test('an optional saved customized image retains the exact recovery hash and never touches the radio',async()=>{
  const ui=await radioDefaultsWorkbench();chooseRadioDefaults(ui);await ui.elements.get('radio-defaults-apply').onclick();let saved;
  ui.context.download=(name,bytes)=>{saved={name,bytes};};await ui.elements.get('radio-defaults-download').onclick();assert.equal(saved.name,'custom-defaults-board.bin');assert.equal(firmwareHash(saved.bytes),ui.evaluate('state.pkg.sha256'));assert.deepEqual(saved.bytes,ui.evaluate('state.pkg.payload'));assert.deepEqual(ui.calls,[]);
  ui.elements.get('radio-defaults-frequency').value='911.3';ui.elements.get('radio-defaults-frequency').oninput();saved=null;await ui.elements.get('radio-defaults-download').onclick();assert.equal(saved,null);assert.match(ui.elements.get('notice').textContent,/Apply valid defaults/);
});
test('unapplied or invalid defaults cannot prepare or flash, even through direct handlers',async()=>{
  const ui=await radioDefaultsWorkbench(),sha=ui.evaluate('state.pkg.sha256');chooseRadioDefaults(ui);ui.elements.get('radio-defaults-frequency').value='';await ui.elements.get('radio-defaults-apply').onclick();assert.match(ui.elements.get('notice').textContent,/frequency/);assert.equal(ui.evaluate('state.radioDefaults.dirty'),true);assert.equal(ui.evaluate('state.pkg.sha256'),sha);
  await assert.rejects(ui.evaluate('prepareSelectedFirmware()'),/Apply the edited/);await assert.rejects(ui.evaluate('flashPreparedFirmware()'),/Apply the edited/);assert.deepEqual(ui.calls,[]);
});
test('firmware replacement and validation failure discard defaults drafts rather than carrying them to the next board',async()=>{
  const ui=await radioDefaultsWorkbench();chooseRadioDefaults(ui);await ui.elements.get('radio-defaults-apply').onclick();
  ui.context.inspectFirmware=()=>{throw Error('Invalid new image');};ui.elements.get('expected-sha').value='';await assert.rejects(ui.evaluate('loadFirmware("other.bin",originalImage)'),/Invalid new image/);ui.evaluate('controls()');assert.equal(ui.evaluate('state.radioDefaults'),null);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.elements.get('radio-defaults-enabled').checked,false);assert.equal(ui.elements.get('radio-defaults-frequency').value,'');assert.equal(ui.elements.get('radio-defaults-editor').hidden,true);
});
test('defaults editor is locked during handoff, migration, recovery and verification without cancelling or modifying them',async()=>{
  for(const mode of ['handoff','recovery','migration','verification','espRecovery','finishedFirmware']){
    const ui=await radioDefaultsWorkbench();chooseRadioDefaults(ui);const before=ui.evaluate('state.pkg.sha256');ui.context.lockedMode=mode;ui.evaluate('state[lockedMode]=lockedMode==="handoff"?true:{sha256:state.pkg.sha256};controls()');
    assert.equal(ui.elements.get('radio-defaults-apply').disabled,true,mode);assert.equal(ui.elements.get('radio-defaults-load').disabled,true,mode);assert.equal(ui.elements.get('radio-defaults-frequency').disabled,true,mode);await ui.elements.get('radio-defaults-apply').onclick();assert.match(ui.elements.get('notice').textContent,/Finish the current/);assert.equal(ui.evaluate('state.pkg.sha256'),before);assert.ok(ui.evaluate('state[lockedMode]'));assert.deepEqual(ui.calls,[]);
  }
});
test('changed source bytes cannot be customized or pass as their previously verified release',async()=>{
  const ui=await radioDefaultsWorkbench();chooseRadioDefaults(ui);const sha=ui.evaluate('state.pkg.sha256');ui.evaluate('state.radioDefaults.bytes[100]^=1');await ui.elements.get('radio-defaults-apply').onclick();assert.match(ui.elements.get('notice').textContent,/Original firmware changed/);assert.equal(ui.evaluate('state.pkg.sha256'),sha);assert.equal(ui.evaluate('state.radioDefaults.dirty'),true);assert.deepEqual(ui.calls,[]);
});
test('uneditable application builds stay unchanged and expose the post-flash settings fallback',async()=>{
  const ui=await radioDefaultsWorkbench();ui.context.inspectRadioDefaults=()=>({supported:false,settings:null,reason:'No editable block in this older build.'});await ui.elements.get('radio-defaults-load').onclick();assert.equal(ui.elements.get('radio-defaults-editor').hidden,false);assert.equal(ui.evaluate('state.radioDefaults.dirty'),false);assert.match(ui.elements.get('radio-defaults-status').textContent,/image stays unchanged.*over USB/);assert.equal(ui.evaluate('state.pkg.sha256'),firmwareHash(ui.context.originalImage));assert.deepEqual(ui.calls,[]);
});
test('uneditable primary and custom MediaMesh values queue without changing the firmware or sending USB commands',async()=>{
  const ui=await radioDefaultsWorkbench();ui.context.inspectRadioDefaults=()=>({supported:false,settings:null,reason:'Older release'});await ui.elements.get('radio-defaults-load').onclick();chooseRadioDefaults(ui);ui.elements.get('radio-defaults-preamble').value='';
  ui.elements.get('media-mesh-preset').value='custom';ui.elements.get('media-mesh-frequency').value='911.3';ui.elements.get('media-mesh-cross').value='off';ui.elements.get('media-mesh-preset').onchange();await ui.elements.get('radio-defaults-apply').onclick();
  assert.equal(ui.evaluate('state.pkg.sha256'),firmwareHash(ui.context.originalImage));assert.equal(ui.evaluate('state.radioDefaults.postFlashPlan.primary.preambleSymbols'),null);assert.equal(ui.evaluate('state.radioDefaults.postFlashPlan.mediaMesh.frequencyHz'),911300000);assert.equal(ui.evaluate('state.postFlashSettingsApproval'),null);assert.match(ui.evaluate('radioDefaultsSummary()'),/After startup verification.*MediaMesh/);assert.match(ui.elements.get('radio-defaults-status').textContent,/queued/);assert.deepEqual(ui.calls,[]);
});
test('post-flash settings gain one-run approval only from the final firmware confirmation',async()=>{
  for(const accepted of [false,true]){
    const ui=await skipBackupWorkbench();ui.context.postPlan=createPostFlashSettingsPlan({mediaMesh:{preset:'mediamesh-range',cross:'off'}});ui.evaluate('state.radioDefaults={name:pkg.name,sourceSha256:pkg.sha256,postFlashPlan:postPlan};');let shown;
    ui.context.confirm=async(title,detail)=>{if(title==='Write this firmware?'){shown=detail;return accepted;}return true;};await ui.elements.get('flash').onclick();assert.match(shown,/After startup verification.*MediaMesh radio2/);
    assert.equal(!!ui.evaluate('state.postFlashSettingsApproval'),accepted);assert.equal(ui.calls.includes('write-final'),accepted);if(accepted){assert.equal(ui.evaluate('state.postFlashSettingsApproval.sha256'),ui.context.pkg.sha256);assert.equal(ui.evaluate('state.postFlashSettingsApproval.attempted'),false);assert.match(ui.evaluate('state.verification.postFlashSettingsSummary'),/MediaMesh/);}
  }
});
test('catalog version fallback is bound to the exact verified original source, never a custom filename alone',async()=>{
  const ui=await radioDefaultsWorkbench();ui.evaluate('state.item={...state.item,version:"v1.18.0.1-halo-keymind-cascade-dev-03214a16",sha256:null};');assert.equal(ui.evaluate('verificationRecord(state.pkg).version'),'v1.18.0.1-halo-keymind-cascade-dev-03214a16');ui.evaluate('state.radioDefaults.verifiedSourceSha256=null;');assert.equal(ui.evaluate('verificationRecord(state.pkg).version'),null);ui.evaluate('state.radioDefaults.verifiedSourceSha256="0".repeat(64);');assert.equal(ui.evaluate('verificationRecord(state.pkg).version'),null);
});
test('community presets fill only radio values for review and custom edits retain manual control',async()=>{
  const ui=await radioDefaultsWorkbench();ui.context.presetRows=[{id:'usa',title:'USA',frequencyHz:910525000,bandwidthHz:62500,spreadingFactor:7,codingRate:5,notes:'Additional network settings are not changed.'}];ui.evaluate('state.radioPresets=presetRows;');ui.elements.get('radio-preset').value='usa';ui.elements.get('radio-preset').onchange();
  assert.equal(ui.elements.get('radio-defaults-frequency').value,'910.525');assert.equal(ui.elements.get('radio-defaults-bandwidth').value,'62500');assert.equal(ui.elements.get('radio-defaults-enabled').checked,true);assert.equal(ui.evaluate('state.radioDefaults.dirty'),true);assert.match(ui.elements.get('radio-preset-status').textContent,/Additional network settings/);assert.equal(ui.evaluate('state.pkg.sha256'),firmwareHash(ui.context.originalImage));
  ui.elements.get('radio-defaults-sf').value='9';ui.elements.get('radio-defaults-sf').oninput();assert.equal(ui.elements.get('radio-preset').value,'custom');assert.equal(ui.elements.get('radio-defaults-sf').value,'9');assert.deepEqual(ui.calls,[]);
});
async function queuedSettingsVerificationWorkbench(){
  const ui=await storageVerificationWorkbench('common-cli','int:esp32=8192K'),radio={frequency:869.618,bw:125,sf:8,cr:5,preamble:'auto'};
  ui.context.postPlan=createPostFlashSettingsPlan({primary:{enabled:true,frequencyHz:910525000,bandwidthHz:62500,spreadingFactor:7,codingRate:5,preambleSymbols:32,txPowerDbm:null}});
  ui.evaluate('state.postFlashSettingsApproval={sha256:expected.sha256,plan:postPlan,attempted:false};state.verification.postFlashSettingsSummary=postPlan.summary;');
  ui.context.SerialLink.prototype.command=async command=>{ui.calls.push(command);if(command==='ver')return 'v1.18.0.1';if(command==='get storage.layout')return 'int:esp32=8192K';if(command==='get radio')return `${radio.frequency},${radio.bw},${radio.sf},${radio.cr}`;if(command==='get radio.preamble')return String(radio.preamble);if(command.startsWith('set radio ')){const [f,b,s,c,p]=command.slice(10).split(',');Object.assign(radio,{frequency:Number(f),bw:Number(b),sf:Number(s),cr:Number(c),preamble:p});return '> OK';}return '> Error: unsupported setting';};return {...ui,radio};
}
test('post-flash settings run once through the verified owned application link and are read back before completion',async()=>{
  const ui=await queuedSettingsVerificationWorkbench();await ui.evaluate('verifyApplication()');assert.equal(ui.radio.frequency,910.525);assert.equal(ui.radio.preamble,'32');assert.equal(ui.evaluate('state.postFlashSettingsResult.complete'),true);assert.equal(ui.evaluate('state.postFlashSettingsApproval.attempted'),true);assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.calls.filter(c=>c.startsWith('set radio ')).length,1);assert.ok(ui.calls.indexOf('ver')<ui.calls.indexOf('get radio'));assert.match(ui.elements.get('notice').textContent,/settings applied and read back/);
  ui.evaluate('state.verification=expected;');await ui.evaluate('verifyApplication()');assert.equal(ui.calls.filter(c=>c.startsWith('set radio ')).length,1);assert.equal(ui.calls.filter(c=>c==='application-open').length,2);
});
test('a verified source catalog version with a release suffix matches the running numeric firmware before settings apply',async()=>{
  const ui=await queuedSettingsVerificationWorkbench();ui.context.expected.version='v1.18.0.1-halo-keymind-cascade-dev-03214a16';await ui.evaluate('verifyApplication()');assert.equal(ui.evaluate('state.postFlashSettingsResult.complete'),true);assert.equal(ui.evaluate('state.finishedFirmware.verified'),true);
});
test('wrong identity, wrong firmware and changed application context cannot apply queued settings to another radio',async()=>{
  for(const fault of ['identity','version','stale']){const ui=await queuedSettingsVerificationWorkbench();if(fault==='identity')ui.context.detectMeshCore=async()=>({role:'common-cli',publicKey:'22'.repeat(32),model:ui.context.expected.model,version:'v1.18.0.1'});if(fault==='version')ui.context.expected.version='v1.18.0.2';if(fault==='stale'){const original=ui.context.SerialLink.prototype.command;ui.context.SerialLink.prototype.command=async function(command){const result=await original.call(this,command);if(command==='get radio')ui.evaluate('state.generation++');return result;};}
    await assert.rejects(ui.evaluate('verifyApplication()'));assert.equal(ui.calls.filter(c=>c.startsWith('set ')).length,0,fault);assert.ok(ui.evaluate('state.verification'));}
});
test('unknown target versions and reloaded verification reminders cannot silently authorize settings writes',async()=>{
  for(const fault of ['unknown-version','no-memory-approval']){const ui=await queuedSettingsVerificationWorkbench();if(fault==='unknown-version')ui.context.expected.version=null;else ui.evaluate('state.postFlashSettingsApproval=null;');await ui.evaluate('verifyApplication()');assert.equal(ui.calls.filter(c=>c.startsWith('set ')).length,0);assert.match(ui.elements.get('notice').textContent,fault==='unknown-version'?/target firmware version could not be established/:/reloaded.*no post-flash settings/);}
});
test('unsupported post-flash settings stay explicit and do not turn a successful firmware startup into a settings-success claim',async()=>{
  const ui=await queuedSettingsVerificationWorkbench(),original=ui.context.SerialLink.prototype.command;ui.context.SerialLink.prototype.command=async function(command){if(command==='get radio'){ui.calls.push(command);return '> Error: unsupported setting';}return original.call(this,command);};await ui.evaluate('verifyApplication()');assert.equal(ui.evaluate('state.finishedFirmware.verified'),true);assert.equal(ui.evaluate('state.postFlashSettingsResult.complete'),false);assert.equal(ui.calls.filter(c=>c.startsWith('set ')).length,0);assert.match(ui.elements.get('notice').textContent,/not applied or verified/);assert.doesNotMatch(ui.elements.get('notice').textContent,/settings applied and read back/);
});
test('legacy binary companion startup can complete without claiming a storage-layout query it cannot support',async()=>{
  const ui=await storageVerificationWorkbench('companion','');ui.context.detectMeshCore=async()=>({role:'companion',protocol:13,model:ui.context.expected.model,publicKey:ui.context.expected.publicKey,version:'v1.18.0.1'});ui.context.MeshCore=class{async cli(){throw Error('Legacy firmware must never receive CMD66');}};await ui.evaluate('verifyApplication()');assert.equal(ui.evaluate('state.finishedFirmware.verified'),true);assert.equal(ui.evaluate('state.finishedFirmware.layoutVerified'),false);assert.ok(!ui.calls.includes('get storage.layout'));assert.match(ui.elements.get('progress-label').textContent,/does not expose storage-layout/);
});
const meshtasticDevice=(more={})=>({firmwareFamily:'meshtastic',role:'meshtastic',meshtasticHardware:69,model:'Meshtastic hardware 69',nodeNum:1234,name:'H2T test',version:'2.7.4',catalogRole:null,publicKey:null,...more});
async function meshtasticWorkbench({device=meshtasticDevice()}={}){
  const ui=workbench({productionDefaults:true});await Promise.resolve();serialMock(ui);ui.context.selectedPort=ui.port;ui.port.getInfo=()=>({usbVendorId:0x239a,usbProductId:0x4405});
  ui.context.inventory=[t114MeshtasticItem(),t114MeshtasticItem({hardware:'Heltec v2',architecture:'esp32',name:'Heltec_v2_companion_radio_full.bin',action:'flash-update'})];ui.evaluate('state.items=inventory;filterCatalog();');
  ui.context.detectApplication=async()=>({...device});return ui;
}

test('Meshtastic H2T/T114 read selects the nRF52 MeshCore target and Companion Full without MeshCore commands or writes',async()=>{
  const ui=await meshtasticWorkbench();await ui.elements.get('select-port').onclick();
  assert.equal(ui.elements.get('hardware').value,'Heltec T114');assert.equal(ui.elements.get('role').value,'companionFull');assert.equal(ui.elements.get('provider').value,'Keymind Cascade');assert.equal(ui.elements.get('artifact').value,'0');
  assert.equal(ui.evaluate('state.device.architecture'),'nrf52');assert.equal(ui.evaluate('state.device.publicKey'),null);assert.equal(ui.evaluate('state.knownApplicationPort'),null);assert.equal(ui.evaluate('state.device.bootloaderVersion'),null);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.installMode'),'install');assert.equal(ui.elements.get('install-mode-install').checked,true);assert.equal(ui.elements.get('flash-action').value,'wipe');
  assert.match(ui.elements.get('device-meta').textContent,/Meshtastic.*Heltec Mesh Node T114/);assert.match(ui.elements.get('automatic-summary').textContent,/not converted into a MeshCore backup/);assert.doesNotMatch(ui.elements.get('automatic-summary').textContent,/downgrade/i);assert.equal(ui.elements.get('nrf-bootloader-offer').hidden,true);assert.deepEqual(ui.calls,['chooser','open','close']);
});

test('Meshtastic wire metadata selects Repeater only for Router, Router Late and Client Base on the connected board',async()=>{
  const frame=payload=>[0x94,0xc3,payload.length>>8,payload.length&255,...payload];
  for(const role of [0,1,2,3,4,5,6,7,8,9,10,11,12,127]){
    // Official FromRadio.my_info + DeviceMetadata with role=field7 and
    // hw_model=field9. This is the actual parser, not a catalogRole fixture.
    const metadata=[0x0a,6,...new TextEncoder().encode('2.7.15'),0x38,role,0x48,69],wire=Uint8Array.from([...frame([0x1a,2,0x08,9]),...frame([0x6a,metadata.length,...metadata])]);
    const writes=[],device=await detectMeshtastic({buffer:[],async write(value){writes.push([...value]);},async read(){return wire;}},{delay:async()=>{}});
    const ui=await meshtasticWorkbench({device});ui.context.inventory.push(t114MeshtasticItem({role:'repeater',name:'Heltec_t114_repeater-v1.18.0.1.zip',url:'https://example.test/t114-repeater.zip'}));ui.evaluate('filterCatalog();');
    await ui.elements.get('select-port').onclick();
    const expected=[2,11,12].includes(role)?'repeater':'companionFull';
    assert.equal(ui.elements.get('hardware').value,'Heltec T114');assert.equal(ui.elements.get('role').value,expected,device.meshtasticRoleName);assert.equal(ui.elements.get('artifact').value,expected==='repeater'?'2':'0');assert.equal(ui.evaluate('state.device.meshtasticRole'),role);
    assert.ok(ui.elements.get('device-meta').textContent.includes(device.meshtasticRoleName.replaceAll('_',' ')));assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.backupApproved'),null);assert.equal(ui.evaluate('state.installMode'),'install');
    assert.deepEqual(ui.calls,['chooser','open','close']);assert.equal(writes.length,2);assert.deepEqual(writes[1],[0x94,0xc3,0,4,0x18,0xac,0x9e,4]);
  }
});

test('a user can change the Meshtastic-based role default without a new probe, reset or flash',async()=>{
  for(const meshtasticRole of [0,2,11,12]){
    const ui=await meshtasticWorkbench({device:meshtasticDevice({meshtasticRole})});ui.context.inventory.push(t114MeshtasticItem({role:'repeater',name:'Heltec_t114_repeater-v1.18.0.1.zip',url:'https://example.test/t114-repeater.zip'}));ui.evaluate('filterCatalog();');await ui.elements.get('select-port').onclick();
    const role=meshtasticRole===0?'repeater':'companionFull';ui.elements.get('role').value=role;await ui.elements.get('role').onchange();ui.evaluate('applyAutomaticSelections();');
    assert.equal(ui.elements.get('role').value,role);assert.equal(ui.evaluate('state.manualSelections.role'),role);assert.equal(ui.evaluate('state.device.meshtasticRole'),meshtasticRole);assert.deepEqual(ui.calls,['chooser','open','close']);assert.equal(ui.evaluate('state.plan'),null);
  }
});

test('a connected Meshtastic RAK3401 selects its universal hardware and the appropriate standard firmware without USB writes',async()=>{
  const hardware='RAK WisMesh 1W Booster (3401 + 13302)',version='v1.18.0.1-halo-keymind-cascade-dev-03214a16';
  const application=(target,profile='',more={})=>t114MeshtasticItem({hardware,version,role:'repeater',name:target+(profile?'-'+profile:'')+'-'+version+'.zip',url:'https://example.test/'+target+profile+'.zip',releaseNotes:'EXACT TARGET - '+target+'. Match the exact board.',bootloaderInfo:{hardwareId:'RAK_3401',profile:'wiscore_rak3401_auto',url:'https://example.test/rak3401-bootloader.zip',sha256:'f'.repeat(64),size:64,version:'2.4.12'},...more});
  const full=application('RAK_3401_repeater_unified_lora_ota','full-ota'),companion=application('RAK_3401_companion_radio_full','',{role:'companionFull'});
  for(const role of [0,2,11,12])for(const reverse of [false,true]){
    const ui=await meshtasticWorkbench({device:meshtasticDevice({meshtasticHardware:117,model:'Meshtastic hardware 117',meshtasticRole:role})});
    const inventory=[application('RAK_3401_repeater_bridge_rs232_serial1','full-ota'),application('RAK_3401_repeater_unified_lora_ota','reduced-ota'),application('RAK_3401_repeater_rak13302_w25q16_lora_ota','full-ota'),companion,full,t114MeshtasticItem()];
    ui.context.inventory=reverse?inventory.toReversed():inventory;ui.evaluate('state.items=inventory;filterCatalog();');ui.port.getInfo=()=>({usbVendorId:0x239a,usbProductId:0x8029});
    await ui.elements.get('select-port').onclick();
    const expected=role===0?companion:full,index=Number(ui.elements.get('artifact').value);
    assert.equal(ui.elements.get('hardware').value,hardware,ui.elements.get('notice').textContent);assert.equal(ui.elements.get('role').value,role===0?'companionFull':'repeater');assert.notEqual(ui.elements.get('artifact').value,'');assert.equal(ui.context.inventory[index].name,expected.name);
    assert.equal(ui.elements.get('provider').value,'Keymind Cascade');assert.equal(ui.evaluate('state.device.architecture'),'nrf52');assert.equal(ui.evaluate('state.device.model'),'RAK3401');assert.equal(ui.elements.get('transport-mode').value,'auto');
    assert.doesNotMatch(ui.elements.get('automatic-summary').textContent,/carrier|storage profile|Choose the exact hardware manually|Multiple exact-board builds remain/i);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.installMode'),'install');
    assert.deepEqual(ui.calls,['chooser','open','close']);
  }
});

test('legacy Meshtastic RAK3401 wire identity selects 3401, preserves the reported enum, and never chooses 4631 firmware',async()=>{
  const version='v1.18.0.1',h3401='RAK WisMesh 1W Booster (3401 + 13302)',h4631='RAK WisBlock / WisMesh (RAK 4631)';
  const application=(hardware,target,role)=>t114MeshtasticItem({hardware,role,version,name:target+(role==='repeater'?'-full-ota':'')+'-'+version+'.zip',url:'https://example.test/'+target+'.zip',releaseNotes:'EXACT TARGET - '+target+'.'});
  const inventory=[application(h4631,'RAK_4631_companion_radio_full','companionFull'),application(h4631,'RAK_4631_repeater_unified_lora_ota','repeater'),application(h3401,'RAK_3401_companion_radio_full','companionFull'),application(h3401,'RAK_3401_repeater_unified_lora_ota','repeater')];
  const frame=payload=>[0x94,0xc3,payload.length>>8,payload.length&255,...payload];
  for(const hw of [9,117])for(const role of [0,2]){
    const environment=new TextEncoder().encode('rak3401-1watt'),info=[8,9,0x6a,environment.length,...environment],versionBytes=new TextEncoder().encode('2.7.11.47bf2b4a'),metadata=[0x0a,versionBytes.length,...versionBytes,0x38,role,0x48,hw],wire=Uint8Array.from([...frame([0x1a,info.length,...info]),...frame([0x6a,metadata.length,...metadata])]);
    const writes=[],device=await detectMeshtastic({buffer:[],async write(value){writes.push([...value]);},async read(){return wire;}},{delay:async()=>{}});
    const ui=await meshtasticWorkbench({device});ui.context.inventory=inventory;ui.evaluate('state.items=inventory;filterCatalog();');ui.port.getInfo=()=>({usbVendorId:0x239a,usbProductId:0x8029});
    await ui.elements.get('select-port').onclick();
    assert.equal(ui.elements.get('hardware').value,h3401);assert.equal(ui.elements.get('artifact').value,role===0?'2':'3');assert.equal(ui.evaluate('state.device.model'),'RAK3401');assert.equal(ui.evaluate('state.device.meshtasticHardware'),hw);assert.equal(ui.evaluate('state.device.meshtasticPioEnv'),'rak3401-1watt');assert.match(ui.elements.get('device-meta').textContent,/Meshtastic · RAK3401/);
    assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,['chooser','open','close']);assert.equal(writes.length,2);assert.deepEqual(writes[1],[0x94,0xc3,0,4,0x18,0xac,0x9e,4]);
  }
});

test('a real Meshtastic RAK4631 remains 4631 while conflicting build reports cannot retain an automatic choice',async()=>{
  const h3401='RAK WisMesh 1W Booster (3401 + 13302)',h4631='RAK WisBlock / WisMesh (RAK 4631)';
  for(const [meshtasticHardware,meshtasticPioEnv,expected] of [[9,'rak4631',h4631],[9,'rak3401-1watt',h3401],[69,'rak3401-1watt','']]){
    const ui=await meshtasticWorkbench({device:meshtasticDevice({meshtasticHardware,meshtasticPioEnv})});ui.context.inventory=[h3401,h4631,'Heltec T114'].map((hardware,index)=>t114MeshtasticItem({hardware,name:'radio-'+index+'.zip'}));ui.evaluate('state.items=inventory;filterCatalog();');
    await ui.elements.get('select-port').onclick();assert.equal(ui.elements.get('hardware').value,expected);if(!expected){assert.equal(ui.elements.get('artifact').value,'');assert.match(ui.elements.get('board-detection').textContent,/conflict/i);}
    assert.equal(ui.evaluate('state.pkg'),null);assert.deepEqual(ui.calls,['chooser','open','close']);
  }
});

test('Wio local build targets resolve Pro and E-Ink without guessing the 1W variant or changing roles',async()=>{
  const pro='Seeed Studio Wio Tracker L1 Pro',eink='Seeed Studio Wio Tracker L1 E-Ink',oneW='Seeed WioTracker L1 1W';
  for(const [meshtasticHardware,meshtasticPioEnv,expected] of [[99,'seeed_wio_tracker_L1',pro],[99,'seeed_wio_tracker_L1_eink-inkhud',eink],[100,'seeed_wio_tracker_L1_eink',eink],[144,'seeed_wio_tracker_L1_eink',''],[99,'private_wio_build','']]){
    const ui=await meshtasticWorkbench({device:meshtasticDevice({meshtasticHardware,meshtasticPioEnv})});ui.context.inventory=[pro,eink,oneW].map((hardware,index)=>t114MeshtasticItem({hardware,name:'wio-'+index+'.zip'}));ui.evaluate('state.items=inventory;filterCatalog();');
    await ui.elements.get('select-port').onclick();assert.equal(ui.elements.get('hardware').value,expected);assert.equal(ui.elements.get('role').value,expected?'companionFull':'');if(!expected)assert.equal(ui.elements.get('artifact').value,'');
    assert.equal(ui.evaluate('state.pkg'),null);assert.deepEqual(ui.calls,['chooser','open','close']);
  }
});

test('equivalent provider hardware labels auto-select one board and remain usable after an explicit provider/role change',async()=>{
  const cases=[
    [100,'Seeed Studio Wio Tracker L1 E-Ink','Seeed Studio Wio Tracker L1 EINK'],
    [128,'Seeed SenseCAP MeshTracker X1','Seeed Studio SenseCAP MeshTracker X1'],
    [95,'Seeed Studio SenseCAP Solar','Seeed Studio SenseCAP Solar Node P1'],
  ];
  for(const [meshtasticHardware,canonical,oldStock] of cases){
    const items=[t114MeshtasticItem({hardware:canonical,name:'board_companion_radio_full-v1.18.0.1.zip'}),t114MeshtasticItem({hardware:oldStock,provider:'MeshCore',role:'companionBle',name:'board_companion_radio_ble-v1.18.0.1.zip'})];
    const ui=workbench({productionDefaults:true,catalogPromise:Promise.resolve({items,warnings:[],generatedAt:'2026-10-30T00:00:00Z'})});await new Promise(resolve=>setImmediate(resolve));serialMock(ui);ui.context.detectApplication=async()=>meshtasticDevice({meshtasticHardware});ui.port.getInfo=()=>({usbVendorId:0x239a,usbProductId:0x8029});
    await ui.elements.get('select-port').onclick();assert.equal(ui.elements.get('hardware').value,canonical);assert.equal(ui.elements.get('artifact').value,'0');assert.equal(ui.elements.get('role').value,'companionFull');
    ui.elements.get('provider').value='MeshCore';await ui.elements.get('provider').onchange();ui.elements.get('role').value='companionBle';await ui.elements.get('role').onchange();
    assert.equal(ui.elements.get('hardware').value,canonical);assert.equal(ui.elements.get('artifact').value,'1');assert.equal(ui.evaluate('state.items[1].hardware'),canonical);assert.equal(items[1].hardware,oldStock,'source catalog is not mutated');assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,['chooser','open','close']);
  }
});

test('historical hardware names in saved selections and shared URLs resolve to canonical catalog labels without USB',async()=>{
  const old='Seeed Studio Wio Tracker L1 EINK',canonical='Seeed Studio Wio Tracker L1 E-Ink';
  for(const linked of [false,true]){
    let resolveCatalog;const catalogPromise=new Promise(resolve=>resolveCatalog=resolve),search=linked?'?'+new URLSearchParams({hardware:old,provider:'Keymind Cascade',role:'companionFull'}):'',ui=workbench({catalogPromise,search,productionDefaults:true});
    if(!linked)ui.context.localStorage.setItem('meshfirmware.selections',JSON.stringify({hardware:old,provider:'Keymind Cascade',role:'companionFull'}));
    resolveCatalog({items:[t114MeshtasticItem({hardware:canonical})],warnings:[],generatedAt:'2026-10-30T00:00:00Z'});await new Promise(resolve=>setImmediate(resolve));
    assert.equal(ui.elements.get('hardware').value,canonical);assert.deepEqual(ui.calls,[]);assert.equal(ui.evaluate('state.port'),null);
  }
});

test('Nano G2 Ultra and Muzi Base factory DFU IDs skip application probes without selecting a physical board',async()=>{
  for(const [usbVendorId,usbProductId] of [[0x4251,0x8695],[0x239a,0x0081]]){
    const ui=workbench({productionDefaults:true});await Promise.resolve();ui.port.getInfo=()=>({usbVendorId,usbProductId});ui.context.detectApplication=async()=>{throw Error('A DFU port must not be probed as an application');};
    await ui.elements.get('select-port').onclick();assert.equal(ui.elements.get('already-bootloader').checked,true);assert.equal(ui.evaluate('state.device'),null);assert.equal(ui.elements.get('hardware').value,'');assert.equal(ui.evaluate('state.connection.mode'),'nrf52');assert.deepEqual(ui.calls,['chooser']);
    await ui.elements.get('backup').onclick();assert.match(ui.elements.get('notice').textContent,/DFU|bootloader/);assert.deepEqual(ui.calls,['chooser']);
  }
});

test('slow Meshtastic detection shows the waiting period without claiming a connection failure',async()=>{
  const ui=await meshtasticWorkbench();let release,report;
  ui.context.detectApplication=(link,{onProgress})=>new Promise(resolve=>{release=resolve;report=onProgress;});
  const connecting=ui.elements.get('select-port').onclick();
  for(let tick=0;!release&&tick<20;tick++)await Promise.resolve();
  assert.equal(typeof release,'function');assert.match(ui.elements.get('notice').textContent,/Reading.*USB identity/);assert.match(ui.elements.get('notice').textContent,/No reset or firmware write/);
  assert.equal(ui.evaluate('state.busy'),true);assert.equal(ui.evaluate('state.device'),null);assert.deepEqual(ui.calls,['chooser','open']);
  assert.equal(ui.elements.get('detection-status').hidden,false);assert.equal(ui.elements.get('detection-stage').textContent,'Checking MeshCore…');assert.equal(ui.elements.get('detection-timer').hidden,true);
  report({stage:'meshtastic',elapsedSeconds:0,timeoutSeconds:25});assert.equal(ui.elements.get('detection-stage').textContent,'Checking Meshtastic…');assert.equal(ui.elements.get('detection-timer').hidden,false);assert.equal(ui.elements.get('detection-timer').textContent,'0s / 25s');
  report({stage:'meshtastic',elapsedSeconds:8,timeoutSeconds:25});assert.equal(ui.elements.get('detection-timer').textContent,'8s / 25s');assert.equal(ui.elements.get('detection-timer').getAttribute('aria-label'),'8 seconds elapsed; 25 second limit');
  release(meshtasticDevice());await connecting;
  assert.match(ui.elements.get('notice').textContent,/Meshtastic detected/);assert.doesNotMatch(ui.elements.get('notice').textContent,/25 seconds/);assert.deepEqual(ui.calls,['chooser','open','close']);
  assert.equal(ui.elements.get('detection-status').hidden,true);assert.equal(ui.elements.get('detection-timer').textContent,'');
  report({stage:'meshtastic',elapsedSeconds:9,timeoutSeconds:25});assert.equal(ui.elements.get('detection-status').hidden,true);
});

test('detection timer is cleared on timeout, transport failure and a disconnected or changed port',async()=>{
  for(const failure of ['timeout','transport','disconnect','changed-port']){
    const ui=await meshtasticWorkbench();let reject,report;
    ui.context.detectApplication=(link,{onProgress})=>new Promise((resolve,fail)=>{reject=fail;report=onProgress;onProgress({stage:'meshtastic',elapsedSeconds:0,timeoutSeconds:25});});
    const connecting=ui.elements.get('select-port').onclick();for(let tick=0;!reject&&tick<20;tick++)await Promise.resolve();
    assert.equal(typeof reject,'function');assert.equal(ui.elements.get('detection-status').hidden,false);
    if(failure==='disconnect')ui.serialEvents.disconnect({port:ui.port});
    if(failure==='changed-port'){ui.evaluate('state.generation++;controls();');}
    if(['disconnect','changed-port'].includes(failure))assert.equal(ui.elements.get('detection-status').hidden,true,'stale detection should disappear immediately');
    reject(Object.assign(Error(failure==='timeout'?'No supported application answered':'Port unavailable'),{code:failure==='timeout'?'APPLICATION_UNIDENTIFIED':undefined}));await connecting;
    assert.equal(ui.elements.get('detection-status').hidden,true);assert.equal(ui.elements.get('detection-timer').textContent,'');assert.equal(ui.evaluate('state.applicationDetection'),null);
    report({stage:'meshtastic',elapsedSeconds:25,timeoutSeconds:25});assert.equal(ui.elements.get('detection-status').hidden,true);
  }
});

test('a detected MeshCore node never shows the Meshtastic seconds counter',async()=>{
  const ui=await meshtasticWorkbench();ui.context.detectApplication=async(link,{onProgress})=>{assert.equal(ui.elements.get('detection-stage').textContent,'Checking MeshCore…');assert.equal(ui.elements.get('detection-timer').hidden,true);onProgress({stage:'meshcore'});return {firmwareFamily:'meshcore',role:'common-cli',model:'Heltec T114',publicKey:'11'.repeat(32),version:'v1.18.0.2'};};
  await ui.elements.get('select-port').onclick();assert.equal(ui.elements.get('detection-status').hidden,true);assert.equal(ui.elements.get('detection-timer').textContent,'');assert.equal(ui.evaluate('state.applicationDetection'),null);
});

test('observed restart readiness remains adaptive beyond five seconds and finishes as soon as the API answers',async()=>{
  for(const readyAt of [5.6,15.715]){
    const ui=await meshtasticWorkbench();let release,report;
    ui.context.SerialLink.prototype.open=async function(_baud,options){assert.equal(options.application,true);assert.equal(options.onStartupProgress,undefined);this.startupEvidence={observedRomBoot:true};ui.calls.push('open');};
    ui.context.detectApplication=(_link,{onProgress})=>{report=onProgress;assert.equal(ui.elements.get('detection-stage').textContent,'Waiting for radio startup…');return new Promise(resolve=>{release=resolve;});};
    const connecting=ui.elements.get('select-port').onclick();for(let tick=0;!release&&tick<30;tick++)await Promise.resolve();assert.equal(typeof release,'function');
    report({stage:'startup',elapsedSeconds:5,timeoutSeconds:25});assert.equal(ui.evaluate('state.busy'),true);assert.equal(ui.evaluate('state.device'),null);assert.equal(ui.elements.get('detection-timer').textContent,'5s / 25s');
    report({stage:'startup',elapsedSeconds:Math.floor(readyAt),timeoutSeconds:25});assert.equal(ui.elements.get('detection-stage').textContent,'Waiting for radio startup…');assert.match(ui.elements.get('notice').textContent,/Opening USB restarted the radio.*Read-only checks stop as soon as it answers/);assert.doesNotMatch(ui.elements.get('detection-stage').textContent,/Meshtastic/);
    release({firmwareFamily:'meshcore',role:'common-cli',model:'Heltec T114',publicKey:'11'.repeat(32),version:'v1.18.0.2'});await connecting;assert.equal(ui.elements.get('detection-status').hidden,true);assert.equal(ui.elements.get('detection-timer').textContent,'');assert.match(ui.elements.get('progress-label').textContent,/USB API answered/);
    report({stage:'startup',elapsedSeconds:25,timeoutSeconds:25});assert.equal(ui.elements.get('detection-status').hidden,true);assert.deepEqual(ui.calls,['chooser','open','get bootloader.ver','close']);
  }
});

test('stale or failed adaptive startup readiness cannot repaint another selected radio',async()=>{
  for(const fault of ['generation','disconnect','timeout']){
    const ui=await meshtasticWorkbench();let release,report;
    ui.context.SerialLink.prototype.open=async function(){this.startupEvidence={observedRomBoot:true};ui.calls.push('open');};
    ui.context.detectApplication=(_link,{onProgress})=>{report=onProgress;return new Promise((_resolve,reject)=>{release=reject;});};
    const connecting=ui.elements.get('select-port').onclick();for(let tick=0;!release&&tick<30;tick++)await Promise.resolve();assert.equal(typeof release,'function');
    if(fault==='generation')ui.evaluate('state.generation++;controls();');
    if(fault==='disconnect')ui.serialEvents.disconnect({port:ui.port});
    if(fault!=='timeout')assert.equal(ui.elements.get('detection-status').hidden,true);else report({stage:'startup',elapsedSeconds:25,timeoutSeconds:25});
    release(Error(fault==='timeout'?'Radio startup readiness timed out.':'Selected radio changed.'));await connecting;assert.equal(ui.evaluate('state.device'),null);assert.equal(ui.elements.get('detection-status').hidden,true);assert.equal(ui.evaluate('state.applicationDetection'),null);
    const notice=ui.elements.get('notice').textContent;report({stage:'startup',elapsedSeconds:25,timeoutSeconds:25});assert.equal(ui.elements.get('notice').textContent,notice);assert.equal(ui.elements.get('detection-status').hidden,true);assert.deepEqual(ui.calls,['chooser','open','close']);
  }
});

test('backup reconnect and verification share adaptive readiness progress without changing transfer progress or proof checks',async()=>{
  for(const workflow of ['backup','verify']){
    const ui=workflow==='backup'?await dfuBackupApplicationWorkbench():await storageVerificationWorkbench('common-cli','> int:esp32=8192K ext:none');
    let report;ui.elements.get('progress').value=.96;ui.elements.get('flash-progress-dialog').open=true;
    ui.context.SerialLink.prototype.open=async function(baud,options){assert.equal(baud,115200);assert.equal(options.application,true);assert.equal(options.onStartupProgress,undefined);this.startupEvidence={observedRomBoot:true};ui.calls.push('application-open');};
    const original=ui.context.detectApplication;ui.context.detectApplication=async(link,options)=>{report=options.onProgress;if(workflow==='backup')assert.equal(options.meshCoreOnly,true);for(const elapsedSeconds of [0,5,15]){report({stage:'startup',elapsedSeconds,timeoutSeconds:25});assert.equal(ui.elements.get('detection-timer').textContent,`${elapsedSeconds}s / 25s`);assert.match(ui.elements.get('flash-progress-stage').textContent,/Opening USB restarted the radio/);assert.equal(ui.elements.get('progress').value,.96);}return original(link,options);};
    if(workflow==='backup')assert.equal(await ui.evaluate('readBackupApplicationPort(appPort,{expectedPublicKey:expectedBackupKey});'),true);
    else await ui.evaluate('verifyApplication();');
    assert.equal(ui.elements.get('detection-status').hidden,true,workflow);assert.equal(ui.elements.get('detection-timer').textContent,'',workflow);const notice=ui.elements.get('notice').textContent;report({stage:'startup',elapsedSeconds:25,timeoutSeconds:25});assert.equal(ui.elements.get('notice').textContent,notice,workflow);
    assert.ok(!ui.calls.some(call=>/reset|write-final|set /.test(call)),workflow);assert.equal(ui.calls.filter(call=>call==='application-open').length,1,workflow);
  }
});

test('changed verification proof stops adaptive readiness while nRF activation retains its unchanged direct probe',async()=>{
  const ui=await storageVerificationWorkbench('common-cli','> int:esp32=8192K ext:none');let report;
  ui.context.SerialLink.prototype.open=async function(){this.startupEvidence={observedRomBoot:true};ui.calls.push('application-open');};
  ui.context.detectApplication=async(_link,options)=>{report=options.onProgress;report({stage:'startup',elapsedSeconds:0,timeoutSeconds:25});ui.evaluate('state.verification={sha256:"new"};');options.assertCurrent();return ui.context.detectMeshCore();};
  await assert.rejects(ui.evaluate('verifyApplication();'),/port changed/);assert.equal(ui.elements.get('detection-status').hidden,true);assert.equal(ui.evaluate('state.applicationDetection'),null);report({stage:'startup',elapsedSeconds:25,timeoutSeconds:25});assert.equal(ui.elements.get('detection-status').hidden,true);
  const activation=await nrfActivationWorkbench();activation.context.detectApplication=async()=>assert.fail('Native nRF activation must not start adaptive UART retries');activation.evaluate('nrfApplicationActivationCheck(pkg);');const fresh=await activation.activationOptions.readApplication(activation.appPort);assert.equal(fresh.publicKey,activation.context.activationDevice.publicKey);assert.deepEqual(activation.calls,['application-open','application-detect','application-close']);
});

test('unknown Meshtastic hardware does not inherit an old MeshCore board or use the shared USB ID to guess',async()=>{
  const ui=await meshtasticWorkbench({device:meshtasticDevice({meshtasticHardware:99999,model:'Heltec v2'})});ui.context.pkg=fakePackage();ui.evaluate('state.pkg=pkg;state.item=inventory[0];state.detectedHardware="Heltec T114";state.device={model:"Heltec T114",catalogRole:"companionFull"};');
  await ui.elements.get('select-port').onclick();assert.equal(ui.elements.get('hardware').value,'');assert.equal(ui.elements.get('artifact').value,'');assert.equal(ui.evaluate('state.detectedHardware'),null);assert.equal(ui.evaluate('state.pkg'),null);assert.match(ui.elements.get('board-detection').textContent,/manual|unknown|reviewed/i);assert.deepEqual(ui.calls,['chooser','open','close']);
});

test('moving from Meshtastic defaults to Install but its backup prompt neither erases nor claims a MeshCore backup',async()=>{
  for(const answer of ['cancel','skip']){
    const ui=await meshtasticWorkbench();await ui.elements.get('select-port').onclick();ui.context.pkg=fakePackage({architecture:'nrf52'});ui.evaluate('state.pkg=pkg;');ui.calls.length=0;
    ui.context.choose=async(title,detail,buttons)=>{ui.calls.push('question');assert.match(title,/Meshtastic.*MeshCore/);assert.match(detail,/does not create or restore Meshtastic/);assert.ok(buttons.some(([,label])=>label==='Continue to MeshCore without backup'));return answer;};
    if(answer==='cancel'){await assert.rejects(ui.evaluate('ensureBackup();'),/Cancelled/);assert.equal(ui.evaluate('state.backupApproved'),null);}
    else {await ui.evaluate('ensureBackup();');assert.equal(ui.evaluate('state.backupApproved.skipped'),true);assert.equal(ui.evaluate('state.backupApproved.publicKey'),null);assert.equal(ui.evaluate('state.backupApproved.sourceFirmware'),'meshtastic');}
    assert.equal(ui.evaluate('state.backup'),null);assert.equal(ui.evaluate('state.installMode'),'install');assert.deepEqual(ui.calls,['question']);
  }
});

test('Meshtastic ESP32 defaults to its exact merged install, never silently falling back to an application-only update',async()=>{
  for(const hasMerged of [true,false]){
    const ui=await meshtasticWorkbench({device:meshtasticDevice({meshtasticHardware:110})}),update=t114MeshtasticItem({hardware:'Heltec v4',architecture:'esp32',action:'flash-update',name:'heltec_v4_companion_radio_full-v1.18.0.1.bin',url:'https://example.test/v4.bin'});
    ui.context.inventory=hasMerged?[update,mergedItem(update)]:[update];ui.evaluate('state.items=inventory;filterCatalog();');ui.port.getInfo=()=>({usbVendorId:0x303a,usbProductId:0x1001});
    await ui.elements.get('select-port').onclick();
    assert.equal(ui.evaluate('state.installMode'),'install');assert.equal(ui.elements.get('install-mode-install').checked,true);assert.equal(ui.elements.get('install-mode-update').checked,false);assert.equal(ui.elements.get('flash-action').value,'wipe');assert.equal(ui.elements.get('hardware').value,'Heltec v4');assert.equal(ui.elements.get('artifact').value,hasMerged?'1':'');assert.equal(ui.elements.get('prepare-label').textContent,'Backup & prepare install');
    assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.backupApproved'),null);assert.equal(ui.elements.get('flash').disabled,!hasMerged);assert.deepEqual(ui.calls,['chooser','open','close']);
  }
});

test('a manual Update choice survives Meshtastic redetection, same-port selection and a late linked catalog',async()=>{
  let resolveCatalog;const catalogPromise=new Promise(resolve=>resolveCatalog=resolve),ui=workbench({productionDefaults:true,catalogPromise,search:'?mode=install'});serialMock(ui);ui.context.inventory=[t114MeshtasticItem()];ui.context.detectApplication=async()=>meshtasticDevice();ui.evaluate('state.items=inventory;filterCatalog();');ui.port.getInfo=()=>({usbVendorId:0x239a,usbProductId:0x4405});
  await ui.elements.get('select-port').onclick();assert.equal(ui.evaluate('state.installMode'),'install');
  ui.elements.get('install-mode-update').checked=true;ui.elements.get('install-mode-install').checked=false;await ui.elements.get('install-mode-update').onchange();assert.equal(ui.evaluate('state.installMode'),'update');
  await ui.elements.get('probe').onclick();assert.equal(ui.evaluate('state.installMode'),'update');await ui.elements.get('select-port').onclick();assert.equal(ui.evaluate('state.installMode'),'update');
  resolveCatalog({items:ui.context.inventory,warnings:[],generatedAt:'2026-10-31T00:00:00Z'});await new Promise(resolve=>setImmediate(resolve));assert.equal(ui.evaluate('state.installMode'),'update');assert.equal(ui.elements.get('flash-action').value,'update');assert.equal(ui.elements.get('install-mode-update').checked,true);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,['chooser','open','close','open','close','chooser','open','close']);
});

test('a new radio resets the Meshtastic default scope without carrying an automatic erase into MeshCore',async()=>{
  for(const manualMode of [null,'update','install'])for(const nextIsMeshtastic of [false,true]){
    const ui=await meshtasticWorkbench();await ui.elements.get('select-port').onclick();
    if(manualMode){await ui.evaluate("setInstallMode('update');");if(manualMode==='install')await ui.evaluate("setInstallMode('install');");}
    const nextPort={getInfo:()=>({usbVendorId:0x239a,usbProductId:0x4405})};ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');return nextPort;};ui.context.detectApplication=async()=>nextIsMeshtastic?meshtasticDevice():{firmwareFamily:'meshcore',role:'common-cli',model:'Heltec T114',catalogRole:'repeater',publicKey:null};
    await ui.elements.get('select-port').onclick();assert.equal(ui.evaluate('state.installMode'),nextIsMeshtastic?'install':'update');assert.equal(ui.elements.get('flash-action').value,nextIsMeshtastic?'wipe':'update');assert.equal(ui.evaluate('state.port'),nextPort);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.ok(!ui.calls.includes('rom')&&!ui.calls.includes('write'));
  }
});

test('a deliberately chosen pre-connection mode belongs to the first radio, not the next one',async()=>{
  const ui=await meshtasticWorkbench();await ui.evaluate("setInstallMode('install');");ui.context.detectApplication=async()=>({firmwareFamily:'meshcore',role:'common-cli',model:'Heltec T114',catalogRole:'repeater',publicKey:null});
  await ui.elements.get('select-port').onclick();assert.equal(ui.evaluate('state.installMode'),'install');
  const nextPort={getInfo:()=>({usbVendorId:0x239a,usbProductId:0x4405})};ui.context.navigator.serial.requestPort=async()=>nextPort;await ui.elements.get('select-port').onclick();assert.equal(ui.evaluate('state.installMode'),'update');assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);
});

test('an automatic Meshtastic install default clears when the same connected port later answers as MeshCore',async()=>{
  const ui=await meshtasticWorkbench();await ui.elements.get('select-port').onclick();assert.equal(ui.evaluate('state.installMode'),'install');ui.context.detectApplication=async()=>({firmwareFamily:'meshcore',role:'common-cli',model:'Heltec T114',catalogRole:'repeater',publicKey:null});
  await ui.elements.get('probe').onclick();assert.equal(ui.evaluate('state.installMode'),'update');assert.equal(ui.elements.get('flash-action').value,'update');assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.ok(!ui.calls.includes('rom')&&!ui.calls.includes('write'));
});

test('Meshtastic detection cannot promote a locked handoff, written plan or startup-verification flow to erase',async()=>{
  for(const [field,value] of [['handoff',true],['verification',{sha256:'a'.repeat(64)}],['plan',{written:true}]]){
    const ui=await meshtasticWorkbench();ui.context.selectedPort=ui.port;ui.context.pendingValue=value;ui.evaluate('state.port=selectedPort;state.'+field+'=pendingValue;');
    await ui.evaluate('detectSelectedBoard();');assert.equal(ui.evaluate('state.installMode'),'update');assert.equal(ui.evaluate('state.'+field),field==='plan'?null:value);assert.deepEqual(ui.calls,['open','close']);
  }
});

test('known Meshtastic nodes cannot enter MeshCore backup, restore, binary or serial-console operations',async()=>{
  const ui=await meshtasticWorkbench();await ui.elements.get('select-port').onclick();ui.calls.length=0;
  await assert.rejects(ui.evaluate('captureBackup();'),/Meshtastic is running/);
  ui.elements.get('command').value='set name Test';for(const id of ['backup','restore','send-command','binary-mode']){assert.equal(ui.elements.get(id).disabled,true);await ui.elements.get(id).onclick();assert.match(ui.elements.get('notice').textContent,/Meshtastic is running/);}
  assert.equal(ui.evaluate('state.backup'),null);assert.equal(ui.evaluate('state.device.role'),'meshtastic');assert.deepEqual(ui.calls,[]);
});

test('a responding Meshtastic node cannot satisfy pending MeshCore startup verification',async()=>{
  const ui=await meshtasticWorkbench();ui.evaluate('state.port=selectedPort;state.verification={sha256:"a".repeat(64),architecture:"nrf52",publicKey:null,role:null,model:null};');
  await ui.elements.get('verify-app').onclick();assert.ok(ui.evaluate('state.verification'));assert.match(ui.elements.get('notice').textContent,/Meshtastic is still running.*not verified/);assert.equal(ui.evaluate('state.finishedFirmware'),null);assert.equal(ui.evaluate('state.knownApplicationPort'),null);assert.deepEqual(ui.calls,['open','close']);
});

test('a changed port during Meshtastic detection cannot select its board or grant backup approval',async()=>{
  const ui=await meshtasticWorkbench();ui.context.detectApplication=async()=>{ui.serialEvents.disconnect({port:ui.port});return meshtasticDevice();};
  await ui.elements.get('select-port').onclick();assert.equal(ui.evaluate('state.device'),null);assert.equal(ui.evaluate('state.backupApproved'),null);assert.equal(ui.evaluate('state.detectedHardware'),null);assert.equal(ui.elements.get('artifact').value,'');assert.match(ui.elements.get('notice').textContent,/changed or disconnected/);assert.deepEqual(ui.calls,['chooser','open','close']);
});

const bootloaderInfoText=(version='0.11.0-OTAFIX2.4.12')=>`UF2 Bootloader ${version}\r\nModel: HT-n5262\r\nBoard-ID: HT-n5262\r\nSoftDevice: S140 6.1.1\r\n`;
async function bootloaderInfoWorkbench({dfu=false,code='APPLICATION_UNIDENTIFIED',usbInfo}={}){
  const ui=await meshtasticWorkbench();ui.port.getInfo=()=>usbInfo||(dfu?{usbVendorId:0x239a,usbProductId:0x0071}:{});
  ui.context.detectApplication=async()=>{throw Object.assign(Error('Application was not identified'),{code});};await ui.elements.get('select-port').onclick();return ui;
}

test('an unidentified or DFU port highlights Hardware and offers drive info only as an optional advanced tool',async()=>{
  for(const dfu of [false,true]){
    const ui=await bootloaderInfoWorkbench({dfu});assert.equal(ui.elements.get('bootloader-info-fallback').hidden,false);assert.equal(ui.elements.get('read-bootloader-info').disabled,false);assert.ok(!ui.elements.get('bootloader-info-fallback').open);assert.deepEqual(nextHighlight(ui),['hardware']);assert.match(ui.elements.get('step-guidance').textContent,/exact hardware/);assert.ok(!ui.calls.includes('file-picker'));assert.equal(ui.evaluate('state.bootloaderInfo'),null);
  }
  const normal=await meshtasticWorkbench();await normal.elements.get('select-port').onclick();assert.equal(normal.elements.get('bootloader-info-fallback').hidden,true);assert.ok(!normal.calls.includes('file-picker'));
});

test('an unidentified UART application keeps manual hardware and guarded ESP entry without offering UF2 drive info',async()=>{
  for(const [usbVendorId,usbProductId] of [[0x10c4,0xea60],[0x1a86,0x7523],[0x0403,0x6001]]){
    const ui=await bootloaderInfoWorkbench({usbInfo:{usbVendorId,usbProductId}});
    assert.equal(ui.elements.get('bootloader-info-fallback').hidden,true);
    assert.equal(ui.elements.get('read-bootloader-info').disabled,true);
    assert.deepEqual(nextHighlight(ui),['hardware']);
    assert.match(ui.elements.get('step-guidance').textContent,/exact hardware/);
    assert.equal(ui.evaluate('state.connection.mode'),'default_reset');
    assert.equal(ui.evaluate('state.connection.source'),'uart-usb');
    assert.equal(ui.elements.get('already-bootloader').checked,false);
    assert.equal(ui.evaluate('state.applicationProbeFailed'),true);
    assert.equal(ui.evaluate('state.device'),null);
    assert.equal(ui.evaluate('state.detectedHardware'),null);
    assert.equal(ui.evaluate('state.bootloaderInfo'),null);
    assert.equal(ui.evaluate('state.backupApproved'),null);
    assert.equal(ui.evaluate('state.plan'),null);
    assert.equal(ui.evaluate('state.pkg'),null);
    assert.equal(ui.elements.get('artifact').value,'');
    assert.equal(ui.elements.get('flash').disabled,true);
    await ui.elements.get('read-bootloader-info').onclick();
    assert.deepEqual(ui.calls,['chooser','open','close']);
  }
});

const rak3401Hardware='RAK WisMesh 1W Booster (3401 + 13302)',rak4631Hardware='RAK WisBlock / WisMesh (RAK 4631)';
async function nrfCandidateWorkbench({id=[0x239a,0x002a],automatic=true}={}){
  const ui=workbench({productionDefaults:automatic});await Promise.resolve();
  ui.context.inventory=[t114MeshtasticItem({hardware:'Heltec v4',architecture:'esp32',name:'v4.bin',action:'flash-update'}),t114MeshtasticItem({hardware:rak3401Hardware,name:'rak3401.zip'}),t114MeshtasticItem(),t114MeshtasticItem({hardware:rak4631Hardware,name:'rak4631.zip'}),t114MeshtasticItem({hardware:'Other nRF52 board',name:'other.zip'}),t114MeshtasticItem({hardware:'RP2040',architecture:'noflash',action:'download',name:'rp.uf2'})];
  ui.evaluate('state.items=inventory;filterCatalog();');ui.port.getInfo=()=>({usbVendorId:id[0],usbProductId:id[1]});await ui.elements.get('select-port').onclick();return ui;
}
const hardwareChoices=ui=>[...ui.elements.get('hardware').options].filter(option=>option.value).map(option=>option.value).sort();
test('an unidentified RAK DFU port shows only matching nRF52 candidates and preserves original artifact indices',async()=>{
  for(const automatic of [false,true]){
    const ui=await nrfCandidateWorkbench({automatic});assert.deepEqual(hardwareChoices(ui),[rak3401Hardware,rak4631Hardware].sort());assert.deepEqual([...ui.elements.get('artifact').options].filter(option=>option.value).map(option=>option.value),['1','3']);
    assert.equal(ui.elements.get('hardware').value,'');assert.equal(ui.elements.get('hardware').options[0].text,'Matching nRF52 boards');assert.equal(ui.elements.get('show-all-nrf-option').hidden,false);assert.equal(ui.elements.get('show-all-nrf').checked,false);assert.match(ui.elements.get('hardware-filter-status').textContent,/2 matching.*shared/);
    assert.deepEqual(nextHighlight(ui),['hardware']);assert.equal(ui.evaluate('state.device'),null);assert.equal(ui.evaluate('state.detectedHardware'),null);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,['chooser']);
  }
});
test('showing all remains nRF52-only and switching back discards incompatible manual catalog choices and approvals',async()=>{
  const ui=await nrfCandidateWorkbench();ui.elements.get('show-all-nrf').checked=true;await ui.elements.get('show-all-nrf').onchange();assert.deepEqual(hardwareChoices(ui),['Heltec T114','Other nRF52 board',rak3401Hardware,rak4631Hardware].sort());
  ui.elements.get('hardware').value='Heltec T114';await ui.elements.get('hardware').onchange();assert.equal(ui.elements.get('artifact').value,'2');
  ui.context.pkg=fakePackage({architecture:'nrf52'});ui.evaluate('state.pkg=pkg;state.backupApproved={};state.plan={port:state.port};');ui.elements.get('show-all-nrf').checked=false;await ui.elements.get('show-all-nrf').onchange();
  assert.deepEqual(hardwareChoices(ui),[rak3401Hardware,rak4631Hardware].sort());assert.equal(ui.elements.get('hardware').value,'');assert.equal(ui.elements.get('artifact').value,'');assert.equal(ui.evaluate('state.manualSelections.hardware'),undefined);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.backupApproved'),null);assert.deepEqual(ui.calls,['chooser']);
});
test('nRF52 candidate filtering never turns a single remaining USB hint into an automatic physical-board match',async()=>{
  const ui=await nrfCandidateWorkbench();ui.context.inventory=[ui.context.inventory[1]];ui.evaluate('state.items=inventory;filterCatalog();controls();');assert.deepEqual(hardwareChoices(ui),[rak3401Hardware]);assert.equal(ui.elements.get('hardware').value,'');assert.equal(ui.elements.get('artifact').value,'');assert.deepEqual(nextHighlight(ui),['hardware']);assert.equal(ui.evaluate('state.detectedHardware'),null);assert.deepEqual(ui.calls,['chooser']);
});
test('an unknown or ESP ROM interface is not nRF52 evidence, while explicit nRF52 mode retains all nRF52 choices',async()=>{
  for(const id of [[0x1234,0x5678],[0x303a,0x1001]]){
    const ui=await nrfCandidateWorkbench({id,automatic:false});assert.ok(hardwareChoices(ui).includes('Heltec v4'));assert.equal(ui.elements.get('hardware-filter-status').hidden,id[0]!==0x303a);
    ui.elements.get('already-bootloader').checked=true;await ui.elements.get('already-bootloader').onchange();assert.ok(hardwareChoices(ui).includes('Heltec v4'));
    ui.elements.get('transport-mode').value='nrf52';await ui.elements.get('transport-mode').onchange();assert.deepEqual(hardwareChoices(ui),['Heltec T114','Other nRF52 board',rak3401Hardware,rak4631Hardware].sort());assert.equal(ui.elements.get('show-all-nrf-option').hidden,true);assert.equal(ui.evaluate('state.detectedHardware'),null);assert.deepEqual(ui.calls,['chooser']);
  }
});
test('a board switch or disconnect releases the old candidate scope and never carries show-all into the new radio',async()=>{
  const ui=await nrfCandidateWorkbench();ui.elements.get('show-all-nrf').checked=true;await ui.elements.get('show-all-nrf').onchange();
  ui.serialEvents.disconnect({port:ui.port});assert.ok(hardwareChoices(ui).includes('Heltec v4'));assert.equal(ui.elements.get('hardware-filter-status').hidden,true);
  const nextPort={getInfo:()=>({usbVendorId:0x239a,usbProductId:0x0071})};ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');return nextPort;};await ui.elements.get('select-port').onclick();assert.deepEqual(hardwareChoices(ui),['Heltec T114']);assert.equal(ui.elements.get('show-all-nrf').checked,false);assert.equal(ui.elements.get('hardware').value,'');assert.deepEqual(ui.calls,['chooser','chooser']);
});
test('confirmed same-radio handoff retains the identified nRF52 target instead of replacing it with shared USB hints',async()=>{
  const ui=await meshtasticWorkbench({device:meshtasticDevice({meshtasticHardware:117})});ui.context.inventory=[t114MeshtasticItem({hardware:rak3401Hardware,name:'rak3401.zip'}),t114MeshtasticItem({hardware:rak4631Hardware,name:'rak4631.zip'}),t114MeshtasticItem()];ui.evaluate('state.items=inventory;filterCatalog();');await ui.elements.get('select-port').onclick();assert.deepEqual(hardwareChoices(ui),[rak3401Hardware]);
  ui.evaluate('state.handoff=true;');const dfu={getInfo:()=>({usbVendorId:0x239a,usbProductId:0x002a})};ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');return dfu;};ui.context.confirm=async()=>true;await ui.elements.get('select-port').onclick();assert.deepEqual(hardwareChoices(ui),[rak3401Hardware]);assert.equal(ui.elements.get('hardware').value,rak3401Hardware);assert.match(ui.elements.get('hardware-filter-status').textContent,/previously identified/);assert.equal(ui.evaluate('state.device.firmwareFamily'),'meshtastic');assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,['chooser','open','close','chooser']);
});
test('an explicit nRF52 connection override belongs to its radio and cannot hide a newly detected ESP32',async()=>{
  for(const disconnected of [false,true]){
    const ui=await nrfCandidateWorkbench({id:[0x1234,0x5678]});serialMock(ui);ui.elements.get('transport-mode').value='nrf52';await ui.elements.get('transport-mode').onchange();assert.ok(!hardwareChoices(ui).includes('Heltec v4'));
    if(disconnected)ui.serialEvents.disconnect({port:ui.port});
    const esp={getInfo:()=>({usbVendorId:0x303a,usbProductId:0x1001})};ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');return esp;};ui.context.detectApplication=async()=>({firmwareFamily:'meshcore',role:'common-cli',model:'Heltec V4.2 OLED',catalogRole:'repeater',publicKey:null});
    await ui.elements.get('select-port').onclick();assert.equal(ui.elements.get('transport-mode').value,'auto');assert.equal(ui.evaluate('state.device.architecture'),'esp32');assert.ok(hardwareChoices(ui).includes('Heltec v4'));assert.equal(ui.elements.get('hardware').value,'Heltec v4');assert.equal(ui.elements.get('hardware-filter-status').hidden,false);assert.match(ui.elements.get('hardware-filter-status').textContent,/ESP32-family/);assert.ok(!ui.calls.includes('write')&&!ui.calls.includes('rom'));
  }
});
test('nRF52 scope changes retain pending erase recovery final bytes without a write or renewed approval',async()=>{
  const ui=workbench({recovery:{sha256:'a'.repeat(64),hardware:rak3401Hardware,phase:'reselect-dfu',eraseComplete:true}});await Promise.resolve();ui.context.inventory=[t114MeshtasticItem({hardware:rak3401Hardware,name:'rak3401.zip'}),t114MeshtasticItem({hardware:rak4631Hardware,name:'rak4631.zip'})];ui.context.pkg=fakePackage({architecture:'nrf52',sha256:'a'.repeat(64)});ui.context.selectedPort=ui.port;ui.port.getInfo=()=>({usbVendorId:0x239a,usbProductId:0x002a});ui.evaluate('state.items=inventory;state.port=selectedPort;state.pkg=pkg;controls();');assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);assert.equal(ui.evaluate('state.recovery.phase'),'reselect-dfu');assert.equal(ui.evaluate('state.recovery.eraseComplete'),true);assert.equal(ui.evaluate('state.backupApproved'),null);assert.equal(ui.elements.get('show-all-nrf').disabled,true);assert.deepEqual(ui.calls,[]);
});

const s3Inspection={chip:'ESP32-S3',chipId:9,mac:'aa:bb:cc:dd:ee:ff',flashBytes:16<<20};
async function espCandidateWorkbench({id=[0x303a,0x1001],mode='auto',inspected=false}={}){
  const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;
  ui.port.getInfo=()=>({usbVendorId:id[0],usbProductId:id[1]});ui.elements.get('transport-mode').value=mode;
  ui.context.inventory=['Heltec v4','Heltec v2','Heltec CT62','LilyGo T-LoRa C6','LilyGo T-Deck','LilyGo T-Deck Pro','Unknown future ESP board'].map(hardware=>t114MeshtasticItem({hardware,architecture:'esp32',name:hardware+'.bin',action:'flash-update'}));
  ui.context.inventory.push(t114MeshtasticItem(),t114MeshtasticItem({hardware:'RP2040',architecture:'noflash',name:'rp.uf2',action:'download'}));
  ui.context.inspectedChip=s3Inspection;ui.evaluate('state.items=inventory;state.port=selectedPort;filterCatalog();');
  if(inspected)ui.evaluate('rememberEspChipInfo(state.port,inspectedChip);filterCatalog();');
  return ui;
}
function mockChipInspection(ui,{failure=null}={}){
  ui.context.EspSession=class{
    constructor(port){assert.equal(port,ui.port);}
    async connect(mode,options){ui.calls.push('connect:'+mode);assert.equal(options.singleReset,true);if(failure)throw failure;return s3Inspection;}
    async finishInspection(nativeUsb){ui.calls.push('finishInspection:'+nativeUsb);}
    async close(options){assert.equal(options.strict,true);ui.calls.push('close');}
    async prepare(){assert.fail('Chip inspection must not prepare firmware');}
    async flash(){assert.fail('Chip inspection must not write firmware');}
    async finish(){assert.fail('Chip inspection must not use write completion');}
  };
  ui.context.touch1200=()=>assert.fail('A successful first chip connection must not send another reset');
  ui.context.ensureBackup=()=>assert.fail('Chip inspection must not create firmware/backup approval');
}

test('native ESP USB hints filter architecture only while generic UART and unknown USB keep every architecture available',async()=>{
  for(const id of [[0x303a,0x1001],[0x303a,0x0002],[0x10c4,0xea60],[0x1a86,0x7523],[0x1234,0x5678]]){
    const ui=await espCandidateWorkbench({id}),native=id[0]===0x303a;
    assert.equal(ui.evaluate('catalogArchitecture()'),native?'esp32':'');
    assert.equal(hardwareChoices(ui).includes('Heltec T114'),!native);assert.equal(hardwareChoices(ui).includes('RP2040'),!native);
    assert.ok(hardwareChoices(ui).includes('Heltec v2'));assert.ok(hardwareChoices(ui).includes('Heltec v4'));
    assert.equal(ui.elements.get('hardware').value,'');assert.equal(ui.elements.get('artifact').value,'');
    assert.equal(ui.evaluate('state.detectedHardware'),null);assert.equal(ui.evaluate('currentEspChipInfo()'),null);assert.deepEqual(ui.calls,[]);
  }
});

test('a verified S3 inspection excludes reviewed incompatible chips and nRF52 but keeps T-Deck and unknown metadata without choosing a board',async()=>{
  const ui=await espCandidateWorkbench({inspected:true});
  assert.deepEqual(hardwareChoices(ui),['Heltec v4','LilyGo T-Deck','LilyGo T-Deck Pro','Unknown future ESP board'].sort());
  assert.equal(ui.elements.get('hardware').value,'');assert.equal(ui.elements.get('artifact').value,'');assert.equal(ui.evaluate('state.detectedHardware'),null);
  assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.boardDetected'),false);
  assert.equal(ui.elements.get('show-all-esp-option').hidden,false);assert.equal(ui.elements.get('inspect-esp-chip').hidden,true);
  assert.match(ui.elements.get('hardware-filter-status').textContent,/ESP32-S3.*16\.00 MiB.*unknown chip metadata.*not used to guess/);
  assert.deepEqual(nextHighlight(ui),['hardware']);assert.deepEqual(ui.calls,[]);
});

test('show-all ESP override remains ESP-only and invalidates loaded firmware, preparation and backup before changing candidates',async()=>{
  const ui=await espCandidateWorkbench({inspected:true});ui.context.pkg=fakePackage({architecture:'esp32'});ui.context.record=ui.calls;
  ui.evaluate('state.pkg=pkg;state.plan={port:state.port};state.backupApproved={};state.esp={close:async()=>record.push("close-old-session")};');
  ui.elements.get('show-all-esp').checked=true;await ui.elements.get('show-all-esp').onchange();
  assert.ok(hardwareChoices(ui).includes('Heltec v2'));assert.ok(!hardwareChoices(ui).includes('Heltec T114'));
  assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.backupApproved'),null);
  ui.elements.get('hardware').value='Heltec v2';await ui.elements.get('hardware').onchange();
  ui.elements.get('show-all-esp').checked=false;await ui.elements.get('show-all-esp').onchange();
  assert.ok(!hardwareChoices(ui).includes('Heltec v2'));assert.equal(ui.elements.get('hardware').value,'');assert.equal(ui.evaluate('state.manualSelections.hardware'),undefined);
  assert.deepEqual(ui.calls,['close-old-session']);
});

test('stale, disconnected and newly chosen ports never inherit a previous radio chip or show-all override',async()=>{
  for(const outcome of ['changed-port','changed-usb','disconnect','new-selection']){
    const ui=await espCandidateWorkbench({inspected:true}),nextPort={getInfo:()=>({usbVendorId:0x303a,usbProductId:0x1001})};ui.context.nextPort=nextPort;
    if(outcome==='changed-port')ui.evaluate('state.port=nextPort;state.generation++;controls();');
    if(outcome==='changed-usb'){ui.port.getInfo=()=>({usbVendorId:0x303a,usbProductId:0x0002});ui.evaluate('controls();');}
    if(outcome==='disconnect')ui.serialEvents.disconnect({port:ui.port});
    if(outcome==='new-selection'){
      ui.elements.get('show-all-esp').checked=true;await ui.elements.get('show-all-esp').onchange();
      ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');return nextPort;};await ui.elements.get('select-port').onclick();
      assert.equal(ui.elements.get('show-all-esp').checked,false);assert.equal(ui.evaluate('state.espChipFilter'),null);
    }
    assert.equal(ui.evaluate('currentEspChipInfo()'),null,outcome);assert.ok(hardwareChoices(ui).includes('Heltec v2'),outcome);
    assert.equal(ui.evaluate('state.detectedHardware'),null,outcome);assert.deepEqual(ui.calls,outcome==='new-selection'?['chooser']:[],outcome);
  }
});

test('optional chip reading needs no firmware and waits for final consent before its local connect, inspection finish and close only',async()=>{
  for(const [mode,id,connection,native]of [
    ['auto',[0x303a,0x1001],'no_reset',true],['no_reset',[0x303a,0x1001],'no_reset',true],
    ['usb_reset',[0x303a,0x1001],'usb_reset',true],['default_reset',[0x10c4,0xea60],'default_reset',false],
  ]){
    const ui=await espCandidateWorkbench({id,mode});mockChipInspection(ui);
    assert.equal(ui.elements.get('inspect-esp-chip').hidden,false);assert.equal(ui.elements.get('inspect-esp-chip').disabled,false);assert.deepEqual(ui.calls,[]);
    const pending=ui.elements.get('inspect-esp-chip').onclick();assert.equal(ui.elements.get('confirm-dialog').open,true);
    assert.equal(ui.elements.get('confirm-submit').textContent,'Restart & read chip');assert.match(ui.elements.get('confirm-warning').textContent,/No firmware is downloaded, erased or flashed/);
    assert.deepEqual(ui.calls,[]);closeConfirm(ui);await pending;
    assert.deepEqual(ui.calls,['connect:'+connection,'finishInspection:'+native,'close']);assert.equal(ui.evaluate('currentEspChipInfo().chipId'),9);
    assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.esp'),null);assert.equal(ui.evaluate('state.backupApproved'),null);
    assert.equal(ui.evaluate('state.chipInspection'),null);assert.equal(ui.evaluate('state.boardDetected'),false);assert.equal(ui.evaluate('state.verification'),null);
    assert.equal(ui.elements.get('hardware').value,'');assert.match(ui.elements.get('notice').textContent,/normal-boot restart was requested, not verified/i);
  }
});

test('declined or stale chip-read confirmation cannot construct a session, open USB or reset a radio',async()=>{
  for(const outcome of ['cancel','escape','port','generation','firmware','plan','transport']){
    const ui=await espCandidateWorkbench();mockChipInspection(ui);const pending=ui.elements.get('inspect-esp-chip').onclick();
    if(outcome==='port')ui.evaluate('state.port={getInfo:()=>({})};');if(outcome==='generation')ui.evaluate('state.generation++;');
    if(outcome==='firmware')ui.evaluate('state.pkg={name:"new.bin"};');if(outcome==='plan')ui.evaluate('state.plan={};');
    if(outcome==='transport')ui.elements.get('transport-mode').value='usb_reset';
    closeConfirm(ui,outcome==='cancel'?'cancel':outcome==='escape'?'':'confirm');await pending;
    assert.deepEqual(ui.calls,[],outcome);assert.equal(ui.evaluate('currentEspChipInfo()'),null,outcome);assert.equal(ui.evaluate('state.chipInspection')??null,null,outcome);
  }
});

test('failed or disconnected chip connections close their owned session without granting a completion reset or retaining stale chip evidence',async()=>{
  for(const outcome of ['failed','disconnect']){
    const ui=await espCandidateWorkbench({mode:'no_reset'});mockChipInspection(ui,{failure:outcome==='failed'?Error('Post-sync flash-ID read failed'):null});
    if(outcome==='disconnect')ui.context.EspSession.prototype.connect=async()=>{ui.calls.push('connect:no_reset');ui.serialEvents.disconnect({port:ui.port});return s3Inspection;};
    const pending=ui.elements.get('inspect-esp-chip').onclick();closeConfirm(ui);await pending;
    assert.deepEqual(ui.calls,['connect:no_reset','close']);assert.equal(ui.evaluate('currentEspChipInfo()'),null);assert.equal(ui.evaluate('state.chipInspection'),null);
    assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.verification'),null);
    assert.match(ui.elements.get('notice').textContent,outcome==='failed'?/flash-ID read failed/:/selected radio changed/);
  }
});

test('chip reading cannot bypass loaded firmware, prepared sessions, recovery or pending startup verification',async()=>{
  for(const blocked of ['firmware','plan','session','recovery','espRecovery','migration','verification','handoff']){
    const ui=await espCandidateWorkbench();mockChipInspection(ui);
    if(blocked==='firmware')ui.evaluate('state.pkg={name:"loaded.bin",architecture:"esp32",warnings:[]};');
    if(blocked==='plan')ui.evaluate('state.plan={port:state.port};');if(blocked==='session')ui.evaluate('state.esp={};');
    if(blocked==='recovery')ui.evaluate('state.recovery={phase:"reselect-dfu"};');if(blocked==='espRecovery')ui.evaluate('state.espRecovery={};');
    if(blocked==='migration')ui.evaluate('state.migration={};');if(blocked==='verification')ui.evaluate('state.verification={name:"old"};');if(blocked==='handoff')ui.evaluate('state.handoff=true;');
    ui.evaluate('controls();');assert.equal(ui.elements.get('inspect-esp-chip').hidden,true,blocked);
    await ui.elements.get('inspect-esp-chip').onclick();assert.deepEqual(ui.calls,[],blocked);assert.notEqual(ui.elements.get('confirm-dialog').open,true,blocked);
    assert.match(ui.elements.get('notice').textContent,/before loading firmware.*no pending/);
  }
});

test('one explicit bootloader-info choice parses and selects the exact firmware without any drive write or flash',async()=>{
  const ui=await bootloaderInfoWorkbench({dfu:true});ui.calls.length=0;ui.context.chooseBootloaderInfoFile=async options=>{ui.calls.push('file-picker');assert.equal(options.maxBytes,8192);return {name:'INFO_UF2.TXT',text:bootloaderInfoText()};};
  await ui.elements.get('read-bootloader-info').onclick();assert.deepEqual(ui.calls,['file-picker']);assert.equal(ui.elements.get('hardware').value,'Heltec T114');assert.equal(ui.elements.get('role').value,'companionFull');assert.equal(ui.elements.get('provider').value,'Keymind Cascade');assert.equal(ui.elements.get('artifact').value,'0');assert.equal(ui.evaluate('state.device.role'),'bootloader');assert.equal(ui.evaluate('state.device.publicKey'),null);assert.equal(ui.evaluate('state.device.bootloaderVersion'),null);assert.equal(ui.evaluate('state.knownApplicationPort'),null);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.installMode'),'update');assert.equal(ui.elements.get('nrf-bootloader-offer').hidden,true);assert.match(ui.elements.get('bootloader-info-status').textContent,/not proof/);assert.equal(ui.elements.get('already-bootloader').checked,true);
});

test('permission and access failures do not offer or open an alternate file-based detection path',async()=>{
  for(const code of ['NotAllowedError','SecurityError','AccessDenied']){
    const ui=await bootloaderInfoWorkbench({code});assert.equal(ui.elements.get('bootloader-info-fallback').hidden,true);assert.equal(ui.elements.get('read-bootloader-info').disabled,true);await ui.elements.get('read-bootloader-info').onclick();assert.ok(!ui.calls.includes('file-picker'));assert.equal(ui.evaluate('state.bootloaderInfo'),null);
  }
});

test('ambiguous legacy bootloader information shows candidates and highlights Hardware rather than looping back to the file',async()=>{
  const ui=await bootloaderInfoWorkbench({dfu:true});ui.context.inventory.push(t114MeshtasticItem({hardware:'Heltec MeshTower V2',name:'meshtower_full.zip'}));ui.evaluate('filterCatalog();');ui.context.chooseBootloaderInfoFile=async()=>({name:'INFO_UF2.TXT',text:bootloaderInfoText('0.9.2')});
  await ui.elements.get('read-bootloader-info').onclick();assert.equal(ui.elements.get('hardware').value,'');assert.equal(ui.elements.get('artifact').value,'');assert.deepEqual(nextHighlight(ui),['hardware']);assert.match(ui.elements.get('bootloader-info-status').textContent,/shared/);assert.match(ui.elements.get('bootloader-info-status').textContent,/Candidates:.*Heltec MeshTower V2.*Heltec T114/);assert.equal(ui.evaluate('state.pkg'),null);
});

test('cancelled, invalid and stale info-file reads do not retain board evidence or create a backup approval',async()=>{
  for(const mode of ['cancel','invalid','port','generation','workflow']){
    const ui=await bootloaderInfoWorkbench({dfu:true});ui.context.chooseBootloaderInfoFile=async()=>{
      if(mode==='cancel')return null;if(mode==='invalid')return {name:'INFO_UF2.TXT',text:'not a valid bootloader info file'};
      if(mode==='port')ui.evaluate('state.port={getInfo:()=>({})};');if(mode==='generation')ui.evaluate('state.generation++;');if(mode==='workflow')ui.evaluate('state.plan={};');return {name:'INFO_UF2.TXT',text:bootloaderInfoText()};
    };
    await ui.elements.get('read-bootloader-info').onclick();assert.equal(ui.evaluate('state.bootloaderInfo'),null,mode);assert.equal(ui.evaluate('state.device'),null,mode);assert.equal(ui.evaluate('state.backupApproved'),null,mode);assert.equal(ui.elements.get('artifact').value,'',mode);assert.ok(!ui.calls.some(call=>/write|reset|touch/.test(call)),mode);
  }
  const replacement=await bootloaderInfoWorkbench({dfu:true});replacement.context.chooseBootloaderInfoFile=async()=>({name:'INFO_UF2.TXT',text:bootloaderInfoText()});await replacement.elements.get('read-bootloader-info').onclick();assert.equal(replacement.elements.get('hardware').value,'Heltec T114');replacement.context.chooseBootloaderInfoFile=async()=>({name:'INFO_UF2.TXT',text:'invalid replacement'});await replacement.elements.get('read-bootloader-info').onclick();assert.equal(replacement.evaluate('state.bootloaderInfo'),null);assert.equal(replacement.elements.get('hardware').value,'');assert.equal(replacement.elements.get('artifact').value,'');
});

test('file hints expire on operation changes, disconnect and selection of another port',async()=>{
  for(const action of ['generation','disconnect','port']){
    const ui=await bootloaderInfoWorkbench({dfu:true});ui.context.chooseBootloaderInfoFile=async()=>({name:'INFO_UF2.TXT',text:bootloaderInfoText()});await ui.elements.get('read-bootloader-info').onclick();assert.ok(ui.evaluate('state.bootloaderInfo'));
    if(action==='generation')ui.evaluate('state.generation++;controls();');if(action==='disconnect')ui.serialEvents.disconnect({port:ui.port});if(action==='port')await ui.elements.get('select-port').onclick();
    assert.equal(ui.evaluate('state.bootloaderInfo'),null,action);assert.equal(ui.evaluate('state.device'),null,action);assert.equal(ui.evaluate('state.backupApproved'),null,action);assert.equal(ui.evaluate('state.knownApplicationPort'),null,action);
  }
});

test('an info file does not assert DFU mode on an unknown port or grant protected-board identity evidence',async()=>{
  const ui=await bootloaderInfoWorkbench();ui.context.chooseBootloaderInfoFile=async()=>({name:'INFO_UF2.TXT',text:bootloaderInfoText()});await ui.elements.get('read-bootloader-info').onclick();assert.equal(ui.elements.get('already-bootloader').checked,false);assert.equal(ui.elements.get('transport-mode').value,'auto');assert.equal(ui.evaluate('state.connection.mode'),null);assert.equal(ui.evaluate('state.backupApproved'),null);assert.deepEqual(nextHighlight(ui),['select-port']);assert.match(ui.elements.get('step-guidance').textContent,/same radio’s DFU serial port/);
  let assessment;ui.context.assessBoard=(_pkg,input)=>{assessment=input;return {requiresOverride:true,payloadFamily:'unknown'};};ui.context.pkg=fakePackage({architecture:'nrf52'});ui.evaluate('boardAssessment(pkg);');assert.equal(assessment.deviceModel,'');assert.equal(ui.evaluate('verificationRecord(pkg).model'),null);
  await assert.rejects(ui.evaluate('captureBackup();'),/Only bootloader information/);assert.equal(ui.evaluate('state.backup'),null);assert.equal(ui.elements.get('restore').disabled,true);assert.equal(ui.elements.get('binary-mode').disabled,true);
  ui.calls.length=0;ui.elements.get('command').value='set name Test';for(const id of ['backup','restore','send-command','binary-mode']){await ui.elements.get(id).onclick();assert.match(ui.elements.get('notice').textContent,/Only bootloader information/);}assert.deepEqual(ui.calls,[]);
});

test('bootloader-file source cannot count as running MeshCore during post-flash verification',async()=>{
  const ui=await bootloaderInfoWorkbench();ui.context.chooseBootloaderInfoFile=async()=>({name:'INFO_UF2.TXT',text:bootloaderInfoText()});await ui.elements.get('read-bootloader-info').onclick();ui.context.detectApplication=async()=>({firmwareFamily:'bootloader',role:'bootloader',model:'HT-n5262',publicKey:null});ui.evaluate('state.verification={sha256:"a".repeat(64),architecture:"nrf52",publicKey:null,role:null,model:null};');ui.calls.length=0;
  await ui.elements.get('verify-app').onclick();assert.ok(ui.evaluate('state.verification'));assert.equal(ui.evaluate('state.finishedFirmware'),null);assert.match(ui.elements.get('notice').textContent,/Only bootloader information.*startup is not verified/);assert.deepEqual(ui.calls,['open','close']);
});
test('every UI id exists once and all wired controls have matching HTML',()=>{
  assert.equal(new Set(ids).size,ids.length);
  for(const match of source.matchAll(/\$\('([^']+)'\)/g))assert.ok(ids.includes(match[1]),match[1]);
});

test('large flashing progress appears only for the scoped write and waits for final checks before 100%',async()=>{
  const ui=workbench();await Promise.resolve();const dialog=ui.elements.get('flash-progress-dialog');assert.equal(dialog.open,undefined);
  ui.evaluate("progress(.4,'Capturing backup');");assert.equal(dialog.open,undefined);assert.equal(ui.evaluate('state.flashProgress'),null);
  let finish;ui.context.transfer=()=>new Promise(resolve=>{finish=resolve;});const pending=ui.evaluate("withFlashProgress('exact-firmware.zip','Preparing DFU',transfer);");
  assert.equal(dialog.open,true);assert.equal(ui.elements.get('flash-progress-file').textContent,'exact-firmware.zip');assert.equal(ui.elements.get('flash-progress-percent').textContent,'0%');assert.deepEqual(nextHighlight(ui),[]);
  ui.evaluate("progress(.25,'Writing DFU');");assert.equal(ui.elements.get('flash-progress').value,.25);assert.equal(ui.elements.get('flash-progress-percent').textContent,'25%');assert.equal(ui.elements.get('flash-progress-stage').textContent,'Writing DFU');
  ui.evaluate("progress(1,'Writing + verifying application');");assert.equal(ui.elements.get('flash-progress-percent').textContent,'99%');assert.match(ui.elements.get('flash-progress-stage').textContent,/final checks/);assert.equal(dialog.open,true);
  ui.elements.get('flash-progress-close').onclick();assert.equal(dialog.open,true,'Close cannot dismiss an active transfer');
  finish('verified-result');assert.equal(await pending,'verified-result');assert.equal(dialog.open,true);assert.equal(ui.elements.get('flash-progress-title').textContent,'DONE');assert.equal(ui.elements.get('flash-progress-percent').textContent,'100%');assert.match(ui.elements.get('flash-progress-stage').textContent,/startup remains unverified/);assert.equal(ui.evaluate('state.flashProgress'),null);assert.equal(ui.elements.get('flash-progress-close').hidden,false);assert.equal(ui.elements.get('flash-progress-close').disabled,false);assert.deepEqual(nextHighlight(ui),['flash-progress-close']);assert.deepEqual(ui.calls,[]);
  ui.elements.get('flash-progress-close').onclick();assert.equal(dialog.open,false);assert.equal(ui.evaluate('state.flashResult'),null);
});

test('the flashing popup shows recent console context and live plain-text output while retaining the normal log',async()=>{
  const ui=workbench();await Promise.resolve();const output=ui.elements.get('flash-progress-log');ui.evaluate("log('USB connection verified');");assert.equal(output.textContent,'');let finish;
  ui.context.transfer=()=>new Promise(resolve=>{finish=resolve;});const pending=ui.evaluate("withFlashProgress('firmware.bin','Preparing firmware transfer',transfer);");
  assert.match(output.textContent,/USB connection verified/);assert.match(output.textContent,/Preparing firmware transfer/);
  ui.evaluate("log('\\x1b[32mWriting bytes <not-html>\\x1b[0m');");assert.match(output.textContent,/Writing bytes <not-html>/);assert.ok(!output.textContent.includes('\x1b'));assert.match(ui.elements.get('log').textContent,/Writing bytes <not-html>/);
  finish();await pending;assert.match(output.textContent,/Transfer stage finished/);ui.evaluate("log('Read-only startup verification');");assert.match(output.textContent,/Read-only startup verification/);ui.elements.get('flash-progress-close').onclick();const closedText=output.textContent;ui.evaluate("log('Further work after closing');");assert.equal(output.textContent,closedText);assert.match(ui.elements.get('log').textContent,/Further work after closing/);assert.deepEqual(ui.calls,[]);
});

test('flashing console follows new output at the bottom but does not jump while reading earlier lines',async()=>{
  const ui=workbench();await Promise.resolve();const output=ui.elements.get('flash-progress-log');output.clientHeight=200;output.scrollHeight=1000;let finish;
  ui.context.transfer=()=>new Promise(resolve=>{finish=resolve;});const pending=ui.evaluate("withFlashProgress('firmware.bin','Writing firmware',transfer);");assert.equal(output.scrollTop,1000);
  output.scrollTop=100;ui.evaluate("log('Next chunk');");assert.equal(output.scrollTop,100);
  output.scrollTop=800;ui.evaluate("log('Another chunk');");assert.equal(output.scrollTop,1000);finish();await pending;assert.deepEqual(ui.calls,[]);
});

test('popup console is bounded, stage changes are logged once and reopening refreshes the current context',async()=>{
  const ui=workbench();await Promise.resolve();let finish;ui.context.transfer=()=>new Promise(resolve=>{finish=resolve;});let pending=ui.evaluate("withFlashProgress('firmware.bin','Preparing DFU',transfer);");
  ui.evaluate("progress(.1,'Writing DFU');progress(.2,'Writing DFU');");assert.equal(ui.elements.get('log').textContent.split('Writing DFU').length-1,1);assert.match(ui.elements.get('flash-progress-log').textContent,/Writing DFU/);
  ui.context.longMessage='x'.repeat(110000);ui.evaluate('log(longMessage);');assert.equal(ui.elements.get('log').textContent.length,100000);assert.equal(ui.elements.get('flash-progress-log').textContent.length,32000);
  ui.elements.get('clear-log').onclick();assert.equal(ui.elements.get('flash-progress-log').textContent,'Log cleared locally.');finish();await pending;
  ui.evaluate("log('Final image after expansion');");pending=ui.evaluate("withFlashProgress('final.bin','Writing final image',transfer);");assert.match(ui.elements.get('flash-progress-log').textContent,/Final image after expansion/);assert.match(ui.elements.get('flash-progress-log').textContent,/Writing final image/);finish();await pending;assert.deepEqual(ui.calls,[]);
});

test('progress modal prevents Escape and requests a browser leave warning only while transfer is active',async()=>{
  const ui=workbench();await Promise.resolve();let finish;ui.context.transfer=()=>new Promise(resolve=>{finish=resolve;});const pending=ui.evaluate("withFlashProgress('app.bin','Writing firmware',transfer);");
  let prevented=0,stopped=0;const leave={preventDefault(){prevented++;}};ui.elements.get('flash-progress-dialog').emit('cancel',{preventDefault(){prevented++;}});ui.elements.get('flash-progress-dialog').emit('keydown',{key:'Escape',preventDefault(){prevented++;},stopPropagation(){stopped++;}});ui.windowEvents.beforeunload(leave);assert.equal(prevented,3);assert.equal(stopped,1);assert.equal(leave.returnValue,'');assert.equal(ui.elements.get('flash-progress-dialog').open,true);
  finish();await pending;ui.elements.get('flash-progress-dialog').emit('cancel',{preventDefault(){prevented++;}});ui.elements.get('flash-progress-dialog').emit('keydown',{key:'Escape',preventDefault(){prevented++;},stopPropagation(){stopped++;}});ui.windowEvents.beforeunload({preventDefault(){prevented++;}});assert.equal(prevented,3);assert.equal(stopped,1);assert.deepEqual(ui.calls,[]);
});

test('failed transfers and modal-open failures clean up without retrying or claiming completion',async()=>{
  for(const stage of ['write','open']){
    const ui=workbench();await Promise.resolve();const original=Error('Test '+stage+' failure');ui.context.original=original;const dialog=ui.elements.get('flash-progress-dialog');
    if(stage==='open')dialog.showModal=()=>{throw original;};
    ui.context.transfer=async()=>{ui.calls.push('write');ui.evaluate("progress(.3,'Writing firmware');");throw original;};
    await assert.rejects(ui.evaluate("withFlashProgress('app.bin','Preparing',transfer);"),error=>error===original);assert.equal(ui.evaluate('state.flashProgress'),null);assert.ok(!dialog.open);assert.notEqual(ui.elements.get('flash-progress-percent').textContent,'100%');assert.deepEqual(ui.calls,stage==='write'?['write']:[]);assert.equal(ui.elements.get('flash-stop-auto').hidden,true);
  }
});

test('a nested transfer cannot replace or close an active progress window',async()=>{
  const ui=workbench();await Promise.resolve();let finish;ui.context.transfer=()=>new Promise(resolve=>{finish=resolve;});const pending=ui.evaluate("withFlashProgress('original.zip','Preparing',transfer);");
  await assert.rejects(ui.evaluate("withFlashProgress('other.zip','Preparing',()=>{throw Error('must not start');});"),/already active/);assert.equal(ui.elements.get('flash-progress-file').textContent,'original.zip');assert.equal(ui.elements.get('flash-progress-dialog').open,true);finish();await pending;assert.equal(ui.elements.get('flash-progress-dialog').open,true);assert.equal(ui.elements.get('flash-progress-title').textContent,'DONE');ui.elements.get('flash-progress-close').onclick();assert.equal(ui.elements.get('flash-progress-dialog').open,false);assert.deepEqual(ui.calls,[]);
});

test('DONE remains visible for later workflow errors and resets fully for the next transfer',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.completed=async()=>{};
  await ui.evaluate("operation(async()=>{await withFlashProgress('final.bin','Writing',completed);throw Error('Startup check failed');});");
  const dialog=ui.elements.get('flash-progress-dialog');assert.equal(dialog.open,true);assert.equal(ui.elements.get('flash-progress-title').textContent,'DONE — check required');assert.match(ui.elements.get('flash-progress-warning').textContent,/Startup check failed/);assert.match(ui.elements.get('flash-progress-log').textContent,/Stopped: Startup check failed/);assert.equal(ui.elements.get('flash-progress-close').disabled,false);assert.equal(ui.evaluate('state.flashProgress'),null);
  ui.elements.get('flash-progress-close').onclick();let finish;ui.context.nextTransfer=()=>new Promise(resolve=>{finish=resolve;});const next=ui.evaluate("withFlashProgress('next.bin','Writing next',nextTransfer);");assert.equal(dialog.open,true);assert.equal(ui.elements.get('flash-progress-title').textContent,'Flashing firmware');assert.equal(ui.elements.get('flash-progress-percent').textContent,'0%');assert.equal(ui.elements.get('flash-progress-close').hidden,true);assert.equal(ui.elements.get('flash-progress-close').disabled,true);assert.equal(dialog.classList.contains('flash-result-error'),false);assert.match(ui.elements.get('flash-progress-warning').textContent,/Do not unplug/);finish();await next;assert.equal(ui.elements.get('flash-progress-title').textContent,'DONE');
});

test('a follow-up confirmation above DONE owns the highlighted action instead of the close button behind it',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.completed=async()=>{};await ui.evaluate("withFlashProgress('firmware.zip','Writing',completed);");assert.deepEqual(nextHighlight(ui),['flash-progress-close']);
  ui.evaluate("state.nextDialogAction=$('confirm-submit');updateNextAction();");assert.deepEqual(nextHighlight(ui),['confirm-submit']);ui.evaluate('state.nextDialogAction=null;updateNextAction();');assert.deepEqual(nextHighlight(ui),['flash-progress-close']);
});

test('all final firmware-write paths keep DONE open while subsequent workflow state advances',async()=>{
  for(const kind of ['nrf52','erase','esp32','uf2']){
    const ui=workbench();await Promise.resolve();serialMock(ui);ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage({name:kind==='uf2'?'firmware.uf2':'firmware.zip',architecture:kind==='esp32'?'esp32':kind==='uf2'?'uf2':'nrf52'});ui.evaluate('state.port=selectedPort;state.pkg=pkg;state.plan={generation:state.generation,port:selectedPort,sha256:pkg.sha256,addresses:[0x10000]};');
    const dialog=ui.elements.get('flash-progress-dialog');ui.context.confirm=async()=>false;await ui.elements.get('flash').onclick();assert.ok(!dialog.open);assert.equal(ui.evaluate('state.flashProgress'),null);
    ui.context.confirm=async()=>true;
    const onWrite=()=>{assert.equal(dialog.open,true,kind);assert.ok(ui.evaluate('state.flashProgress'),kind);ui.calls.push('write');ui.evaluate("progress(.42,'Writing firmware');");assert.equal(ui.elements.get('flash-progress-percent').textContent,'42%',kind);};
    ui.context.flashNrf=async(_link,actual)=>{onWrite();assert.equal(ui.elements.get('flash-progress-file').textContent,actual.name);};
    if(kind==='erase'){ui.context.erase=fakePackage({name:'erase.zip',sha256:'e'.repeat(64),erase:true,destructive:true});ui.evaluate('state.plan.erasePkg=erase;');}
    if(kind==='esp32')ui.evaluate('state.esp={flash:async()=>onWrite()};');
    if(kind==='esp32')ui.context.onWrite=onWrite;
    if(kind==='uf2'){ui.context.hash=()=>ui.context.pkg.payloadHash;ui.context.drive={getFileHandle:async(name)=>name==='INFO_UF2.TXT'?{getFile:async()=>({text:async()=>'UF2 Bootloader Test'})}:{createWritable:async()=>({write:async()=>onWrite(),close:async()=>assert.equal(dialog.open,true),abort:async()=>{}})}};ui.evaluate('state.directory=drive;state.plan.uf2Info="UF2 Bootloader Test";');}
    await ui.elements.get('flash').onclick();assert.equal(ui.calls.filter(call=>call==='write').length,1,kind);assert.equal(dialog.open,true,kind);assert.equal(ui.elements.get('flash-progress-title').textContent,kind==='erase'?'DONE — ERASE STEP ONLY':'DONE',kind);assert.equal(ui.evaluate('state.flashProgress'),null,kind);
    assert.equal(ui.evaluate('state.flashResult.sha256'),kind==='erase'?ui.context.erase.sha256:ui.context.pkg.sha256,kind);
    if(kind==='erase')assert.equal(ui.evaluate('state.recovery.phase'),'reselect-dfu');
    if(kind==='esp32'||kind==='nrf52')assert.ok(ui.evaluate('state.verification'),kind);
    ui.elements.get('flash-progress-close').onclick();assert.equal(dialog.open,false,kind);
  }
});

async function eraseCompletionWorkbench(){
  const ui=workbench();await Promise.resolve();serialMock(ui);ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0057});
  ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage({name:'t1000e_companion_radio_full-v1.18.0.1-keymind-cascade.zip'});ui.context.erase=fakePackage({name:'reviewed-utility.zip',sha256:'e'.repeat(64),erase:true,destructive:true});
  ui.evaluate('state.port=selectedPort;state.pkg=pkg;state.plan={generation:state.generation,port:selectedPort,sha256:pkg.sha256,erasePkg:erase};');
  ui.context.confirm=async(_title,_detail,_warning,token)=>{assert.equal(token,'WIPE WITHOUT BACKUP');ui.calls.push('confirm-wipe');return true;};
  return ui;
}

test('erase DONE explicitly says MeshCore is not installed and directs the same DFU radio to its retained final firmware',async()=>{
  const ui=await eraseCompletionWorkbench();let finish;
  ui.context.flashNrf=async(_link,pkg)=>{assert.equal(pkg,ui.context.erase);ui.calls.push('write-erase');return new Promise(resolve=>{finish=resolve;});};
  const pending=ui.elements.get('flash').onclick();for(let i=0;i<10&&!finish;i++)await Promise.resolve();assert.ok(finish);
  assert.equal(ui.elements.get('flash-progress-title').textContent,'Flashing firmware');assert.match(ui.elements.get('flash-progress-warning').textContent,/Do not unplug/);assert.equal(ui.elements.get('flash-progress-close').hidden,true);assert.notEqual(ui.elements.get('flash-progress-percent').textContent,'100%');
  finish();await pending;
  assert.equal(ui.elements.get('flash-progress-dialog').open,true);assert.equal(ui.elements.get('flash-progress-title').textContent,'DONE — ERASE STEP ONLY');assert.equal(ui.elements.get('flash-progress-percent').textContent,'100%');
  assert.match(ui.elements.get('flash-progress-stage').textContent,/Erase utility transfer finished.*MeshCore has NOT been installed yet/);
  assert.match(ui.elements.get('flash-progress-warning').textContent,/Keep USB connected.*SAME radio.*DFU USB port.*highlighted button/);assert.ok(ui.elements.get('flash-progress-warning').textContent.includes(ui.context.pkg.name));
  assert.match(ui.elements.get('flash-progress-close').textContent,/Close.*continue installation/);assert.equal(ui.elements.get('flash-progress-advice').hidden,true);assert.equal(ui.evaluate('state.flashResult.sha256'),ui.context.erase.sha256);
  assert.equal(ui.evaluate('state.recovery.eraseComplete'),true);assert.equal(ui.evaluate('state.recovery.phase'),'reselect-dfu');assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);assert.equal(ui.evaluate('state.verification'),null);
  assert.deepEqual(ui.calls,['confirm-wipe','open','write-erase','close']);assert.match(ui.elements.get('progress-label').textContent,/MeshCore has not been installed yet/);
  ui.context.expected={sha256:ui.context.erase.sha256};ui.evaluate('markFlashResultStartupVerified(expected);');assert.equal(ui.elements.get('flash-progress-title').textContent,'DONE — ERASE STEP ONLY');assert.notEqual(ui.evaluate('state.flashResult.applicationVerified'),true);
  ui.elements.get('flash-progress-close').onclick();assert.equal(ui.elements.get('flash-progress-dialog').open,false);assert.deepEqual(nextHighlight(ui),['select-port']);assert.deepEqual(ui.calls,['confirm-wipe','open','write-erase','close']);
  ui.context.completed=async()=>{};await ui.evaluate("withFlashProgress('final.zip','Writing final firmware',completed,{sha256:pkg.sha256});");
  assert.equal(ui.elements.get('flash-progress-title').textContent,'DONE');assert.match(ui.elements.get('flash-progress-stage').textContent,/startup remains unverified/);assert.doesNotMatch(ui.elements.get('flash-progress-warning').textContent,/NOT been installed|erase step|retained firmware/i);assert.equal(ui.elements.get('flash-progress-close').textContent,'Close');
});

test('an interrupted erase transfer never shows erase-step DONE or first-startup identity claims',async()=>{
  const ui=await eraseCompletionWorkbench();ui.context.flashNrf=async()=>{ui.calls.push('write-erase');throw Error('Erase utility transfer interrupted');};
  await ui.elements.get('flash').onclick();assert.equal(ui.elements.get('flash-progress-dialog').open,false);assert.notEqual(ui.elements.get('flash-progress-percent').textContent,'100%');assert.notEqual(ui.elements.get('flash-progress-title').textContent,'DONE — ERASE STEP ONLY');
  assert.equal(ui.evaluate('state.recovery.eraseComplete'),false);assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);assert.doesNotMatch(ui.elements.get('notice').textContent,/First startup|create a new private identity/);assert.deepEqual(ui.calls,['confirm-wipe','open','write-erase','close']);
});

test('first-startup identity guidance requires a matching completed erase or a matching merged ESP install plan',async()=>{
  for(const scenario of ['nrf-erased','nrf-update','mode-only','incomplete-erase','wrong-erase-image','erase-still-running','component','erase-utility','esp-merged','esp-update','esp-wrong-plan','esp-expert']){
    const ui=workbench();await Promise.resolve();ui.context.pkg=fakePackage({...(scenario.startsWith('esp')?{architecture:'esp32',merged:scenario!=='esp-update',expert:scenario==='esp-expert'}:{}),...(scenario==='component'?{kind:'bootloader'}:{}),...(scenario==='erase-utility'?{erase:true}:{})});
    ui.evaluate('state.pkg=pkg;');
    if(!['nrf-update','mode-only'].includes(scenario)&&!scenario.startsWith('esp'))ui.evaluate(`state.recovery={sha256:${scenario==='wrong-erase-image'?"'c'.repeat(64)":'pkg.sha256'},phase:${scenario==='erase-still-running'?"'erasing'":"'final'"},eraseComplete:${scenario!=='incomplete-erase'}};`);
    if(scenario==='mode-only')ui.evaluate('state.installMode="install";');
    if(scenario.startsWith('esp'))ui.evaluate(`state.plan={merged:${scenario!=='esp-update'},sha256:${scenario==='esp-wrong-plan'?"'c'.repeat(64)":'pkg.sha256'}};`);
    const advice=ui.evaluate('firstStartupAdvice(pkg)'),record=ui.evaluate('verificationRecord(pkg)'),expected=['nrf-erased','esp-merged'].includes(scenario);
    assert.equal(!!advice,expected,scenario);assert.equal(!!record.startupAdvice,expected,scenario);
    if(expected){assert.match(advice,/First startup may create a new private identity and initialize storage/);assert.doesNotMatch(advice,/generating|generated|\d+%/i);}
    assert.deepEqual(ui.calls,[],scenario);
  }
});

test('a final fresh T1000-E install keeps startup guidance and BLE advice until actual startup verification',async()=>{
  const ui=workbench();await Promise.resolve();serialMock(ui);ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0057});ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage({name:'t1000e_companion_radio_full-v1.18.0.1-keymind-cascade.zip'});
  ui.evaluate('state.port=selectedPort;state.pkg=pkg;state.device={role:"companion",model:"Seeed Tracker T1000-E",publicKey:"11".repeat(32)};state.recovery={sha256:pkg.sha256,name:pkg.name,phase:"final",eraseComplete:true,deviceModel:"Seeed Tracker T1000-E"};state.plan={generation:state.generation,port:selectedPort,sha256:pkg.sha256,erasePkg:null};');
  ui.context.confirm=async()=>true;ui.context.flashNrf=async()=>ui.calls.push('write-final');await ui.elements.get('flash').onclick();
  assert.equal(ui.elements.get('flash-progress-title').textContent,'DONE');assert.match(ui.elements.get('flash-progress-stage').textContent,/startup remains unverified/);
  for(const id of ['flash-progress-advice','post-flash-advice']){assert.equal(ui.elements.get(id).hidden,false);assert.match(ui.elements.get(id).textContent,/First startup may create a new private identity and initialize storage/);assert.match(ui.elements.get(id).textContent,/Bluetooth \(BLE\) stays off/);}
  assert.equal(ui.evaluate('state.verification.publicKey'),null);assert.ok(ui.evaluate('state.verification.startupAdvice'));assert.match(ui.elements.get('reconnect-detail').textContent,/First startup may create a new private identity/);assert.equal(ui.evaluate('state.recovery'),null);
  const stored=JSON.parse(ui.context.localStorage.getItem('meshfirmware.verifyApplication'));assert.ok(stored.startupAdvice);const fresh=workbench({verification:stored});await Promise.resolve();assert.match(fresh.elements.get('reconnect-detail').textContent,/First startup may create a new private identity/);assert.deepEqual(fresh.calls,[]);
  ui.context.freshApplication={role:'companion',model:'Seeed Tracker T1000-E',name:'Fresh fixture',protocol:14,publicKey:'22'.repeat(32)};ui.context.appPort={getInfo:()=>({usbVendorId:0x239a,usbProductId:0x8029})};ui.evaluate('state.port=appPort;state.generation++;$("already-bootloader").checked=false;');
  ui.context.readApplication=async()=>{ui.calls.push('application-read');ui.evaluate('state.device=freshApplication;');return ui.context.freshApplication;};ui.context.MeshCore=class{async cli(command){assert.equal(command,'version');return 'Companion v1.18.0.1';}};
  await ui.evaluate('verifyApplication();');assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.elements.get('flash-progress-dialog').open,true);assert.equal(ui.elements.get('flash-progress-stage').textContent,'Application startup verified.');assert.equal(ui.evaluate('state.flashResult.applicationVerified'),true);
  assert.match(ui.elements.get('flash-progress-advice').textContent,/Bluetooth \(BLE\) stays off/);assert.doesNotMatch(ui.elements.get('flash-progress-advice').textContent,/First startup|create a new private identity/);ui.evaluate('controls();');assert.doesNotMatch(ui.elements.get('post-flash-advice').textContent,/First startup/);assert.doesNotMatch(ui.elements.get('reconnect-detail').textContent,/First startup/);
});

async function nrfActivationWorkbench(){
  const ui=workbench();await Promise.resolve();
  ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0057});const appPort={getInfo:()=>({usbVendorId:0x239a,usbProductId:0x8029})};
  ui.context.dfuPort=ui.port;ui.context.appPort=appPort;ui.context.pkg=fakePackage({name:'t1000e_companion_radio_full-v1.18.0.1-keymind-cascade.zip',firmwareIdentity:{versionText:'v1.18.0.1-keymind-cascade'}});
  ui.context.activationItem={name:ui.context.pkg.name,hardware:'Seeed Studio SenseCAP T1000-E',role:'companionFull'};
  ui.context.activationDevice={role:'companion',model:'Seeed Tracker T1000-E',publicKey:'11'.repeat(32),architecture:'nrf52',bootloaderVersion:'0.11.0-OTAFIX2.4.12',version:'Companion v1.18.0.0-keymind-cascade'};
  ui.evaluate('state.port=dfuPort;state.pkg=pkg;state.item=activationItem;state.device=activationDevice;state.knownApplicationPort={port:appPort,publicKey:activationDevice.publicKey,available:false};state.handoff=true;state.plan={generation:state.generation,port:dfuPort,sha256:pkg.sha256,installMode:"update"};');
  ui.context.SerialLink=class{
    constructor(port){assert.ok(port===ui.port||port===appPort);this.port=port;}
    async open(baudRate,options){if(this.port===appPort){assert.equal(baudRate,115200);assert.equal(options?.application,true);}ui.calls.push(this.port===appPort?'application-open':'dfu-open');}
    async close(){ui.calls.push(this.port===appPort?'application-close':'dfu-close');}
  };
  ui.context.readApplication=async()=>assert.fail('Activation optimization cannot use the state-mutating application reader');
  ui.context.detectMeshCore=async(link,options)=>{assert.equal(link.port,appPort);assert.ok(options.timeoutMs>0&&options.timeoutMs<=700);ui.calls.push('application-detect');return {...ui.context.activationDevice,version:'Companion v1.18.0.1-keymind-cascade'};};
  ui.context.confirm=async()=>true;ui.context.createNrfActivationCheck=options=>{ui.activationOptions=options;return ui.activationCallback||null;};
  ui.appPort=appPort;return ui;
}

test('a qualified nRF update passes only its read-only activation callback without prematurely marking startup verified',async()=>{
  const ui=await nrfActivationWorkbench();
  ui.context.requestAutomaticVerification=()=>{assert.equal(ui.evaluate('state.knownApplicationPort.available'),true);assert.ok(ui.evaluate('state.verification'));assert.notEqual(ui.evaluate('state.finishedFirmware.verified'),true);ui.calls.push('normal-verification-requested');};
  ui.activationCallback=async()=>{assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.evaluate('state.flashResult'),null);assert.equal(ui.evaluate('state.finishedFirmware'),null);ui.calls.push('activation-proof');const fresh=await ui.activationOptions.readApplication(ui.appPort,{timeoutMs:3000});assert.equal(fresh.publicKey,ui.context.activationDevice.publicKey);return true;};
  ui.context.flashNrf=async(link,pkg,_progress,options)=>{assert.equal(link.port,ui.port);assert.equal(pkg,ui.context.pkg);assert.equal(typeof options.activationCheck,'function');ui.calls.push('write-final');assert.equal(await options.activationCheck({link,pkg,maxWaitMs:5000}),true);assert.equal(ui.evaluate('state.knownApplicationPort.available'),true);assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.evaluate('state.flashResult'),null);};
  const beforeDevice=ui.evaluate('state.device');await ui.elements.get('flash').onclick();
  assert.equal(ui.activationOptions.expectedRole,'companion');assert.equal(ui.activationOptions.hardware,'Seeed Studio SenseCAP T1000-E');assert.equal(ui.activationOptions.pkg,ui.context.pkg);assert.equal(ui.activationOptions.knownApplicationPort.port,ui.appPort);
  assert.deepEqual(ui.calls,['dfu-open','write-final','activation-proof','application-open','application-detect','application-close','dfu-close','normal-verification-requested']);assert.equal(ui.evaluate('state.device'),beforeDevice);assert.equal(ui.evaluate('state.port'),ui.port);
  assert.ok(ui.evaluate('state.verification'));assert.notEqual(ui.evaluate('state.finishedFirmware.verified'),true);assert.equal(ui.elements.get('flash-progress-title').textContent,'DONE');assert.match(ui.elements.get('flash-progress-stage').textContent,/startup remains unverified/);assert.doesNotMatch(ui.elements.get('flash-progress-advice').textContent,/First startup|new private identity/);
});

test('only a strict fresh activation result in unchanged context marks the captured app port available',async()=>{
  for(const scenario of ['true','false','truthy','stale-package','stale-port','stale-key','protected']){
    const ui=await nrfActivationWorkbench(),known=ui.evaluate('state.knownApplicationPort');
    ui.activationCallback=async()=>{
      assert.equal(ui.evaluate('state.knownApplicationPort.available'),false);assert.equal(ui.evaluate('state.verification'),null);
      if(scenario==='stale-package')ui.evaluate('state.pkg={...pkg};');
      if(scenario==='stale-port')ui.evaluate('state.port=appPort;');
      if(scenario==='stale-key')ui.evaluate('state.knownApplicationPort.publicKey="22".repeat(32);');
      if(scenario==='protected')ui.evaluate('state.recovery={};');
      return scenario==='false'?false:scenario==='truthy'?1:true;
    };
    const check=ui.evaluate('nrfApplicationActivationCheck(pkg);');assert.equal(typeof check,'function');
    assert.equal(await check({}),scenario==='true',scenario);assert.equal(known.available,scenario==='true',scenario);assert.equal(ui.evaluate('state.verification'),null,scenario);assert.equal(ui.evaluate('state.flashResult'),null,scenario);assert.equal(ui.evaluate('state.finishedFirmware'),null,scenario);assert.deepEqual(ui.calls,[],scenario);
  }
});

test('a proven app-port availability hint lets normal post-transfer startup verification finish without another chooser',async()=>{
  const ui=await nrfActivationWorkbench();ui.context.pkg.firmwareIdentity.versionText='v1.18.0.1';
  ui.activationCallback=async()=>{assert.equal(ui.evaluate('state.verification'),null);ui.calls.push('activation-proof');return true;};
  ui.context.flashNrf=async(link,pkg,_progress,options)=>{ui.calls.push('write-final');assert.equal(await options.activationCheck({link,pkg,maxWaitMs:5000}),true);assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.evaluate('state.flashResult'),null);};
  ui.context.readApplication=async link=>{assert.equal(link.port,ui.appPort);assert.ok(ui.evaluate('state.verification'));assert.notEqual(ui.evaluate('state.finishedFirmware.verified'),true);ui.calls.push('normal-startup-read');ui.context.freshDevice={...ui.context.activationDevice,version:'Companion v1.18.0.1-keymind-cascade'};ui.evaluate('state.device=freshDevice;');return ui.context.freshDevice;};
  ui.context.MeshCore=class{async cli(command){assert.equal(command,'version');ui.calls.push('version');return 'Companion v1.18.0.1-keymind-cascade';}};
  await ui.elements.get('flash').onclick();await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.evaluate('state.finishedFirmware.verified'),true);assert.equal(ui.evaluate('state.port'),ui.appPort);assert.equal(ui.elements.get('flash-progress-dialog').open,true);assert.equal(ui.elements.get('flash-progress-stage').textContent,'Application startup verified.');assert.equal(ui.evaluate('state.flashResult.applicationVerified'),true);
  assert.deepEqual(ui.calls,['dfu-open','write-final','activation-proof','dfu-close','application-open','normal-startup-read','version','application-close']);assert.ok(!ui.calls.includes('chooser'));
});

test('fast nRF activation is unavailable for installs, erase recovery, components or another protected flow',async()=>{
  for(const scenario of ['install','erase-plan','recovery','migration','migrationApproval','espRecovery','verification','backupApplicationRequest','esp','nrfPrepareResume','component','erase','expert','destructive','missing-key','wrong-key','wrong-plan']){
    const ui=await nrfActivationWorkbench();ui.context.createNrfActivationCheck=()=>assert.fail('Unqualified context cannot construct a fast activation probe');
    if(scenario==='install')ui.evaluate('state.installMode="install";');
    else if(scenario==='erase-plan')ui.evaluate('state.plan.erasePkg={};');
    else if(scenario==='component')ui.evaluate('state.pkg.kind="bootloader";');
    else if(['erase','expert','destructive'].includes(scenario))ui.evaluate(`state.pkg.${scenario}=true;`);
    else if(scenario==='missing-key')ui.evaluate('state.knownApplicationPort.publicKey=null;');
    else if(scenario==='wrong-key')ui.evaluate('state.device.publicKey="22".repeat(32);');
    else if(scenario==='wrong-plan')ui.evaluate('state.plan.sha256="c".repeat(64);');
    else ui.evaluate(`state.${scenario}={};`);
    assert.equal(ui.evaluate('nrfApplicationActivationCheck(pkg);'),null,scenario);assert.deepEqual(ui.calls,[],scenario);
  }
});

test('the activation scope permits only its own DFU disconnect and rejects foreign selections or changed proofs',async()=>{
  for(const change of ['own-disconnect','extra-generation','foreign-port','package-object','digest','mode','known-object','known-key','device-key','item','plan','recovery','verification']){
    const ui=await nrfActivationWorkbench();ui.evaluate('nrfApplicationActivationCheck(pkg);');assert.equal(ui.activationOptions.isCurrent(),true,change);
    if(change==='own-disconnect'){ui.serialEvents.disconnect({port:ui.port});ui.evaluate('state.knownApplicationPort.available=true;');}
    if(change==='extra-generation')ui.evaluate('state.port=null;state.plan=null;state.generation+=2;');
    if(change==='foreign-port')ui.evaluate('state.port=appPort;');
    if(change==='package-object')ui.evaluate('state.pkg={...pkg};');
    if(change==='digest')ui.evaluate('state.pkg.sha256="c".repeat(64);');
    if(change==='mode')ui.evaluate('state.installMode="install";');
    if(change==='known-object')ui.evaluate('state.knownApplicationPort={...state.knownApplicationPort};');
    if(change==='known-key')ui.evaluate('state.knownApplicationPort.publicKey="22".repeat(32);');
    if(change==='device-key')ui.evaluate('state.device.publicKey="22".repeat(32);');
    if(change==='item')ui.evaluate('state.item={...state.item};');
    if(change==='plan')ui.evaluate('state.plan={...state.plan};');
    if(['recovery','verification'].includes(change))ui.evaluate(`state.${change}={};`);
    assert.equal(ui.activationOptions.isCurrent(),change==='own-disconnect',change);assert.deepEqual(ui.calls,[],change);
  }
});

test('the activation application adapter owns only its exact app link and aborts without resets or state adoption',async()=>{
  for(const phase of ['pre-aborted','after-open','during-read','open-denied','foreign-port']){
    const ui=await nrfActivationWorkbench();ui.evaluate('nrfApplicationActivationCheck(pkg);');const controller=new AbortController(),options=ui.activationOptions;
    const beforeDevice=ui.evaluate('state.device'),beforePort=ui.evaluate('state.port');let finish;
    if(phase==='pre-aborted')controller.abort();
    if(phase==='after-open')ui.context.SerialLink.prototype.open=async()=>{ui.calls.push('application-open');controller.abort();};
    if(phase==='during-read')ui.context.detectMeshCore=()=>{ui.calls.push('application-detect');return new Promise(resolve=>{finish=resolve;});};
    if(phase==='open-denied')ui.context.SerialLink.prototype.open=async()=>{ui.calls.push('application-open');throw Object.assign(Error('Port is in use'),{name:'NotAllowedError'});};
    const pending=options.readApplication(phase==='foreign-port'?ui.port:ui.appPort,{timeoutMs:3000,signal:controller.signal});
    if(phase==='during-read'){for(let i=0;i<10&&!finish;i++)await Promise.resolve();assert.ok(finish);controller.abort();finish({...ui.context.activationDevice});}
    await assert.rejects(pending,/cancelled|Port is in use|context changed/);
    assert.equal(ui.evaluate('state.device'),beforeDevice,phase);assert.equal(ui.evaluate('state.port'),beforePort,phase);assert.equal(ui.evaluate('state.verification'),null,phase);
    assert.deepEqual(ui.calls,phase==='pre-aborted'||phase==='foreign-port'?[]:phase==='open-denied'?['application-open']:phase==='during-read'?['application-open','application-detect','application-close']:['application-open','application-close'],phase);
  }
});

test('successful startup updates only the open DONE window bound to that exact transferred image',async()=>{
  const ui=await storageVerificationWorkbench('companion','> int:esp32=16384K ext:none; app0*@0x10000+6400K');
  ui.context.completed=async()=>{};
  await ui.evaluate("withFlashProgress('exact.bin','Writing firmware',completed,{sha256:expected.sha256,completionAdvice:'Keep the Bluetooth reminder.'});");
  assert.match(ui.elements.get('flash-progress-stage').textContent,/startup remains unverified/);
  await ui.evaluate('verifyApplication();');
  assert.equal(ui.elements.get('flash-progress-dialog').open,true);
  assert.equal(ui.elements.get('flash-progress-title').textContent,'DONE');
  assert.equal(ui.elements.get('flash-progress-stage').textContent,'Application startup verified.');
  assert.match(ui.elements.get('flash-progress-warning').textContent,/transfer and application startup verified/);
  assert.doesNotMatch(ui.elements.get('flash-progress-warning').textContent,/unverified|separately/);
  assert.equal(ui.elements.get('flash-progress-advice').textContent,'Keep the Bluetooth reminder.');
  assert.equal(ui.elements.get('flash-progress-advice').hidden,false);
  assert.equal(ui.evaluate('state.flashResult.applicationVerified'),true);
  assert.equal(ui.calls.filter(call=>call==='application-open').length,1);
});

test('startup proof cannot repaint another image, a failed result, an active write or a closed DONE window',async()=>{
  for(const scenario of ['different-digest','no-digest','failed','active','closed']){
    const ui=workbench();await Promise.resolve();ui.context.completed=async()=>{};
    await ui.evaluate(`withFlashProgress('old.bin','Writing firmware',completed,{sha256:${scenario==='no-digest'?'null':"'a'.repeat(64)"}});`);
    ui.evaluate(`state.verification={sha256:${scenario==='different-digest'?"'b'.repeat(64)":"'a'.repeat(64)"}};`);
    if(scenario==='failed')ui.evaluate('state.flashResult.failed=true;');
    if(scenario==='active')ui.evaluate('state.flashProgress={name:"new.bin"};');
    if(scenario==='closed')ui.elements.get('flash-progress-dialog').close();
    const before=['flash-progress-title','flash-progress-stage','flash-progress-warning'].map(id=>ui.elements.get(id).textContent);
    ui.evaluate('markFlashResultStartupVerified(state.verification);');
    assert.deepEqual(['flash-progress-title','flash-progress-stage','flash-progress-warning'].map(id=>ui.elements.get(id).textContent),before,scenario);
    assert.notEqual(ui.evaluate('state.flashResult.applicationVerified'),true,scenario);assert.deepEqual(ui.calls,[],scenario);
  }
});

test('failed identity, version and storage checks leave the matching DONE startup state unverified',async()=>{
  for(const scenario of ['identity','version','storage']){
    const ui=await storageVerificationWorkbench('companion',scenario==='storage'?'Error: unavailable':'int:esp32=16384K');
    ui.context.completed=async()=>{};await ui.evaluate("withFlashProgress('exact.bin','Writing firmware',completed,{sha256:expected.sha256});");
    if(scenario==='identity')ui.context.detectMeshCore=async()=>({role:'companion',model:ui.context.expected.model,publicKey:'22'.repeat(32),protocol:14});
    if(scenario==='version')ui.context.expected.version='v1.18.0.2';
    await assert.rejects(ui.evaluate('verifyApplication();'),/identity differs|version does not match|storage-layout verification/);
    assert.match(ui.elements.get('flash-progress-stage').textContent,/startup remains unverified/,scenario);
    assert.notEqual(ui.evaluate('state.flashResult.applicationVerified'),true,scenario);
    assert.ok(ui.evaluate('state.verification'),scenario);assert.equal(ui.elements.get('flash-progress-dialog').open,true,scenario);
  }
});

test('automatic same-port startup verification updates the matching DONE window without closing it',async()=>{
  const ui=await automaticStartupWorkbench();ui.context.completed=async()=>{};
  await ui.evaluate("withFlashProgress(pkg.name,'Writing firmware',completed,{sha256:pkg.sha256});");
  ui.serialEvents.connect({port:ui.appPort});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.elements.get('flash-progress-dialog').open,true);
  assert.equal(ui.elements.get('flash-progress-stage').textContent,'Application startup verified.');
  assert.equal(ui.evaluate('state.flashResult.applicationVerified'),true);
  assert.deepEqual(ui.calls,['application-open','detect','ver','application-close']);
});

test('a later optional-step error does not contradict the same image’s already verified startup in DONE',async()=>{
  const ui=await storageVerificationWorkbench('companion','int:esp32=16384K');ui.context.completed=async()=>{};
  await ui.evaluate("withFlashProgress('exact.bin','Writing firmware',completed,{sha256:expected.sha256});");
  await ui.evaluate("operation(async()=>{await verifyApplication();throw Error('Optional follow-up unavailable');});");
  assert.equal(ui.elements.get('flash-progress-dialog').open,true);assert.equal(ui.elements.get('flash-progress-title').textContent,'DONE — check required');
  assert.match(ui.elements.get('flash-progress-stage').textContent,/startup verified.*later step stopped/);
  assert.match(ui.elements.get('flash-progress-warning').textContent,/Optional follow-up unavailable.*startup was already verified/);
  assert.doesNotMatch(ui.elements.get('flash-progress-warning').textContent,/does not prove application startup/);
  assert.equal(ui.evaluate('state.finishedFirmware.verified'),true);
});

test('T1000-E Bluetooth reminder appears only after the final application succeeds and survives closing DONE',async()=>{
  const ui=workbench();await Promise.resolve();serialMock(ui);ui.context.selectedPort=ui.port;
  ui.context.pkg=fakePackage({name:'t1000e_companion_radio_full-v1.18.0.1-keymind-cascade.zip'});
  ui.evaluate('state.port=selectedPort;state.pkg=pkg;state.plan={generation:state.generation,port:selectedPort,sha256:pkg.sha256};');
  let finish;ui.context.confirm=async()=>true;ui.context.flashNrf=()=>new Promise(resolve=>{finish=resolve;});
  const pending=ui.elements.get('flash').onclick();
  for(let i=0;i<10&&!finish;i++)await Promise.resolve();
  assert.ok(finish);assert.equal(ui.elements.get('flash-progress-advice').hidden,true);assert.equal(ui.elements.get('post-flash-advice').hidden,true);
  assert.match(ui.elements.get('flash-progress-warning').textContent,/Do not unplug/);
  finish();await pending;
  assert.equal(ui.elements.get('flash-progress-dialog').scrollTop,0);
  for(const id of ['flash-progress-advice','post-flash-advice']){assert.equal(ui.elements.get(id).hidden,false);assert.match(ui.elements.get(id).textContent,/Finish any USB verification, then unplug USB/);}
  assert.ok(ui.evaluate('state.verification.completionAdvice'));assert.match(ui.elements.get('log').textContent,/Bluetooth \(BLE\) stays off/);
  ui.elements.get('flash-progress-close').onclick();assert.equal(ui.elements.get('post-flash-advice').hidden,false);
  ui.evaluate('state.finishedFirmware={...state.finishedFirmware,verified:true};clearVerification();controls();');assert.equal(ui.elements.get('post-flash-advice').hidden,false);
  ui.evaluate('state.finishedFirmware=null;controls();');assert.equal(ui.elements.get('post-flash-advice').hidden,true);
  assert.deepEqual(ui.calls,['open','close']);
});

test('T1000-E completion advice is absent on failed writes and during the erase stage',async()=>{
  for(const scenario of ['failed','erase','bootloader']){
    const ui=workbench();await Promise.resolve();serialMock(ui);ui.context.selectedPort=ui.port;
    ui.context.pkg=fakePackage({name:'t1000e_companion_radio_full-v1.18.0.1-keymind-cascade.zip',...(scenario==='bootloader'?{kind:'bootloader',destructive:true}:{})});
    ui.evaluate('state.port=selectedPort;state.pkg=pkg;state.plan={generation:state.generation,port:selectedPort,sha256:pkg.sha256};');
    if(scenario==='erase'){ui.context.erase=fakePackage({name:'erase.zip',erase:true});ui.evaluate('state.plan.erasePkg=erase;');}
    ui.context.confirm=async()=>true;ui.context.flashNrf=async()=>{if(scenario==='failed')throw Error('Transfer interrupted');};await ui.elements.get('flash').onclick();
    assert.equal(ui.elements.get('flash-progress-advice').hidden,true,scenario);assert.equal(ui.elements.get('post-flash-advice').hidden,true,scenario);
    assert.doesNotMatch(ui.elements.get('log').textContent,/then unplug USB/,scenario);assert.deepEqual(ui.calls,['open','close'],scenario);
  }
});

test('a returning startup reminder retains Bluetooth advice without changing ports or settings',async()=>{
  const completionAdvice=postFlashBleAdvice(fakePackage({name:'t1000e_companion_radio_ble-v1.18.0.1-keymind-cascade.zip'}));
  const ui=workbench({verification:{sha256:'a'.repeat(64),architecture:'nrf52',completionAdvice}});await Promise.resolve();
  assert.equal(ui.elements.get('post-flash-advice').textContent,completionAdvice);assert.equal(ui.elements.get('post-flash-advice').hidden,false);assert.deepEqual(ui.calls,[]);
  ui.context.completed=async()=>{};await ui.evaluate("withFlashProgress('new-device.bin','Writing firmware',completed);");
  assert.equal(ui.elements.get('flash-progress-advice').hidden,true);
});

test('same-device and flash confirmations use enabled action buttons without typing',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.evaluate('state.port=selectedPort;');let close;
  ui.elements.get('confirm-dialog').addEventListener=(type,handler)=>{assert.equal(type,'close');close=handler;};
  const same=ui.evaluate("confirm('Confirm bootloader handoff','XIAO','Confirm the same radio.','SAME DEVICE');");
  assert.equal(ui.elements.has('confirm-token'),false);assert.equal(ui.elements.get('confirm-submit').disabled,false);assert.equal(ui.elements.get('confirm-submit').textContent,'Yes, this is the same radio');
  ui.elements.get('confirm-dialog').returnValue='confirm';close();assert.equal(await same,true);assert.deepEqual(ui.calls,[]);
  const flash=ui.evaluate("confirm('Write this firmware?','Exact image','Flash warning','FLASH');");
  assert.equal(ui.elements.get('confirm-submit').disabled,false);assert.equal(ui.elements.get('confirm-submit').textContent,'Flash firmware');assert.equal(ui.elements.get('confirm-warning').textContent,'Flash warning');
  ui.elements.get('confirm-dialog').returnValue='confirm';close();assert.equal(await flash,true);assert.deepEqual(ui.calls,[]);
});

test('same-radio button confirmation rejects cancel, Escape and a disconnected or replaced interface',async()=>{
  for(const action of ['cancel','escape','disconnect','replace','generation']){
    const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.evaluate('state.port=selectedPort;');let close;
    ui.elements.get('confirm-dialog').addEventListener=(_type,handler)=>{close=handler;};
    const pending=ui.evaluate("confirm('Confirm bootloader handoff','XIAO','Same radio','SAME DEVICE');");
    ui.elements.get('confirm-dialog').returnValue=action==='cancel'?'cancel':action==='escape'?'':'confirm';
    if(action==='disconnect')ui.serialEvents.disconnect({port:ui.port});
    if(action==='replace')ui.evaluate('state.port={getInfo:()=>({})};');
    if(action==='generation')ui.evaluate('state.generation++;');
    close();assert.equal(await pending,false,action);assert.deepEqual(ui.calls,[],action);
  }
});

test('all confirmation kinds have clear buttons without exposing internal action codes as commands',async()=>{
  const cases=[['FLASH','Flash firmware'],['WIPE WITHOUT BACKUP','Erase & flash without backup'],['CONTINUE WITHOUT BACKUP','Continue without backup'],['CUSTOM ERASE','Use custom erase utility'],['ENTER BOOTLOADER','Enter USB bootloader'],['BINARY MODE','Enable binary USB mode'],['FORCE CHIP REVISION','Flash despite revision mismatch'],['RETRY IN CHUNKS','Retry write in chunks'],['EXPAND AND FLASH','Expand & flash firmware'],['EXPAND PARTITIONS','Expand partitions'],['DISCARD RETRY STATE','Discard retry record'],['WRITE 0x1000','Write at 0x1000'],['RECOVERY gat562','Install recovery bridge'],['RESTORE abcdef12','Restore settings'],['unknown-to-rak4631','Override board mismatch'],['constructor','Confirm operation']];
  for(const [action,label] of cases){
    const ui=workbench();await Promise.resolve();let close;ui.elements.get('confirm-dialog').addEventListener=(_type,handler)=>{close=handler;};ui.context.action=action;
    const pending=ui.evaluate("confirm('Review operation','Exact target','Keep this warning',action);");
    assert.equal(ui.elements.get('confirm-submit').disabled,false,action);assert.equal(ui.elements.get('confirm-submit').textContent,label,action);assert.equal(ui.elements.get('confirm-warning').textContent,'Keep this warning');
    ui.elements.get('confirm-dialog').returnValue='cancel';close();assert.equal(await pending,false,action);assert.deepEqual(ui.calls,[]);
  }
  assert.doesNotMatch(source,/confirm-token|token-label|buttonOnly/);
});

test('action-button confirmation rejects cancel, Escape and changed port image plan mode or generation',async()=>{
  for(const action of ['cancel','escape','disconnect','replace','image','plan','mode','generation']){
    const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.evaluate('state.port=selectedPort;');let close;ui.elements.get('confirm-dialog').addEventListener=(_type,handler)=>{close=handler;};
    const pending=ui.evaluate("confirm('Write firmware?','Exact image','Warning','FLASH');");
    ui.elements.get('confirm-dialog').returnValue=action==='cancel'?'cancel':action==='escape'?'':'confirm';
    if(action==='disconnect')ui.serialEvents.disconnect({port:ui.port});
    if(action==='replace')ui.evaluate('state.port={getInfo:()=>({})};');
    if(action==='image')ui.evaluate('state.pkg={sha256:"other"};');
    if(action==='plan')ui.evaluate('state.plan={sha256:"other"};');
    if(action==='mode')ui.evaluate('state.installMode="install";');
    if(action==='generation')ui.evaluate('state.generation++;');
    close();assert.equal(await pending,false,action);assert.deepEqual(ui.calls,[],action);
  }
});

test('component replacement buttons name the actual nRF52 component instead of promising an application erase',async()=>{
  for(const [kind,label] of [['bootloader','Replace bootloader'],['softdevice','Replace SoftDevice'],['softdevice_bootloader','Replace bootloader & SoftDevice']]){
    const ui=workbench();await Promise.resolve();ui.context.pkg=fakePackage({kind,destructive:true});ui.evaluate('state.pkg=pkg;');let close;ui.elements.get('confirm-dialog').addEventListener=(_type,handler)=>{close=handler;};
    const pending=ui.evaluate("confirm('Write this firmware?','Exact component','Component warning','WIPE WITHOUT BACKUP');");assert.equal(ui.elements.get('confirm-submit').textContent,label);ui.elements.get('confirm-dialog').returnValue='cancel';close();assert.equal(await pending,false);assert.deepEqual(ui.calls,[]);
    ui.evaluate('state.plan={erasePkg:{}};');const erase=ui.evaluate("confirm('Write this firmware?','Erase then component','Erase warning','WIPE WITHOUT BACKUP');");assert.equal(ui.elements.get('confirm-submit').textContent,'Erase & flash without backup');ui.elements.get('confirm-dialog').returnValue='cancel';close();assert.equal(await erase,false);
  }
});

test('button confirmations allow explicit portless operations but never approve same-radio without a port',async()=>{
  for(const action of ['FLASH','DISCARD RETRY STATE','SAME DEVICE']){
    const ui=workbench();await Promise.resolve();let close;ui.elements.get('confirm-dialog').addEventListener=(_type,handler)=>{close=handler;};ui.context.action=action;
    const pending=ui.evaluate("confirm('Review operation','Exact target','Warning',action);");ui.elements.get('confirm-dialog').returnValue='confirm';close();assert.equal(await pending,action!=='SAME DEVICE');assert.deepEqual(ui.calls,[]);
  }
});

test('reconnect guidance warns about VM USB capture without promising a timed return or an administrator CLI',()=>{
  assert.match(html,/pause VMs configured for USB auto-capture/);assert.match(html,/do not assume it will be returned after 30 seconds/);assert.match(html,/No administrator CLI command is part of the browser workflow/);assert.match(html,/Never interrupt an active partition-migration bridge/);
});

const v4Item={project:'MeshCore',provider:'MeshCore',hardware:'Heltec v4',architecture:'esp32',role:'repeater',version:'v1.18.0',name:'heltec_v4_repeater-v1.18.0.bin',action:'flash-update',url:'https://example.test/v4.bin'};
const nextHighlight=ui=>[...ui.elements.values()].filter(element=>element.classList.contains('next-action')).map(element=>element.id);

test('optional step 5 stays available without replacing Flash a new device as the main next action',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.evaluate("state.port=selectedPort;state.verification={sha256:'a'.repeat(64)};controls();");
  assert.equal(ui.elements.get('verify-app').disabled,false);assert.deepEqual(nextHighlight(ui),['start-new-radio']);assert.match(ui.elements.get('step-guidance').textContent,/Flash a new device.*optionally verify/);assert.ok(!ui.elements.get('verification-options').open);assert.ok(!ui.elements.get('advanced-options').open);assert.deepEqual(ui.calls,[]);
  ui.evaluate("state.verification=null;state.finishedFirmware={sha256:'a'.repeat(64),verified:true};controls();");assert.equal(ui.elements.get('verify-app').disabled,true);
});

test('verification cannot discard an ESP session or its pending reset proof',async()=>{
  for(const written of [true,false]){
    const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.written=written;ui.context.session={close:async()=>ui.calls.push('unsafe-close')};ui.evaluate("state.port=selectedPort;state.verification={sha256:'a'.repeat(64)};state.esp=session;state.plan={written};controls();");
    assert.equal(ui.elements.get('verify-app').disabled,true);const plan=ui.evaluate('state.plan'),verification=ui.evaluate('state.verification');await assert.rejects(ui.evaluate('verifyApplication();'),/pending ESP32 session\/reset/);assert.equal(ui.evaluate('state.esp'),ui.context.session);assert.equal(ui.evaluate('state.plan'),plan);assert.equal(ui.evaluate('state.verification'),verification);assert.equal(ui.evaluate('state.autoVerifyAttempt'),null);assert.deepEqual(ui.calls,[]);
  }
});

test('step 5 is disabled for known bootloader ports and unfinished recovery flows',async()=>{
  for(const scenario of ['dfu','already-bootloader','migration','recovery','espRecovery']){
    const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.evaluate("state.port=selectedPort;state.verification={sha256:'a'.repeat(64)};");if(scenario==='dfu')ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0044});else if(scenario==='already-bootloader')ui.elements.get('already-bootloader').checked=true;else ui.evaluate(`state.${scenario}={};`);ui.evaluate('controls();');assert.equal(ui.elements.get('verify-app').disabled,true,scenario);await assert.rejects(ui.evaluate('verifyApplication();'),/running application|pending write recovery/);assert.deepEqual(ui.calls,[],scenario);
  }
});

const previousVerification=()=>({sha256:'a'.repeat(64),name:'previous-firmware.bin',architecture:'esp32',publicKey:'11'.repeat(32),model:'Heltec V4.3 OLED',role:'common-cli',version:'v1.18.0.1'});

test('a restored verification reminder makes flashing another device primary; cancellation retains the old workflow',async()=>{
  const expected=previousVerification(),ui=workbench({verification:expected});await Promise.resolve();assert.equal(ui.elements.get('start-new-radio').hidden,false);assert.equal(ui.elements.get('start-new-radio').disabled,false);assert.equal(ui.elements.get('reconnect-title').textContent,'Firmware transferred');
  assert.deepEqual(nextHighlight(ui),['start-new-radio']);assert.equal(ui.elements.get('select-port').classList.contains('secondary'),true);assert.equal(ui.elements.get('select-port').classList.contains('primary'),false);
  ui.context.confirm=async(title,_detail,warning,action)=>{assert.equal(title,'Flash a new device?');assert.match(warning,/startup-unverified/);assert.match(warning,/No radio is reset, erased or written/);assert.equal(action,'START NEW RADIO');return false;};
  await ui.elements.get('start-new-radio').onclick();assert.ok(ui.evaluate('state.verification'));assert.equal(JSON.parse(ui.context.localStorage.getItem('meshfirmware.verifyApplication')).sha256,expected.sha256);assert.equal(ui.evaluate('state.port'),null);assert.deepEqual(ui.calls,[]);
});

test('starting a new radio clears only the startup reminder and old selections without USB actions or a chooser',async()=>{
  const expected=previousVerification(),ui=workbench({verification:expected,productionDefaults:true});await Promise.resolve();ui.context.pkg=fakePackage({architecture:'esp32'});ui.context.selectedPort=ui.port;ui.context.backup={schema:'old-private-backup'};
  ui.evaluate("state.port=selectedPort;state.pkg=pkg;state.device={publicKey:'11'.repeat(32),model:'Old board'};state.backup=backup;state.backupApproved={port:selectedPort};state.knownApplicationPort={port:selectedPort,available:true};state.manualSelections={provider:'Keymind Cascade',hardware:'Old board',role:'repeater'};state.handoff=true;state.installMode='install';state.connectionTrial={port:selectedPort,generation:state.generation};");
  for(const id of ['hardware','role','version','expected-sha','expert-offset','firmware-file','custom-url'])ui.elements.get(id).value='old';ui.elements.get('transport-mode').value='usb_reset';ui.elements.get('already-bootloader').checked=true;ui.elements.get('skip-backup').checked=true;ui.evaluate("progress(1,'Old transfer finished');");
  ui.context.localStorage.setItem('unrelated-backup-record','keep');ui.context.confirm=async()=>true;await ui.elements.get('start-new-radio').onclick();
  for(const field of ['verification','port','pkg','plan','device','backup','backupApproved','knownApplicationPort','autoVerifyAttempt','connectionTrial'])assert.equal(ui.evaluate(`state.${field}`),null,field);
  assert.equal(ui.context.localStorage.getItem('meshfirmware.verifyApplication'),undefined);assert.equal(ui.context.localStorage.getItem('unrelated-backup-record'),'keep');assert.equal(ui.evaluate('state.installMode'),'update');assert.equal(ui.elements.get('transport-mode').value,'auto');assert.equal(ui.elements.get('already-bootloader').checked,false);assert.equal(ui.elements.get('skip-backup').checked,false);assert.equal(ui.elements.get('expected-sha').value,'');assert.equal(ui.elements.get('expert-offset').value,'');assert.equal(ui.evaluate('state.manualSelections.provider'),'Keymind Cascade');assert.equal(ui.evaluate('state.manualSelections.hardware'),undefined);
  assert.equal(ui.elements.get('start-new-radio').hidden,true);assert.equal(ui.elements.get('reconnect-callout').hidden,true);assert.deepEqual(nextHighlight(ui),['select-port']);assert.match(ui.elements.get('notice').textContent,/Ready for a new radio/);assert.match(ui.elements.get('log').textContent,/startup verification was skipped/);assert.deepEqual(ui.calls,[]);
  for(const id of ['firmware-file','custom-url'])assert.equal(ui.elements.get(id).value,'');assert.equal(ui.elements.get('progress').value,0);assert.match(ui.elements.get('progress-label').textContent,/Ready for a new radio/);
});

test('Start a new radio cannot discard active writes, pending resets or recovery records',async()=>{
  for(const field of ['flashProgress','autoVerificationRunning','migrationApproval','migration','recovery','espRecovery','esp','written']){
    const ui=workbench({verification:previousVerification()});await Promise.resolve();const key=ui.context.localStorage.getItem('meshfirmware.verifyApplication');ui.context.field=field;ui.evaluate("if(field==='written')state.plan={written:true};else state[field]=field==='autoVerificationRunning'?true:{};controls();");ui.context.confirm=async()=>assert.fail('Protected flows must stop before prompting');
    assert.equal(ui.elements.get('start-new-radio').disabled,true,field);const protectedState=ui.evaluate(field==='written'?'state.plan':`state.${field}`);await ui.elements.get('start-new-radio').onclick();assert.equal(ui.context.localStorage.getItem('meshfirmware.verifyApplication'),key,field);assert.ok(ui.evaluate('state.verification'));assert.equal(ui.evaluate(field==='written'?'state.plan':`state.${field}`),protectedState,field);assert.deepEqual(ui.calls,[],field);
  }
});

test('changed verification state or storage failure cannot unlock or clear a different radio reminder',async()=>{
  for(const change of ['cancelled-generation','changed-verification','in-place-verification','storage-failure','other-page']){
    const ui=workbench({verification:previousVerification()});await Promise.resolve();const expected=ui.evaluate('state.verification'),stored=ui.context.localStorage.getItem('meshfirmware.verifyApplication');
    ui.context.confirm=async()=>{if(change==='cancelled-generation')ui.evaluate('state.generation++;');if(change==='changed-verification')ui.evaluate("state.verification={sha256:'b'.repeat(64)};");if(change==='in-place-verification')ui.evaluate("state.verification.publicKey='22'.repeat(32);");return true;};
    if(change==='storage-failure')ui.context.localStorage.removeItem=()=>{throw Error('Browser storage unavailable');};
    if(change==='other-page')ui.context.localStorage.setItem('meshfirmware.verifyApplication',JSON.stringify({...previousVerification(),publicKey:'22'.repeat(32)}));
    await ui.elements.get('start-new-radio').onclick();assert.ok(ui.evaluate('state.verification'),change);assert.equal(ui.context.localStorage.getItem('meshfirmware.verifyApplication'),change==='other-page'?JSON.stringify({...previousVerification(),publicKey:'22'.repeat(32)}):stored,change);if(change!=='changed-verification')assert.equal(ui.evaluate('state.verification'),expected,change);assert.deepEqual(ui.calls,[],change);
  }
});

test('restored or cross-tab recovery records cannot be bypassed by starting another radio',async()=>{
  const records=[['meshfirmware.pendingMigration','pending',{sha256:'b'.repeat(64),mac:'11:22:33:44:55:66'}],['meshfirmware.nrfRecovery','recovery',{sha256:'b'.repeat(64),eraseComplete:true}],['meshfirmware.espRecovery','espRecovery',{sha256:'b'.repeat(64),merged:true,attempts:1}]];
  for(const [key,option,record] of records)for(const timing of ['restored','before-confirm','during-confirm']){
    const ui=workbench({verification:previousVerification(),...(timing==='restored'?{[option]:record}:{})});await Promise.resolve();const stored=ui.context.localStorage.getItem('meshfirmware.verifyApplication');
    if(timing==='before-confirm')ui.context.localStorage.setItem(key,JSON.stringify(record));
    ui.context.confirm=async()=>{assert.equal(timing,'during-confirm','Existing recovery must stop before confirmation');ui.context.localStorage.setItem(key,JSON.stringify(record));return true;};
    await ui.elements.get('start-new-radio').onclick();assert.ok(ui.evaluate('state.verification'));assert.equal(ui.context.localStorage.getItem('meshfirmware.verifyApplication'),stored);assert.equal(ui.context.localStorage.getItem(key),JSON.stringify(record));assert.deepEqual(ui.calls,[],`${key} ${timing}`);
  }
});

test('cancelling or invalidating Start a new radio never resumes USB verification or revokes newer approval',async()=>{
  for(const action of ['cancel','changed-approval','busy']){
    const ui=workbench({verification:previousVerification()});await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.newerApproval={revoke:()=>assert.fail('Do not revoke a newer approval')};
    ui.evaluate('state.port=selectedPort;state.knownApplicationPort={port:selectedPort,available:true};');ui.context.requestAutomaticVerification=()=>assert.fail('A browser-only dismissal must not resume USB operations');
    ui.context.confirm=async()=>{assert.notEqual(action,'busy');if(action==='changed-approval')ui.evaluate('state.migrationApproval=newerApproval;');return action!=='cancel';};if(action==='busy')ui.evaluate('state.busy=true;');
    await ui.elements.get('start-new-radio').onclick();assert.ok(ui.evaluate('state.verification'));if(action==='changed-approval')assert.equal(ui.evaluate('state.migrationApproval'),ui.context.newerApproval);if(action==='busy')assert.equal(ui.evaluate('state.busy'),true);assert.deepEqual(ui.calls,[]);
  }
});

test('after starting over, step 1 detects the new radio instead of verifying it against the previous identity',async()=>{
  const ui=workbench({verification:previousVerification(),productionDefaults:true});await Promise.resolve();ui.context.confirm=async()=>true;await ui.elements.get('start-new-radio').onclick();
  ui.context.inventory=[headlessV4Item()];ui.evaluate('state.items=inventory;filterCatalog();');ui.context.SerialLink=class{async open(){ui.calls.push('new-radio-open');}async close(){ui.calls.push('new-radio-close');}async command(command){assert.equal(command,'get usb.mode');return 'usb.mode hardware-cdc-jtag';}};
  ui.context.detectMeshCore=async()=>({model:'Heltec V4.3 OLED',role:'common-cli',publicKey:'22'.repeat(32),version:'v1.18.0.1'});ui.context.verifyApplication=async()=>assert.fail('Do not verify a new radio against the old identity');await ui.elements.get('select-port').onclick();
  assert.equal(ui.evaluate('state.device.publicKey'),'22'.repeat(32));assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.elements.get('hardware').value,'Heltec v4');assert.deepEqual(ui.calls,['chooser','new-radio-open','new-radio-close']);assert.equal(ui.evaluate('state.pkg'),null);
});

async function automaticStartupWorkbench(){
  const ui=workbench();await Promise.resolve();const appPort={getInfo:()=>({usbVendorId:0x303a,usbProductId:0x1001})},dfuPort={getInfo:()=>({usbVendorId:0x2886,usbProductId:0x0044})};
  const device={name:'Known radio',model:'Known application board',role:'common-cli',publicKey:'11'.repeat(32)};
  Object.assign(ui.context,{appPort,dfuPort,knownDevice:device,pkg:fakePackage({name:'board_repeater.zip'})});ui.context.detectMeshCore=async()=>{ui.calls.push('detect');return {...device};};
  ui.context.SerialLink=class{constructor(port){assert.equal(port,appPort,'Never probe a same-VID/PID substitute');}async open(){ui.calls.push('application-open');}async close(){ui.calls.push('application-close');}async command(command){ui.calls.push(command);return 'v1.18.0';}};
  ui.evaluate('state.port=appPort;state.pkg=pkg;');await ui.evaluate('readApplication({});');assert.equal(ui.evaluate('state.knownApplicationPort.port'),appPort);ui.calls.length=0;
  ui.evaluate('state.handoff=true;');ui.serialEvents.disconnect({port:appPort});ui.evaluate('state.port=dfuPort;state.verification={sha256:pkg.sha256,name:pkg.name,architecture:"nrf52",publicKey:knownDevice.publicKey,model:knownDevice.model,role:knownDevice.role};state.handoff=false;');
  return {...ui,appPort,dfuPort,device};
}

test('completion makes another device primary while clearly distinguishing optional verification from verified startup',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.pkg=fakePackage();ui.context.selectedPort={getInfo:()=>({usbVendorId:0x2886,usbProductId:0x0044})};ui.evaluate('state.pkg=pkg;state.port=selectedPort;state.verification={sha256:pkg.sha256};controls();');
  assert.equal(ui.elements.get('reconnect-title').textContent,'Firmware transferred');assert.equal(ui.elements.get('select-port-label').textContent,'Verify previous device (optional)');assert.equal(ui.elements.get('reconnect-callout').hidden,false);assert.match(ui.elements.get('reconnect-detail').textContent,/application USB port.*not DFU\/ROM/);assert.match(ui.elements.get('reconnect-detail').textContent,/optionally.*startup has not been verified/);assert.deepEqual(nextHighlight(ui),['start-new-radio']);assert.equal(ui.elements.get('flasher').classList.contains('reconnect-needed'),false);assert.equal(ui.elements.get('flasher').classList.contains('next-device'),true);assert.equal(ui.elements.get('reconnect-callout').getAttribute('role'),'status');assert.equal(ui.elements.get('reconnect-callout').getAttribute('aria-live'),'polite');
  ui.evaluate('state.verification=null;state.finishedFirmware={sha256:pkg.sha256,verified:true};controls();');assert.equal(ui.elements.get('reconnect-title').textContent,'Firmware verified');assert.equal(ui.elements.get('select-port-label').textContent,'Flash a new device');assert.equal(ui.elements.get('flasher').classList.contains('verification-complete'),true);assert.equal(ui.elements.get('flasher').classList.contains('reconnect-needed'),false);assert.equal(ui.elements.get('select-port').classList.contains('primary'),true);assert.deepEqual(nextHighlight(ui),['select-port']);assert.deepEqual(ui.calls,[]);
});

test('ordinary nRF52 completion and completed ESP32 reset lead to another device, not mandatory verification',async()=>{
  const nrf=workbench();await Promise.resolve();nrf.context.pkg=fakePackage({architecture:'nrf52',kind:'application'});nrf.evaluate('state.pkg=pkg;completeNrfTransfer(pkg);controls();');
  assert.ok(nrf.evaluate('state.verification'));assert.deepEqual(nextHighlight(nrf),['start-new-radio']);assert.match(nrf.elements.get('notice').textContent,/Flash a new device.*optionally/);assert.equal(nrf.elements.get('flasher').classList.contains('reconnect-needed'),false);assert.deepEqual(nrf.calls,[]);
  const esp=workbench({verification:previousVerification()});await Promise.resolve();esp.context.selectedPort=esp.port;esp.context.session={port:esp.port,finish:async()=>esp.calls.push('finish'),close:async()=>esp.calls.push('close')};esp.evaluate('state.port=selectedPort;state.plan={written:true,transportMode:"usb_reset"};state.esp=session;controls();');
  assert.deepEqual(nextHighlight(esp),['finish']);assert.equal(esp.elements.get('start-new-radio').disabled,true);await esp.elements.get('finish').onclick();
  assert.deepEqual(esp.calls,['finish','close']);assert.ok(esp.evaluate('state.verification'));assert.deepEqual(nextHighlight(esp),['start-new-radio']);assert.match(esp.elements.get('notice').textContent,/Flash a new device.*optionally/);assert.equal(esp.elements.get('flasher').classList.contains('next-device'),true);
  assert.match(esp.elements.get('progress-label').textContent,/Reset requested; application startup has not been checked/);assert.doesNotMatch(esp.elements.get('progress-label').textContent,/Reset pending|startup verified/);
});

test('verification remains an explicit alternate path and never chooses or resets another device',async()=>{
  const ui=workbench({verification:previousVerification()});await Promise.resolve();ui.context.selectedPort=ui.port;ui.evaluate('state.port=selectedPort;controls();');
  assert.deepEqual(nextHighlight(ui),['start-new-radio']);assert.equal(ui.elements.get('verify-app').disabled,false);ui.context.verifyApplication=async()=>ui.calls.push('verify-previous-device');await ui.elements.get('verify-app').onclick();
  assert.deepEqual(ui.calls,['verify-previous-device']);assert.ok(ui.evaluate('state.verification'));assert.equal(ui.evaluate('state.port'),ui.port);
});

test('post-transfer guards keep the old image locked but point to another device instead of requiring verification',async()=>{
  const ui=workbench({verification:previousVerification()});await Promise.resolve();assert.match(ui.elements.get('install-mode-hint').textContent,/Use Flash a new device.*optionally verify/);
  await assert.rejects(ui.evaluate('reviewAndFlashSelectedFirmware();'),/Use Flash a new device.*optionally verify/);await assert.rejects(ui.evaluate("setInstallMode('install');"),/Use Flash a new device.*optionally verify/);
  assert.ok(ui.evaluate('state.verification'));assert.equal(ui.evaluate('state.installMode'),'update');assert.deepEqual(ui.calls,[]);
});

test('exact remembered application port automatically verifies once without a chooser, scan, reset or write',async()=>{
  const ui=await automaticStartupWorkbench();ui.serialEvents.connect({port:ui.appPort});ui.serialEvents.connect({port:ui.appPort});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.evaluate('state.finishedFirmware.verified'),true);assert.equal(ui.evaluate('state.port'),ui.appPort);assert.deepEqual(ui.calls,['application-open','detect','ver','application-close']);assert.match(ui.elements.get('notice').textContent,/Previously authorized application port reused/);assert.equal(ui.elements.get('reconnect-title').textContent,'Firmware verified');
  ui.serialEvents.connect({port:ui.appPort});await new Promise(resolve=>setImmediate(resolve));assert.equal(ui.calls.filter(call=>call==='application-open').length,1);
});

test('an application reconnect during a write is remembered but only checked after that operation ends',async()=>{
  const ui=await automaticStartupWorkbench(),expected=ui.evaluate('state.verification');ui.context.expected=expected;ui.evaluate('state.verification=null;');let finish;
  ui.context.activeWrite=async()=>{ui.serialEvents.connect({port:ui.appPort});ui.serialEvents.connect({port:ui.appPort});await new Promise(resolve=>{finish=resolve;});ui.evaluate('state.verification=expected;');};
  const pending=ui.evaluate('operation(activeWrite);');assert.deepEqual(ui.calls,[]);finish();await pending;await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.calls.filter(call=>call==='application-open').length,1);
});

test('a still-connected application port is reused only after the verified ESP write is explicitly started',async()=>{
  const ui=await automaticStartupWorkbench();ui.context.SerialLink.prototype.command=async command=>{ui.calls.push(command);return command==='get storage.layout'?'int:esp32=8192K':'v1.18.0';};
  ui.evaluate('state.knownApplicationPort.available=true;state.port=appPort;state.pkg={...pkg,architecture:"esp32"};state.verification.architecture="esp32";state.plan={written:true,transportMode:"default_reset"};');ui.context.session={port:ui.appPort,finish:async()=>ui.calls.push('finish'),close:async()=>ui.calls.push('esp-close')};ui.evaluate('state.esp=session;requestAutomaticVerification();');assert.deepEqual(ui.calls,[]);
  await ui.elements.get('finish').onclick();await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));assert.equal(ui.calls[0],'finish');assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.evaluate('state.finishedFirmware.verified'),true);assert.ok(ui.calls.includes('get storage.layout'));assert.equal(ui.calls.filter(call=>call==='application-open').length,1);assert.ok(!ui.calls.includes('chooser'));
});

async function storageVerificationWorkbench(role,layout,{verification=null}={}){
  const ui=workbench({verification});await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.expected=verification?ui.evaluate('state.verification'):{sha256:'a'.repeat(64),architecture:'esp32',role,model:'Heltec V4.3 OLED',publicKey:'11'.repeat(32),version:'v1.18.0.1'};
  const reply=command=>{ui.calls.push(command);if(command==='get storage.layout')return layout;if(command==='ver'||command==='version')return 'MeshCore v1.18.0.1';throw Error('Unexpected command '+command);};
  ui.context.detectMeshCore=async()=>({role,model:ui.context.expected.model,publicKey:ui.context.expected.publicKey,protocol:14,version:'v1.18.0.1'});ui.context.SerialLink=class{async open(){ui.calls.push('application-open');}async close(){ui.calls.push('application-close');}async command(command){return reply(command);}};ui.context.MeshCore=class{async cli(command){return reply(command);}};
  ui.evaluate('state.port=selectedPort;state.verification=expected;');return ui;
}

test('startup verification accepts the real firmware equals-sign storage layout on CommonCLI and Companion',async()=>{
  // Esp32StorageLayoutWriter emits "> int:esp32=%luK ext:none; ...".
  for(const role of ['common-cli','companion'])for(const layout of ['> int:esp32=8192K ext:none; app0*@0x10000+3072K,app1@0x310000+3072K','> get storage.layout\r\n> int:esp32=16384K ext:none; nvs@0x9000+20K,app0*@0x10000+6400K,app1@0x650000+6400K,...']){
    const ui=await storageVerificationWorkbench(role,layout);await ui.evaluate('verifyApplication();');ui.evaluate('controls();');assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.evaluate('state.finishedFirmware.verified'),true);assert.match(ui.elements.get('notice').textContent,/Application startup verified.*Storage layout answered/);assert.ok(ui.calls.includes('get storage.layout'));assert.equal(ui.calls.filter(call=>call==='application-open').length,1);assert.equal(ui.elements.get('verify-app').disabled,true);
  }
});

test('startup verification accepts a refined legacy model only for the selected hardware and unchanged public identity',async()=>{
  const key='11'.repeat(32),items=[
    t114MeshtasticItem({hardware:'Seeed Studio Wio Tracker L1 Pro'}),t114MeshtasticItem({hardware:'Seeed WioTracker L1 1W'}),t114MeshtasticItem({hardware:'Seeed Studio Wio Tracker L1 E-Ink'}),
    {...v4Item,hardware:'Seeed Studio SenseCAP Indicator LoRa'},{...v4Item,hardware:'Seeed Studio SenseCAP Indicator ESP-NOW'},
  ];
  const cases=[['Seeed Wio Tracker L1','Seeed Wio Tracker L1 Pro',items[0].hardware],['Seeed Wio Tracker L1','Seeed Wio Tracker L1 1W',items[1].hardware],['Seeed Wio Tracker L1','Seeed Wio Tracker L1 E-Ink',items[2].hardware],['Seeed SenseCAP Indicator','Seeed SenseCAP Indicator LoRa',items[3].hardware],['Seeed SenseCAP Indicator','Seeed SenseCAP Indicator ESP-NOW',items[4].hardware]];
  for(const [model,newModel,hardware] of cases)for(const scenario of ['same-key','missing-key','changed-key','wrong-variant','missing-target']){
    const ui=workbench();await Promise.resolve();ui.context.inventory=items;ui.context.expected={sha256:'a'.repeat(64),architecture:'nrf52',model,hardware:scenario==='missing-target'?null:hardware,publicKey:scenario==='missing-key'?null:key};
    ui.context.actual={model:newModel,publicKey:scenario==='changed-key'?'22'.repeat(32):key};if(scenario==='wrong-variant')ui.context.actual.model=model==='Seeed Wio Tracker L1'?'Heltec T114':'Seeed Wio Tracker L1 Pro';
    ui.evaluate('state.items=inventory;');assert.equal(ui.evaluate('verificationModelMatches(expected,actual);'),scenario==='same-key',`${model} → ${newModel}: ${scenario}`);assert.deepEqual(ui.calls,[]);
  }
  const ui=workbench();await Promise.resolve();ui.context.inventory=items;ui.evaluate('state.items=inventory;');
  assert.equal(ui.evaluate('verificationModelMatches({model:"arbitrary old model",hardware:"Seeed Studio Wio Tracker L1 Pro",publicKey:"11".repeat(32)},{model:"Seeed Wio Tracker L1 Pro",publicKey:"11".repeat(32)});'),false);
});

test('a real startup check accepts new Wio E-Ink reporting after a legacy-model update on the same selected node',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x9667});
  ui.context.inventory=[t114MeshtasticItem({hardware:'Seeed Studio Wio Tracker L1 E-Ink'}),t114MeshtasticItem({hardware:'Seeed Studio Wio Tracker L1 Pro'}),t114MeshtasticItem({hardware:'Seeed WioTracker L1 1W'})];ui.context.pkg=fakePackage();
  ui.context.expected={sha256:ui.context.pkg.sha256,architecture:'nrf52',hardware:'Seeed Studio Wio Tracker L1 E-Ink',model:'Seeed Wio Tracker L1',publicKey:'11'.repeat(32),role:'common-cli',version:'v1.18.0.1'};
  ui.evaluate('state.items=inventory;state.port=selectedPort;state.pkg=pkg;state.verification=expected;');
  ui.context.detectMeshCore=async()=>({model:'Seeed Wio Tracker L1 E-Ink',publicKey:ui.context.expected.publicKey,role:'common-cli',version:'v1.18.0.1'});
  ui.context.SerialLink=class{async open(){ui.calls.push('open');}async close(){ui.calls.push('close');}async command(command){ui.calls.push(command);return command==='ver'?'MeshCore v1.18.0.1':'Unknown command';}};
  await ui.elements.get('verify-app').onclick();assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.evaluate('state.finishedFirmware.verified'),true);assert.match(ui.elements.get('notice').textContent,/Application startup verified/);assert.deepEqual(ui.calls,['open','get bootloader.ver','ver','close']);
});

test('successful startup replaces pre-flash Meshtastic, downgrade and reset-pending messages without changing the selected image',async()=>{
  for(const approvedMigration of [false,true]){
    const ui=await storageVerificationWorkbench('companion','> int:esp32=16384K ext:none; app0*@0x10000+6400K,app1@0x650000+6400K');
    ui.context.pkg=fakePackage({architecture:'esp32',name:'heltec_v4_companion-v1.18.0.1.bin',warnings:['Physical partitions and chip MAC must be checked before writes.']});ui.context.inventory=[{...v4Item,role:'companionFull',version:'v1.18.0.1',name:ui.context.pkg.name}];
    ui.evaluate('state.items=inventory;filterCatalog();state.pkg=pkg;state.item=inventory[0];state.device={firmwareFamily:"meshtastic",version:"2.7.15"};$("artifact").value="0";$("skip-backup").checked=true;updateFirmwareSelectionSummary();refreshFirmwareWarnings();progress(1,"Flash verified. Reset pending; application startup remains unverified.");');
    assert.match(ui.elements.get('automatic-summary').textContent,/Meshtastic is running/);assert.match(ui.elements.get('image-warning').textContent,/before writes/);
    if(approvedMigration)ui.evaluate('state.migrationApproval={phase:"waiting-application"};');
    const generation=ui.evaluate('state.generation');await ui.evaluate('verifyApplication();');
    if(approvedMigration)ui.evaluate('state.migrationApproval=null;');
    ui.evaluate('controls();');
    assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);assert.equal(ui.evaluate('state.generation'),generation);assert.equal(ui.elements.get('artifact').value,'0');
    assert.match(ui.elements.get('progress-label').textContent,/Application startup verified.*Storage layout confirmed/);assert.equal(ui.elements.get('progress').value,1);
    assert.match(ui.elements.get('automatic-summary').textContent,/Installed firmware startup verified/);assert.match(ui.elements.get('automatic-summary').textContent,/v1\.18\.0\.1/);assert.match(ui.elements.get('automatic-summary').textContent,/No further flashing is required/);
    assert.doesNotMatch(ui.elements.get('automatic-summary').textContent,/Meshtastic is running|Nothing is flashed|Prepare update|downgrade/i);assert.equal(ui.elements.get('image-warning').textContent,'');
    for(const id of ['prepare','flash','retry','skip-backup','verify-app'])assert.equal(ui.elements.get(id).disabled,true,id);
    assert.deepEqual(nextHighlight(ui),['select-port']);assert.equal(ui.calls.filter(call=>call==='application-open').length,1);
  }
});

test('completed firmware cannot be prepared or flashed again through stale controls or direct handlers',async()=>{
  for(const scenario of ['verified','component','erase','no-loaded-image']){
    const ui=workbench();await Promise.resolve();ui.context.pkg=fakePackage();ui.context.selectedPort=ui.port;
    ui.evaluate(`state.pkg=pkg;state.port=selectedPort;state.plan={generation:state.generation,port:selectedPort,sha256:pkg.sha256};state.finishedFirmware={sha256:pkg.sha256,verified:${scenario==='verified'||scenario==='no-loaded-image'}};$("skip-backup").checked=true;`);
    if(scenario==='no-loaded-image')ui.evaluate('state.pkg=null;state.plan=null;');
    ui.evaluate('controls();');
    for(const id of ['prepare','flash','retry'])assert.equal(ui.elements.get(id).disabled,true,scenario+': '+id);
    for(const handler of ['prepareSelectedFirmware','flashPreparedFirmware','reviewAndFlashSelectedFirmware'])await assert.rejects(ui.evaluate(handler+'();'),/already (?:verified|been transferred)/,scenario+': '+handler);
    assert.deepEqual(ui.calls,[],scenario);
  }
});

test('a written ESP plan cannot be repeated by bypassing the review handler before its reset',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.pkg=fakePackage({architecture:'esp32'});ui.context.selectedPort=ui.port;
  ui.evaluate('state.pkg=pkg;state.port=selectedPort;state.plan={generation:state.generation,port:state.port,sha256:pkg.sha256,written:true};controls();');
  for(const handler of ['prepareSelectedFirmware','flashPreparedFirmware','reviewAndFlashSelectedFirmware'])await assert.rejects(ui.evaluate(handler+'();'),/already been transferred.*pending reset/);
  assert.equal(ui.elements.get('prepare').disabled,true);assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(ui.calls,[]);
});

test('explicitly loading a new image or selecting another radio clears completion and restores preparation',async()=>{
  for(const next of ['image','port']){
    const ui=workbench();await Promise.resolve();ui.context.pkg=fakePackage({architecture:'esp32',name:'previous.bin'});ui.context.selectedPort=ui.port;
    ui.evaluate('state.pkg=pkg;state.port=selectedPort;state.finishedFirmware={sha256:pkg.sha256,verified:true};progress(1,"Application startup verified.");updateFirmwareSelectionSummary();controls();');
    if(next==='image'){
      ui.context.nextPkg=fakePackage({architecture:'esp32',name:'next.bin',sha256:'c'.repeat(64),warnings:['Review this new image.']});ui.context.inspectFirmware=()=>ui.context.nextPkg;
      await ui.evaluate('loadFirmware(nextPkg.name,new Uint8Array(64));');ui.evaluate('controls();');
      assert.match(ui.elements.get('image-warning').textContent,/Review this new image/);assert.match(ui.elements.get('automatic-summary').textContent,/next\.bin/);assert.match(ui.elements.get('progress-label').textContent,/Image validated locally/);assert.deepEqual(ui.calls,[]);
    }else{
      await ui.elements.get('select-port').onclick();assert.match(ui.elements.get('progress-label').textContent,/New USB port selected/);assert.deepEqual(ui.calls,['chooser']);
    }
    assert.equal(ui.evaluate('state.finishedFirmware'),null);assert.equal(ui.elements.get('prepare').disabled,false);assert.doesNotMatch(ui.elements.get('automatic-summary').textContent,/startup verified|No further flashing is required/i);
  }
});

test('errors and malformed storage replies still retain pending startup verification instead of claiming success',async()=>{
  for(const role of ['common-cli','companion'])for(const layout of ['', 'Unknown command\nextra reply', 'Error: unavailable', 'Error: int:esp32=16384K', 'int:esp32-16384K', 'int:esp32=unknown']){
    const ui=await storageVerificationWorkbench(role,layout);await assert.rejects(ui.evaluate('verifyApplication();'),/storage-layout verification is unavailable or invalid/);ui.evaluate('controls();');assert.equal(ui.evaluate('state.verification'),ui.context.expected);assert.equal(ui.evaluate('state.finishedFirmware'),null);assert.equal(ui.calls.at(-1),'application-close');assert.notEqual(ui.elements.get('reconnect-title').textContent,'Firmware verified');assert.doesNotMatch(ui.elements.get('progress-label').textContent,/startup verified/);
  }
});

test('explicit unsupported storage capability completes ordinary startup without claiming verified layout',async()=>{
  for(const role of ['common-cli','companion'])for(const layout of ['Unknown command','> get storage.layout\r\n> Unknown command\r\n> ']){
    const ui=await storageVerificationWorkbench(role,layout);await ui.evaluate('verifyApplication();');
    assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.evaluate('state.finishedFirmware.verified'),true);assert.equal(ui.evaluate('state.finishedFirmware.layoutVerified'),false);
    assert.match(ui.elements.get('notice').textContent,/not supported.*not verified/);assert.doesNotMatch(ui.elements.get('notice').textContent,/Storage layout answered|Storage layout confirmed/);assert.doesNotMatch(ui.elements.get('progress-label').textContent,/Storage layout confirmed/);
  }
});

test('protocol-14 Companion uses the read-only ver fallback only after an exact unsupported version reply',async()=>{
  const ui=await storageVerificationWorkbench('companion','Unknown command');ui.context.expected.version='v1.18.0';
  ui.context.MeshCore=class{async cli(command){ui.calls.push(command);if(command==='version')return '> version\r\n> Unknown command\r\n> ';if(command==='ver')return 'v1.18.0-81dbae5 (Build: 15-Oct-2026)';if(command==='get storage.layout')return 'Unknown command';throw Error('Unexpected command '+command);}};
  await ui.evaluate('verifyApplication();');assert.equal(ui.evaluate('state.finishedFirmware.verified'),true);assert.equal(ui.evaluate('state.finishedFirmware.layoutVerified'),false);assert.deepEqual(ui.calls,['application-open','version','ver','get storage.layout','application-close']);
});

test('stale version replies stop before any fallback, layout query or settings write',async()=>{
  for(const phase of ['version','ver'])for(const change of ['port','generation','verification','cleared-verification']){
    const ui=await storageVerificationWorkbench('companion','int:esp32=8192K');ui.context.applyQueuedRadioSettings=async()=>ui.calls.push('settings-write');
    ui.context.MeshCore=class{async cli(command){
      ui.calls.push(command);
      if(command===phase){
        await Promise.resolve();
        ui.evaluate({port:'state.port={getInfo:()=>({usbVendorId:0x303a,usbProductId:0x1001})};',generation:'state.generation++;',verification:'state.verification={...expected};','cleared-verification':'state.verification=null;'}[change]);
      }
      if(command==='version')return 'Unknown command';if(command==='ver')return 'v1.18.0.1';throw Error('Unexpected command '+command);
    }};
    await assert.rejects(ui.evaluate('verifyApplication();'),/Application port changed during verification/);
    assert.equal(ui.evaluate('state.finishedFirmware'),null,`${phase}: ${change}`);
    assert.deepEqual(ui.calls,['application-open','version',...(phase==='ver'?['ver']:[]),'application-close'],`${phase}: ${change}`);
  }
});

test('version fallback never hides I/O, malformed replies, mismatched versions or changed public identity',async()=>{
  for(const fault of ['timeout','io','empty','error','multiline','identity','wrong-fallback','malformed-fallback','unknown-expected']){
    const ui=await storageVerificationWorkbench('companion','int:esp32=8192K');ui.context.applyQueuedRadioSettings=async()=>ui.calls.push('settings-write');
    if(fault==='identity')ui.context.detectMeshCore=async()=>({role:'companion',model:ui.context.expected.model,publicKey:'22'.repeat(32),protocol:14});
    if(fault==='unknown-expected')ui.context.expected.version=null;
    ui.context.MeshCore=class{async cli(command){ui.calls.push(command);if(command==='version'){if(fault==='timeout')throw Error('Timed out waiting for version');if(fault==='io')throw new DOMException('Access denied','NotAllowedError');return {empty:'',error:'Error: unknown command',multiline:'Unknown command\nMeshCore v1.18.0.1'}[fault]??'Unknown command';}if(command==='ver')return fault==='malformed-fallback'?'Error: v1.18.0.1':'v1.17.1 (Build: 09-Oct-2026)';throw Error('Unexpected command '+command);}};
    await assert.rejects(ui.evaluate('verifyApplication();'),/identity differs|version does not match|Timed out|Access denied/);assert.ok(ui.evaluate('state.verification'));assert.equal(ui.evaluate('state.finishedFirmware'),null);assert.ok(!ui.calls.includes('settings-write'));assert.ok(!ui.calls.includes('get storage.layout'));
    assert.equal(ui.calls.includes('ver'),['wrong-fallback','malformed-fallback','unknown-expected'].includes(fault),fault);if(fault==='identity')assert.deepEqual(ui.calls,['application-open','application-close']);
  }
});

test('storage proof is required before settings writes for migration reminders and legacy Companion',async()=>{
  for(const protocol of [13,14])for(const requiredBy of ['persisted','approval']){
    const ui=await storageVerificationWorkbench('companion','Unknown command');ui.context.detectMeshCore=async()=>({role:'companion',model:ui.context.expected.model,publicKey:ui.context.expected.publicKey,protocol,version:'v1.18.0.1'});ui.context.applyQueuedRadioSettings=async()=>ui.calls.push('settings-write');
    ui.evaluate(requiredBy==='persisted'?'state.verification.requiresStorageLayout=true;':'state.migrationApproval={phase:"waiting-application"};');
    await assert.rejects(ui.evaluate('verifyApplication();'),/storage-layout verification is unavailable or invalid/);assert.ok(ui.evaluate('state.verification'));assert.equal(ui.evaluate('state.finishedFirmware'),null);assert.ok(!ui.calls.includes('settings-write'));assert.equal(ui.calls.includes('get storage.layout'),protocol===14);
  }
  for(const failure of ['Timed out waiting for storage','Storage I/O failed']){
    const ui=await storageVerificationWorkbench('companion','');ui.context.MeshCore=class{async cli(command){ui.calls.push(command);if(command==='version')return 'v1.18.0.1';throw Error(failure);}};
    await assert.rejects(ui.evaluate('verifyApplication();'),new RegExp(failure));assert.ok(ui.evaluate('state.verification'));assert.equal(ui.evaluate('state.finishedFirmware'),null);
  }
});

test('migration storage requirements are persisted from every proof source and survive a page reload',async()=>{
  for(const source of ['migration','approval','needed-plan','verified-plan','captured-option','ordinary']){
    const ui=await storageVerificationWorkbench('companion','');ui.context.pkg=fakePackage({architecture:'esp32',name:'heltec_v4_companion-v1.18.0.1.bin'});ui.evaluate('state.device={model:expected.model,publicKey:expected.publicKey};');
    if(source==='migration')ui.evaluate('state.migration={};');if(source==='approval')ui.evaluate('state.migrationApproval={};');if(source==='needed-plan')ui.evaluate('state.plan={needed:true};');if(source==='verified-plan')ui.evaluate('state.plan={verified:true};');
    ui.evaluate(`queueVerification(pkg,{requiresStorageLayout:${source==='captured-option'}});`);const saved=JSON.parse(ui.context.localStorage.getItem('meshfirmware.verifyApplication'));assert.equal(saved.requiresStorageLayout,source==='ordinary'?undefined:true,source);
    if(source==='ordinary')continue;
    const fresh=await storageVerificationWorkbench('companion','Unknown command',{verification:saved});assert.equal(fresh.evaluate('state.verification.requiresStorageLayout'),true);assert.equal(fresh.evaluate('state.migration'),null);assert.equal(fresh.evaluate('state.migrationApproval'),null);
    await assert.rejects(fresh.evaluate('verifyApplication();'),/storage-layout verification is unavailable or invalid/);assert.ok(fresh.evaluate('state.verification'));assert.equal(fresh.evaluate('state.finishedFirmware'),null);assert.equal(JSON.parse(fresh.context.localStorage.getItem('meshfirmware.verifyApplication')).requiresStorageLayout,true);
  }
});

test('optional bootloader preparation failure does not undo a successful automatic startup check',async()=>{
  const ui=await automaticStartupWorkbench();ui.context.offerBootloaderAfterStartup=async()=>{ui.evaluate('state.finishedFirmware=null;state.pkg=null;');throw Error('Application startup was verified. Separate bootloader preparation failed: download unavailable.');};
  ui.serialEvents.connect({port:ui.appPort});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.evaluate('state.finishedFirmware.verified'),true);assert.equal(ui.evaluate('state.port'),ui.appPort);assert.ok(ui.evaluate('state.device'));assert.match(ui.elements.get('notice').textContent,/Separate bootloader preparation failed/);assert.doesNotMatch(ui.elements.get('notice').textContent,/Automatic startup verification did not complete|Reconnect to verify/);assert.equal(ui.elements.get('reconnect-title').textContent,'Firmware verified');
});

test('ambiguous identity, replacement ports and unfinished or unrelated operations stay on manual verification',async()=>{
  for(const scenario of ['same-id-other-object','unknown-key','changed-key','changed-image','written-esp','migration','erase','retry','new-selection']){
    const ui=await automaticStartupWorkbench();let port=ui.appPort;
    if(scenario==='same-id-other-object')port={getInfo:ui.appPort.getInfo};
    if(scenario==='unknown-key')ui.evaluate('state.verification.publicKey=null;');
    if(scenario==='changed-key')ui.evaluate('state.verification.publicKey="22".repeat(32);');
    if(scenario==='changed-image')ui.evaluate('state.pkg={...pkg,sha256:"b".repeat(64)};');
    if(scenario==='written-esp')ui.evaluate('state.esp={};state.plan={written:true};');
    if(scenario==='migration')ui.evaluate('state.migrationApproval={phase:"bridge-writing"};');
    if(scenario==='erase')ui.evaluate('state.recovery={phase:"final"};');
    if(scenario==='retry')ui.evaluate('state.espRecovery={};');
    if(scenario==='new-selection')ui.evaluate('invalidateApplicationEvidence();');
    ui.serialEvents.connect({port});await new Promise(resolve=>setImmediate(resolve));assert.deepEqual(ui.calls,[],scenario);assert.ok(ui.evaluate('state.verification'),scenario);
  }
});

test('automatic permission, timeout and identity failures stop after one attempt and show the reconnect fallback',async()=>{
  for(const failure of ['permission','timeout','identity']){
    const ui=await automaticStartupWorkbench();if(failure==='identity')ui.context.detectMeshCore=async()=>({...ui.device,publicKey:'22'.repeat(32)});
    else ui.context.SerialLink=class{async open(){ui.calls.push('application-open');throw Error(failure==='permission'?'Access denied':'No response from node');}async close(){ui.calls.push('application-close');}};
    ui.serialEvents.connect({port:ui.appPort});await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));const callCount=ui.calls.length;assert.ok(ui.evaluate('state.verification'));assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.evaluate('state.knownApplicationPort'),null);assert.equal(ui.elements.get('select-port-label').textContent,'Verify previous device (optional)');assert.match(ui.elements.get('notice').textContent,/did not complete/);assert.equal(ui.elements.get('flasher').classList.contains('verification-complete'),false);assert.deepEqual(nextHighlight(ui),['start-new-radio']);
    ui.serialEvents.connect({port:ui.appPort});await new Promise(resolve=>setImmediate(resolve));assert.equal(ui.calls.length,callCount,failure);
  }
});

test('manual verification selection does not show a redundant handoff confirmation',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.pkg=fakePackage();ui.evaluate('state.pkg=pkg;state.handoff=true;state.verification={sha256:pkg.sha256,publicKey:null,name:pkg.name};');let confirmations=0;
  ui.context.confirm=async(title)=>{assert.equal(title,'Confirm application interface');confirmations++;return true;};ui.context.verifyApplication=async()=>ui.calls.push('verify');await ui.elements.get('select-port').onclick();assert.equal(confirmations,1);assert.deepEqual(ui.calls,['chooser','verify']);
});

test('next action moves from USB to prepare or skip-backup flash and clears while working',async()=>{
  const ui=workbench();await Promise.resolve();assert.deepEqual(nextHighlight(ui),['select-port']);assert.equal(ui.elements.get('select-port').getAttribute('aria-current'),'step');
  ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage();ui.evaluate("state.port=selectedPort;state.pkg=pkg;controls();");assert.deepEqual(nextHighlight(ui),['prepare']);assert.equal(ui.elements.get('select-port').getAttribute('aria-current'),null);
  ui.elements.get('skip-backup').checked=true;ui.evaluate('controls();');assert.deepEqual(nextHighlight(ui),['flash']);assert.equal(ui.elements.get('flash').disabled,false);
  ui.evaluate('state.plan={generation:state.generation,port:state.port,sha256:pkg.sha256};controls();');assert.deepEqual(nextHighlight(ui),['flash']);
  ui.evaluate('state.busy=true;controls();');assert.deepEqual(nextHighlight(ui),[]);ui.evaluate('state.busy=false;state.port=null;state.plan=null;state.handoff=true;controls();');assert.deepEqual(nextHighlight(ui),['select-port']);
  ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0044});ui.evaluate('state.port=selectedPort;controls();');assert.deepEqual(nextHighlight(ui),['flash']);assert.deepEqual(ui.calls,[]);
});

test('next-action guidance offers another device after transfer but preserves written ESP and migration requirements',async()=>{
  for(const scenario of ['verify-dfu','verify-application','written','uart-settle','automatic-wait','automatic-busy','verified-done','component-done']){
    const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage();ui.evaluate('state.port=selectedPort;state.pkg=pkg;');
    let expected;
    if(scenario==='verify-dfu'){ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0044});ui.evaluate('state.verification={sha256:pkg.sha256};state.plan={sha256:pkg.sha256};');expected='start-new-radio';}
    if(scenario==='verify-application'){ui.evaluate('state.verification={sha256:pkg.sha256};state.plan={sha256:pkg.sha256};');expected='start-new-radio';}
    if(scenario==='written'){ui.evaluate('state.esp={};state.plan={written:true};state.verification={};');expected='finish';}
    if(scenario==='uart-settle'){ui.evaluate('state.migration={uart:true,settled:false,phase:"running"};');expected='wait-migration';}
    if(scenario==='automatic-wait'){ui.evaluate('state.port=null;state.migrationApproval={phase:"waiting-rom"};');expected='select-port';}
    if(scenario==='automatic-busy'){ui.evaluate('state.migrationApproval={phase:"waiting-rom"};');expected=null;}
    if(scenario==='verified-done'){ui.evaluate('state.finishedFirmware={sha256:pkg.sha256,verified:true};');expected='select-port';}
    if(scenario==='component-done'){ui.context.pkg=fakePackage({kind:'bootloader',destructive:true});ui.evaluate('state.pkg=pkg;completeNrfTransfer(pkg);');expected=null;}
    ui.evaluate('controls();');assert.deepEqual(nextHighlight(ui),expected?[expected]:[],scenario);assert.deepEqual(ui.calls,[],scenario);
    if(scenario==='verified-done')assert.match(ui.elements.get('step-guidance').textContent,/startup verified.*Flash a new device/);
  }
});

test('temporary recovery and erase completion direct selection of the next image, never a repeat utility write',async()=>{
  for(const scenario of ['temporary-unknown','temporary-known','erase']){
    const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.port.getInfo=()=>({usbVendorId:0x239a,usbProductId:0x002a});ui.context.inventory=[t114MeshtasticItem({hardware:'Actual physical board',bootloaderInfo:{profile:'physical-board',url:'https://example.test/normal.zip',sha256:'a'.repeat(64),version:'2.4.12'}})];ui.context.pkg=fakePackage({kind:'bootloader',destructive:true,erase:scenario==='erase'});ui.evaluate('state.items=inventory;state.port=selectedPort;state.pkg=pkg;filterCatalog();');
    if(scenario!=='erase'){ui.context.selectedRecovery=()=>({id:'gat562',installedIdentity:'GAT562_DFU'});if(scenario==='temporary-known'){ui.elements.get('hardware').value='Actual physical board';ui.elements.get('bootloader-source').value='https://example.test/normal.zip';}}
    ui.evaluate('completeNrfTransfer(pkg);controls();');if(scenario!=='erase'){assert.deepEqual(nextHighlight(ui),['select-port']);ui.evaluate('state.port=selectedPort;controls();');}
    assert.deepEqual(nextHighlight(ui),[scenario==='erase'?'artifact':scenario==='temporary-known'?'load-bootloader':'hardware']);assert.doesNotMatch(ui.elements.get('step-guidance').textContent,/^Step [34]:/);assert.deepEqual(ui.calls,[]);
  }
});

test('manual firmware, archive and connection prerequisites get one next-action cue without changing selections',async()=>{
  for(const scenario of ['hardware','role','artifact','archive-entry','load-entry','expert-offset','transport-mode']){
    const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.inventory=[v4Item,{...v4Item,hardware:'Other board',role:'companionFull'}];ui.evaluate('state.items=inventory;state.port=selectedPort;filterCatalog();');
    if(scenario==='role'){ui.elements.get('hardware').value='Heltec v4';ui.elements.get('role').options=[{value:''},{value:'repeater'},{value:'companionFull'}];}
    if(scenario==='artifact'){ui.elements.get('hardware').value='Heltec v4';ui.elements.get('role').value='repeater';}
    if(scenario==='archive-entry'||scenario==='load-entry'){ui.evaluate('state.archive=new Uint8Array(64);');ui.elements.get('archive-entry').value=scenario==='load-entry'?'exact.bin':'';}
    if(scenario==='expert-offset'||scenario==='transport-mode'){ui.context.pkg=fakePackage({architecture:'esp32',expert:scenario==='expert-offset'});ui.evaluate('state.pkg=pkg;');if(scenario==='transport-mode'){ui.elements.get('transport-mode').value='auto';ui.port.getInfo=()=>({usbVendorId:0x1234,usbProductId:0x5678});}}
    ui.evaluate('controls();');assert.deepEqual(nextHighlight(ui),[scenario],scenario);assert.deepEqual(ui.calls,[],scenario);assert.equal(ui.evaluate('state.plan'),null,scenario);
  }
});

test('a newly required low-page connection control is revealed and scrolled into view once without focus or clicks',async()=>{
  const ui=workbench();await Promise.resolve();let frame;const scroll=[];
  ui.context.window.innerHeight=800;ui.context.window.innerWidth=1200;ui.context.window.requestAnimationFrame=callback=>{frame=callback;return 1;};ui.context.window.cancelAnimationFrame=()=>{frame=null;};ui.context.window.matchMedia=()=>({matches:true});
  const target=ui.elements.get('transport-mode');target.getBoundingClientRect=()=>({top:1400,bottom:1450,left:50,right:650});target.scrollIntoView=options=>scroll.push(options);target.focus=()=>assert.fail('Guidance must not steal focus');
  ui.context.selectedPort=ui.port;ui.port.getInfo=()=>({usbVendorId:0x1234,usbProductId:0x5678});ui.context.pkg=fakePackage({architecture:'esp32'});target.value='auto';ui.evaluate('state.port=selectedPort;state.pkg=pkg;controls();');
  assert.equal(ui.elements.get('connection-options').open,true);assert.deepEqual(nextHighlight(ui),['transport-mode']);assert.equal(scroll.length,0);frame();assert.deepEqual(scroll,[{block:'center',behavior:'auto'}]);
  frame=null;ui.evaluate('controls();');assert.equal(frame,null);assert.equal(scroll.length,1);assert.deepEqual(ui.calls,[]);
});

test('confirmation and backup-dialog next buttons take over while busy and release their cue on close',async()=>{
  const ui=workbench();await Promise.resolve();ui.evaluate('state.busy=true;controls();');let close;
  ui.elements.get('confirm-dialog').addEventListener=(_type,handler)=>{close=handler;};const confirmation=ui.evaluate("confirm('Flash?','Exact image','Warning','FLASH');");assert.deepEqual(nextHighlight(ui),['confirm-submit']);ui.elements.get('confirm-dialog').returnValue='cancel';close();assert.equal(await confirmation,false);assert.deepEqual(nextHighlight(ui),[]);
  ui.context.document.createElement=()=>uiElement();ui.elements.get('question-dialog').addEventListener=(_type,handler)=>{close=handler;};
  const backup=ui.evaluate("choose('Backup','Private JSON',[['stop','Stop'],['continue','Continue with flashing']],{backupJson:'{}'});");const actions=ui.elements.get('question-actions').options,continuation=actions.find(action=>action.value==='continue');assert.equal(continuation.classList.contains('next-action'),true);assert.equal(actions.find(action=>action.value==='stop').classList.contains('next-action'),false);assert.deepEqual(nextHighlight(ui),[]);
  ui.elements.get('question-dialog').returnValue='stop';close();assert.equal(await backup,'stop');assert.equal(continuation.classList.contains('next-action'),false);assert.equal(ui.evaluate('state.nextActionElement'),null);assert.deepEqual(ui.calls,[]);
});

test('firmware-files link follows exact hardware and role without needing a USB connection or artifact',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.inventory=[{...v4Item,provider:'Keymind Cascade',hardware:'GAT-IoT GAT562 30s',architecture:'nrf52',role:'companionFull',releaseNotes:'SETUP - https://mikecarper.github.io/MeshCore/firmware_picker/?hardware=GAT562_30S_Mesh_Kit'}];
  ui.evaluate('state.items=inventory;filterCatalog();');ui.elements.get('hardware').value='GAT-IoT GAT562 30s';ui.elements.get('role').value='companionFull';ui.evaluate("filterCatalog('role');");
  assert.equal(ui.elements.get('firmware-files').href,'https://mikecarper.github.io/MeshCore/firmware_picker/?s=1.hGAT562_30S_Mesh_Kit.rcompanion#firmware-picker-1-results');assert.equal(ui.elements.get('download-selected-build').hidden,true);assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.evaluate('state.pkg'),null);assert.deepEqual(ui.calls,[]);
});

test('direct selected-build download keeps the exact filename and version and clears when changing boards',async()=>{
  const ui=workbench();await Promise.resolve();
  ui.context.inventory=[{...v4Item,provider:'Keymind Cascade',hardware:'GAT-IoT GAT562 30s',architecture:'nrf52',role:'companionFull',version:'v1.17.0',name:'gat_companion-v1.17.0.zip',url:'https://github.com/mikecarper/MeshCore/releases/download/v1.17.0/gat_companion-v1.17.0.zip',releaseNotes:'SETUP - https://mikecarper.github.io/MeshCore/firmware_picker/?hardware=GAT562_30S_Mesh_Kit'},{...v4Item,provider:'Keymind Cascade',hardware:'Seeed Studio Xiao nRF52 WIO',role:'repeater',releaseNotes:'SETUP - https://mikecarper.github.io/MeshCore/firmware_picker/?hardware=Xiao_nrf52'}];
  ui.evaluate('state.items=inventory;filterCatalog();');ui.elements.get('artifact').value='0';await ui.elements.get('artifact').onchange();
  assert.equal(ui.elements.get('download-selected-build').hidden,false);assert.equal(ui.elements.get('download-selected-build').href,ui.context.inventory[0].url);
  ui.elements.get('artifact').value='';ui.elements.get('hardware').value='Seeed Studio Xiao nRF52 WIO';ui.elements.get('role').value='repeater';ui.evaluate("filterCatalog('role');");
  assert.equal(ui.elements.get('download-selected-build').hidden,true);assert.match(ui.elements.get('firmware-files').href,/s=1\.hXiao_nrf52\.rrepeater/);assert.ok(!ui.elements.get('firmware-files').href.includes('GAT562'));assert.deepEqual(ui.calls,[]);
});

test('stock firmware links stay on the official release and never inherit Keymind board links or node secrets',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.inventory=[{...v4Item,url:'https://github.com/meshcore-dev/MeshCore/releases/download/repeater-v1.17.1/heltec_v4_repeater-v1.17.1.bin'}];
  ui.evaluate('state.items=inventory;state.device={name:"PRIVATE_NODE_NAME",publicKey:"PRIVATE_IDENTITY"};filterCatalog();');ui.elements.get('artifact').value='0';ui.evaluate('updateDownload();');
  assert.equal(ui.elements.get('firmware-files').href,'https://github.com/meshcore-dev/MeshCore/releases/tag/repeater-v1.17.1');assert.equal(ui.elements.get('download-selected-build').href,ui.context.inventory[0].url);assert.ok(!ui.elements.get('firmware-files').href.includes('PRIVATE'));assert.deepEqual(ui.calls,[]);
});
test('provider picker shows Keymind Cascade and stock and restores a saved historical Logging choice',async()=>{
  let resolveCatalog;const catalogPromise=new Promise(resolve=>resolveCatalog=resolve),ui=workbench({catalogPromise});
  ui.context.localStorage.setItem('meshfirmware.selections',JSON.stringify({provider:'Keymind Cascade Logging',hardware:v4Item.hardware,role:v4Item.role,version:v4Item.version}));
  resolveCatalog({items:[v4Item,{...v4Item,provider:'Keymind Cascade'}],warnings:[],generatedAt:'2026-10-27T00:00:00Z'});
  await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(ui.elements.get('provider').options.map(option=>[option.text,option.value]),[['All providers',''],['Custom firmware','Custom'],['Keymind Cascade','Keymind Cascade'],['MeshCore (stock)','MeshCore']]);
  assert.equal(ui.elements.get('provider').value,'Keymind Cascade');assert.equal(ui.elements.get('hardware').value,v4Item.hardware);assert.equal(ui.elements.get('role').value,v4Item.role);assert.equal(ui.elements.get('version').value,v4Item.version);
  assert.equal(JSON.parse(ui.context.localStorage.getItem('meshfirmware.selections')).provider,'Keymind Cascade');assert.deepEqual(ui.calls,[]);
});
test('page defaults to Keymind while a saved explicit stock choice remains available',async()=>{
  for(const saved of [null,{provider:'MeshCore'},'invalid']){
    let resolveCatalog;const catalogPromise=new Promise(resolve=>resolveCatalog=resolve),ui=workbench({catalogPromise});
    if(saved!==null)ui.context.localStorage.setItem('meshfirmware.selections',JSON.stringify(saved));
    resolveCatalog({items:[v4Item,{...v4Item,provider:'Keymind Cascade'}],warnings:[],generatedAt:'2026-10-27T00:00:00Z'});await new Promise(resolve=>setImmediate(resolve));
    assert.equal(ui.elements.get('provider').value,saved?.provider||'Keymind Cascade');assert.deepEqual(ui.calls,[]);
  }
});
test('Keymind defaults to latest after board and role selection, and an explicit older version follows later selections',async()=>{
  const make=(hardware,role,version)=>({...v4Item,provider:'Keymind Cascade',hardware,role,version,name:`${hardware}-${role}-${version}.bin`,url:`https://example.test/${hardware}-${role}-${version}.bin`});
  const items=[make('Board A','repeater','v1.18.0.1'),make('Board A','repeater','v1.18.0.2'),make('Board A','roomServer','v1.18.0.1'),make('Board A','roomServer','v1.18.0.2'),make('Board B','repeater','v1.18.0.2')];
  const ui=workbench({catalogPromise:Promise.resolve(linkedCatalog(items))});await new Promise(resolve=>setImmediate(resolve));
  ui.elements.get('hardware').value='Board A';await ui.elements.get('hardware').onchange();
  ui.elements.get('role').value='repeater';await ui.elements.get('role').onchange();
  assert.equal(ui.elements.get('version').value,'v1.18.0.2');
  ui.elements.get('version').value='v1.18.0.1';await ui.elements.get('version').onchange();
  ui.elements.get('role').value='roomServer';await ui.elements.get('role').onchange();
  assert.equal(ui.elements.get('version').value,'v1.18.0.1');
  assert.equal(ui.elements.get('artifact').options.filter(x=>x.value).length,1);
  ui.elements.get('hardware').value='Board B';await ui.elements.get('hardware').onchange();
  ui.elements.get('role').value='repeater';await ui.elements.get('role').onchange();
  assert.equal(ui.elements.get('version').value,'v1.18.0.1');
  assert.equal(ui.elements.get('artifact').options.filter(x=>x.value).length,0,'an unavailable explicit version must not silently select a new version');
  assert.deepEqual(ui.calls,[]);
});
test('pre-upgrade remembered Keymind selections use the newest version; explicitly saved older choices stay selected',async()=>{
  const old={...v4Item,provider:'Keymind Cascade',version:'v1.18.0.1',name:'old-v1.18.0.1.bin',url:'https://example.test/old.bin'};
  const current={...old,version:'v1.18.0.2',name:'new-v1.18.0.2.bin',url:'https://example.test/new.bin'};
  for(const explicit of [false,true]){
    const saved={provider:old.provider,hardware:old.hardware,role:old.role,version:old.version,...(explicit?{versionExplicit:true}:{})};
    const ui=workbench({savedSelections:saved,catalogPromise:Promise.resolve(linkedCatalog([old,current]))});await new Promise(resolve=>setImmediate(resolve));
    assert.equal(ui.elements.get('version').value,explicit?old.version:current.version);
    assert.deepEqual(ui.calls,[]);
  }
  const pending=workbench({verification:{sha256:'a'.repeat(64),name:'final.bin'},savedSelections:{provider:old.provider,hardware:old.hardware,role:old.role,version:old.version},catalogPromise:Promise.resolve(linkedCatalog([old,current]))});
  await new Promise(resolve=>setImmediate(resolve));assert.equal(pending.elements.get('version').value,old.version,'an unfinished verification retains its version');
});
const linkedT114Item={...v4Item,provider:'Keymind Cascade',hardware:'Heltec T114',architecture:'nrf52',action:'flash',role:'companionFull',version:'v1.18.0.1-halo-keymind',name:'Heltec_t114_companion_radio_full.zip',url:'https://example.test/t114.zip'};
const linkedCatalog=items=>({items,warnings:[],generatedAt:'2026-10-27T00:00:00Z'});

test('normal and hard reloads clear remembered catalog selections before the catalog loads without touching USB',async()=>{
  for(const transferSize of [0,1024]){
    let resolveCatalog;const catalogPromise=new Promise(resolve=>resolveCatalog=resolve),performanceApi={getEntriesByType:kind=>{assert.equal(kind,'navigation');return [{type:'reload',transferSize}];}},ui=workbench({catalogPromise,performanceApi,savedSelections:{provider:'MeshCore',hardware:v4Item.hardware,role:v4Item.role,version:v4Item.version},productionDefaults:true});
    assert.equal(ui.context.localStorage.getItem('meshfirmware.selections'),undefined);
    // An older tab can rewrite the preference while this catalog is loading.
    if(transferSize)ui.context.localStorage.setItem('meshfirmware.selections',JSON.stringify(v4Item));
    resolveCatalog(linkedCatalog([v4Item,{...v4Item,provider:'Keymind Cascade'}]));await new Promise(resolve=>setImmediate(resolve));
    assert.equal(ui.elements.get('provider').value,'Keymind Cascade');for(const id of ['hardware','role','version','artifact'])assert.equal(ui.elements.get(id).value,'',id);assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.evaluate('state.device'),null);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.installMode'),'update');assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(ui.calls,[]);
    const saved=JSON.parse(ui.context.localStorage.getItem('meshfirmware.selections'));assert.equal(saved.provider,'Keymind Cascade');assert.equal(saved.hardware,'');assert.equal(saved.role,'');assert.equal(saved.version,'');
  }
});

test('ordinary navigation, history traversal and unavailable timing APIs retain normal saved-choice behavior',async()=>{
  for(const performanceApi of [undefined,{}, {getEntriesByType:()=>[]},{getEntriesByType:()=>[{type:'navigate'}]},{getEntriesByType:()=>[{type:'back_forward'}]},{getEntriesByType:()=>{throw Error('Timing unavailable');}}]){
    const ui=workbench({performanceApi,savedSelections:{provider:v4Item.provider,hardware:v4Item.hardware,role:v4Item.role,version:v4Item.version},catalogPromise:Promise.resolve(linkedCatalog([v4Item]))});await new Promise(resolve=>setImmediate(resolve));
    for(const id of ['provider','hardware','role','version'])assert.equal(ui.elements.get(id).value,v4Item[id],id);assert.deepEqual(ui.calls,[]);
  }
});

test('reload preserves an explicit shared selection while ignoring unrelated remembered filters',async()=>{
  const search='?'+new URLSearchParams({provider:linkedT114Item.provider,hardware:linkedT114Item.hardware,role:linkedT114Item.role,version:linkedT114Item.version,build:linkedT114Item.name}),ui=workbench({search,performanceApi:{getEntriesByType:()=>[{type:'reload'}]},savedSelections:v4Item,catalogPromise:Promise.resolve(linkedCatalog([v4Item,linkedT114Item]))});await new Promise(resolve=>setImmediate(resolve));
  for(const id of ['provider','hardware','role','version'])assert.equal(ui.elements.get(id).value,linkedT114Item[id],id);assert.equal(ui.elements.get('artifact').value,'1');assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.port'),null);assert.deepEqual(ui.calls,[]);
});

test('reload retains unfinished migration, erase recovery and verification records and their selections',async()=>{
  for(const pending of [{pending:{mac:'aa:bb:cc:dd:ee:ff',sha256:'a'.repeat(64)}},{recovery:{sha256:'a'.repeat(64),name:'final.zip',eraseComplete:true}},{espRecovery:{sha256:'a'.repeat(64),mac:'aa:bb:cc:dd:ee:ff',merged:true}},{verification:{sha256:'a'.repeat(64),name:'final.zip'}}]){
    const ui=workbench({...pending,performanceApi:{getEntriesByType:()=>[{type:'reload'}]},savedSelections:v4Item,catalogPromise:Promise.resolve(linkedCatalog([v4Item]))});
    const keys=['meshfirmware.pendingMigration','meshfirmware.nrfRecovery','meshfirmware.espRecovery','meshfirmware.verifyApplication'],before=keys.map(key=>ui.context.localStorage.getItem(key));await new Promise(resolve=>setImmediate(resolve));assert.deepEqual(keys.map(key=>ui.context.localStorage.getItem(key)),before);assert.ok(ui.evaluate('continuingDeviceFlow()'));assert.equal(ui.elements.get('hardware').value,v4Item.hardware);assert.equal(ui.evaluate('state.migrationApproval'),null);assert.equal(ui.evaluate('state.port'),null);assert.deepEqual(ui.calls,[]);
  }
});

test('a late catalog after reload keeps a newly detected board instead of restoring the old selection',async()=>{
  let resolveCatalog;const catalogPromise=new Promise(resolve=>resolveCatalog=resolve),ui=workbench({catalogPromise,productionDefaults:true,performanceApi:{getEntriesByType:()=>[{type:'reload'}]},savedSelections:v4Item});
  ui.context.selectedPort=ui.port;ui.context.inventory=[v4Item,linkedT114Item];ui.evaluate("state.items=inventory;state.port=selectedPort;state.device={model:'Heltec T114',role:'companion',version:'v1.18.0.1'};state.boardDetected=true;filterCatalog();selectDetectedBoard();");assert.equal(ui.elements.get('hardware').value,'Heltec T114');
  resolveCatalog(linkedCatalog(ui.context.inventory));await new Promise(resolve=>setImmediate(resolve));assert.equal(ui.elements.get('hardware').value,'Heltec T114');assert.equal(ui.elements.get('artifact').value,'1');assert.equal(ui.evaluate('state.port'),ui.port);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,[]);
});

test('shared URL applies exact catalog filters and build after loading, overriding saved choices without USB or downloads',async()=>{
  let resolveCatalog;const catalogPromise=new Promise(resolve=>resolveCatalog=resolve);
  const search='?'+new URLSearchParams({...Object.fromEntries(['provider','hardware','role','version'].map(id=>[id,linkedT114Item[id]])),mode:'update',build:linkedT114Item.name});
  const ui=workbench({catalogPromise,search,productionDefaults:true});
  ui.context.localStorage.setItem('meshfirmware.selections',JSON.stringify({provider:v4Item.provider,hardware:v4Item.hardware,role:v4Item.role,version:v4Item.version}));
  assert.equal(ui.elements.get('artifact').value,'');resolveCatalog(linkedCatalog([v4Item,linkedT114Item]));await new Promise(resolve=>setImmediate(resolve));
  for(const id of ['provider','hardware','role','version'])assert.equal(ui.elements.get(id).value,linkedT114Item[id],id);
  assert.equal(ui.elements.get('artifact').value,'1');assert.equal(ui.elements.get('download-selected-build').href,linkedT114Item.url);
  assert.equal(ui.elements.get('firmware-choices').open,true);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(ui.calls,[]);
});

test('partial shared filters clear unrelated saved hardware role and version',async()=>{
  let resolveCatalog;const catalogPromise=new Promise(resolve=>resolveCatalog=resolve),ui=workbench({catalogPromise,search:'?hardware=Heltec+T114&role=companionFull'});
  ui.context.localStorage.setItem('meshfirmware.selections',JSON.stringify(v4Item));
  resolveCatalog(linkedCatalog([v4Item,linkedT114Item]));await new Promise(resolve=>setImmediate(resolve));
  assert.equal(ui.elements.get('provider').value,'Keymind Cascade');assert.equal(ui.elements.get('hardware').value,'Heltec T114');assert.equal(ui.elements.get('role').value,'companionFull');assert.equal(ui.elements.get('version').value,'');assert.equal(ui.elements.get('artifact').value,'');assert.deepEqual(ui.calls,[]);
});

test('URL mode filters builds, and an exact filename must match one visible artifact',async()=>{
  const merged=mergedItem(v4Item);
  for(const [mode,build,expected] of [['install',merged.name,'1'],['update',merged.name,''],['update',v4Item.name,'0']]){
    const search='?'+new URLSearchParams({provider:'MeshCore',hardware:v4Item.hardware,role:v4Item.role,mode,build});
    const ui=workbench({search,catalogPromise:Promise.resolve(linkedCatalog([v4Item,merged]))});await new Promise(resolve=>setImmediate(resolve));
    assert.equal(ui.evaluate('state.installMode'),mode);assert.equal(ui.elements.get('artifact').value,expected);assert.equal(ui.elements.get('install-mode-install').checked,mode==='install');assert.equal(ui.evaluate('state.pkg'),null);assert.deepEqual(ui.calls,[]);
  }
  const ui=workbench({search:'?build='+encodeURIComponent(linkedT114Item.name),catalogPromise:Promise.resolve(linkedCatalog([linkedT114Item,{...linkedT114Item,url:'https://example.test/duplicate.zip'}]))});await new Promise(resolve=>setImmediate(resolve));
  assert.equal(ui.elements.get('artifact').value,'');assert.deepEqual(ui.calls,[]);
});

test('invalid and duplicate URL values are ignored and unavailable filters cannot select a build',async()=>{
  for(const search of ['?hardware=missing&build='+linkedT114Item.name,'?build=missing.zip','?mode=wipe&hardware=a&hardware=b&role=%00&version='+ 'x'.repeat(513)]){
    const ui=workbench({search,catalogPromise:Promise.resolve(linkedCatalog([linkedT114Item]))});await new Promise(resolve=>setImmediate(resolve));
    assert.equal(ui.evaluate('state.installMode'),'update');assert.equal(ui.elements.get('artifact').value,'');assert.equal(ui.evaluate('state.pkg'),null);assert.deepEqual(ui.calls,[]);
  }
});

test('URL selections preserve pending recovery migration and startup verification records',async()=>{
  for(const pending of [{pending:{mac:'aa:bb:cc:dd:ee:ff',sha256:'a'.repeat(64)}},{recovery:{sha256:'a'.repeat(64)}},{espRecovery:{sha256:'a'.repeat(64),merged:true}},{verification:previousVerification()}]){
    const ui=workbench({...pending,search:'?hardware=Heltec+T114&role=companionFull&mode=install&build='+linkedT114Item.name,catalogPromise:Promise.resolve(linkedCatalog([linkedT114Item]))});
    await new Promise(resolve=>setImmediate(resolve));
    assert.equal(ui.elements.get('hardware').value,'');assert.equal(ui.elements.get('artifact').value,'');assert.equal(ui.evaluate('state.installMode'),pending.recovery||pending.espRecovery?'install':'update');assert.deepEqual(ui.calls,[]);
  }
});

test('Copy selection link works for any catalog hardware without USB and keeps unselected build/version filters unpinned',async()=>{
  const rows=[linkedT114Item,v4Item,{...linkedT114Item,hardware:'RAK WisBlock / WisMesh (RAK 4631)',name:'RAK_companion.zip'}],ui=workbench({catalogPromise:Promise.resolve(linkedCatalog(rows))});await new Promise(resolve=>setImmediate(resolve));
  assert.equal(ui.elements.get('copy-selection-link').disabled,true);delete ui.context.navigator.serial;
  for(const item of rows){
    ui.elements.get('provider').value=item.provider;ui.evaluate("filterCatalog('provider');");ui.elements.get('hardware').value=item.hardware;ui.evaluate("filterCatalog('hardware');");ui.elements.get('role').value=item.role;ui.elements.get('version').value='';ui.elements.get('artifact').value='';ui.evaluate('updateDownload();controls();');
    assert.equal(ui.elements.get('copy-selection-link').disabled,false,item.hardware);await ui.elements.get('copy-selection-link').onclick();const url=new URL(ui.elements.get('selection-link-text').value);assert.equal(url.origin,'https://mikecarper.github.io');assert.equal(url.pathname,'/meshfirmware/');assert.equal(url.searchParams.get('hardware'),item.hardware);assert.equal(url.searchParams.get('role'),item.role);assert.equal(url.searchParams.has('version'),false);assert.equal(url.searchParams.has('build'),false);assert.equal(url.hash,'#firmware-choices');assert.equal(ui.elements.get('selection-link-fallback').hidden,false);
  }
  assert.deepEqual(ui.calls,[]);assert.equal(ui.evaluate('state.port'),null);
});

test('copying a selected catalog build pins its exact public item and follows installation-mode changes',async()=>{
  const item={...linkedT114Item,provider:'MeshCore'},ui=workbench({catalogPromise:Promise.resolve(linkedCatalog([item]))});await new Promise(resolve=>setImmediate(resolve));const copied=[];ui.context.navigator.clipboard={writeText:async value=>copied.push(value)};
  ui.elements.get('provider').value='';ui.elements.get('hardware').value='';ui.elements.get('role').value='';ui.elements.get('version').value='';ui.elements.get('artifact').value='0';ui.evaluate('updateDownload();');
  await ui.elements.get('copy-selection-link').onclick();let url=new URL(copied[0]);for(const key of ['provider','hardware','role','version'])assert.equal(url.searchParams.get(key),item[key],key);assert.equal(url.searchParams.get('build'),item.name);assert.equal(url.searchParams.get('mode'),'update');assert.equal(ui.elements.get('copy-selection-link').textContent,'Link copied');assert.match(ui.elements.get('selection-link-status').textContent,/Link copied/);
  await ui.evaluate("setInstallMode('install');");assert.equal(ui.elements.get('selection-link-status').textContent,'');assert.equal(ui.elements.get('copy-selection-link').textContent,'Copy selection link');ui.elements.get('artifact').value='0';ui.evaluate('updateDownload();');await ui.elements.get('copy-selection-link').onclick();url=new URL(copied[1]);assert.equal(url.searchParams.get('mode'),'install');assert.equal(url.searchParams.get('build'),item.name);ui.evaluate('clearTimeout(state.selectionCopyTimer);');assert.deepEqual(ui.calls,[]);
});

test('denied clipboard access shows a selectable public URL without exposing errors or altering flash approval',async()=>{
  const ui=workbench({catalogPromise:Promise.resolve(linkedCatalog([linkedT114Item]))});await new Promise(resolve=>setImmediate(resolve));ui.elements.get('hardware').value=linkedT114Item.hardware;ui.evaluate('updateDownload();');
  ui.context.navigator.clipboard={writeText:async()=>{throw Error('PRIVATE_CLIPBOARD_DETAILS');}};let selected=0;ui.elements.get('selection-link-text').focus=()=>selected++;ui.elements.get('selection-link-text').select=()=>selected++;
  ui.evaluate('state.backupApproved={sha256:"private-approval"};state.plan={sha256:"ready-plan"};state.migrationApproval={phase:"ready",privateKey:"PRIVATE"};');const before=ui.evaluate('JSON.stringify([state.backupApproved,state.plan,state.migrationApproval])');
  await ui.elements.get('copy-selection-link').onclick();assert.equal(ui.elements.get('selection-link-fallback').hidden,false);assert.equal(selected,2);assert.match(ui.elements.get('selection-link-status').textContent,/Copy the link below/);assert.doesNotMatch(ui.elements.get('selection-link-status').textContent,/PRIVATE/);assert.equal(ui.evaluate('JSON.stringify([state.backupApproved,state.plan,state.migrationApproval])'),before);assert.deepEqual(ui.calls,[]);
});

test('selection changes while clipboard permission is pending cannot claim the newer link was copied',async()=>{
  for(const reject of [false,true]){
    const ui=workbench({catalogPromise:Promise.resolve(linkedCatalog([linkedT114Item,v4Item]))});await new Promise(resolve=>setImmediate(resolve));ui.elements.get('hardware').value=linkedT114Item.hardware;ui.elements.get('provider').value='';ui.evaluate('updateDownload();');let finish;const written=[];ui.context.navigator.clipboard={writeText:value=>{written.push(value);return new Promise((resolve,fail)=>{finish=reject?()=>fail(Error('denied')):resolve;});}};
    const pending=ui.elements.get('copy-selection-link').onclick();ui.elements.get('hardware').value=v4Item.hardware;ui.evaluate('updateDownload();');finish();await pending;assert.equal(new URL(written[0]).searchParams.get('hardware'),linkedT114Item.hardware);assert.equal(ui.elements.get('copy-selection-link').textContent,'Copy selection link');assert.equal(ui.elements.get('selection-link-status').textContent,'');assert.equal(ui.elements.get('selection-link-fallback').hidden,true);assert.equal(new URL(ui.elements.get('selection-link-text').value).searchParams.get('hardware'),v4Item.hardware);assert.deepEqual(ui.calls,[]);
  }
});

test('local firmware and private page/device state never become share-link fields and inconsistent artifacts stay disabled',async()=>{
  const ui=workbench({search:'?private=PRIVATE_QUERY',catalogPromise:Promise.resolve(linkedCatalog([linkedT114Item,v4Item]))});await new Promise(resolve=>setImmediate(resolve));ui.elements.get('hardware').value=linkedT114Item.hardware;ui.elements.get('artifact').value='1';ui.evaluate('updateDownload();');assert.equal(ui.elements.get('copy-selection-link').disabled,true);
  ui.evaluate('state.pkg={name:"C:/private/PRIVATE_LOCAL.zip",url:"https://private.test/secret"};state.item={hardware:"Heltec T114"};state.device={publicKey:"PRIVATE_IDENTITY"};state.backup={json:"PRIVATE_BACKUP"};');ui.elements.get('version').value='';ui.evaluate('updateDownload();');await ui.elements.get('copy-selection-link').onclick();const url=ui.elements.get('selection-link-text').value;assert.ok(url);assert.doesNotMatch(url,/PRIVATE|private\.test|private=|skip|backup|port/);assert.equal(new URL(url).searchParams.has('build'),false);assert.deepEqual(ui.calls,[]);
});

test('a saved or pre-connect explicit stock provider survives connection without keeping the previous board or version',async()=>{
  for(const saved of [false,true]){
    let resolveCatalog;const catalogPromise=new Promise(resolve=>resolveCatalog=resolve),ui=workbench({productionDefaults:true,catalogPromise});serialMock(ui);
    if(saved)ui.context.localStorage.setItem('meshfirmware.selections',JSON.stringify({provider:'MeshCore'}));
    resolveCatalog({items:[v4Item,headlessV4Item()],warnings:[],generatedAt:'2026-10-27T00:00:00Z'});await new Promise(resolve=>setImmediate(resolve));
    if(!saved){ui.elements.get('provider').value='MeshCore';await ui.elements.get('provider').onchange();}
    ui.evaluate("state.manualSelections.hardware='Previous board';state.manualSelections.version='v0.1.0';");
    ui.context.detectMeshCore=async()=>({model:'Heltec V4 OLED',catalogRole:'repeater',version:'v1.14.1'});await ui.elements.get('select-port').onclick();
    assert.equal(ui.elements.get('provider').value,'MeshCore');assert.equal(ui.elements.get('hardware').value,v4Item.hardware);assert.equal(ui.elements.get('version').value,v4Item.version);assert.equal(ui.elements.get('artifact').value,'0');
    assert.equal(ui.evaluate('state.manualSelections.hardware'),undefined);assert.equal(ui.evaluate('state.manualSelections.version'),undefined);assert.deepEqual(ui.calls,['chooser','open','close']);
  }
});

test('production defaults select connected old V4 role, latest update and TinyUSB without downloads or reset',async()=>{
  assert.match(html,/id="auto-detect-board" checked/);assert.match(html,/id="auto-backup"[^>]*checked/);assert.match(html,/id="auto-finish"[^>]*checked/);assert.match(html,/value="auto" selected/);
  const ui=workbench({productionDefaults:true});await Promise.resolve();serialMock(ui);ui.context.inventory=[headlessV4Item({version:'v1.18.0'}),{...v4Item,action:'flash-wipe',name:'merged.bin'},v4Item];ui.evaluate('state.items=inventory;filterCatalog();');ui.port.getInfo=()=>({usbVendorId:0x303a,usbProductId:0x0002});ui.context.detectMeshCore=async()=>({model:'Heltec V4 OLED',role:'common-cli',catalogRole:'repeater',version:'v1.14.1'});
  await ui.elements.get('select-port').onclick();assert.equal(ui.elements.get('hardware').value,'Heltec v4');assert.equal(ui.elements.get('provider').value,'Keymind Cascade');assert.equal(ui.elements.get('role').value,'repeater');assert.equal(ui.elements.get('version').value,'v1.18.0');assert.equal(ui.elements.get('artifact').value,'0');assert.equal(ui.evaluate('connectionMode()'),'tinyusb');assert.equal(ui.evaluate('state.pkg'),null);assert.deepEqual(ui.calls,['chooser','open','close']);assert.equal(ui.elements.get('prepare').disabled,false);assert.equal(ui.elements.get('flash').disabled,true);
});

const headlessV4Item=(more={})=>({...v4Item,provider:'Keymind Cascade',version:'v1.18.0.2-halo-keymind-cascade-dev-eab29a12',name:'heltec_v4_repeater-full-usb-wifi-ota-v1.18.0.2-halo-keymind-cascade-dev-eab29a12.bin',releaseNotes:'EXACT TARGET - heltec_v4_repeater. Match exact hardware.\nSETUP - https://mikecarper.github.io/MeshCore/firmware_picker/?hardware=heltec_v4',...more});

test('connecting a reviewed screenless V4 selects exact hardware and firmware without resetting; unknown connection is tested only during preparation',async()=>{
  for(const model of ['Heltec V4.2 none detected','Heltec V4.3 none detected']){
    const ui=workbench({productionDefaults:true});await Promise.resolve();serialMock(ui);
    const matching=headlessV4Item();ui.context.inventory=[matching,
      headlessV4Item({name:'heltec_v4_tft_repeater-full-logging-ota-v1.18.0.2-halo-keymind-cascade-dev-eab29a12.bin',url:'https://example.test/tft.bin',releaseNotes:'EXACT TARGET - heltec_v4_tft_repeater. Match exact hardware.\nSETUP - https://mikecarper.github.io/MeshCore/firmware_picker/?hardware=heltec_v4_tft'}),
      headlessV4Item({hardware:'Heltec v4 R8',url:'https://example.test/r8.bin'}),
      headlessV4Item({action:'flash-wipe',name:'heltec_v4_repeater-v1.19.0-merged.bin',version:'v1.19.0',url:'https://example.test/merged.bin'})];
    ui.evaluate('state.items=inventory;filterCatalog();');
    ui.context.detectMeshCore=async()=>{ui.calls.push('detect');return {model,name:'MQTT Observer',role:'common-cli',catalogRole:'repeater',version:'v1.18.0.2-halo-keymind-cascade-dev-observer-eab29a12 (Build: 27-Oct-2026)',publicKey:'a'.repeat(64)};};
    assert.deepEqual(ui.calls,[]);await ui.elements.get('select-port').onclick();
    assert.equal(ui.elements.get('hardware').value,'Heltec v4',model);assert.equal(ui.elements.get('provider').value,'Keymind Cascade');assert.equal(ui.elements.get('role').value,'repeater');assert.equal(ui.elements.get('version').value,matching.version);assert.equal(ui.elements.get('artifact').value,'0');
    assert.equal(ui.evaluate('state.device.architecture'),'esp32');assert.match(ui.elements.get('board-detection').textContent,/Selected Heltec v4/);assert.match(ui.elements.get('automatic-summary').textContent,/Write-only update selected/);
    assert.deepEqual(ui.calls,['chooser','open','detect','get usb.mode','close']);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('flash').disabled,true);
    assert.equal(ui.evaluate('state.connection.mode'),null);assert.match(ui.elements.get('connection-summary').textContent,/test the qualified USB methods.*after backup/); // Shared 303a:1001 alone still is not reset-protocol proof.
  }
});

test('connecting an updated V4 automatically selects its firmware-reported hardware USB reset method',async()=>{
  const ui=workbench({productionDefaults:true});await Promise.resolve();serialMock(ui);ui.context.inventory=[headlessV4Item()];ui.evaluate('state.items=inventory;filterCatalog();');
  ui.context.detectMeshCore=async()=>({model:'Heltec V4.2 none detected',name:'Test V4',role:'common-cli',catalogRole:'repeater',version:'v1.18.0.2',publicKey:'11'.repeat(32)});
  ui.context.SerialLink.prototype.command=async command=>{ui.calls.push(command);assert.equal(command,'get usb.mode');return '> usb.mode hardware-cdc-jtag\r\n';};
  await ui.elements.get('select-port').onclick();assert.equal(ui.elements.get('hardware').value,'Heltec v4');assert.equal(ui.elements.get('artifact').value,'0');assert.equal(ui.elements.get('transport-mode').value,'auto');assert.equal(ui.evaluate('state.connection.mode'),'usb_reset');assert.equal(ui.evaluate('state.device.usbMode'),'hardware-cdc-jtag');assert.deepEqual(nextHighlight(ui),['prepare']);assert.deepEqual(ui.calls,['chooser','open','get usb.mode','close']);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.pkg'),null);
});

test('a newer screenless V4 auto-selects the available older catalog build with a downgrade warning',async()=>{
  const ui=workbench({productionDefaults:true});await Promise.resolve();serialMock(ui);
  ui.context.inventory=[headlessV4Item({version:'v1.18.0.1-halo-keymind-cascade-dev-03214a16',name:'heltec_v4_repeater-full-usb-wifi-ota-v1.18.0.1-halo-keymind-cascade-dev-03214a16.bin'})];ui.evaluate('state.items=inventory;filterCatalog();');
  ui.context.detectMeshCore=async()=>({model:'Heltec V4.2 none detected',name:'MQTT Observer',role:'common-cli',catalogRole:'repeater',version:'v1.18.0.2-halo-keymind-cascade-dev-observer-eab29a12 (Build: 27-Oct-2026)'});
  await ui.elements.get('select-port').onclick();
  assert.equal(ui.elements.get('hardware').value,'Heltec v4');assert.equal(ui.elements.get('provider').value,'Keymind Cascade');assert.equal(ui.elements.get('role').value,'repeater');assert.equal(ui.elements.get('artifact').value,'0');assert.match(ui.elements.get('automatic-summary').textContent,/downgrade/i);assert.match(ui.elements.get('automatic-summary').textContent,/v1\.18\.0\.2/);assert.match(ui.elements.get('automatic-summary').textContent,/v1\.18\.0\.1/);assert.match(ui.elements.get('board-detection').textContent,/Selected Heltec v4/);
  assert.deepEqual(ui.calls,['chooser','open','close']);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('flash').disabled,true);
});

test('a headless V4 connected before the catalog arrives is selected automatically without a second USB query',async()=>{
  let resolveCatalog;const catalogPromise=new Promise(resolve=>resolveCatalog=resolve),ui=workbench({productionDefaults:true,catalogPromise});serialMock(ui);
  ui.context.detectMeshCore=async()=>({model:'Heltec V4.3 none detected',role:'common-cli',catalogRole:'repeater',version:'v1.18.0.2-halo-keymind-cascade-dev-observer-eab29a12'});
  await ui.elements.get('select-port').onclick();assert.equal(ui.elements.get('hardware').value,'');
  resolveCatalog({items:[headlessV4Item()],warnings:[],generatedAt:new Date().toISOString()});await new Promise(resolve=>setTimeout(resolve,0));
  assert.equal(ui.elements.get('hardware').value,'Heltec v4');assert.equal(ui.elements.get('provider').value,'Keymind Cascade');assert.equal(ui.elements.get('role').value,'repeater');assert.equal(ui.elements.get('artifact').value,'0');
  assert.equal(ui.evaluate('state.device.architecture'),'esp32');assert.equal(ui.evaluate('state.pkg'),null);assert.deepEqual(ui.calls,['chooser','open','close']);
});

const xiaoRepeaterItem=(more={})=>({...v4Item,provider:'MeshCore',hardware:'Seeed Studio Xiao nRF52 WIO',architecture:'nrf52',version:'v1.18.0.1',name:'Xiao_nrf52_repeater-v1.18.0.1.zip',action:'flash',url:'https://example.test/xiao.zip',...more});
test('a detected board without a Keymind build stays selected without falling back to stock; stock can be chosen explicitly',async()=>{
  const ui=workbench({productionDefaults:true});await Promise.resolve();ui.context.inventory=[headlessV4Item(),xiaoRepeaterItem()];
  ui.evaluate("state.items=inventory;state.device={model:'Seeed Xiao-nrf52',catalogRole:'repeater',version:'v1.17.0'};filterCatalog();selectDetectedBoard();");
  assert.equal(ui.elements.get('hardware').value,'Seeed Studio Xiao nRF52 WIO');assert.equal(ui.elements.get('provider').value,'Keymind Cascade');assert.equal(ui.elements.get('artifact').value,'');assert.match(ui.elements.get('automatic-summary').textContent,/No write-only application update/);assert.equal(ui.elements.get('prepare').disabled,true);
  ui.elements.get('provider').value='MeshCore';await ui.elements.get('provider').onchange();
  assert.equal(ui.elements.get('provider').value,'MeshCore');assert.equal(ui.elements.get('hardware').value,'Seeed Studio Xiao nRF52 WIO');assert.equal(ui.elements.get('artifact').value,'1');assert.deepEqual(ui.calls,[]);
});

test('manual board changes refresh the right-side summary even with automatic setup off',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.inventory=[v4Item,xiaoRepeaterItem({version:'v1.20.0'})];
  ui.evaluate("state.items=inventory;state.device={version:'v1.19.0'};filterCatalog();");
  ui.elements.get('hardware').value='Heltec v4';ui.elements.get('provider').value='MeshCore';ui.elements.get('artifact').value='0';
  ui.elements.get('automatic-summary').textContent=`Old Heltec v4 selection ${v4Item.name}. Downgrade warning from the previous board.`;
  ui.context.pkg=fakePackage({name:v4Item.name,architecture:'esp32'});ui.evaluate('state.pkg=pkg;state.item=inventory[0];state.plan={written:true};');
  ui.elements.get('hardware').value='Seeed Studio Xiao nRF52 WIO';await ui.elements.get('hardware').onchange();
  const summary=ui.elements.get('automatic-summary').textContent;
  assert.equal(ui.elements.get('hardware').value,'Seeed Studio Xiao nRF52 WIO');assert.match(summary,/Seeed Studio Xiao nRF52 WIO/);
  assert.ok(!summary.includes(v4Item.name));assert.doesNotMatch(summary,/Old Heltec|previous board|Downgrade warning/);
  assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(ui.calls,[]);
});

test('manually choosing another artifact replaces the automatic filename and warning summary',async()=>{
  const ui=workbench({productionDefaults:true});await Promise.resolve();
  const base=headlessV4Item({version:'v1.18.0.1',name:'heltec_v4_repeater-v1.18.0.1.bin'}),alternate={...base,name:'heltec_v4_tft_repeater-v1.18.0.1.bin',url:'https://example.test/tft.bin',releaseNotes:'SETUP - https://mikecarper.github.io/MeshCore/firmware_picker/?hardware=heltec_v4_tft'};
  ui.context.inventory=[base,alternate];ui.evaluate("state.items=inventory;state.device={model:'Heltec V4.2 none detected',catalogRole:'repeater',version:'v1.18.0.2-keymind-cascade'};filterCatalog();selectDetectedBoard();");
  assert.equal(ui.elements.get('artifact').value,'0');assert.ok(ui.elements.get('automatic-summary').textContent.includes(base.name));
  ui.context.pkg=fakePackage({name:base.name,architecture:'esp32'});ui.evaluate('state.pkg=pkg;state.item=inventory[0];state.plan={written:true};');
  ui.elements.get('artifact').value='1';await ui.elements.get('artifact').onchange();
  const summary=ui.elements.get('automatic-summary').textContent;
  assert.equal(ui.elements.get('artifact').value,'1');assert.ok(summary.includes(alternate.name));assert.ok(!summary.includes(base.name));assert.match(summary,/downgrade/i);
  assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(ui.calls,[]);
});

test('a fresh USB choice clears previous automatic firmware state before a failed or unknown board probe',async()=>{
  for(const probeResult of ['failure','unknown']){
    const ui=workbench({productionDefaults:true});await Promise.resolve();serialMock(ui);
    ui.context.inventory=[headlessV4Item(),xiaoRepeaterItem()];ui.evaluate("state.items=inventory;state.device={model:'Heltec V4.2 none detected',catalogRole:'repeater',version:'v1.18.0.2-keymind-cascade'};filterCatalog();selectDetectedBoard();");
    ui.context.pkg=fakePackage({name:ui.context.inventory[0].name,architecture:'esp32'});ui.context.oldPort=ui.port;
    ui.evaluate('state.port=oldPort;state.pkg=pkg;state.item=inventory[0];state.plan={written:true};');
    const newPort={getInfo:()=>({usbVendorId:0x2886,usbProductId:0x8044})};ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');return newPort;};
    let beforeProbe;
    ui.context.detectMeshCore=async()=>{
      beforeProbe={filters:Object.fromEntries(['provider','hardware','role','version','artifact'].map(id=>[id,ui.elements.get(id).value])),summary:ui.elements.get('automatic-summary').textContent,pkg:ui.evaluate('state.pkg'),plan:ui.evaluate('state.plan')};
      if(probeResult==='failure')throw Error('Fixture node did not answer');
      return {model:'Unreviewed new bench board',role:'common-cli'};
    };
    await ui.elements.get('select-port').onclick();
    assert.ok(beforeProbe,probeResult);
    for(const [id,value]of Object.entries(beforeProbe.filters))assert.equal(value,'',`${probeResult}: stale ${id} before the new probe`);
    assert.equal(beforeProbe.pkg,null);assert.equal(beforeProbe.plan,null);assert.ok(!beforeProbe.summary.includes(ui.context.inventory[0].name));
    assert.equal(ui.elements.get('hardware').value,'');assert.equal(ui.elements.get('artifact').value,'');assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);
    assert.equal(ui.elements.get('prepare').disabled,true);assert.equal(ui.elements.get('flash').disabled,true);assert.ok(!ui.elements.get('automatic-summary').textContent.includes(ui.context.inventory[0].name));
    assert.deepEqual(ui.calls,['chooser','open','close']);
  }
});

test('detecting again on an unknown model cannot retain a previous automatic board match',async()=>{
  const ui=workbench({productionDefaults:true});await Promise.resolve();serialMock(ui);ui.context.selectedPort=ui.port;ui.context.inventory=[headlessV4Item(),xiaoRepeaterItem()];
  ui.evaluate("state.items=inventory;state.port=selectedPort;state.device={model:'Heltec V4.2 none detected',catalogRole:'repeater',version:'v1.18.0.2-keymind-cascade'};filterCatalog();selectDetectedBoard();");
  assert.equal(ui.elements.get('hardware').value,'Heltec v4');
  ui.context.pkg=fakePackage({name:ui.context.inventory[0].name,architecture:'esp32'});ui.evaluate('state.pkg=pkg;state.item=inventory[0];state.plan={written:true};state.backupApproved={sha256:pkg.sha256,port:selectedPort};');
  ui.context.detectMeshCore=async()=>({model:'Unreviewed replacement board',role:'common-cli'});
  await ui.elements.get('probe').onclick();
  assert.equal(ui.elements.get('hardware').value,'');assert.equal(ui.elements.get('artifact').value,'');assert.equal(ui.evaluate('state.detectedHardware'),null);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.backupApproved'),null);
  assert.ok(!ui.elements.get('automatic-summary').textContent.includes(ui.context.inventory[0].name));assert.doesNotMatch(ui.elements.get('automatic-summary').textContent,/Downgrade warning/);assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(ui.calls,['open','close']);
});

test('a deliberately loaded custom file survives a new unknown or failed probe only as an unapproved manual image',async()=>{
  for(const probeResult of ['failure','unknown']){
    const ui=workbench({productionDefaults:true});await Promise.resolve();serialMock(ui);ui.context.selectedPort=ui.port;ui.context.inventory=[headlessV4Item(),xiaoRepeaterItem()];
    ui.evaluate("state.items=inventory;state.port=selectedPort;state.device={model:'Heltec V4.2 none detected',catalogRole:'repeater'};filterCatalog();selectDetectedBoard();");
    ui.context.pkg=fakePackage({name:'deliberate-custom-v1.18.0.2.zip'});ui.evaluate("state.pkg=pkg;state.item={hardware:'Heltec v4',erase:[],bootloader:[]};state.plan={written:true};state.backupApproved={sha256:pkg.sha256,port:selectedPort};state.backup={filename:'old-radio-backup.json'};");
    const nextPort={getInfo:()=>({usbVendorId:0x2886,usbProductId:0x8044})};ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');return nextPort;};
    ui.context.detectMeshCore=async()=>{if(probeResult==='failure')throw Error('Fixture node did not answer');return {model:'Unreviewed replacement board',role:'common-cli'};};
    await ui.elements.get('select-port').onclick();
    assert.equal(ui.evaluate('state.pkg'),ui.context.pkg,probeResult);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.backupApproved'),null);assert.equal(ui.evaluate('state.backup'),null);
    assert.ok(ui.elements.get('automatic-summary').textContent.includes(ui.context.pkg.name));assert.match(ui.elements.get('automatic-summary').textContent,/manual/i);assert.equal(ui.elements.get('hardware').value,'');assert.equal(ui.elements.get('artifact').value,'');assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(ui.calls,['chooser','open','close']);
  }
});

test('a new DFU radio after a known automatic board disconnect clears that old board without guessing physical hardware',async()=>{
  const ui=workbench({productionDefaults:true});await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.inventory=[headlessV4Item(),xiaoRepeaterItem()];
  ui.evaluate("state.items=inventory;state.port=selectedPort;state.device={model:'Heltec V4.2 none detected',catalogRole:'repeater'};filterCatalog();selectDetectedBoard();");
  ui.context.pkg=fakePackage({name:ui.context.inventory[0].name,architecture:'esp32'});ui.evaluate('state.pkg=pkg;state.item=inventory[0];state.plan={written:true};');
  ui.serialEvents.disconnect({port:ui.port});
  const nextPort={getInfo:()=>({usbVendorId:0x2886,usbProductId:0x0044})};ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');return nextPort;};
  await ui.elements.get('select-port').onclick();
  for(const id of ['hardware','role','version','artifact'])assert.equal(ui.elements.get(id).value,'',id);
  assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.device'),null);assert.ok(!ui.elements.get('automatic-summary').textContent.includes(ui.context.inventory[0].name));assert.match(ui.elements.get('notice').textContent,/without sending/);assert.deepEqual(ui.calls,['chooser']);
});

test('switching connected radios refreshes hardware provider role and artifact for the newly read node',async()=>{
  const ui=workbench({productionDefaults:true});await Promise.resolve();serialMock(ui);
  const first=headlessV4Item(),second=xiaoRepeaterItem({provider:'Keymind Cascade'});ui.context.inventory=[first,second];ui.evaluate('state.items=inventory;filterCatalog();');
  let device={model:'Heltec V4.2 none detected',role:'common-cli',catalogRole:'repeater',version:'v1.18.0.2-keymind-cascade'};
  ui.context.detectMeshCore=async()=>device;await ui.elements.get('select-port').onclick();assert.equal(ui.elements.get('hardware').value,'Heltec v4');assert.equal(ui.elements.get('artifact').value,'0');
  const secondPort={getInfo:()=>({usbVendorId:0x2886,usbProductId:0x8044})};ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');return secondPort;};
  device={model:'Seeed Xiao-nrf52',name:'Second radio',role:'common-cli',catalogRole:'repeater',version:'v1.17.0'};
  await ui.elements.get('select-port').onclick();
  assert.equal(ui.evaluate('state.port'),secondPort);assert.equal(ui.elements.get('hardware').value,second.hardware);assert.equal(ui.elements.get('provider').value,'Keymind Cascade');assert.equal(ui.elements.get('role').value,'repeater');assert.equal(ui.elements.get('version').value,second.version);assert.equal(ui.elements.get('artifact').value,'1');
  const summary=ui.elements.get('automatic-summary').textContent;assert.ok(summary.includes(second.name));assert.ok(!summary.includes(first.name));assert.doesNotMatch(summary,/downgrade/i);
  assert.equal(ui.evaluate('state.device.architecture'),'nrf52');assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(ui.calls,['chooser','open','close','chooser','open','get bootloader.ver','ota bootloader status','close']);
});

test('a manual hardware override with automatic setup on immediately refreshes the chosen target',async()=>{
  const ui=workbench({productionDefaults:true});await Promise.resolve();ui.context.inventory=[v4Item,xiaoRepeaterItem()];
  ui.evaluate("state.items=inventory;state.manualSelections={provider:'MeshCore'};state.device={model:'Heltec V4 OLED',catalogRole:'repeater',version:'v1.17.0'};filterCatalog();selectDetectedBoard();");
  assert.equal(ui.elements.get('artifact').value,'0');
  ui.elements.get('hardware').value='Seeed Studio Xiao nRF52 WIO';await ui.elements.get('hardware').onchange();
  assert.equal(ui.elements.get('hardware').value,'Seeed Studio Xiao nRF52 WIO');assert.equal(ui.elements.get('artifact').value,'1');assert.ok(ui.elements.get('automatic-summary').textContent.includes(ui.context.inventory[1].name));assert.ok(!ui.elements.get('automatic-summary').textContent.includes(v4Item.name));assert.deepEqual(ui.calls,[]);
});

test('cancelling the first-awaited USB chooser preserves the existing board firmware and write context',async()=>{
  const ui=workbench({productionDefaults:true});await Promise.resolve();ui.context.pkg=fakePackage({name:v4Item.name,architecture:'esp32'});ui.context.selectedPort=ui.port;ui.context.inventory=[v4Item];
  ui.evaluate("state.items=inventory;state.port=selectedPort;state.pkg=pkg;state.item=inventory[0];state.device={model:'Heltec V4 OLED'};state.manualSelections={hardware:'Heltec v4'};state.plan={written:true};filterCatalog();");
  ui.elements.get('hardware').value='Heltec v4';ui.elements.get('artifact').value='0';ui.elements.get('automatic-summary').textContent='Existing chosen V4 firmware';
  const prior={plan:ui.evaluate('state.plan'),device:ui.evaluate('state.device'),generation:ui.evaluate('state.generation')};
  ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');throw Error('Fixture chooser cancelled');};
  await ui.elements.get('select-port').onclick();
  assert.equal(ui.evaluate('state.port'),ui.port);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);assert.equal(ui.evaluate('state.plan'),prior.plan);assert.equal(ui.evaluate('state.device'),prior.device);assert.equal(ui.evaluate('state.generation'),prior.generation);
  assert.equal(ui.elements.get('hardware').value,'Heltec v4');assert.equal(ui.elements.get('artifact').value,'0');assert.equal(ui.elements.get('automatic-summary').textContent,'Existing chosen V4 firmware');assert.equal(ui.evaluate('state.manualSelections.hardware'),'Heltec v4');assert.deepEqual(ui.calls,['chooser']);
});

test('explicit USB chooser cancellation is informational and preserves pending workflow without automatically resuming it',async()=>{
  for(const message of ['No port selected by the user','No port selected by the user.',"Failed to execute 'requestPort' on 'Serial': No port selected by the user."]){
    const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage();
    ui.evaluate('state.port=selectedPort;state.pkg=pkg;state.device={model:"Existing radio"};state.plan={written:true};state.backupApproved={port:selectedPort};state.verification={sha256:pkg.sha256};');
    const before=['port','pkg','device','plan','backupApproved','verification','generation'].map(field=>ui.evaluate('state.'+field));
    ui.context.requestAutomaticVerification=()=>assert.fail('Chooser cancellation must not resume hardware work');
    ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');const error=Error(message);error.name='NotFoundError';throw error;};
    await ui.elements.get('select-port').onclick();
    assert.deepEqual(['port','pkg','device','plan','backupApproved','verification','generation'].map(field=>ui.evaluate('state.'+field)),before);
    assert.match(ui.elements.get('notice').textContent,/USB selection cancelled.*unchanged/);assert.equal(ui.elements.get('notice').classList.contains('error'),false);
    assert.match(ui.elements.get('log').textContent,/cancelled by the user/);assert.doesNotMatch(ui.elements.get('log').textContent,/Stopped:/);assert.deepEqual(ui.calls,['chooser']);
  }
});

test('permission, transport and non-cancellation NotFound errors from USB selection remain visible errors',async()=>{
  for(const [name,message] of [['NotAllowedError','Access denied'],['SecurityError','No port selected by the user.'],['NetworkError','Serial device disconnected'],['NotFoundError','Device no longer available'],['Error','No port selected by the user.']]){
    const ui=workbench();await Promise.resolve();ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');const error=Error(message);error.name=name;throw error;};
    await ui.elements.get('select-port').onclick();assert.equal(ui.elements.get('notice').textContent,message,name);
    assert.equal(ui.elements.get('notice').classList.contains('error'),true,name);assert.match(ui.elements.get('log').textContent,/Stopped:/,name);assert.deepEqual(ui.calls,['chooser'],name);
  }
});

test('nRF52 preparation replaces stale reconnect guidance with the ready step 4 action',async()=>{
  for(const wipe of [false,true]){
    const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0057});ui.context.pkg=fakePackage();ui.context.erase=fakePackage({name:'erase.zip',erase:true,destructive:true});
    ui.evaluate('state.port=selectedPort;state.pkg=pkg;$("transport-mode").value="nrf52";progress(0,"USB handoff requested. Step 1: select the same radio.");');
    if(wipe)ui.evaluate('state.installMode="install";$("flash-action").value="wipe";');
    ui.context.ensureBackup=async()=>ui.calls.push('backup-considered');ui.context.erasePackage=async()=>ui.context.erase;
    await ui.elements.get('prepare').onclick();
    assert.match(ui.elements.get('progress-label').textContent,/DFU ready\. Step 4: Review & flash/);
    assert.doesNotMatch(ui.elements.get('progress-label').textContent,/handoff requested|Step 1/);assert.equal(ui.elements.get('progress').value,0);
    assert.ok(ui.evaluate('state.plan'));assert.deepEqual(nextHighlight(ui),['flash']);assert.deepEqual(ui.calls,['backup-considered']);
    if(wipe)assert.equal(ui.evaluate('state.plan.erasePkg'),ui.context.erase);
  }
});

test('handoff recovery migration and verification re-selection retain the exact in-progress firmware image',async()=>{
  for(const mode of ['handoff','recovery','migration','espRecovery','verification']){
    const ui=workbench({productionDefaults:true});await Promise.resolve();
    ui.context.pkg=fakePackage({name:'in-progress.bin',architecture:mode==='recovery'?'nrf52':'esp32'});ui.context.selectedPort=ui.port;ui.evaluate('state.pkg=pkg;state.port=selectedPort;');
ui.context.confirm=async(_title,_detail,_warning,token,options)=>{assert.equal(token,'SAME DEVICE');ui.calls.push('same-device');return true;};
    if(mode==='handoff')ui.evaluate('state.handoff=true;');
    else if(mode==='recovery'){ui.evaluate('state.recovery={sha256:pkg.sha256,name:pkg.name,phase:"reselect-dfu",eraseComplete:true};');ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0044});}
    else if(mode==='migration')ui.evaluate('state.migration={mac:"aa:bb:cc:dd:ee:ff",sha256:pkg.sha256,phase:"running"};');
    else if(mode==='espRecovery')ui.evaluate('state.espRecovery={mac:"aa:bb:cc:dd:ee:ff",sha256:pkg.sha256,name:pkg.name};');
    else {ui.evaluate('state.verification={sha256:pkg.sha256,name:pkg.name,publicKey:null};');ui.context.verifyApplication=async()=>{ui.calls.push('verify-application');assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);};}
    await ui.elements.get('select-port').onclick();
    assert.equal(ui.evaluate('state.pkg'),ui.context.pkg,mode);assert.ok(!ui.calls.includes('open'),mode);assert.ok(!ui.calls.includes('rom'),mode);assert.ok(!ui.calls.includes('mock-write'),mode);
  }
});

test('automatic selection invalidates an older merged/custom image and its ready write proof',async()=>{
  const ui=workbench({productionDefaults:true});await Promise.resolve();ui.context.inventory=[{...v4Item,provider:'Keymind Cascade'}];ui.evaluate("state.items=inventory;state.device={catalogRole:'repeater',version:'v1.14.1'};state.pkg={name:'old-merged.bin',destructive:true};state.item={name:'old-merged.bin',url:'https://example.test/old.bin'};state.plan={written:true};filterCatalog();");ui.elements.get('hardware').value='Heltec v4';ui.evaluate('applyAutomaticSelections();');assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.match(ui.elements.get('automatic-summary').textContent,/Write-only/);assert.equal(ui.elements.get('artifact').value,'0');
});

test('unsupported explicit automatic preferences stay refused and do not display stale dropdown values',async()=>{
  const ui=workbench({productionDefaults:true});await Promise.resolve();ui.context.inventory=[v4Item];ui.evaluate("state.items=inventory;state.device={catalogRole:'repeater'};filterCatalog();state.manualSelections={provider:'Unavailable'};");ui.elements.get('hardware').value='Heltec v4';ui.evaluate('applyAutomaticSelections();');assert.equal(ui.elements.get('provider').value,'');assert.equal(ui.elements.get('artifact').value,'');assert.equal(ui.evaluate('state.manualSelections.provider'),'Unavailable');assert.match(ui.elements.get('automatic-summary').textContent,/No write-only/);
});

test('Prepare update with a live TinyUSB report loads the automatic artifact and requests guarded handoff, never flashes',async()=>{
  const ui=workbench({productionDefaults:true});await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage({architecture:'esp32'});ui.context.inventory=[v4Item];ui.evaluate("state.items=inventory;state.port=selectedPort;state.device={model:'Heltec V4 OLED',architecture:'esp32'};filterCatalog();");ui.port.getInfo=()=>({usbVendorId:0x303a,usbProductId:0x0002});ui.elements.get('artifact').value='0';ui.context.fetchSelectedFirmware=async()=>{ui.calls.push('fetch');ui.evaluate('state.pkg=pkg;');};ui.context.ensureBackup=async()=>ui.calls.push('backup');ui.context.confirm=async(_t,_d,_w,token)=>{ui.calls.push(token);return true;};ui.context.touch1200=async(_port,kind)=>ui.calls.push(kind);
  ui.evaluate("state.device.usbMode='tinyusb';state.device.usbModeStatus='reported';");await ui.elements.get('prepare').onclick();assert.deepEqual(ui.calls,['fetch','backup','ENTER BOOTLOADER','tinyusb']);assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.elements.get('transport-mode').value,'no_reset');assert.equal(ui.elements.get('already-bootloader').checked,true);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);
});

test('XIAO S3 handoff explains physical BOOT and VM port reselection without another write',async()=>{
  const ui=workbench({productionDefaults:true});await Promise.resolve();
  ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage({architecture:'esp32'});ui.context.inventory=[{...v4Item,hardware:'Seeed Studio Xiao S3'}];
  ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0059});
  ui.evaluate("state.items=inventory;state.port=selectedPort;state.device={model:'Seeed XIAO ESP32-S3',architecture:'esp32',usbMode:'tinyusb',usbModeStatus:'reported'};filterCatalog();");
  ui.elements.get('artifact').value='0';ui.context.fetchSelectedFirmware=async()=>{ui.calls.push('fetch');ui.evaluate('state.pkg=pkg;');};
  ui.context.ensureBackup=async()=>ui.calls.push('backup');ui.context.confirm=async()=>true;
  ui.context.touch1200=async(_port,kind)=>ui.calls.push(kind);
  await ui.elements.get('prepare').onclick();
  assert.deepEqual(ui.calls,['fetch','backup','tinyusb']);
  assert.match(ui.elements.get('notice').textContent,/If the ROM port does not appear, try a USB hub/);
  assert.match(ui.elements.get('notice').textContent,/hold BOOT, tap RESET, then release BOOT/);
  assert.match(ui.elements.get('notice').textContent,/In a VM, attach the newly appeared USB device/);
  assert.match(ui.elements.get('notice').textContent,/Already in ROM\/DFU/);
  assert.equal(ui.elements.get('already-bootloader').checked,true);
  assert.equal(ui.evaluate('state.plan'),null);
});

test('manual XIAO S3 handoff offers hub advice only if the ROM port does not appear',async()=>{
  const ui=workbench({productionDefaults:true});await Promise.resolve();
  ui.context.selectedPort=ui.port;
  ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0059});
  ui.evaluate("state.port=selectedPort;state.device={model:'Seeed XIAO ESP32-S3',architecture:'esp32',usbMode:'tinyusb',usbModeStatus:'reported'};");
  ui.context.ensureBackup=async()=>ui.calls.push('backup');ui.context.confirm=async()=>true;
  ui.context.touch1200=async(_port,kind)=>ui.calls.push(kind);
  await ui.elements.get('touch').onclick();
  assert.deepEqual(ui.calls,['backup','tinyusb']);
  assert.match(ui.elements.get('notice').textContent,/Choose USB port again for the same device/);
  assert.match(ui.elements.get('notice').textContent,/If the ROM port does not appear, try a USB hub/);
  assert.equal(ui.evaluate('state.port'),null);
});

test('successful application rereads retain exact-model architecture for automatic connection choice',async()=>{
  const ui=workbench({productionDefaults:true});await Promise.resolve();serialMock(ui);ui.context.inventory=[v4Item];ui.context.selectedPort=ui.port;ui.evaluate('state.items=inventory;state.port=selectedPort;');ui.port.getInfo=()=>({usbVendorId:0x303a,usbProductId:0x0002});ui.context.detectMeshCore=async()=>({model:'Heltec V4 OLED',role:'common-cli',catalogRole:'repeater'});
  await ui.evaluate('linkOperation(readApplication)');assert.equal(ui.evaluate('state.device.architecture'),'esp32');assert.equal(ui.evaluate('connectionMode()'),'tinyusb');
});

test('automatic verified finish retains UART transport even after the handoff flag becomes set',async()=>{
  const ui=workbench({productionDefaults:true});await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.record=ui.calls;ui.evaluate("state.port=selectedPort;state.handoff=true;state.plan={written:true,transportMode:'default_reset'};state.esp={connectMode:'default_reset',finish:async native=>record.push(native),close:async()=>record.push('close')};");
  await ui.elements.get('finish').onclick();assert.deepEqual(ui.calls,[false,'close']);assert.equal(ui.evaluate('state.port'),null);
});

test('auto finish never starts expert components or failed writes; ordinary verified app starts once',async()=>{
  for(const expert of [false,true])for(const succeeds of [false,true]){
    const ui=workbench({productionDefaults:true});await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.record=ui.calls;ui.context.pkg=fakePackage({architecture:'esp32',expert});ui.context.succeeds=succeeds;ui.evaluate("state.pkg=pkg;state.port=selectedPort;state.plan={generation:0,port:selectedPort,sha256:pkg.sha256,addresses:[65536],transportMode:'usb_reset'};state.esp={flash:async()=>{record.push('write');if(!succeeds)throw Error('readback failed');},finish:async()=>record.push('finish'),close:async()=>record.push('close')};");ui.context.confirm=async()=>true;ui.context.queueVerification=()=>ui.calls.push('verify-record');
    await ui.elements.get('flash').onclick();assert.equal(ui.calls.includes('finish'),!expert&&succeeds);assert.equal(ui.calls.filter(x=>x==='finish').length,!expert&&succeeds?1:0);if(!succeeds)assert.match(ui.elements.get('notice').textContent,/readback failed/);
  }
});
test('page initialization never opens, probes, resets or enumerates serial devices',async()=>{
  const ui=workbench();await Promise.resolve();assert.deepEqual(ui.calls,[]);assert.equal(ui.elements.get('flash').disabled,true);assert.equal(ui.elements.get('restore').disabled,true);
});
test('port chooser is the first awaited operation and invalidates previous flash proof',async()=>{
  const ui=workbench();ui.context.record=ui.calls;
  ui.evaluate("state.esp={close:async()=>record.push('close')};state.plan={written:true};");
  await ui.elements.get('select-port').onclick();
  assert.deepEqual(ui.calls,['chooser','close']);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.port'),ui.port);
});

test('optional detection probes only after choosing a port and selects exact hardware without loading an image',async()=>{
  const ui=workbench();await Promise.resolve();serialMock(ui);
  ui.context.inventory=[{project:'MeshCore',provider:'MeshCore',hardware:'UnitEng/BQ Voyage Station G3',role:'repeater',version:'v1.18.0',name:'g3.bin',architecture:'esp32'}];ui.evaluate('state.items=inventory;filterCatalog();');
  ui.context.detectMeshCore=async()=>{ui.calls.push('detect');return {role:'common-cli',model:'Station G3 ESP32',name:'G3'};};ui.elements.get('auto-detect-board').checked=true;
  await ui.elements.get('select-port').onclick();
  assert.deepEqual(ui.calls,['chooser','open','detect','close']);assert.equal(ui.elements.get('hardware').value,'UnitEng/BQ Voyage Station G3');assert.equal(ui.elements.get('artifact').value,'');assert.equal(ui.evaluate('state.pkg'),null);assert.match(ui.elements.get('board-detection').textContent,/Selected.*Station G3/);
});

test('manual detection works with automatic port probing disabled and unknown models preserve manual hardware',async()=>{
  const ui=workbench();await Promise.resolve();serialMock(ui);ui.context.selectedPort=ui.port;ui.context.inventory=[{...v4Item,hardware:'Manual board'}];ui.evaluate('state.items=inventory;state.port=selectedPort;filterCatalog();');ui.elements.get('hardware').value='Manual board';ui.context.detectMeshCore=async()=>({role:'companion',model:'Station G3 ESP'});
  await ui.elements.get('probe').onclick();assert.deepEqual(ui.calls,['open','close']);assert.equal(ui.elements.get('hardware').value,'Manual board');assert.match(ui.elements.get('board-detection').textContent,/No complete exact/);
});

test('DFU detection checks hints without probing or treating USB as physical board proof',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.inventory=[t114MeshtasticItem({hardware:'Physical RAK'})];ui.evaluate('state.items=inventory;filterCatalog();');ui.port.getInfo=()=>({usbVendorId:0x239a,usbProductId:0x0029});ui.elements.get('auto-detect-board').checked=true;ui.elements.get('hardware').value='Physical RAK';
  await ui.elements.get('select-port').onclick();assert.deepEqual(ui.calls,['chooser']);assert.equal(ui.elements.get('hardware').value,'Physical RAK');assert.equal(ui.elements.get('recovery-profile').value,'');assert.match(ui.elements.get('notice').textContent,/without sending/);
});

test('new port selection clears stale recovery identity hints',async()=>{
  const ui=workbench();await Promise.resolve();ui.elements.get('installed-identity').value='gat562';ui.elements.get('recovery-profile').value='gat562';ui.elements.get('recovery-detection').textContent='old match';
  await ui.elements.get('select-port').onclick();assert.equal(ui.elements.get('installed-identity').value,'');assert.equal(ui.elements.get('recovery-profile').value,'');assert.equal(ui.elements.get('recovery-detection').textContent,'');
});

test('bootloader can be selected from unambiguous exact hardware without choosing an application artifact',async()=>{
  const ui=workbench();await Promise.resolve();const info={profile:'test',url:'https://example.test/test_bootloader.zip',sha256:'a'.repeat(64),version:'2.4.12'};ui.context.inventory=[{project:'MeshCore',hardware:'Test',architecture:'nrf52',provider:'MeshCore',bootloaderInfo:info,bootloader:[info.url],role:'companion',version:'v1'}, {project:'MeshCore',hardware:'Test',architecture:'nrf52',provider:'Keymind Cascade',bootloaderInfo:info,bootloader:[info.url],role:'repeater',version:'v2'}];ui.evaluate('state.items=inventory;');ui.elements.get('hardware').value='Test';ui.evaluate('updateDownload();controls();');assert.equal(ui.elements.get('bootloader-source').value,info.url);assert.equal(ui.elements.get('load-bootloader').disabled,false);assert.equal(ui.evaluate('bootloaderItem().role'),undefined);assert.equal(ui.evaluate('state.pkg'),null);
  ui.context.inventory[1]={...ui.context.inventory[1],bootloaderInfo:{...info,url:'https://example.test/different.zip'}};ui.evaluate('updateDownload();controls();');assert.equal(ui.elements.get('bootloader-source').value,'');assert.equal(ui.elements.get('load-bootloader').disabled,true);
});

test('board detection cannot open a port or change choices during pending writes',async()=>{
  const ui=workbench({pending:{mac:'aa:bb:cc:dd:ee:ff',sha256:'a'.repeat(64)}});ui.context.selectedPort=ui.port;ui.evaluate('state.port=selectedPort;');ui.elements.get('already-bootloader').checked=true;
  await ui.elements.get('probe').onclick();assert.deepEqual(ui.calls,[]);assert.match(ui.elements.get('notice').textContent,/pending write or migration/);
});

test('a disconnect during an outstanding board query cannot repopulate stale device evidence or selection',async()=>{
  const ui=workbench();await Promise.resolve();serialMock(ui);ui.context.selectedPort=ui.port;ui.context.inventory=[{...v4Item,hardware:'Manual'}];ui.evaluate('state.items=inventory;state.port=selectedPort;filterCatalog();');ui.elements.get('hardware').value='Manual';
  ui.context.detectMeshCore=async()=>{ui.serialEvents.disconnect({port:ui.port});return {model:'Station G3 ESP32'};};
  await ui.elements.get('probe').onclick();assert.equal(ui.evaluate('state.device'),null);assert.equal(ui.evaluate('state.boardDetected'),false);assert.equal(ui.elements.get('hardware').value,'Manual');assert.match(ui.elements.get('notice').textContent,/disconnected/);
});

test('recovery matching selects the returned installed-profile hint without opening, loading or writing',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.catalog={tag:'v0.11.0-OTAFIX2.4.12',profiles:[{id:'t1000_e'}]};ui.evaluate('state.port=selectedPort;state.recoveryCatalog=catalog;');ui.context.detectRecoveryProfile=args=>{assert.equal(args.tag,ui.context.catalog.tag);assert.equal(args.profiles,ui.context.catalog.profiles);return {profile:'t1000_e',candidates:['t1000_e'],source:'usb',reason:'unique'};};
  await ui.elements.get('match-recovery').onclick();assert.equal(ui.elements.get('recovery-profile').value,'t1000_e');assert.match(ui.elements.get('recovery-detection').textContent,/unique reviewed USB ID/);assert.equal(ui.evaluate('state.pkg'),null);assert.deepEqual(ui.calls,[]);
});

test('manual recovery choices survive catalog choice updates, but shared identity matching clears a stale selection',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.catalog={version:'2.4.12',bundle:{url:'https://example.test/recovery.zip'},profiles:[{id:'xiao_nrf52840_ble',installedIdentity:'XIAO_DFU'},{id:'xiao_nrf52840_ble_sense',installedIdentity:'XIAO_DFU'}]};ui.evaluate('state.recoveryCatalog=catalog;updateRecoveryChoices();');ui.elements.get('recovery-profile').value='xiao_nrf52840_ble';ui.elements.get('recovery-profile').onchange();ui.evaluate('updateRecoveryChoices();');assert.equal(ui.elements.get('recovery-profile').value,'xiao_nrf52840_ble');
  ui.elements.get('installed-identity').value='XIAO_DFU';await ui.elements.get('match-recovery').onclick();assert.equal(ui.elements.get('recovery-profile').value,'');assert.match(ui.elements.get('recovery-detection').textContent,/shared/);assert.deepEqual(ui.calls,[]);
});

test('a late catalog response cannot rematch recovery after the selected DFU port disconnected',async()=>{
  let resolveCatalog;const catalogPromise=new Promise(resolve=>resolveCatalog=resolve),ui=workbench({catalogPromise});ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0057});ui.elements.get('auto-detect-board').checked=true;
  ui.context.detectRecoveryProfile=()=>({profile:'t1000_e',candidates:['t1000_e'],source:'usb',reason:'unique'});
  await ui.elements.get('select-port').onclick();assert.equal(ui.elements.get('recovery-profile').value,'t1000_e');ui.serialEvents.disconnect({port:ui.port});
  resolveCatalog({items:[],warnings:[],generatedAt:new Date().toISOString(),recoveryCatalog:{version:'2.4.12',profiles:[{id:'t1000_e',installedIdentity:'T1KE_DFU'}],bundle:{url:'https://example.test/recovery.zip'}}});await new Promise(resolve=>setTimeout(resolve,0));
  assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.elements.get('recovery-profile').value,'');assert.equal(ui.elements.get('recovery-detection').textContent,'');assert.equal(ui.evaluate('state.recoveryDetectionRequested'),false);assert.deepEqual(ui.calls,['chooser']);
});

test('a late catalog applies a requested running-model match without additional port operations',async()=>{
  let resolveCatalog;const catalogPromise=new Promise(resolve=>resolveCatalog=resolve),ui=workbench({catalogPromise});serialMock(ui);ui.context.detectMeshCore=async()=>({model:'Station G3 ESP32'});ui.elements.get('auto-detect-board').checked=true;
  await ui.elements.get('select-port').onclick();assert.equal(ui.elements.get('hardware').value,'');
  resolveCatalog({items:[{project:'MeshCore',provider:'MeshCore',hardware:'UnitEng/BQ Voyage Station G3',architecture:'esp32',version:'v1'}],warnings:[],generatedAt:new Date().toISOString()});await new Promise(resolve=>setTimeout(resolve,0));assert.equal(ui.elements.get('hardware').value,'UnitEng/BQ Voyage Station G3');assert.deepEqual(ui.calls,['chooser','open','close']);
});
test('failed replacement image cannot leave a previous file flashable',async()=>{
  const ui=workbench();ui.evaluate("state.pkg={architecture:'esp32',name:'old.bin'};state.plan={written:true};");
  ui.elements.get('firmware-file').files=[{name:'new.bin',size:64,arrayBuffer:async()=>new ArrayBuffer(64)}];
  await ui.elements.get('firmware-file').onchange();
  assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('flash').disabled,true);assert.equal(ui.elements.get('image-name').textContent,'No image loaded');
});
test('unsettled UART migration forbids a ROM session before any reset can be sent',async()=>{
  const ui=workbench({pending:{mac:'aa:bb:cc:dd:ee:ff',sha256:'a'.repeat(64),uart:true,settled:false}});
  ui.context.selectedPort=ui.port;ui.evaluate("state.port=selectedPort;state.pkg={architecture:'esp32',sha256:'"+'a'.repeat(64)+"'};");
  await ui.elements.get('prepare').onclick();
  assert.deepEqual(ui.calls,[]);assert.match(ui.elements.get('notice').textContent,/must report settled/);
});
test('partial and unknown captures never enable unsupported restore',()=>{
  const ui=workbench();ui.context.selectedPort=ui.port;
  for(const archive of [{schema:'org.meshfirmware.web-backup/v1',payload:{role:'common-cli'}},{schema:'unsupported-format',payload:{}}]){
    ui.context.archive=archive;ui.evaluate('state.port=selectedPort;state.restore=archive;controls();');assert.equal(ui.elements.get('restore').disabled,true);
  }
});
test('pending native migration prevents reset-producing inspection and unrelated application operations',async()=>{
  const ui=workbench({pending:{mac:'aa:bb:cc:dd:ee:ff',sha256:'a'.repeat(64),uart:false,phase:'running'}});
  ui.context.selectedPort=ui.port;ui.evaluate("state.port=selectedPort;state.pkg={architecture:'esp32',sha256:'"+'a'.repeat(64)+"'};");
  ui.elements.get('transport-mode').value='usb_reset';await ui.elements.get('prepare').onclick();assert.match(ui.elements.get('notice').textContent,/no reset/);
  for(const id of ['touch','probe','backup'])await ui.elements.get(id).onclick();
  assert.deepEqual(ui.calls,[]);
});
test('nRF52 mode never opens a mounted-drive picker even for a non-Nordic UF2',async()=>{
  const ui=workbench();ui.evaluate("state.pkg={architecture:'uf2'};");ui.elements.get('transport-mode').value='nrf52';
  await ui.elements.get('prepare').onclick();assert.match(ui.elements.get('notice').textContent,/serial DFU ZIP/);assert.deepEqual(ui.calls,[]);
});
const fakePackage=(extra={})=>({name:'final.zip',architecture:'nrf52',kind:'application',sha256:'a'.repeat(64),payloadHash:'b'.repeat(64),payload:new Uint8Array(64),warnings:[],destructive:false,...extra});
function serialMock(ui){ui.context.SerialLink=class{async open(){ui.calls.push('open');}async close(){ui.calls.push('close');}async command(command){ui.calls.push(command);return '';}};}

test('manual catalog downgrade is warned before loading and stays loadable without a device operation',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.inventory=[v4Item];ui.context.pkg=fakePackage({name:v4Item.name,architecture:'esp32'});ui.evaluate("state.items=inventory;state.device={version:'v1.19.0'};filterCatalog();");ui.elements.get('artifact').value='0';ui.evaluate('updateDownload();controls();');
  assert.match(ui.elements.get('catalog-detail').textContent,/downgrade/i);assert.match(ui.elements.get('catalog-detail').textContent,/v1\.19\.0/);assert.match(ui.elements.get('catalog-detail').textContent,/v1\.18\.0/);assert.equal(ui.elements.get('fetch-firmware').disabled,false);
  ui.context.inspectFirmware=()=>ui.context.pkg;await ui.evaluate("loadFirmware(pkg.name,new Uint8Array(64),inventory[0])");
  assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);assert.match(ui.elements.get('image-warning').textContent,/downgrade/i);assert.deepEqual(ui.calls,[]);
  ui.elements.get('artifact').value='';ui.evaluate('updateDownload();');assert.equal(ui.elements.get('catalog-detail').textContent,'');
});

test('custom application downgrade warnings prefer verified payload version and never inherit another catalog version',async()=>{
  const ui=workbench();await Promise.resolve();ui.evaluate("state.device={version:'v1.18.0.2'};");
  ui.context.pkg=fakePackage({name:'custom-v1.17.0.zip',firmwareIdentity:{versionText:'v1.18.0.2'}});ui.context.inspectFirmware=()=>ui.context.pkg;ui.context.checkedZip=()=>[{name:'manifest.json'},{name:'app.bin'},{name:'app.dat'}];
  await ui.evaluate('loadFirmware(pkg.name,new Uint8Array(64))');assert.doesNotMatch(ui.elements.get('image-warning').textContent,/downgrade/i);
  ui.context.pkg=fakePackage({name:'renamed.zip',firmwareIdentity:{versionText:'v1.17.0'}});await ui.evaluate('loadFirmware(pkg.name,new Uint8Array(64))');assert.match(ui.elements.get('image-warning').textContent,/downgrade/i);assert.match(ui.elements.get('image-warning').textContent,/v1\.17\.0/);
  ui.context.pkg=fakePackage({name:'custom_v1.17.0.bin',architecture:'esp32'});await ui.evaluate('loadFirmware(pkg.name,new Uint8Array(64))');assert.match(ui.elements.get('image-warning').textContent,/downgrade/i);
  ui.elements.get('hardware').value='Heltec v4';ui.context.inventory=[v4Item];ui.evaluate('state.items=inventory;');ui.context.pkg=fakePackage({name:'unversioned.bin',architecture:'esp32'});await ui.evaluate('loadFirmware(pkg.name,new Uint8Array(64))');assert.doesNotMatch(ui.elements.get('image-warning').textContent,/downgrade/i);
  ui.context.pkg=fakePackage({name:'board_bootloader-v0.11.0.zip',kind:'softdevice_bootloader',destructive:true});await ui.evaluate('loadFirmware(pkg.name,new Uint8Array(64))');assert.doesNotMatch(ui.elements.get('image-warning').textContent,/downgrade/i);assert.deepEqual(ui.calls,[]);
});

test('reading the connected version refreshes a previously loaded application downgrade warning',async()=>{
  const ui=workbench();serialMock(ui);ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage({name:'older.bin',architecture:'esp32'});ui.context.endfIdentity=()=>({versionText:'v1.17.0'});ui.evaluate('state.port=selectedPort;state.pkg=pkg;refreshFirmwareWarnings();');assert.doesNotMatch(ui.elements.get('image-warning').textContent,/downgrade/i);
  ui.context.detectMeshCore=async()=>({role:'common-cli',version:'v1.18.0.2'});await ui.evaluate('linkOperation(readApplication)');assert.match(ui.elements.get('image-warning').textContent,/downgrade/i);assert.deepEqual(ui.calls,['open','close']);
});

test('downgrade can prepare and continue after the ordinary FLASH warning acknowledgement, never automatically',async()=>{
  const ui=workbench();serialMock(ui);ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage({firmwareIdentity:{versionText:'v1.17.0'}});ui.evaluate("state.port=selectedPort;state.pkg=pkg;state.device={version:'v1.18.0.2',model:'Test board'};");ui.elements.get('transport-mode').value='nrf52';ui.elements.get('already-bootloader').checked=true;
  ui.context.ensureBackup=async()=>ui.calls.push('backup-considered');await ui.elements.get('prepare').onclick();assert.ok(ui.evaluate('state.plan'));assert.deepEqual(ui.calls,['backup-considered']);
  let warnings=[];ui.context.confirm=async(title,_detail,warning,token)=>{assert.equal(title,'Write this firmware?');assert.equal(token,'FLASH');warnings.push(warning);return false;};ui.context.flashNrf=async()=>ui.calls.push('mock-write');await ui.elements.get('flash').onclick();assert.match(warnings[0],/downgrade/i);assert.match(warnings[0],/v1\.18\.0\.2/);assert.match(warnings[0],/v1\.17\.0/);assert.ok(!ui.calls.includes('mock-write'));
  ui.context.confirm=async(_title,_detail,warning,token)=>{assert.equal(token,'FLASH');assert.match(warning,/downgrade/i);return true;};await ui.elements.get('flash').onclick();assert.ok(ui.calls.includes('mock-write'));assert.equal(ui.evaluate('state.verification.version'),'v1.17.0');
});
test('default backup flow validates the archive and explicitly continues from its popup before ROM entry',async()=>{
  const ui=workbench();serialMock(ui);ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage({name:'app.bin',architecture:'esp32'});ui.evaluate('state.port=selectedPort;state.pkg=pkg;');ui.elements.get('backup-role').value='auto';
  ui.context.choose=async title=>{ui.calls.push(title);return title.startsWith('Back up')?'backup':'continue';};
  ui.context.detectMeshCore=async()=>({role:'companion',publicKey:'11'.repeat(32),model:'test',name:'test'});
  ui.context.MeshCore=class{async backup(){ui.calls.push('backup');return {payload:{role:'companion'}};}};
  ui.context.exportNativeBackup=async()=>({schema:'native'});ui.context.download=()=>ui.calls.push('download');
  ui.context.EspSession=class{async connect(){ui.calls.push('enter-rom');return {chip:'ESP32-S3',mac:'aa:bb:cc:dd:ee:ff',flashBytes:4<<20};}async prepare(){return {addresses:[0x10000],sha256:ui.context.pkg.sha256};}async close(){}};
  await ui.elements.get('prepare').onclick();
  assert.ok(ui.calls.indexOf('backup')<ui.calls.indexOf('enter-rom'));assert.ok(ui.calls.indexOf('Backup JSON')<ui.calls.indexOf('enter-rom'));assert.equal(ui.evaluate('state.plan.sha256'),ui.context.pkg.sha256);
});

async function backupJsonWorkbench(){
  const ui=workbench();await Promise.resolve();serialMock(ui);collapsedPanels(ui);
  const sentinel='PRIVATE_BACKUP_SENTINEL',native={schema:'org.meshfirmware.backup/v1',payload:{private_key:sentinel,bluetooth_name:'<script>not executable</script>',channels:[{name:'Private channel',key:'fixture-channel-key'}]}},downloads=[],stored=[];
  ui.context.selectedPort=ui.port;ui.evaluate("state.port=selectedPort;state.device={role:'companion',model:'Test board'};");
  ui.context.MeshCore=class{async backup(){ui.calls.push('capture-backup');return {payload:{role:'companion'}};}};
  ui.context.exportNativeBackup=async()=>native;ui.context.download=(name,json,type)=>downloads.push({name,json,type});
  const setItem=ui.context.localStorage.setItem;ui.context.localStorage.setItem=(key,value)=>{stored.push([key,value]);setItem(key,value);};
  return {...ui,native,sentinel,downloads,stored};
}

test('validated backup JSON is byte-identical to its download, kept as safe text and never automatically copied or persisted',async()=>{
  const ui=await backupJsonWorkbench();let clipboardWrites=0;ui.context.navigator.clipboard={writeText:async()=>{clipboardWrites++;}};
  await ui.elements.get('backup').onclick();
  const json=JSON.stringify(ui.native,null,2);
  assert.equal(ui.downloads.length,1);assert.equal(ui.downloads[0].json,json);assert.equal(ui.downloads[0].type,'application/json');assert.equal(ui.evaluate('state.backup.json'),json);
  assert.equal(ui.elements.get('backup-json').value,json);assert.equal(ui.elements.get('backup-json-view').hidden,false);assert.equal(ui.elements.get('backups').open,false);
  assert.equal(ui.elements.get('question-backup-json').value,'');assert.equal(ui.elements.get('question-backup-json-view').hidden,true);assert.equal(clipboardWrites,0);
  assert.ok(ui.elements.get('backup-json').value.includes('<script>not executable</script>'));assert.equal(ui.elements.get('backup-json').innerHTML,undefined);
  assert.ok(ui.stored.every(([_key,value])=>!String(value).includes(ui.sentinel)));assert.ok(!ui.elements.get('log').textContent.includes(ui.sentinel));assert.ok(!ui.elements.get('notice').textContent.includes(ui.sentinel));
  assert.deepEqual(ui.calls,['open','capture-backup','close']);assert.equal(ui.evaluate('state.backupApproved'),null);
});

test('copy JSON needs its explicit button and does not grant flash or saved-backup approval; clear removes both boxes only',async()=>{
  const ui=await backupJsonWorkbench(),clipboard=[];ui.context.navigator.clipboard={writeText:async value=>clipboard.push(value)};
  await ui.elements.get('backup').onclick();const json=ui.downloads[0].json,before=ui.calls.length;
  ui.elements.get('question-backup-json').value=json;ui.elements.get('question-backup-json-view').hidden=false;
  await ui.elements.get('copy-backup-json').onclick();await ui.elements.get('copy-question-backup-json').onclick();
  assert.deepEqual(clipboard,[json,json]);assert.equal(ui.evaluate('state.backupApproved'),null);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls.slice(before),[]);
  for(const prefix of ['backup','question-backup']){assert.match(ui.elements.get(prefix+'-json-status').textContent,/copied|privately|secrets/i);assert.ok(!ui.elements.get(prefix+'-json-status').textContent.includes(ui.sentinel));}
  ui.elements.get('clear-backup-json').onclick();
  for(const prefix of ['backup','question-backup']){assert.equal(ui.elements.get(prefix+'-json').value,'');assert.equal(ui.elements.get(prefix+'-json-view').hidden,true);assert.equal(ui.elements.get(prefix+'-json-status').textContent,'');}
  assert.equal(ui.evaluate('state.backup.json'),undefined);assert.equal(ui.downloads.length,1);assert.equal(ui.downloads[0].json,json);assert.deepEqual(clipboard,[json,json]);assert.deepEqual(ui.calls.slice(before),[]);
  assert.match(ui.elements.get('notice').textContent,/downloaded files and your clipboard were not changed/i);
});

test('missing or denied clipboard access keeps selectable JSON and falls back to manual copying without device commands',async()=>{
  for(const clipboard of ['missing','denied']){
    const ui=await backupJsonWorkbench();await ui.elements.get('backup').onclick();const json=ui.downloads[0].json,before=ui.calls.length;let focused=0,selected=0;
    ui.elements.get('backup-json').focus=()=>focused++;ui.elements.get('backup-json').select=()=>selected++;
    if(clipboard==='denied')ui.context.navigator.clipboard={writeText:async()=>{throw Error('Permission denied');}};
    await ui.elements.get('copy-backup-json').onclick();
    assert.equal(focused,1,clipboard);assert.equal(selected,1,clipboard);assert.equal(ui.elements.get('backup-json').value,json);assert.equal(ui.elements.get('backup-json-view').hidden,false);
    assert.match(ui.elements.get('backup-json-status').textContent,/copy it manually/i,clipboard);assert.equal(ui.evaluate('state.backupApproved'),null);assert.deepEqual(ui.calls.slice(before),[],clipboard);
  }
});

test('clearing JSON revokes pending copy UI updates but preserves an existing saved-backup approval',async()=>{
  for(const result of ['resolve','reject'])for(const prefix of ['backup','question-backup']){
    const ui=await backupJsonWorkbench();assert.equal(ui.evaluate('state.backupTextGeneration'),0);await ui.elements.get('backup').onclick();const json=ui.downloads[0].json;
    ui.elements.get(prefix+'-json').value=json;ui.elements.get(prefix+'-json-view').hidden=false;let complete,focused=0,selected=0;
    ui.context.navigator.clipboard={writeText:()=>new Promise((resolve,reject)=>{complete=result==='resolve'?resolve:()=>reject(Error('Late clipboard denial'));})};
    ui.elements.get(prefix+'-json').focus=()=>focused++;ui.elements.get(prefix+'-json').select=()=>selected++;
    ui.context.savedApproval={sha256:'a'.repeat(64),port:ui.port};ui.evaluate('state.backupApproved=savedApproval;');const generation=ui.evaluate('state.backupTextGeneration');
    const pending=ui.elements.get('copy-'+prefix+'-json').onclick();ui.elements.get('clear-backup-json').onclick();
    assert.ok(ui.evaluate('state.backupTextGeneration')>generation);assert.equal(ui.evaluate('state.backupApproved'),ui.context.savedApproval);
    complete();await pending;
    for(const name of ['backup','question-backup']){assert.equal(ui.elements.get(name+'-json').value,'');assert.equal(ui.elements.get(name+'-json-status').textContent,'');assert.equal(ui.elements.get(name+'-json-view').hidden,true);}
    assert.equal(focused,0,result+' '+prefix);assert.equal(selected,0,result+' '+prefix);assert.equal(ui.evaluate('state.backupApproved'),ui.context.savedApproval);assert.equal(ui.downloads.length,1);
  }
});

test('a new identical backup has a new text generation so a late copy cannot label or select the replacement',async()=>{
  for(const result of ['resolve','reject']){
    const ui=await backupJsonWorkbench();await ui.elements.get('backup').onclick();const json=ui.downloads[0].json;let complete,focused=0,selected=0;
    ui.context.navigator.clipboard={writeText:()=>new Promise((resolve,reject)=>{complete=result==='resolve'?resolve:()=>reject(Error('Late clipboard denial'));})};
    ui.elements.get('backup-json').focus=()=>focused++;ui.elements.get('backup-json').select=()=>selected++;
    const generation=ui.evaluate('state.backupTextGeneration'),pending=ui.elements.get('copy-backup-json').onclick();
    await ui.elements.get('backup').onclick();assert.equal(ui.elements.get('backup-json').value,json);assert.ok(ui.evaluate('state.backupTextGeneration')>generation);
    complete();await pending;
    assert.equal(ui.elements.get('backup-json').value,json);assert.equal(ui.elements.get('backup-json-status').textContent,'');assert.equal(focused,0,result);assert.equal(selected,0,result);assert.equal(ui.downloads.length,2);
  }
});

test('closing and reopening a same-JSON save dialog invalidates an older pending clipboard result',async()=>{
  for(const result of ['resolve','reject']){
    const ui=await backupJsonWorkbench();await ui.elements.get('backup').onclick();ui.context.json=ui.downloads[0].json;let close,complete,focused=0,selected=0;
ui.context.document.createElement=()=>uiElement();ui.elements.get('question-dialog').addEventListener=(_event,handler)=>{close=handler;};
    ui.context.navigator.clipboard={writeText:()=>new Promise((resolve,reject)=>{complete=result==='resolve'?resolve:()=>reject(Error('Late clipboard denial'));})};
    ui.elements.get('question-backup-json').focus=()=>focused++;ui.elements.get('question-backup-json').select=()=>selected++;
    const initial=ui.evaluate('state.backupTextGeneration'),oldDialog=ui.evaluate("choose('Save backup','Save privately',[['cancel','Cancel']],{backupJson:json});");
    assert.ok(ui.evaluate('state.backupTextGeneration')>initial);const opened=ui.evaluate('state.backupTextGeneration'),copy=ui.elements.get('copy-question-backup-json').onclick();
    close();await oldDialog;assert.ok(ui.evaluate('state.backupTextGeneration')>opened);
    const replacement=ui.evaluate("choose('Save replacement backup','Save privately',[['cancel','Cancel']],{backupJson:json});");
    complete();await copy;
    assert.equal(ui.elements.get('question-backup-json').value,ui.context.json);assert.equal(ui.elements.get('question-backup-json-status').textContent,'');assert.equal(focused,0,result);assert.equal(selected,0,result);
    close();await replacement;
  }
});

test('backup prompts hide verbose details and clear their JSON when closed without changing generic questions',async()=>{
  const ui=await backupJsonWorkbench();await ui.elements.get('backup').onclick();const json=ui.downloads[0].json;let close;
  ui.context.document.createElement=()=>uiElement();ui.elements.get('question-dialog').addEventListener=(event,handler)=>{assert.equal(event,'close');close=handler;};ui.context.json=json;
  const pending=ui.evaluate("choose('Confirm your backup download','Save privately',[['saved','I saved the backup']],{backupJson:json});");
  assert.equal(ui.elements.get('question-backup-json').value,json);assert.equal(ui.elements.get('question-backup-json-view').hidden,false);assert.equal(ui.elements.get('backup-json').value,json);
  assert.equal(ui.elements.get('question-backup-title').hidden,false);assert.equal(ui.elements.get('question-title').hidden,true);
  assert.equal(ui.elements.get('question-detail').textContent,'');assert.equal(ui.elements.get('question-detail').hidden,true);
  ui.elements.get('question-dialog').returnValue='saved';close();assert.equal(await pending,'saved');
  assert.equal(ui.elements.get('question-backup-json').value,'');assert.equal(ui.elements.get('question-backup-json-view').hidden,true);assert.equal(ui.elements.get('backup-json').value,json);
  assert.equal(ui.elements.get('question-backup-title').hidden,true);assert.equal(ui.elements.get('question-title').hidden,false);
  const other=ui.evaluate("choose('Unrelated question','No secrets here',[['cancel','Cancel']]);");
  assert.equal(ui.elements.get('question-backup-title').hidden,true);assert.equal(ui.elements.get('question-title').hidden,false);
  assert.equal(ui.elements.get('question-detail').hidden,false);assert.equal(ui.elements.get('question-detail').textContent,'No secrets here');
  assert.equal(ui.elements.get('question-backup-json').value,'');assert.equal(ui.elements.get('question-backup-json-view').hidden,true);close();await other;
  assert.ok(!ui.elements.get('question-detail').textContent.includes(ui.sentinel));assert.ok(!ui.elements.get('log').textContent.includes(ui.sentinel));
});

test('copying a captured backup cannot start preparation when its compact window is dismissed',async()=>{
  const ui=await backupJsonWorkbench();ui.context.pkg=fakePackage({architecture:'esp32'});ui.evaluate('state.pkg=pkg;');ui.elements.get('auto-backup').checked=true;
  let copied='';ui.context.navigator.clipboard={writeText:async value=>{copied=value;}};
  ui.context.choose=async(title,_detail,_buttons,options)=>{assert.equal(title,'Backup JSON');assert.equal(options.backupJson,ui.downloads[0].json);ui.elements.get('question-backup-json').value=options.backupJson;await ui.elements.get('copy-question-backup-json').onclick();return 'cancel';};
  await assert.rejects(ui.evaluate('ensureBackup();'),/Preparation cancelled before reset or flash/);
  assert.equal(copied,ui.downloads[0].json);assert.equal(ui.evaluate('state.backupApproved'),null);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,['open','capture-backup','close']);
});

test('the backup window offers Stop and Continue, without a save claim or automatic clipboard write',async()=>{
  const ui=await backupJsonWorkbench();ui.context.pkg=fakePackage({architecture:'esp32'});ui.evaluate('state.pkg=pkg;');ui.elements.get('auto-backup').checked=true;
  let copied=0;ui.context.navigator.clipboard={writeText:async()=>copied++};
  ui.context.choose=async(title,detail,buttons,options)=>{
    assert.equal(title,'Backup JSON');assert.equal(detail,'');assert.deepEqual(Array.from(buttons,pair=>Array.from(pair)),[['stop','Stop'],['continue','Continue with flashing']]);assert.equal(options.backupJson,ui.downloads[0].json);assert.match(options.backupDetails,/Not backed up:/);assert.match(options.backupDetails,/Firmware and bootloader files/);assert.match(options.backupDetails,/Stored messages/);assert.match(options.backupDetails,/Runtime logs/);assert.doesNotMatch(options.backupDetails,/partial backup|incomplete backup|not protected/i);return 'continue';
  };
  await ui.evaluate('ensureBackup();');
  assert.equal(copied,0);assert.equal(ui.evaluate('state.backupApproved.port'),ui.port);assert.equal(ui.evaluate('state.backupApproved.sha256'),ui.context.pkg.sha256);assert.equal(ui.evaluate('state.plan'),null);
  assert.deepEqual(ui.calls,['open','capture-backup','close']);assert.equal(ui.elements.get('backups').open,false);
});

test('a device disconnect or firmware change during the backup window cannot approve preparation',async()=>{
  for(const change of ['disconnect','firmware']){
    const ui=await backupJsonWorkbench();ui.context.pkg=fakePackage({architecture:'esp32'});ui.evaluate('state.pkg=pkg;');ui.elements.get('auto-backup').checked=true;
    ui.context.choose=async()=>{if(change==='disconnect')ui.serialEvents.disconnect({port:ui.port});else ui.evaluate('state.pkg={...state.pkg,sha256:"different"};');return 'continue';};
    await assert.rejects(ui.evaluate('ensureBackup();'),/changed while the backup window was open/);
    assert.equal(ui.evaluate('state.backupApproved'),null);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,['open','capture-backup','close']);
  }
});

test('Continue displays exact uncaptured values and failed reads without a blanket partial warning or another prompt',async()=>{
  const ui=await backupJsonWorkbench();ui.context.pkg=fakePackage({architecture:'esp32'});ui.evaluate('state.pkg=pkg;');ui.elements.get('auto-backup').checked=true;
  ui.native.payload.sections={usb_logging:{state:'error',command:'get usb.logging'},radio_rxgain:{state:'unsupported',command:'get radio.rxgain'}};
  ui.context.backupSummary=()=>({complete:false,privateIdentity:false,reasons:['Unsupported query']});ui.context.choose=async(_title,_detail,_buttons,options)=>{assert.match(options.backupDetails,/USB logging preference/);assert.match(options.backupDetails,/RX gain/);assert.match(options.backupDetails,/read failed/i);assert.doesNotMatch(options.backupDetails,/partial backup|incomplete backup|automatic restore is unavailable|not protected/i);return 'continue';};
  ui.context.confirm=async()=>{throw Error('Coverage details must not require another typed prompt');};
  await ui.evaluate('ensureBackup();');assert.equal(ui.evaluate('state.backupApproved.port'),ui.port);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,['open','capture-backup','close']);
  assert.match(ui.elements.get('backup-summary').textContent,/Backup verified/);assert.match(ui.elements.get('backup-summary').textContent,/USB logging preference/);assert.doesNotMatch(ui.elements.get('backup-summary').textContent,/Partial backup/);assert.ok(!ui.elements.get('backup-summary').textContent.includes(ui.sentinel));
});

test('friendly coverage copy does not alter conservative archive metadata or grant flash permission',async()=>{
  const ui=await backupJsonWorkbench();ui.native.payload.completeness={status:'partial',safe_for_wipe:false,safe_for_restore:false,missing_required:[],optional_errors:[],reasons:[]};const metadata=JSON.stringify(ui.native.payload.completeness);await ui.elements.get('backup').onclick();
  assert.equal(JSON.stringify(ui.native.payload.completeness),metadata);assert.equal(ui.evaluate('state.backup.summary.complete'),false);assert.equal(ui.evaluate('state.backupApproved'),null);assert.equal(ui.evaluate('state.plan'),null);assert.match(ui.elements.get('backup-summary').textContent,/Backup verified/);assert.doesNotMatch(ui.elements.get('backup-summary').textContent,/partial backup|incomplete backup|erase is not protected/i);assert.deepEqual(ui.calls,['open','capture-backup','close']);
});

test('a real capture or checksum failure still requires explicit no-backup approval and never claims a verified backup',async()=>{
  for(const accepted of [false,true]){
    const ui=await backupJsonWorkbench();ui.context.pkg=fakePackage();ui.evaluate('state.pkg=pkg;');ui.elements.get('auto-backup').checked=true;ui.context.captureBackup=async()=>{throw Error('Archive checksum validation failed');};
    ui.context.confirm=async(title,detail,warning,action)=>{assert.equal(title,'Backup could not be created');assert.match(detail,/checksum validation failed/);assert.match(warning,/without a newly verified backup/);assert.equal(action,'CONTINUE WITHOUT BACKUP');return accepted;};
    if(accepted){await ui.evaluate('ensureBackup();');assert.equal(ui.evaluate('state.backupApproved.port'),ui.port);}else{await assert.rejects(ui.evaluate('ensureBackup();'),/checksum validation failed/);assert.equal(ui.evaluate('state.backupApproved'),null);}
    assert.equal(ui.evaluate('state.backup'),null);assert.equal(ui.downloads.length,0);assert.doesNotMatch(ui.elements.get('notice').textContent,/Backup verified/);assert.deepEqual(ui.calls,[]);
  }
});

test('Stop or Escape on either complete or partial backup prevents preparation and device reset',async()=>{
  for(const complete of [true,false])for(const answer of ['stop','cancel']){
    const ui=await backupJsonWorkbench();ui.context.pkg=fakePackage({architecture:'esp32'});ui.evaluate('state.pkg=pkg;');ui.elements.get('auto-backup').checked=true;
    ui.context.backupSummary=()=>({complete,privateIdentity:true,reasons:[]});ui.context.choose=async()=>answer;ui.context.confirm=async()=>{throw Error('Stop must not open another confirmation');};
    await assert.rejects(ui.evaluate('ensureBackup();'),/Backup stopped/);assert.equal(ui.evaluate('state.backupApproved'),null);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,['open','capture-backup','close']);
  }
});

test('nRF52 backup Continue enters DFU once without another typed prompt and Stop sends no reset',async()=>{
  for(const answer of ['continue','stop','cancel']){
    const ui=await backupJsonWorkbench();ui.context.pkg=fakePackage({architecture:'nrf52',kind:'application'});ui.evaluate('state.pkg=pkg;');ui.elements.get('auto-backup').checked=true;ui.elements.get('transport-mode').value='nrf52';
    ui.context.backupSummary=()=>({complete:false,privateIdentity:true,reasons:[]});
    ui.context.choose=async(title,_detail,buttons,options)=>{assert.equal(title,'Backup JSON');assert.deepEqual(Array.from(buttons,pair=>Array.from(pair)),[['stop','Stop'],['continue','Continue with flashing']]);assert.match(options.backupDetails,/Not backed up:/);assert.doesNotMatch(options.backupDetails,/partial backup/i);return answer;};
    ui.context.confirm=async()=>{throw Error('nRF52 DFU entry must not ask for another typed confirmation');};
    ui.context.touch1200=async(port,mode)=>{assert.equal(port,ui.port);assert.equal(mode,'nrf52');ui.calls.push('enter-dfu');};ui.context.flashNrf=async()=>{throw Error('DFU entry is not permission to write firmware');};
    await ui.elements.get('prepare').onclick();
    assert.deepEqual(ui.calls,answer==='continue'?['open','capture-backup','close','enter-dfu']:['open','capture-backup','close'],answer);
    assert.equal(ui.evaluate('state.plan'),null,answer);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg,answer);
    if(answer==='continue'){assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.evaluate('state.handoff'),true);assert.match(ui.elements.get('notice').textContent,/same radio.*DFU serial port/i);}
    else{assert.equal(ui.evaluate('state.port'),ui.port);assert.match(ui.elements.get('notice').textContent,/Backup stopped/);}
  }
});

async function queuedNrfPreparationWorkbench({action='prepare',wipe=false,disconnect=false,interrupted=false}={}){
  const ui=await backupJsonWorkbench(),dfuPort={getInfo:()=>({usbVendorId:0x2886,usbProductId:0x0057})};
  ui.port.getInfo=()=>({usbVendorId:0x239a,usbProductId:0x8029});ui.context.pkg=fakePackage();
  ui.evaluate('state.pkg=pkg;state.device={role:"companion",model:"Seeed Tracker T1000-E",architecture:"nrf52",publicKey:"11".repeat(32)};');
  ui.elements.get('auto-backup').checked=true;ui.elements.get('transport-mode').value='nrf52';
  if(wipe)ui.evaluate('state.installMode="install";syncInstallMode();');
  ui.context.choose=async title=>{assert.equal(title,'Backup JSON');ui.calls.push('backup-popup');return 'continue';};
  ui.context.confirm=async(_title,_detail,_warning,token)=>{assert.equal(token,'SAME DEVICE');ui.calls.push('confirm:'+token);return true;};
  ui.context.touch1200=async(port,kind)=>{
    assert.equal(port,ui.port);assert.equal(kind,'nrf52');ui.calls.push('enter-dfu');
    if(disconnect)ui.serialEvents.disconnect({port:ui.port});
    if(interrupted)throw Object.assign(Error('Final control request interrupted'),{name:'NetworkError',nrf52HandoffPending:true});
  };
  ui.context.flashNrf=async()=>assert.fail('DFU selection/preparation cannot flash firmware');
  ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');return dfuPort;};
  await ui.elements.get(action).onclick();
  return {...ui,dfuPort};
}

test('the second DFU selection finishes a queued preparation automatically without repeating backup or starting a write',async()=>{
  for(const options of [{},{disconnect:true},{interrupted:true},{disconnect:true,interrupted:true}]){
    const ui=await queuedNrfPreparationWorkbench(options),queued=ui.evaluate('state.nrfPrepareResume'),approval=ui.evaluate('state.backupApproved');
    assert.ok(queued);assert.ok(Object.isFrozen(queued));assert.equal(queued.pkg,ui.context.pkg);assert.equal(queued.sha256,ui.context.pkg.sha256);assert.equal(queued.approval,approval);assert.equal(queued.port,ui.port);assert.equal(queued.installMode,'update');
    assert.equal(ui.elements.get('prepare').disabled,true);assert.equal(ui.elements.get('flash').disabled,true);assert.equal(ui.elements.get('prepare-label').textContent,'Backup & prepare update (DFU)');
    assert.equal(ui.evaluate('state.plan'),null);assert.match(ui.elements.get('step-guidance').textContent,/preparation finishes automatically/i);
    const before=[...ui.calls];await ui.elements.get('select-port').onclick();
    assert.deepEqual(ui.calls,[...before,'chooser','confirm:SAME DEVICE']);assert.equal(ui.calls.filter(call=>call==='capture-backup').length,1);assert.equal(ui.calls.filter(call=>call==='enter-dfu').length,1);assert.equal(ui.downloads.length,1);
    assert.equal(ui.evaluate('state.nrfPrepareResume'),null);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);assert.equal(ui.evaluate('state.plan.port'),ui.dfuPort);assert.equal(ui.evaluate('state.plan.sha256'),ui.context.pkg.sha256);assert.equal(ui.evaluate('state.plan.installMode'),'update');assert.equal(ui.evaluate('state.plan.generation'),ui.evaluate('state.generation'));
    assert.equal(ui.evaluate('state.backupApproved.port'),ui.dfuPort);assert.equal(ui.evaluate('state.backupApproved.sha256'),ui.context.pkg.sha256);assert.equal(ui.elements.get('prepare').disabled,true);assert.equal(ui.elements.get('flash').disabled,false);assert.deepEqual(nextHighlight(ui),['flash']);
    assert.match(ui.elements.get('progress-label').textContent,/DFU ready\. Step 4/);assert.ok(!ui.calls.includes('confirm:FLASH'));assert.ok(ui.stored.every(([key])=>!/nrf.*prepar/i.test(key)));
  }
});

test('automatic DFU preparation still requires a new final step 4 confirmation before opening or writing DFU',async()=>{
  const ui=await queuedNrfPreparationWorkbench();await ui.elements.get('select-port').onclick();const before=[...ui.calls];
  ui.context.confirm=async(_title,_detail,_warning,token)=>{assert.equal(token,'FLASH');ui.calls.push('confirm:FLASH');return false;};
  await ui.elements.get('flash').onclick();assert.deepEqual(ui.calls,[...before,'confirm:FLASH']);assert.ok(ui.evaluate('state.plan'));assert.equal(ui.evaluate('state.verification'),null);
  ui.context.confirm=async(_title,_detail,_warning,token)=>{assert.equal(token,'FLASH');ui.calls.push('confirm:FLASH');return true;};ui.context.flashNrf=async(_link,pkg)=>{assert.equal(pkg,ui.context.pkg);ui.calls.push('write-final');};
  await ui.elements.get('flash').onclick();assert.deepEqual(ui.calls.slice(before.length),['confirm:FLASH','confirm:FLASH','open','write-final','close']);assert.equal(ui.calls.filter(call=>call==='enter-dfu').length,1);assert.equal(ui.evaluate('state.verification.sha256'),ui.context.pkg.sha256);
});

test('manual nRF52 Touch and generic remembered handoffs cannot create automatic preparation permission',async()=>{
  const manual=await queuedNrfPreparationWorkbench({action:'touch'});assert.equal(manual.evaluate('state.nrfPrepareResume'),null);const before=[...manual.calls];await manual.elements.get('select-port').onclick();
  assert.equal(manual.evaluate('state.plan'),null);assert.deepEqual(manual.calls,[...before,'chooser','confirm:SAME DEVICE']);assert.equal(manual.calls.filter(call=>call==='enter-dfu').length,1);
  const generic=workbench();await Promise.resolve();generic.context.selectedPort=generic.port;generic.context.pkg=fakePackage();generic.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0057});
  generic.evaluate('state.pkg=pkg;state.handoff=true;state.backupApproved={sha256:pkg.sha256,port:{},publicKey:"11".repeat(32)};');generic.context.confirm=async()=>{generic.calls.push('same-device');return true;};generic.context.prepareSelectedFirmware=async()=>assert.fail('An old handoff is not queued preparation');
  await generic.elements.get('select-port').onclick();assert.equal(generic.evaluate('state.plan'),null);assert.equal(generic.evaluate('state.nrfPrepareResume'),null);assert.deepEqual(generic.calls,['chooser','same-device']);
});

test('queued DFU preparation is bound to the exact package object, digest, mode and original backup approval',async()=>{
  for(const change of ['package-object','digest','mode','approval-object','approval-digest','approval-port','approval-public-key','approval-skipped','approval-source']){
    const ui=await queuedNrfPreparationWorkbench();
    if(change==='package-object'){ui.context.replacement=fakePackage();ui.evaluate('state.pkg=replacement;');}
    if(change==='digest')ui.evaluate('state.pkg.sha256="c".repeat(64);');
    if(change==='mode')ui.evaluate('state.installMode="install";');
    if(change==='approval-object')ui.evaluate('state.backupApproved={...state.backupApproved};');
    if(change==='approval-digest')ui.evaluate('state.backupApproved.sha256="c".repeat(64);');
    if(change==='approval-port')ui.evaluate('state.backupApproved.port={};');
    if(change==='approval-public-key')ui.evaluate('state.backupApproved.publicKey="22".repeat(32);');
    if(change==='approval-skipped')ui.evaluate('state.backupApproved.skipped=true;');
    if(change==='approval-source')ui.evaluate('state.backupApproved.sourceFirmware="meshtastic";');
    const before=[...ui.calls];await ui.elements.get('select-port').onclick();
    assert.equal(ui.evaluate('state.nrfPrepareResume'),null,change);assert.equal(ui.evaluate('state.plan'),null,change);assert.equal(ui.evaluate('state.backupApproved'),null,change);assert.deepEqual(ui.calls,[...before,'chooser','confirm:SAME DEVICE'],change);assert.match(ui.elements.get('notice').textContent,/changed during USB handoff/i,change);
  }
});

test('manual connection or backup overrides cancel queued DFU preparation without sending another reset',async()=>{
  for(const id of ['transport-mode','skip-backup','already-bootloader']){
    const ui=await queuedNrfPreparationWorkbench(),before=[...ui.calls];
    if(id==='transport-mode')ui.elements.get(id).value='nrf52';else ui.elements.get(id).checked=true;
    await ui.elements.get(id).onchange();
    assert.equal(ui.evaluate('state.nrfPrepareResume'),null,id);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg,id);assert.equal(ui.evaluate('state.plan'),null,id);assert.deepEqual(ui.calls,before,id);
  }
});

test('an unrecognized DFU interface can be explicitly marked as bootloader and then prepared manually without a second reset',async()=>{
  const ui=await queuedNrfPreparationWorkbench(),unknownPort={getInfo:()=>({usbVendorId:0x1209,usbProductId:0x0001})};
  ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('unknown-port-chooser');return unknownPort;};await ui.elements.get('select-port').onclick();assert.ok(ui.evaluate('state.nrfPrepareResume'));
  const before=[...ui.calls];ui.elements.get('already-bootloader').checked=true;await ui.elements.get('already-bootloader').onchange();assert.equal(ui.evaluate('state.nrfPrepareResume'),null);assert.deepEqual(ui.calls,before);assert.match(ui.elements.get('notice').textContent,/Manual bootloader selection accepted.*without another reset/);
  ui.context.choose=async(_title,_detail,buttons)=>{assert.ok(buttons.some(([value])=>value==='skip'));ui.calls.push('explicit-backup-decision');return 'skip';};
  await ui.elements.get('prepare').onclick();assert.equal(ui.evaluate('state.plan.port'),unknownPort);assert.equal(ui.calls.filter(call=>call==='enter-dfu').length,1);assert.equal(ui.calls.filter(call=>call==='capture-backup').length,1);assert.deepEqual(nextHighlight(ui),['flash']);assert.ok(!ui.calls.some(call=>call.startsWith('write-')));
});

test('choosing an application or unknown port during queued DFU preparation cannot send a second reset',async()=>{
  for(const wrongPortKind of ['application','unknown']){
    const ui=await queuedNrfPreparationWorkbench(),queued=ui.evaluate('state.nrfPrepareResume'),approval=ui.evaluate('state.backupApproved');
    const wrongPort=wrongPortKind==='application'?ui.port:{getInfo:()=>({usbVendorId:0x1209,usbProductId:0x0001})};
    ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('wrong-port-chooser');return wrongPort;};const before=[...ui.calls];
    await ui.elements.get('select-port').onclick();assert.equal(ui.evaluate('state.nrfPrepareResume'),queued);assert.equal(ui.evaluate('state.backupApproved'),approval);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,[...before,'wrong-port-chooser','confirm:SAME DEVICE']);assert.deepEqual(nextHighlight(ui),['select-port']);assert.match(ui.elements.get('notice').textContent,/not a recognized DFU port.*No second reset/);
    ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('correct-port-chooser');return ui.dfuPort;};await ui.elements.get('select-port').onclick();
    assert.equal(ui.evaluate('state.nrfPrepareResume'),null);assert.equal(ui.evaluate('state.plan.port'),ui.dfuPort);assert.equal(ui.calls.filter(call=>call==='capture-backup').length,1);assert.equal(ui.calls.filter(call=>call==='enter-dfu').length,1);assert.deepEqual(nextHighlight(ui),['flash']);
  }
});

test('cancelling the DFU chooser preserves its queued preparation, while declining same-radio confirmation consumes no write permission',async()=>{
  const ui=await queuedNrfPreparationWorkbench(),queued=ui.evaluate('state.nrfPrepareResume'),approval=ui.evaluate('state.backupApproved');
  ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('cancelled-chooser');throw Object.assign(Error('No port selected by the user.'),{name:'NotFoundError'});};const before=[...ui.calls];
  await ui.elements.get('select-port').onclick();assert.equal(ui.evaluate('state.nrfPrepareResume'),queued);assert.equal(ui.evaluate('state.backupApproved'),approval);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,[...before,'cancelled-chooser']);
  ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');return ui.dfuPort;};ui.context.confirm=async()=>{ui.calls.push('decline-same-device');return false;};
  await ui.elements.get('select-port').onclick();assert.equal(ui.evaluate('state.nrfPrepareResume'),null);assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.calls.filter(call=>call==='enter-dfu').length,1);assert.match(ui.elements.get('notice').textContent,/confirmation cancelled/);
});

test('a disconnect or newly protected flow during same-device confirmation stops queued preparation before reset or write',async()=>{
  for(const change of ['disconnect','generation','package','verification','migration']){
    const ui=await queuedNrfPreparationWorkbench();let finish;
    ui.context.confirm=async()=>{ui.calls.push('pending-same-device');return new Promise(resolve=>{finish=resolve;});};
    const pending=ui.elements.get('select-port').onclick();for(let i=0;i<10&&!finish;i++)await Promise.resolve();assert.ok(finish,change);
    if(change==='disconnect')ui.serialEvents.disconnect({port:ui.dfuPort});
    if(change==='generation')ui.evaluate('state.generation++;');
    if(change==='package'){ui.context.replacement=fakePackage({sha256:'c'.repeat(64)});ui.evaluate('state.pkg=replacement;');}
    if(change==='verification')ui.evaluate('state.verification={sha256:pkg.sha256};');
    if(change==='migration')ui.evaluate('state.migration={};');
    finish(true);await pending;
    assert.equal(ui.evaluate('state.nrfPrepareResume'),null,change);assert.equal(ui.evaluate('state.plan'),null,change);assert.equal(ui.calls.filter(call=>call==='enter-dfu').length,1,change);assert.ok(ui.calls.every(call=>!call.startsWith('write')),change);
  }
});

test('queued Install preparation validates erase files but preserves separate erase consent and final-image reselection',async()=>{
  const ui=await queuedNrfPreparationWorkbench({wipe:true});ui.context.erase=fakePackage({name:'erase.zip',erase:true,destructive:true});ui.context.erasePackage=async()=>{ui.calls.push('validate-erase');return ui.context.erase;};
  const before=[...ui.calls];await ui.elements.get('select-port').onclick();assert.deepEqual(ui.calls,[...before,'chooser','confirm:SAME DEVICE','validate-erase']);assert.equal(ui.evaluate('state.plan.erasePkg'),ui.context.erase);assert.equal(ui.evaluate('state.plan.installMode'),'install');assert.deepEqual(nextHighlight(ui),['flash']);
  ui.context.confirm=async(_title,_detail,_warning,token)=>{assert.equal(token,'WIPE WITHOUT BACKUP');ui.calls.push('confirm:'+token);return false;};await ui.elements.get('flash').onclick();assert.ok(ui.evaluate('state.plan'));assert.ok(!ui.calls.some(call=>call.startsWith('write-')));
  ui.context.confirm=async()=>true;ui.context.flashNrf=async(_link,pkg)=>{assert.equal(pkg,ui.context.erase);ui.calls.push('write-erase');};await ui.elements.get('flash').onclick();
  assert.equal(ui.evaluate('state.recovery.phase'),'reselect-dfu');assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);assert.deepEqual(ui.calls.filter(call=>call.startsWith('write-')),['write-erase']);assert.equal(ui.calls.filter(call=>call==='enter-dfu').length,1);
});

test('queued preparation is not restored from storage and invalidating firmware removes its one-time continuation',async()=>{
  const ui=await queuedNrfPreparationWorkbench();assert.ok(ui.evaluate('state.nrfPrepareResume'));ui.evaluate('invalidateFirmwareSelection();');assert.equal(ui.evaluate('state.nrfPrepareResume'),null);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);
  const fresh=workbench();await Promise.resolve();assert.equal(fresh.evaluate('state.nrfPrepareResume'),null);assert.deepEqual(fresh.calls,[]);
});

test('prepare labels mention DFU only for an nRF52 image or connection and retain update or install wording',async()=>{
  for(const mode of ['update','install'])for(const connection of ['nrf52-application','nrf52-dfu','nrf52-package','esp32']){
    const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.evaluate(`state.port=selectedPort;state.installMode='${mode}';`);
    if(connection==='nrf52-dfu')ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0057});
    else if(connection==='nrf52-package'){ui.context.pkg=fakePackage();ui.evaluate('state.port=null;state.pkg=pkg;');}
    else ui.evaluate(`state.device={architecture:'${connection==='esp32'?'esp32':'nrf52'}'};`);
    ui.evaluate('controls();');
    const suffix=connection==='esp32'?'':' (DFU)';assert.equal(ui.elements.get('prepare-label').textContent,`Backup & prepare ${mode}${suffix}`,connection+' '+mode);assert.equal(ui.elements.get('prepare').getAttribute('aria-label'),`Step 3: Backup and prepare ${mode}${suffix}`,connection+' '+mode);assert.deepEqual(ui.calls,[]);
  }
});

test('explicit nRF52 Enter USB bootloader uses the considered backup without a repeated typed entry prompt',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.evaluate('state.port=selectedPort;');ui.elements.get('transport-mode').value='nrf52';
  ui.context.ensureBackup=async()=>ui.calls.push('backup-considered');ui.context.confirm=async()=>{throw Error('Explicit DFU action must not ask for another typed confirmation');};
  ui.context.touch1200=async(port,mode)=>{assert.equal(port,ui.port);assert.equal(mode,'nrf52');ui.calls.push('enter-dfu');};
  await ui.elements.get('touch').onclick();assert.deepEqual(ui.calls,['backup-considered','enter-dfu']);assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.evaluate('state.handoff'),true);assert.equal(ui.evaluate('state.plan'),null);
});

test('an interrupted final nRF52 reset request guides DFU selection instead of reporting a flash error',async()=>{
  for(const action of ['prepare','touch'])for(const disconnected of [false,true]){
    const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage();
    ui.evaluate('state.port=selectedPort;state.pkg=pkg;state.device={model:"Seeed Tracker T1000-E",role:"companion"};');ui.elements.get('transport-mode').value='nrf52';
    ui.context.ensureBackup=async()=>ui.calls.push('backup-considered');
    ui.context.touch1200=async(port,kind)=>{assert.equal(port,ui.port);assert.equal(kind,'nrf52');ui.calls.push('enter-dfu');if(disconnected)ui.serialEvents.disconnect({port:ui.port});throw Object.assign(Error('Failed to set control signals.'),{name:'NetworkError',nrf52HandoffPending:true});};
    await ui.elements.get(action).onclick();
    assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.handoff'),true);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);
    assert.match(ui.elements.get('notice').textContent,/SAME radio.*DFU serial port/);assert.doesNotMatch(ui.elements.get('notice').textContent,/Failed|Stopped/);
    assert.match(ui.elements.get('progress-label').textContent,/Step 1.*same radio.*DFU/);assert.deepEqual(nextHighlight(ui),['select-port']);assert.deepEqual(ui.calls,['backup-considered','enter-dfu']);
  }
});

test('nRF52 open, permission and early reset failures remain errors and never pretend DFU was requested',async()=>{
  for(const action of ['prepare','touch'])for(const name of ['NotAllowedError','SecurityError','NetworkError','Error']){
    const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage();ui.evaluate('state.port=selectedPort;state.pkg=pkg;');ui.elements.get('transport-mode').value='nrf52';
    ui.context.ensureBackup=async()=>{};ui.context.touch1200=async()=>{ui.calls.push('reset-attempt');throw Object.assign(Error('Original failure before final DTR'),{name});};
    await ui.elements.get(action).onclick();assert.equal(ui.evaluate('state.handoff'),false);assert.equal(ui.evaluate('state.port'),ui.port);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);assert.match(ui.elements.get('notice').textContent,/Original failure/);assert.deepEqual(ui.calls,['reset-attempt']);
  }
});

test('uncaptured-values summary belongs to its active popup only and never leaks into a generic question',async()=>{
  const ui=await backupJsonWorkbench();await ui.elements.get('backup').onclick();ui.context.json=ui.downloads[0].json;let close;
  ui.context.document.createElement=()=>uiElement();ui.elements.get('question-dialog').addEventListener=(_event,handler)=>{close=handler;};
  const pending=ui.evaluate("choose('Backup JSON','',[['stop','Stop'],['continue','Continue with flashing']],{backupJson:json,backupDetails:'Not backed up: Stored messages; runtime logs.'});");
  assert.equal(ui.elements.get('question-backup-summary').hidden,false);assert.match(ui.elements.get('question-backup-summary').textContent,/Not backed up: Stored messages/);
  const actions=ui.elements.get('question-actions').options;assert.deepEqual(actions.map(button=>[button.value,button.textContent,button.className]),[['stop','Stop','secondary'],['continue','Continue with flashing','primary']]);
  ui.elements.get('question-dialog').returnValue='continue';close();assert.equal(await pending,'continue');assert.equal(ui.elements.get('question-backup-summary').textContent,'');assert.equal(ui.elements.get('question-backup-summary').hidden,true);
  const other=ui.evaluate("choose('Other question','Details',[['cancel','Cancel']]);");assert.equal(ui.elements.get('question-backup-summary').hidden,true);close();await other;
});

test('failed captures and changed ports during export cannot display stale JSON or grant saved-backup approval',async()=>{
  for(const failure of ['capture','seal','port']){
    const ui=await backupJsonWorkbench();await ui.elements.get('backup').onclick();const old=ui.downloads[0].json;ui.elements.get('question-backup-json').value=old;ui.elements.get('question-backup-json-view').hidden=false;
    ui.context.savedApproval={sha256:'a'.repeat(64),port:ui.port};ui.evaluate('state.backupApproved=savedApproval;');
    if(failure==='capture')ui.context.MeshCore=class{async backup(){assert.equal(ui.evaluate('state.backupApproved'),null);throw Error('Backup query failed');}};
    else ui.context.exportNativeBackup=async()=>{if(failure==='seal')throw Error('Native backup validation failed');ui.serialEvents.disconnect({port:ui.port});return ui.native;};
    await ui.elements.get('backup').onclick();
    for(const prefix of ['backup','question-backup']){assert.equal(ui.elements.get(prefix+'-json').value,'',failure);assert.equal(ui.elements.get(prefix+'-json-view').hidden,true,failure);}
    assert.equal(ui.evaluate('state.backup'),null,failure);assert.equal(ui.evaluate('state.backupApproved'),null,failure);assert.equal(ui.downloads.length,1,failure);assert.ok(!ui.elements.get('log').textContent.includes(ui.sentinel),failure);
  }
});

test('selecting another radio or invalidating application evidence clears visible backup secrets',async()=>{
  for(const action of ['new-radio','application-change']){
    const ui=await backupJsonWorkbench();await ui.elements.get('backup').onclick();ui.elements.get('question-backup-json').value=ui.downloads[0].json;ui.elements.get('question-backup-json-view').hidden=false;
    if(action==='new-radio'){ui.context.navigator.serial.requestPort=async()=>({getInfo:ui.port.getInfo});await ui.elements.get('select-port').onclick();}
    else ui.evaluate('invalidateApplicationEvidence();');
    for(const prefix of ['backup','question-backup']){assert.equal(ui.elements.get(prefix+'-json').value,'',action);assert.equal(ui.elements.get(prefix+'-json-view').hidden,true,action);}
    assert.equal(ui.evaluate('state.backup'),null,action);assert.equal(ui.evaluate('state.backupApproved'),null,action);assert.equal(ui.downloads.length,1,action);
  }
});
test('cancelling the backup offer prevents all reset and ROM operations',async()=>{
  const ui=workbench();ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage({architecture:'esp32'});ui.evaluate('state.port=selectedPort;state.pkg=pkg;');ui.context.choose=async()=> 'cancel';
  await ui.elements.get('prepare').onclick();assert.deepEqual(ui.calls,[]);assert.match(ui.elements.get('notice').textContent,/Cancelled before reset/);
});
async function dfuBackupApplicationWorkbench({known=true,available=true,publicKey='11'.repeat(32),role='companion'}={}){
  const ui=workbench();await Promise.resolve();
  const dfuPort=ui.port,appPort={getInfo:()=>({usbVendorId:0x239a,usbProductId:0x8029})};
  dfuPort.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0057});
  ui.context.dfuPort=dfuPort;ui.context.appPort=appPort;ui.context.pkg=fakePackage();ui.context.expectedBackupKey=publicKey;
  ui.context.backupApplicationDevice={role,publicKey,model:'Seeed Tracker T1000-E',name:'Fixture radio',protocol:14,architecture:'nrf52'};
  ui.evaluate('state.port=dfuPort;state.pkg=pkg;state.handoff=true;state.device={role:"companion",model:"Previous application"};');
  ui.elements.get('transport-mode').value='nrf52';ui.elements.get('already-bootloader').checked=true;
  if(known)ui.evaluate(`state.knownApplicationPort={port:appPort,publicKey:expectedBackupKey,available:${available}};`);
  ui.context.SerialLink=class{
    constructor(port){assert.equal(port,appPort,'DFU and same-ID substitute ports must never be opened for a backup probe');}
    async open(baudRate,options){assert.equal(baudRate,115200);assert.equal(options?.application,true);ui.calls.push('application-open');}
    async close(){assert.notEqual(ui.evaluate('state.port'),appPort,'Adoption must wait for successful close');ui.calls.push('application-close');}
    async command(){assert.fail('The fixture application detector must not send extra settings/reset commands');}
  };
  ui.context.detectMeshCore=async()=>{ui.calls.push('application-detect');return {...ui.context.backupApplicationDevice};};
  ui.context.touch1200=async()=>assert.fail('Backup reconnect must never reset the DFU or application radio');
  ui.context.flashNrf=async()=>assert.fail('Backup reconnect must never write firmware');
  return {...ui,dfuPort,appPort};
}

test('DFU backup without an eligible exact known application asks for help without opening or enumerating USB',async()=>{
  for(const mode of ['missing','unavailable','invalid-key','dfu-port']){
    const ui=await dfuBackupApplicationWorkbench({known:mode!=='missing',available:mode!=='unavailable',publicKey:mode==='invalid-key'?'invalid':'11'.repeat(32)});
    if(mode==='dfu-port')ui.evaluate('state.knownApplicationPort.port=dfuPort;');
    assert.equal(await ui.evaluate('tryBackupApplication();'),false,mode);
    assert.ok(ui.evaluate('state.backupApplicationRequest'),mode);assert.equal(ui.evaluate('state.port'),ui.dfuPort,mode);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg,mode);
    assert.match(ui.elements.get('notice').textContent,/application|DFU|backup/i,mode);assert.deepEqual(ui.calls,[],mode);
  }
});

test('DFU backup reuses only the exact known application, proves its key and closes before adopting it',async()=>{
  for(const role of ['companion','common-cli']){
    const ui=await dfuBackupApplicationWorkbench({role});ui.evaluate('state.plan={written:false};state.backupApproved={port:dfuPort,sha256:pkg.sha256};');
    assert.equal(await ui.evaluate('tryBackupApplication();'),true,role);
    assert.equal(ui.evaluate('state.port'),ui.appPort,role);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg,role);assert.equal(ui.evaluate('state.device.publicKey'),'11'.repeat(32),role);
    assert.equal(ui.evaluate('state.backupApplicationRequest'),null,role);assert.equal(ui.evaluate('state.handoff'),false,role);assert.equal(ui.evaluate('state.plan'),null,role);assert.equal(ui.evaluate('state.backupApproved'),null,role);
    assert.equal(ui.elements.get('already-bootloader').checked,false,role);assert.deepEqual(ui.calls,['application-open','application-detect','application-close'],role);
  }
});

test('DFU backup cannot adopt a different application identity or an unsupported application role',async()=>{
  for(const scenario of ['wrong-key','missing-key','invalid-key','meshtastic','unknown-role']){
    const ui=await dfuBackupApplicationWorkbench();
    if(scenario==='wrong-key')ui.context.backupApplicationDevice.publicKey='22'.repeat(32);
    if(scenario==='missing-key')delete ui.context.backupApplicationDevice.publicKey;
    if(scenario==='invalid-key')ui.context.backupApplicationDevice.publicKey='not-a-key';
    if(scenario==='meshtastic')ui.context.backupApplicationDevice.role='meshtastic';
    if(scenario==='unknown-role')ui.context.backupApplicationDevice.role='unsupported';
    const oldDevice=ui.evaluate('state.device');
    assert.equal(await ui.evaluate('tryBackupApplication();'),false,scenario);
    assert.equal(ui.evaluate('state.port'),ui.dfuPort,scenario);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg,scenario);assert.equal(ui.evaluate('state.device'),oldDevice,scenario);assert.equal(ui.evaluate('state.backupApproved'),null,scenario);
    assert.deepEqual(ui.calls,['application-open','application-detect','application-close'],scenario);
  }
});

test('DFU backup read and close failures never adopt or reset a radio',async()=>{
  for(const phase of ['open','detect','close']){
    const ui=await dfuBackupApplicationWorkbench(),failure=Error('Fixture '+phase+' failure');
    if(phase==='open')ui.context.SerialLink.prototype.open=async()=>{ui.calls.push('application-open');throw failure;};
    if(phase==='detect')ui.context.detectMeshCore=async()=>{ui.calls.push('application-detect');throw failure;};
    if(phase==='close')ui.context.SerialLink.prototype.close=async()=>{assert.equal(ui.evaluate('state.port'),ui.dfuPort);ui.calls.push('application-close');throw failure;};
    assert.equal(await ui.evaluate('tryBackupApplication();'),false,phase);
    assert.equal(ui.evaluate('state.port'),ui.dfuPort,phase);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg,phase);assert.ok(ui.evaluate('state.backupApplicationRequest'),phase);assert.equal(ui.evaluate('state.backupApproved'),null,phase);
    assert.ok(ui.calls.every(call=>/^application-(?:open|detect|close)$/.test(call)),phase);
  }
});

test('a late DFU backup application read rejects changed context without replacing new requests or showing stale reboot help',async()=>{
  for(const change of ['generation','port','firmware','request','known-application','protected-flow']){
    const ui=await dfuBackupApplicationWorkbench();let finish;
    ui.context.detectMeshCore=()=>{ui.calls.push('application-detect');return new Promise(resolve=>{finish=resolve;});};
    const pending=ui.evaluate('tryBackupApplication();');for(let i=0;i<10&&!finish;i++)await Promise.resolve();assert.ok(finish,change);
    if(change==='generation')ui.evaluate('state.generation++;');
    if(change==='port'){ui.context.nextPort={getInfo:()=>({usbVendorId:0x2886,usbProductId:0x0044})};ui.evaluate('state.port=nextPort;');}
    if(change==='firmware'){ui.context.nextPackage=fakePackage({name:'new.zip',sha256:'c'.repeat(64)});ui.evaluate('state.pkg=nextPackage;');}
    if(change==='request')ui.evaluate('state.backupApplicationRequest={expectedPublicKey:"22".repeat(32)};');
    if(change==='known-application')ui.evaluate('state.knownApplicationPort={port:appPort,publicKey:"22".repeat(32),available:true};');
    if(change==='protected-flow')ui.evaluate('state.verification={sha256:pkg.sha256};');
    const selectedPort=ui.evaluate('state.port'),selectedPackage=ui.evaluate('state.pkg'),selectedRequest=ui.evaluate('state.backupApplicationRequest');
    ui.elements.get('backup-application-status').textContent='Newer workflow guidance';ui.elements.get('backup-application-help').hidden=true;
    finish({...ui.context.backupApplicationDevice});
    await assert.rejects(pending,/changed|pending|finish|verification/i,change);assert.equal(ui.evaluate('state.port'),selectedPort,change);assert.equal(ui.evaluate('state.pkg'),selectedPackage,change);assert.notEqual(ui.evaluate('state.port'),ui.appPort,change);
    assert.equal(ui.evaluate('state.backupApplicationRequest'),selectedRequest,change);assert.equal(ui.elements.get('backup-application-status').textContent,'Newer workflow guidance',change);assert.equal(ui.elements.get('backup-application-help').hidden,true,change);
    assert.deepEqual(ui.calls,['application-open','application-detect','application-close'],change);
  }
});

test('a rejected backup application read or close still propagates stale context without reopening reboot help',async()=>{
  for(const phase of ['detect','close']){
    const ui=await dfuBackupApplicationWorkbench();let rejectRead;
    if(phase==='detect')ui.context.detectMeshCore=()=>{ui.calls.push('application-detect');return new Promise((_resolve,reject)=>{rejectRead=reject;});};
    else ui.context.SerialLink.prototype.close=()=>{ui.calls.push('application-close');return new Promise((_resolve,reject)=>{rejectRead=reject;});};
    const pending=ui.evaluate('tryBackupApplication();');for(let i=0;i<12&&!rejectRead;i++)await Promise.resolve();assert.ok(rejectRead,phase);
    ui.evaluate('state.generation++;');ui.elements.get('backup-application-status').textContent='New state';ui.elements.get('backup-application-help').hidden=true;
    rejectRead(Object.assign(Error('The old application disconnected'),{name:'NetworkError'}));
    await assert.rejects(pending,/changed/i,phase);assert.equal(ui.evaluate('state.backupApplicationRequest'),null,phase);assert.equal(ui.evaluate('state.port'),ui.dfuPort,phase);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg,phase);
    assert.equal(ui.elements.get('backup-application-status').textContent,'New state',phase);assert.equal(ui.elements.get('backup-application-help').hidden,true,phase);assert.deepEqual(ui.calls,['application-open','application-detect','application-close'],phase);
  }
});

test('DFU backup permission, access and security failures propagate without reboot-help or informational waiting',async()=>{
  for(const phase of ['open','detect','close'])for(const [name,message] of [['NotAllowedError','Port permission refused'],['SecurityError','USB security restriction'],['Error','Permission denied'],['NetworkError','Access is denied']]){
    const ui=await dfuBackupApplicationWorkbench(),failure=Object.assign(Error(message),{name});
    if(phase==='open')ui.context.SerialLink.prototype.open=async()=>{ui.calls.push('application-open');throw failure;};
    if(phase==='detect')ui.context.detectMeshCore=async()=>{ui.calls.push('application-detect');throw failure;};
    if(phase==='close')ui.context.SerialLink.prototype.close=async()=>{ui.calls.push('application-close');throw failure;};
    ui.elements.get('backup-application-status').textContent='Existing guidance';ui.elements.get('backup-application-help').hidden=true;
    await assert.rejects(ui.evaluate('tryBackupApplication();'),error=>error===failure,phase+' '+name);
    assert.equal(ui.evaluate('state.backupApplicationRequest'),null);assert.equal(ui.evaluate('state.port'),ui.dfuPort);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);
    assert.equal(ui.elements.get('backup-application-status').textContent,'Existing guidance');assert.equal(ui.elements.get('backup-application-help').hidden,true);
    assert.ok(ui.calls.every(call=>/^application-(?:open|detect|close)$/.test(call)));
  }
  const ui=await dfuBackupApplicationWorkbench();ui.context.SerialLink.prototype.open=async()=>{ui.calls.push('application-open');throw Object.assign(Error('Access is denied'),{name:'NotAllowedError'});};
  await ui.elements.get('backup').onclick();assert.equal(ui.elements.get('notice').classList.contains('error'),true);assert.match(ui.elements.get('log').textContent,/Stopped: Access is denied/);assert.doesNotMatch(ui.elements.get('log').textContent,/Backup waiting/);assert.equal(ui.evaluate('state.backupApplicationRequest'),null);
});

test('DFU backup application recovery is blocked by pending write, verification, migration and ROM sessions',async()=>{
  for(const field of ['migration','migrationApproval','recovery','espRecovery','verification','written-plan','esp','flashProgress']){
    const ui=await dfuBackupApplicationWorkbench();
    if(field==='written-plan')ui.evaluate('state.plan={written:true};');else ui.evaluate(`state.${field}={};`);
    let result;try{result=await ui.evaluate('tryBackupApplication();');}catch(error){assert.match(error.message,/pending|finish|migration|recovery|verification|session|write/i,field);}
    assert.notEqual(result,true,field);assert.equal(ui.evaluate('state.port'),ui.dfuPort,field);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg,field);assert.deepEqual(ui.calls,[],field);
  }
});

test('standalone DFU backup stops for application reconnection rather than pretending a backup or flash succeeded',async()=>{
  const ui=await dfuBackupApplicationWorkbench({known:false});
  await assert.rejects(ui.evaluate('captureBackup();'),/application|DFU|backup/i);
  assert.ok(ui.evaluate('state.backupApplicationRequest'));assert.equal(ui.evaluate('state.backup'),null);assert.equal(ui.evaluate('state.backupApproved'),null);assert.deepEqual(ui.calls,[]);
  await ui.elements.get('backup').onclick();
  assert.equal(ui.elements.get('notice').classList.contains('error'),false);assert.match(ui.elements.get('log').textContent,/Backup waiting:/);assert.doesNotMatch(ui.elements.get('log').textContent,/Stopped:/);assert.deepEqual(ui.calls,[]);
});

test('DFU backup chooser cancellation preserves pending help and sends no automatic continuation',async()=>{
  const ui=await dfuBackupApplicationWorkbench({available:false});assert.equal(await ui.evaluate('tryBackupApplication();'),false);
  const pending=ui.evaluate('state.backupApplicationRequest');ui.context.requestAutomaticVerification=()=>assert.fail('Cancel must not run later device work');
  ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');throw Object.assign(Error('No port selected by the user.'),{name:'NotFoundError'});};
  await ui.elements.get('select-backup-application').onclick();
  assert.equal(ui.evaluate('state.backupApplicationRequest'),pending);assert.equal(ui.evaluate('state.port'),ui.dfuPort);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);assert.deepEqual(ui.calls,['chooser']);
});

test('selecting a DFU port again for backup does not send application commands or flash',async()=>{
  const ui=await dfuBackupApplicationWorkbench({available:false});assert.equal(await ui.evaluate('tryBackupApplication();'),false);
  ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');return ui.dfuPort;};ui.context.captureBackup=async()=>assert.fail('DFU selection is not an application backup');
  await ui.elements.get('select-backup-application').onclick();
  assert.equal(ui.evaluate('state.port'),ui.dfuPort);assert.ok(ui.evaluate('state.backupApplicationRequest'));assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);assert.deepEqual(ui.calls,['chooser']);
});

test('explicit backup application selection reads identity then captures a backup without firmware continuation',async()=>{
  for(const matching of [true,false]){
    const ui=await dfuBackupApplicationWorkbench({available:false});assert.equal(await ui.evaluate('tryBackupApplication();'),false);
    ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');return ui.appPort;};
    if(!matching)ui.context.backupApplicationDevice.publicKey='22'.repeat(32);
    ui.context.captureBackup=async()=>{assert.equal(ui.evaluate('state.port'),ui.appPort);ui.calls.push('capture-backup');};
    await ui.elements.get('select-backup-application').onclick();
    assert.equal(ui.evaluate('state.port'),matching?ui.appPort:ui.dfuPort);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);
    assert.deepEqual(ui.calls,['chooser','application-open','application-detect','application-close',...(matching?['capture-backup']:[])],String(matching));
  }
});

test('an explicitly chosen application without previous identity is backup-only and discards old firmware and board choices',async()=>{
  const ui=await dfuBackupApplicationWorkbench({known:false});assert.equal(await ui.evaluate('tryBackupApplication();'),false);
  ui.evaluate('state.manualSelections={provider:"Keymind Cascade",hardware:"Heltec v4",role:"repeater",version:"v1.18.0.1"};state.item={hardware:"Heltec v4",role:"repeater",name:pkg.name};');
  for(const [id,value] of [['hardware','Heltec v4'],['role','repeater'],['version','v1.18.0.1'],['artifact','0']])ui.elements.get(id).value=value;
  ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');return ui.appPort;};
  ui.context.captureBackup=async()=>{assert.equal(ui.evaluate('state.port'),ui.appPort);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.item'),null);ui.calls.push('capture-backup');};
  await ui.elements.get('select-backup-application').onclick();
  assert.equal(ui.evaluate('state.port'),ui.appPort);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.item'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.backupApproved'),null);assert.equal(ui.evaluate('state.backupApplicationRequest'),null);
  for(const id of ['hardware','role','version','artifact'])assert.equal(ui.elements.get(id).value,'',id);
  for(const key of ['hardware','role','version'])assert.equal(ui.evaluate('state.manualSelections.'+key),undefined,key);
  assert.deepEqual(ui.calls,['chooser','application-open','application-detect','application-close','capture-backup']);
});

test('retry and cancel backup application help are explicit and never reset or write firmware',async()=>{
  const ui=await dfuBackupApplicationWorkbench({available:false});assert.equal(await ui.evaluate('tryBackupApplication();'),false);
  ui.evaluate('state.knownApplicationPort.available=true;');ui.context.captureBackup=async()=>ui.calls.push('capture-backup');
  await ui.elements.get('retry-backup-application').onclick();
  assert.equal(ui.evaluate('state.port'),ui.appPort);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);assert.deepEqual(ui.calls,['application-open','application-detect','application-close','capture-backup']);
  const fresh=await dfuBackupApplicationWorkbench({known:false});assert.equal(await fresh.evaluate('tryBackupApplication();'),false);
  await fresh.elements.get('cancel-backup-application').onclick();assert.equal(fresh.evaluate('state.backupApplicationRequest'),null);assert.equal(fresh.evaluate('state.port'),fresh.dfuPort);assert.equal(fresh.evaluate('state.pkg'),fresh.context.pkg);assert.deepEqual(fresh.calls,[]);
});

test('choosing application backup from DFU completes normal backup before any reset or write',async()=>{
  const ui=await dfuBackupApplicationWorkbench();ui.elements.get('auto-backup').checked=true;
  ui.context.choose=async(title,_detail,buttons)=>{
    if(buttons.some(([value])=>value==='application')){ui.calls.push('offer-application');assert.ok(buttons.some(([value])=>value==='cancel'));assert.ok(buttons.some(([value])=>value==='skip'));return 'application';}
    assert.equal(title,'Backup JSON');ui.calls.push('backup-continue');return 'continue';
  };
  ui.context.captureBackup=async()=>{assert.equal(ui.evaluate('state.port'),ui.appPort);ui.calls.push('capture-backup');ui.context.savedBackup={json:'{}',archive:{},port:ui.appPort};ui.evaluate('state.backup=savedBackup;');return ui.context.savedBackup;};
  await ui.evaluate('ensureBackup();');
  assert.equal(ui.evaluate('state.port'),ui.appPort);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);assert.equal(ui.evaluate('state.backupApproved.port'),ui.appPort);assert.equal(ui.evaluate('state.backupApproved.sha256'),ui.context.pkg.sha256);
  assert.deepEqual(ui.calls,['offer-application','application-open','application-detect','application-close','capture-backup','backup-continue']);
});

test('DFU application-backup request without an available application stops preparation before reset',async()=>{
  const ui=await dfuBackupApplicationWorkbench({known:false});ui.context.choose=async(_title,_detail,buttons)=>{assert.ok(buttons.some(([value])=>value==='application'));ui.calls.push('offer-application');return 'application';};
  await ui.elements.get('prepare').onclick();
  assert.ok(ui.evaluate('state.backupApplicationRequest'));assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.backupApproved'),null);assert.equal(ui.evaluate('state.port'),ui.dfuPort);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);assert.deepEqual(ui.calls,['offer-application']);
});

test('DFU backup skip remains an explicit choice and cancel never creates backup approval',async()=>{
  for(const answer of ['cancel','skip']){
    const ui=await dfuBackupApplicationWorkbench({known:false});ui.context.choose=async(_title,_detail,buttons)=>{assert.ok(buttons.some(([value])=>value==='application'));assert.ok(buttons.some(([value])=>value==='skip'));ui.calls.push('offer');return answer;};
    if(answer==='cancel')await assert.rejects(ui.evaluate('ensureBackup();'),/cancel/i);else await ui.evaluate('ensureBackup();');
    assert.equal(!!ui.evaluate('state.backupApproved'),answer==='skip');assert.equal(ui.evaluate('state.port'),ui.dfuPort);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);assert.deepEqual(ui.calls,['offer']);
  }
});

test('a stale DFU backup prompt cannot authorize skipping or probe an application for changed radio context',async()=>{
  for(const answer of ['skip','application'])for(const change of ['port','generation','firmware']){
    const ui=await dfuBackupApplicationWorkbench();let finish;
    ui.context.choose=async()=>{ui.calls.push('offer');return new Promise(resolve=>{finish=resolve;});};
    const pending=ui.evaluate('ensureBackup();');for(let i=0;i<10&&!finish;i++)await Promise.resolve();assert.ok(finish);
    if(change==='generation')ui.evaluate('state.generation++;');
    if(change==='port'){ui.context.nextPort={getInfo:()=>({usbVendorId:0x2886,usbProductId:0x0044})};ui.evaluate('state.port=nextPort;');}
    if(change==='firmware'){ui.context.nextPackage=fakePackage({name:'replacement.zip',sha256:'c'.repeat(64)});ui.evaluate('state.pkg=nextPackage;');}
    const selectedPort=ui.evaluate('state.port'),selectedPackage=ui.evaluate('state.pkg');finish(answer);
    await assert.rejects(pending,/changed|prepare again|selected.*radio|selected.*firmware/i,answer+' '+change);
    assert.equal(ui.evaluate('state.port'),selectedPort);assert.equal(ui.evaluate('state.pkg'),selectedPackage);assert.equal(ui.evaluate('state.backupApproved'),null);assert.equal(ui.evaluate('state.backupApplicationRequest'),null);assert.deepEqual(ui.calls,['offer']);
  }
});

test('explicit ROM/DFU skips application backup without probing the port',async()=>{
  const ui=workbench();ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage();ui.evaluate('state.port=selectedPort;state.pkg=pkg;');ui.elements.get('transport-mode').value='nrf52';ui.elements.get('already-bootloader').checked=true;
  ui.context.choose=async title=>{assert.match(title,/application mode/);return 'skip';};
  await ui.elements.get('prepare').onclick();assert.deepEqual(ui.calls,[]);assert.equal(ui.evaluate('state.plan.sha256'),ui.context.pkg.sha256);
});
test('nRF52 wipe retains final image, requires separate overrides, and cannot write final before a new chooser acknowledgement',async()=>{
  const ui=workbench();serialMock(ui);ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage();ui.context.erase=fakePackage({name:'FLASH_ERASE.zip',erase:true,destructive:true});
  ui.evaluate('state.port=selectedPort;state.pkg=pkg;state.plan={generation:0,port:selectedPort,sha256:pkg.sha256,erasePkg:erase};');
  ui.context.assessBoard=()=>({requiresOverride:true,token:'unknown-to-rak4631',payloadFamily:'rak4631',firmwareFamily:'rak4631',deviceFamily:'unknown',reason:'unknown connected board'});
  ui.context.confirm=async(_title,_detail,_warn,token)=>{ui.calls.push(token);return true;};ui.context.flashNrf=async(_link,pkg)=>ui.calls.push('flash:'+pkg.name);
  await ui.elements.get('flash').onclick();assert.ok(ui.calls.includes('unknown-to-rak4631'));assert.ok(ui.calls.includes('WIPE WITHOUT BACKUP'));assert.deepEqual(ui.calls.filter(c=>c.startsWith('flash:')),['flash:FLASH_ERASE.zip']);
  assert.equal(ui.evaluate('state.pkg.name'),'final.zip');assert.equal(ui.evaluate('state.recovery.phase'),'reselect-dfu');
  await ui.elements.get('prepare').onclick();assert.match(ui.elements.get('notice').textContent,/explicit selection/);
  ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0044});await ui.elements.get('select-port').onclick();assert.ok(ui.calls.includes('SAME DEVICE'));
  await ui.elements.get('prepare').onclick();assert.equal(ui.evaluate('state.plan.erasePkg'),null);
  await ui.elements.get('flash').onclick();assert.deepEqual(ui.calls.filter(c=>c.startsWith('flash:')),['flash:FLASH_ERASE.zip','flash:final.zip']);assert.equal(ui.evaluate('state.recovery'),null);assert.ok(ui.evaluate('state.verification'));
});
test('board-neutral erase keeps final-board checks and wipe consent without a spurious erase-board override',async()=>{
  for(const outcome of ['erase','cancel-wipe','wrong-final-board']){
    const ui=workbench();serialMock(ui);ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage({name:'RAK_3401_companion.zip'});ui.context.erase=fakePackage({name:'FLASH_ERASE_nrf52_softdevice_v6.zip',erase:true,destructive:true});
    ui.evaluate('state.port=selectedPort;state.pkg=pkg;state.device={model:"RAK3401"};state.plan={generation:0,port:selectedPort,sha256:pkg.sha256,erasePkg:erase};');
    const assessed=[];ui.context.assessBoard=candidate=>{assessed.push(candidate.name);return candidate===ui.context.erase?{requiresOverride:false,boardNeutralErase:true,payloadFamily:'unknown',matched:false}:{requiresOverride:outcome==='wrong-final-board',token:'rak3401-to-rak4631',payloadFamily:'rak3401',firmwareFamily:'rak4631',deviceFamily:'rak3401'};};
    ui.context.confirm=async(_title,_detail,_warning,token)=>{ui.calls.push('confirm:'+token);return outcome==='erase';};ui.context.flashNrf=async(_link,candidate)=>ui.calls.push('write:'+candidate.name);
    await ui.elements.get('flash').onclick();
    assert.equal(assessed[0],ui.context.pkg.name,'Final firmware is checked before the erase utility');
    if(outcome==='wrong-final-board'){assert.ok(assessed.includes(ui.context.pkg.name));assert.ok(ui.calls.includes('confirm:rak3401-to-rak4631'));assert.ok(!ui.calls.includes('confirm:WIPE WITHOUT BACKUP'),'Rejected final firmware never reaches wipe confirmation');}
    else{assert.deepEqual(assessed.slice(0,2),[ui.context.pkg.name,ui.context.erase.name]);assert.ok(ui.calls.includes('confirm:WIPE WITHOUT BACKUP'));assert.ok(!ui.calls.some(call=>call.startsWith('confirm:rak')),'The neutral erase result does not ask for a fake board mismatch');}
    assert.deepEqual(ui.calls.filter(call=>call.startsWith('write:')),outcome==='erase'?['write:'+ui.context.erase.name]:[]);
    assert.equal(ui.evaluate('state.pkg.name'),'RAK_3401_companion.zip','Erasing never substitutes or automatically writes the final image');
    if(outcome==='erase')assert.equal(ui.evaluate('state.recovery.phase'),'reselect-dfu');else assert.ok(!ui.calls.includes('open'),'Cancellation must occur before opening DFU for writing');
  }
});
test('reselection automatically verifies the running application and rejects changed identity without resets',async()=>{
  const ui=workbench();serialMock(ui);ui.context.expected={sha256:'a'.repeat(64),architecture:'nrf52',publicKey:'11'.repeat(32),family:'unknown',version:null};ui.evaluate('state.verification=expected;');
  ui.context.detectMeshCore=async()=>({role:'companion',publicKey:'22'.repeat(32),model:'test',name:'test'});ui.context.MeshCore=class{async cli(){return 'Companion v1.18.0';}};
  await ui.elements.get('select-port').onclick();assert.match(ui.elements.get('notice').textContent,/identity differs/);assert.ok(ui.evaluate('state.verification'));assert.deepEqual(ui.calls,['chooser','open','close']);
  ui.calls.length=0;ui.context.detectMeshCore=async()=>({role:'companion',publicKey:'11'.repeat(32),model:'test',name:'test'});await ui.elements.get('select-port').onclick();assert.equal(ui.evaluate('state.verification'),null);assert.match(ui.elements.get('notice').textContent,/startup verified/);assert.deepEqual(ui.calls,['chooser','open','close']);
});
test('crash during erase forces a new same-device confirmation and retries uncertain erase despite update default',async()=>{
  const pkg=fakePackage(),ui=workbench({recovery:{sha256:pkg.sha256,name:pkg.name,phase:'erasing',eraseComplete:false}});ui.context.pkg=pkg;ui.context.selectedPort=ui.port;ui.evaluate('state.pkg=pkg;state.port=selectedPort;');ui.elements.get('transport-mode').value='nrf52';ui.elements.get('flash-action').value='update';
  assert.equal(ui.evaluate('state.recovery.phase'),'reselect-dfu');await ui.elements.get('prepare').onclick();assert.match(ui.elements.get('notice').textContent,/explicit selection/);
  ui.context.confirm=async(_t,_d,_w,token)=>{ui.calls.push(token);return true;};ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0044});await ui.elements.get('select-port').onclick();await ui.elements.get('select-port').onclick();assert.equal(ui.calls.filter(c=>c==='SAME DEVICE').length,2);
  ui.context.inspectFirmware=()=>fakePackage({name:'erase.zip',erase:true,destructive:true,eraseEvidence:'official SoftDevice v7 erase payload'});ui.elements.get('erase-file').files=[{name:'erase.zip',size:64,arrayBuffer:async()=>new ArrayBuffer(64)}];
  await ui.elements.get('prepare').onclick();assert.equal(ui.evaluate('state.plan.erasePkg.name'),'erase.zip');
});
test('guided erase refuses bootloader components even if named FLASH_ERASE',async()=>{
  const ui=workbench();ui.context.pkg=fakePackage();ui.context.selectedPort=ui.port;ui.evaluate("state.installMode='install';state.pkg=pkg;state.port=selectedPort;");ui.elements.get('transport-mode').value='nrf52';ui.elements.get('already-bootloader').checked=true;ui.context.choose=async()=> 'skip';
  ui.context.inspectFirmware=()=>fakePackage({erase:true,destructive:true,kind:'bootloader'});ui.elements.get('erase-file').files=[{name:'FLASH_ERASE.zip',size:64,arrayBuffer:async()=>new ArrayBuffer(64)}];
  await ui.elements.get('prepare').onclick();assert.equal(ui.evaluate('state.plan'),null);assert.match(ui.elements.get('notice').textContent,/never a bootloader/);assert.deepEqual(ui.calls,[]);
});
test('unexpected disconnect clears source evidence and backup approval',()=>{
  const ui=workbench();ui.context.selectedPort=ui.port;ui.evaluate("state.port=selectedPort;state.device={model:'RAK4631'};state.backupApproved={sha256:'a',port:selectedPort};");
  ui.serialEvents.disconnect({port:ui.port});assert.equal(ui.evaluate('state.device'),null);assert.equal(ui.evaluate('state.backupApproved'),null);
});
test('failed verification on another node cannot reuse the prior node backup approval',async()=>{
  const ui=workbench();serialMock(ui);ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage({architecture:'esp32'});ui.evaluate("state.port=selectedPort;state.pkg=pkg;state.backupApproved={sha256:pkg.sha256,port:selectedPort};state.verification={sha256:pkg.sha256,architecture:'nrf52',publicKey:'old'};");ui.context.detectMeshCore=async()=>({role:'companion',publicKey:'other',model:'test'});
  await ui.elements.get('select-port').onclick();assert.equal(ui.evaluate('state.backupApproved'),null);
  ui.context.choose=async()=>{ui.calls.push('backup-offer');return 'cancel';};await ui.elements.get('prepare').onclick();assert.ok(ui.calls.includes('backup-offer'));assert.ok(!ui.calls.includes('rom'));
});
test('wipe verification keeps model and role checks and extracts app-relative merged EndF',()=>{
  const ui=workbench();ui.context.pkg=fakePackage({name:'repeater-merged.bin',architecture:'esp32',merged:true,destructive:true,payload:new Uint8Array(40)});ui.context.endfIdentity=bytes=>bytes.length===16?{versionText:'v1.18.0.2'}:null;
  ui.evaluate("state.device={model:'Test board',publicKey:'old',role:'companion'};state.esp={plan:{parts:[{type:0,offset:16,size:16}]}};");const record=ui.evaluate('verificationRecord(pkg)');assert.equal(record.publicKey,null);assert.equal(record.model,'Test board');assert.equal(record.role,'common-cli');assert.equal(record.version,'v1.18.0.2');
});
test('no artifact selection cannot expose first board bootloader options',()=>{
  const ui=workbench();ui.context.item={hardware:'Wrong board',bootloader:['https://example.test/boot.zip']};ui.evaluate('state.items=[item];updateDownload();');assert.equal(ui.elements.get('bootloader-source').options.length,0);
});
test('all final nRF52 component kinds release recovery so another application can be selected',async()=>{
  for(const kind of ['bootloader','softdevice','softdevice_bootloader']){
    const ui=workbench();serialMock(ui);ui.context.pkg=fakePackage({name:`board-${kind}.zip`,kind,destructive:true});ui.context.selectedPort=ui.port;
    ui.evaluate("state.port=selectedPort;state.pkg=pkg;state.recovery={phase:'final',sha256:pkg.sha256,eraseComplete:true};state.plan={generation:0,port:selectedPort,sha256:pkg.sha256};state.verification={sha256:pkg.sha256};");
    ui.context.confirm=async()=>true;ui.context.flashNrf=async()=>{};await ui.elements.get('flash').onclick();
    assert.equal(ui.evaluate('state.recovery'),null,kind);assert.equal(ui.evaluate('state.verification'),null,kind);assert.match(ui.elements.get('notice').textContent,/startup remains unverified/);
    ui.context.inspectFirmware=()=>fakePackage({name:'next-companion.bin',sha256:'c'.repeat(64)});await ui.evaluate("loadFirmware('next-companion.bin',new Uint8Array(64))");
    ui.elements.get('transport-mode').value='nrf52';ui.elements.get('already-bootloader').checked=true;ui.context.choose=async()=> 'skip';
    await ui.elements.get('prepare').onclick();assert.equal(ui.evaluate('state.plan.sha256'),'c'.repeat(64),kind);
  }
});
test('failed final component transfer preserves pending recovery instead of claiming completion',async()=>{
  const ui=workbench();serialMock(ui);ui.context.pkg=fakePackage({kind:'bootloader',destructive:true});ui.context.selectedPort=ui.port;
  ui.evaluate("state.port=selectedPort;state.pkg=pkg;state.recovery={phase:'final',sha256:pkg.sha256,eraseComplete:true};state.plan={generation:0,port:selectedPort,sha256:pkg.sha256};");ui.context.confirm=async()=>true;ui.context.flashNrf=async()=>{throw new Error('DFU transfer incomplete');};
  await ui.elements.get('flash').onclick();assert.equal(ui.evaluate('state.recovery.phase'),'final');assert.match(ui.elements.get('notice').textContent,/incomplete/);
});
test('custom firmware reuses only board hints, never an unrelated first catalog role',async()=>{
  const ui=workbench();await Promise.resolve();ui.elements.get('hardware').value='Test board';ui.context.first={name:'stock-companion.bin',hardware:'Test board',role:'companionBle',version:'v1.18',erase:['https://example.test/erase.zip'],bootloader:['https://example.test/boot.zip']};ui.context.custom=fakePackage({name:'custom-repeater.bin',architecture:'esp32'});ui.evaluate('state.items=[first];');ui.context.inspectFirmware=()=>ui.context.custom;
  await ui.evaluate("loadFirmware('custom-repeater.bin',new Uint8Array(64))");const item=ui.evaluate('state.item');assert.equal(item.role,undefined);assert.equal(item.version,undefined);assert.equal(item.hardware,'Test board');assert.equal(item.erase[0],ui.context.first.erase[0]);assert.equal(ui.evaluate('verificationRecord(state.pkg).role'),'common-cli');
  ui.context.custom=fakePackage({name:'custom.bin',architecture:'esp32'});await ui.evaluate("loadFirmware('custom.bin',new Uint8Array(64))");ui.evaluate("state.device={role:'companion'};");assert.equal(ui.evaluate('verificationRecord(state.pkg).role'),null);
});
test('published QSPI formatter enters guided erase with destructive consent and no custom-package misclassification',async()=>{
  const ui=workbench();ui.context.pkg=fakePackage();ui.context.selectedPort=ui.port;ui.evaluate("state.installMode='install';state.pkg=pkg;state.port=selectedPort;");ui.elements.get('transport-mode').value='nrf52';ui.elements.get('already-bootloader').checked=true;ui.context.choose=async()=> 'skip';
  ui.context.inspectFirmware=()=>fakePackage({name:'board_QSPIFlash_Format-v1.2.zip',erase:true,destructive:true,eraseEvidence:'official QSPI formatter payload (board v1.2)'});ui.elements.get('erase-file').files=[{name:'board_QSPIFlash_Format-v1.2.zip',size:64,arrayBuffer:async()=>new ArrayBuffer(64)}];ui.context.confirm=async(_t,_d,_w,token)=>{ui.calls.push(token);return true;};
  await ui.elements.get('prepare').onclick();assert.equal(ui.evaluate('state.plan.erasePkg.destructive'),true);assert.ok(!ui.calls.includes('CUSTOM ERASE'));
  serialMock(ui);ui.context.flashNrf=async()=>{};await ui.elements.get('flash').onclick();assert.ok(ui.calls.includes('WIPE WITHOUT BACKUP'));
});
test('ESP revision force is separately acknowledged and passed only for that confirmed write',async()=>{
  for(const accepted of [false,true]){
    const ui=workbench();ui.context.pkg=fakePackage({architecture:'esp32',expert:true,destructive:true});ui.context.selectedPort=ui.port;ui.context.record=ui.calls;
    ui.evaluate("state.pkg=pkg;state.port=selectedPort;state.plan={generation:0,port:selectedPort,sha256:pkg.sha256,addresses:[0],requiresRevisionOverride:true,revisionOverrideToken:'FORCE CHIP REVISION',compatibilityWarnings:['revision mismatch']};state.esp={flash:async(_pkg,_progress,opts)=>record.push(opts.allowRevisionMismatch?'forced-write':'unforced-write')};");
    ui.context.confirm=async(_t,_d,_w,token)=>{ui.calls.push(token);return token==='FORCE CHIP REVISION'?accepted:true;};
    await ui.elements.get('flash').onclick();assert.ok(ui.calls.includes('FORCE CHIP REVISION'));assert.equal(ui.calls.includes('forced-write'),accepted);assert.ok(!ui.calls.includes('unforced-write'));
  }
});
test('console commands invalidate earlier backup approval and cached board evidence before node access',async()=>{
  for(const role of ['common-cli','auto']){
    const ui=workbench();serialMock(ui);ui.context.selectedPort=ui.port;ui.evaluate("state.port=selectedPort;state.device={model:'old'};state.backupApproved={sha256:'a',port:selectedPort};");ui.elements.get('backup-role').value=role;ui.elements.get('command').value='set name New';
    ui.context.detectMeshCore=async()=>{assert.equal(ui.evaluate('state.device'),null);assert.equal(ui.evaluate('state.backupApproved'),null);return {role:'common-cli',model:'before-command'};};
    await ui.elements.get('send-command').onclick();assert.equal(ui.evaluate('state.backupApproved'),null);assert.equal(ui.evaluate('state.device'),null);assert.ok(ui.calls.includes('set name New'));
  }
});

async function quickSettingsWorkbench(device={role:'common-cli',publicKey:'11'.repeat(32),model:'Test radio'}){
  const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.quickDevice=device;
  ui.port.getInfo=()=>({usbVendorId:0x10c4,usbProductId:0xea60});
  ui.context.SerialLink=class{async open(){ui.calls.push('open');}async close(){ui.calls.push('close');}async command(command){ui.calls.push(command);return '> OK';}};
  ui.context.detectMeshCore=async()=>({...device});
  ui.evaluate('state.port=selectedPort;state.device=quickDevice;controls();');
  return ui;
}

test('common settings are disabled without an application port and never send commands on page load',async()=>{
  const ui=workbench();await Promise.resolve();
  for(const id of ['quick-logging-on','quick-logging-off','quick-wifi-status','quick-wifi-on','quick-wifi-off','quick-wifi-ota-ap','quick-name-save','quick-password-save','quick-wifi-save'])assert.equal(ui.elements.get(id).disabled,true,id);
  assert.deepEqual(ui.calls,[]);
});

test('password Show/Hide controls are local, independent, accessible and do not send USB commands',async()=>{
  const ui=workbench();await Promise.resolve();
  for(const [field,toggle] of [['quick-admin-password','quick-admin-password-toggle'],['quick-wifi-password','quick-wifi-password-toggle']]){
    ui.elements.get(field).value='PRIVATE_A1';
    ui.elements.get(toggle).onclick();assert.equal(ui.elements.get(field).getAttribute('type'),'text');assert.equal(ui.elements.get(toggle).getAttribute('aria-pressed'),'true');assert.equal(ui.elements.get(toggle).textContent,'Hide');assert.equal(ui.elements.get(field).value,'PRIVATE_A1');
    ui.elements.get(toggle).onclick();assert.equal(ui.elements.get(field).getAttribute('type'),'password');assert.equal(ui.elements.get(toggle).getAttribute('aria-pressed'),'false');assert.equal(ui.elements.get(toggle).textContent,'Show');
  }
  assert.deepEqual(ui.calls,[]);assert.ok(!ui.elements.get('log').textContent.includes('PRIVATE_A1'));
});

test('quick name save rechecks the radio and invalidates old backup and flash evidence',async()=>{
  const ui=await quickSettingsWorkbench();ui.elements.get('quick-name').value='Roof radio';
  ui.evaluate('state.backupApproved={sha256:"old"};state.backup={private:"old"};state.plan={written:false};');
  ui.context.detectMeshCore=async()=>{assert.equal(ui.evaluate('state.backupApproved'),null);assert.equal(ui.evaluate('state.plan'),null);return {...ui.context.quickDevice};};
  await ui.elements.get('quick-name-save').onclick();
  assert.deepEqual(ui.calls,['open','set name Roof radio','close']);assert.equal(ui.evaluate('state.backup'),null);assert.equal(ui.evaluate('state.device'),null);assert.equal(ui.evaluate('state.plan'),null);
  assert.match(ui.elements.get('notice').textContent,/command accepted/);assert.equal(ui.elements.get('quick-name-save').disabled,false);
});

test('quick settings use the detected Companion command transport and logging-on sends no follow-up',async()=>{
  const ui=await quickSettingsWorkbench({role:'companion',protocol:14,publicKey:'11'.repeat(32)});
  ui.context.MeshCore=class{async cli(command){ui.calls.push('binary:'+command);return 'OK';}};
  await ui.elements.get('quick-logging-on').onclick();
  assert.deepEqual(ui.calls,['open','binary:set usb.logging on','close']);assert.match(ui.elements.get('notice').textContent,/binary.*text/i);
});

test('quick Wi-Fi buttons use the current role rather than the backup role override',async()=>{
  for(const role of ['common-cli','companion']){
    const ui=await quickSettingsWorkbench({role,protocol:14});ui.elements.get('backup-role').value=role==='companion'?'common-cli':'companion';
    ui.context.MeshCore=class{async cli(command){ui.calls.push(command);return 'OK';}};
    await ui.elements.get('quick-wifi-on').onclick();assert.deepEqual(ui.calls,['open',role==='companion'?'set wifi.enabled 1':'set wifi on','close']);
  }
});

test('secret quick setters never display echoed credentials or raw secret errors and always clear password inputs',async()=>{
  for(const failAt of ['none','reply','throw','close']){
    const ui=await quickSettingsWorkbench(),secret='PRIVATE_A1';ui.elements.get('quick-admin-password').value=secret;ui.elements.get('quick-wifi-password').value='PRIVATE_WIFI';ui.elements.get('quick-admin-password-toggle').onclick();ui.elements.get('quick-wifi-password-toggle').onclick();
    ui.context.SerialLink=class{async open(){ui.calls.push('open');}async close(){if(failAt==='close')throw Error(secret);}async command(command){ui.calls.push(command);if(failAt==='throw')throw Error('bad '+secret);return failAt==='reply'?'Error: '+secret:'password now: '+secret;}};
    await ui.elements.get('quick-password-save').onclick();
    for(const id of ['notice','log','quick-settings-status']){assert.ok(!ui.elements.get(id).textContent.includes(secret),id);assert.ok(!ui.elements.get(id).textContent.includes('PRIVATE_WIFI'),id);}
    assert.equal(ui.elements.get('quick-admin-password').value,'');assert.equal(ui.elements.get('quick-wifi-password').value,'');
    for(const field of ['quick-admin-password','quick-wifi-password'])assert.equal(ui.elements.get(field).getAttribute('type'),'password');
    for(const toggle of ['quick-admin-password-toggle','quick-wifi-password-toggle'])assert.equal(ui.elements.get(toggle).getAttribute('aria-pressed'),'false');
    assert.equal(ui.evaluate("localStorage.getItem('meshfirmware.selections')")?.includes(secret)||false,false);
    assert.match(ui.elements.get('notice').textContent,failAt==='none'?/command accepted/:/could not be completed/);
  }
});

test('Wi-Fi credential save stops between commands if the port or generation changes',async()=>{
  for(const change of ['generation','port']){
    const ui=await quickSettingsWorkbench();ui.elements.get('quick-wifi-ssid').value='Home WiFi';ui.elements.get('quick-wifi-password').value='PRIVATE_WIFI';
    ui.context.SerialLink=class{async open(){}async close(){}async command(command){ui.calls.push(command);ui.evaluate(change==='generation'?'state.generation++':'state.port=null');return 'OK';}};
    await ui.elements.get('quick-wifi-save').onclick();assert.deepEqual(ui.calls,['set wifi.pwd PRIVATE_WIFI']);assert.match(ui.elements.get('notice').textContent,/Earlier values may already have changed/);assert.ok(!ui.elements.get('log').textContent.includes('PRIVATE_WIFI'));
  }
});

test('quick settings refuse known Meshtastic, DFU and pending flash/recovery flows without opening USB',async()=>{
  for(const setup of ["state.device={role:'meshtastic'}","state.device={role:'bootloader'}","$('already-bootloader').checked=true",'state.verification={}', 'state.migration={}', 'state.recovery={phase:"reselect-dfu"}', 'state.espRecovery={}', 'state.migrationApproval={phase:"waiting-rom",revoke(){}}', 'state.esp={}', 'state.plan={written:true}', 'state.handoff=true']){
    const ui=await quickSettingsWorkbench();ui.evaluate(setup+';updateQuickSettingsControls();');assert.equal(ui.elements.get('quick-logging-off').disabled,true,setup);
    await ui.elements.get('quick-logging-off').onclick();assert.deepEqual(ui.calls,[],setup);
  }
  const ui=await quickSettingsWorkbench();ui.port.getInfo=()=>({usbVendorId:0x239a,usbProductId:0x002a});await ui.elements.get('quick-logging-off').onclick();assert.deepEqual(ui.calls,[]);
});

test('a fresh Meshtastic reply, changed identity or old Companion protocol cannot receive a quick setter',async()=>{
  for(const next of [{role:'meshtastic',firmwareFamily:'meshtastic'},{role:'common-cli',publicKey:'22'.repeat(32)},{role:'companion',protocol:13,publicKey:'11'.repeat(32)}]){
    const ui=await quickSettingsWorkbench();ui.context.detectMeshCore=async()=>next;
    await ui.elements.get('quick-logging-off').onclick();assert.deepEqual(ui.calls,['open','close']);assert.doesNotMatch(ui.elements.get('notice').textContent,/command accepted/);
    if(next.role==='meshtastic')assert.equal(ui.evaluate('state.device.role'),'meshtastic');
  }
});

test('invalid quick-setting input fails locally, without USB or leaking values',async()=>{
  for(const invalid of ['Roof\nreboot','Name\u202eunsafe','x'.repeat(32)]){
    const ui=await quickSettingsWorkbench();ui.elements.get('quick-name').value=invalid;
    await ui.elements.get('quick-name-save').onclick();assert.deepEqual(ui.calls,[]);assert.ok(!ui.elements.get('log').textContent.includes(invalid));
  }
});

test('Wi-Fi hotspot shortcut requires fresh ESP32 identity, never a selected nRF52 board',async()=>{
  const nrf=await quickSettingsWorkbench({role:'common-cli',architecture:'nrf52'});nrf.elements.get('hardware').value='Heltec v4';await nrf.elements.get('quick-wifi-ota-ap').onclick();assert.deepEqual(nrf.calls,[]);
  for(const port of ['',':8080']){
    const esp=await quickSettingsWorkbench({role:'common-cli',architecture:'esp32'});esp.context.SerialLink=class{async open(){esp.calls.push('open');}async close(){esp.calls.push('close');}async command(command){esp.calls.push(command);return `Started: http://192.168.4.1${port}/update; Login: admin / node admin password`;}};
    await esp.elements.get('quick-wifi-ota-ap').onclick();assert.deepEqual(esp.calls,['open','start ota ap','close']);assert.match(esp.elements.get('notice').textContent,/hotspot started/);assert.ok(esp.elements.get('notice').textContent.includes(`http://192.168.4.1${port}/update`));
  }
});

test('quick setters require positive firmware acknowledgments rather than unsolicited log banners',async()=>{
  for(const reply of ['MeshCore ready','Saved?','> radio packet received','Started: not a URL']){
    const ui=await quickSettingsWorkbench();ui.context.SerialLink=class{async open(){}async close(){}async command(){return reply;}};
    await ui.elements.get('quick-logging-off').onclick();assert.match(ui.elements.get('notice').textContent,/No setting acknowledgment/);assert.doesNotMatch(ui.elements.get('log').textContent,/command accepted/);
  }
});

test('quick-setting unsupported replies are not reported as saved and Wi-Fi status appears in the console',async()=>{
  const ui=await quickSettingsWorkbench();ui.context.SerialLink=class{async open(){}async close(){}async command(command){ui.calls.push(command);return command==='get wifi.status'?'> wifi.status on, ip=192.0.2.1':'Unknown command';}};
  await ui.elements.get('quick-logging-off').onclick();assert.match(ui.elements.get('notice').textContent,/not supported/);assert.doesNotMatch(ui.elements.get('log').textContent,/command accepted/);
  await ui.elements.get('quick-wifi-status').onclick();assert.match(ui.elements.get('log').textContent,/192\.0\.2\.1/);assert.match(ui.elements.get('notice').textContent,/shown in the console/);
});

test('failed downloads and local reads clear the old firmware and write proof before failure',async()=>{
  for(const action of ['fetch-firmware','fetch-custom','load-bootloader','local-read','local-size','load-entry']){
    const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.record=ui.calls;
    ui.context.inventory=[{...v4Item,name:'new.bin',hardware:'test',url:'https://example.test/new.bin'}];
    ui.evaluate("state.port=selectedPort;state.pkg={name:'old.bin',sha256:'a'.repeat(64)};state.plan={sha256:state.pkg.sha256,generation:0,port:selectedPort};state.esp={close:async()=>record.push('closed-old-session')};state.items=inventory;state.archive=new Uint8Array(8);filterCatalog();");
    ui.elements.get('artifact').value='0';ui.elements.get('custom-url').value='https://example.test/new.bin';ui.elements.get('bootloader-source').value='https://example.test/boot.zip';ui.elements.get('archive-entry').value='new.bin';
    ui.context.fetch=async()=>{assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);throw new Error('download failed');};
    ui.context.checkedZip=()=>{throw new Error('archive entry failed');};
    ui.elements.get('firmware-file').files=[{name:'new.bin',size:action==='local-size'?65<<20:64,arrayBuffer:async()=>{assert.equal(ui.evaluate('state.pkg'),null);throw new Error('file read failed');}}];
    if(action.startsWith('local-'))await ui.elements.get('firmware-file').onchange();else await ui.elements.get(action).onclick();
    assert.equal(ui.evaluate('state.pkg'),null,action);assert.equal(ui.evaluate('state.plan'),null,action);assert.equal(ui.evaluate('state.item'),null,action);assert.equal(ui.elements.get('flash').disabled,true,action);assert.equal(ui.elements.get('image-name').textContent,'No image loaded',action);assert.ok(ui.calls.includes('closed-old-session'),action);
    ui.context.confirm=async()=>{throw new Error('Old image must not reach confirmation');};await ui.elements.get('flash').onclick();assert.match(ui.elements.get('notice').textContent,/Selection changed/);
  }
});

test('restore displays optional unsupported-setting warnings without claiming they were restored',async()=>{
  const ui=workbench();serialMock(ui);ui.context.selectedPort=ui.port;ui.evaluate('state.port=selectedPort;state.restore={};');
  ui.context.verifyBackup=()=>({role:'companion',publicKey:'11'.repeat(32)});ui.context.confirm=async()=>true;
  ui.context.MeshCore=class{async restore(){return {warnings:['USB logging is unsupported on this companion; not changed.'],optional:{usbLogging:{state:'unsupported'}}};}};
  await ui.elements.get('restore').onclick();assert.match(ui.elements.get('notice').textContent,/USB logging is unsupported/);assert.match(ui.elements.get('log').textContent,/not changed/);
});

test('interrupted ESP write requires a new same-device chooser before a separately acknowledged chunk retry',async()=>{
  const ui=workbench(),recovery={mac:'aa:bb:cc:dd:ee:ff',sha256:'a'.repeat(64)};ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage({architecture:'esp32'});ui.context.retryRecord=recovery;ui.context.record=ui.calls;
  ui.evaluate("state.port=selectedPort;state.pkg=pkg;state.plan={generation:0,port:selectedPort,sha256:pkg.sha256,addresses:[65536]};state.esp={flash:async()=>{const error=new Error('Serial transport lost');error.recovery=retryRecord;throw error;},close:async()=>record.push('close-failed-session')};");
  ui.context.confirm=async(_t,_d,_w,token)=>{ui.calls.push(token);return true;};await ui.elements.get('flash').onclick();
  assert.equal(ui.evaluate('state.espRecovery'),recovery);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.elements.get('transport-mode').value,'no_reset');assert.ok(ui.evaluate("localStorage.getItem('meshfirmware.espRecovery')"));assert.match(ui.elements.get('notice').textContent,/SAME physical/);
  await ui.elements.get('select-port').onclick();assert.ok(ui.calls.includes('SAME DEVICE'));assert.equal(ui.elements.get('already-bootloader').checked,true);
  ui.context.EspSession=class{async connect(mode){ui.calls.push('connect:'+mode);return {chip:'ESP32-S3',mac:recovery.mac,flashBytes:4<<20};}async prepare(_pkg,args){assert.equal(args.recovery,recovery);return {sha256:recovery.sha256,mac:recovery.mac,addresses:[65536],chunkedRecovery:true};}async flash(_pkg,_progress,args){assert.equal(args.chunkedRecovery,true);ui.calls.push('chunked-write');}async close(){}};
  await ui.elements.get('prepare').onclick();assert.ok(ui.calls.includes('connect:no_reset'));assert.equal(ui.evaluate('state.plan.chunkedRecovery'),true);
  ui.context.confirm=async(_t,_d,_w,token)=>{ui.calls.push(token);return token!=='RETRY IN CHUNKS';};await ui.elements.get('flash').onclick();assert.ok(!ui.calls.includes('chunked-write'));assert.equal(ui.evaluate('state.espRecovery'),recovery);
  ui.context.confirm=async(_t,_d,_w,token)=>{ui.calls.push(token);return true;};await ui.elements.get('flash').onclick();assert.ok(ui.calls.includes('chunked-write'));assert.equal(ui.evaluate('state.espRecovery'),null);assert.equal(ui.evaluate("localStorage.getItem('meshfirmware.espRecovery')"),undefined);
});

test('persisted ESP retry refuses another image, resetting inspection and another MAC',async()=>{
  const recovery={mac:'aa:bb:cc:dd:ee:ff',sha256:'a'.repeat(64)},ui=workbench({espRecovery:recovery});ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage({architecture:'esp32',sha256:'b'.repeat(64)});ui.evaluate('state.port=selectedPort;state.pkg=pkg;');
  await ui.elements.get('prepare').onclick();assert.match(ui.elements.get('notice').textContent,/original exact ESP32 firmware/);assert.deepEqual(ui.calls,[]);
  ui.context.pkg=fakePackage({architecture:'esp32'});ui.evaluate('state.pkg=pkg;');ui.elements.get('transport-mode').value='usb_reset';await ui.elements.get('prepare').onclick();assert.match(ui.elements.get('notice').textContent,/without resetting/);assert.deepEqual(ui.calls,[]);
  ui.elements.get('transport-mode').value='no_reset';ui.context.EspSession=class{async connect(){return {mac:'00:11:22:33:44:55'};}async prepare(){ui.calls.push('unsafe-prepare');}async close(){}};
  await ui.elements.get('prepare').onclick();assert.match(ui.elements.get('notice').textContent,/Different physical ESP32/);assert.deepEqual(ui.calls,[]);assert.ok(ui.evaluate('state.espRecovery'));
});

test('pre-start UART bridge retry permits only no-reset inspection and keeps migration guarded',async()=>{
  for(const phase of ['writing','written']){
    const pending={mac:'aa:bb:cc:dd:ee:ff',sha256:'a'.repeat(64),uart:true,settled:false,phase},ui=workbench({pending});ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage({architecture:'esp32'});ui.evaluate('state.port=selectedPort;state.pkg=pkg;');
    ui.context.EspSession=class{async connect(mode){assert.equal(mode,'no_reset');ui.calls.push('inspect-ROM');return {mac:pending.mac,chip:'ESP32-S3',flashBytes:4<<20};}async prepare(_pkg,args){assert.equal(args.resume,true);return {sha256:pending.sha256,mac:pending.mac,needed:true,resume:false,addresses:[65536]};}async close(){}};
    await ui.elements.get('prepare').onclick();assert.ok(ui.calls.includes('inspect-ROM'));assert.ok(ui.evaluate('state.plan'));assert.match(ui.elements.get('notice').textContent,/partial bridge can be rewritten/);assert.equal(ui.evaluate('state.migration.phase'),phase);
    ui.elements.get('transport-mode').value='default_reset';await ui.elements.get('prepare').onclick();assert.match(ui.elements.get('notice').textContent,/before any ROM reset/);assert.equal(ui.calls.length,1);
  }
});

test('discarding an ESP retry needs explicit consent and never clears pending partition migration',async()=>{
  const pending={mac:'aa:bb:cc:dd:ee:ff',sha256:'a'.repeat(64),uart:true,phase:'writing'},ui=workbench({pending,espRecovery:{mac:pending.mac,sha256:pending.sha256}});
  ui.context.confirm=async(_t,_d,_w,token)=>{assert.equal(token,'DISCARD RETRY STATE');return false;};await ui.elements.get('discard-esp-recovery').onclick();assert.ok(ui.evaluate('state.espRecovery'));
  ui.context.confirm=async()=>true;await ui.elements.get('discard-esp-recovery').onclick();assert.equal(ui.evaluate('state.espRecovery'),null);assert.equal(ui.evaluate('state.migration.sha256'),pending.sha256);assert.deepEqual(ui.calls,[]);assert.match(ui.elements.get('notice').textContent,/migration remains pending/);
});

test('release ZIP digest is verified on the container, not mistakenly compared with its selected inner image',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.outer=new Uint8Array(8);ui.context.inner=new Uint8Array(64);ui.context.catalogItem={name:'release.zip',hardware:'Test board',role:'companion',erase:['https://example.test/erase.zip'],bootloader:[]};
  ui.context.hash=bytes=>bytes.length===8?'a'.repeat(64):'b'.repeat(64);ui.context.checkedZip=(_bytes,options)=>options.directoryOnly?[{name:'nested/repeater.bin',length:64}]:{'nested/repeater.bin':ui.context.inner};ui.context.inspectFirmware=()=>fakePackage({name:'repeater.bin',sha256:'b'.repeat(64),architecture:'esp32'});
  ui.elements.get('expected-sha').value='a'.repeat(64);await ui.evaluate("loadFirmware('release.zip',outer,catalogItem)");assert.ok(ui.evaluate('state.archive'));assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.elements.get('archive-picker').hidden,false);
  ui.elements.get('archive-entry').value='nested/repeater.bin';await ui.elements.get('load-entry').onclick();assert.equal(ui.evaluate('state.pkg.name'),'repeater.bin');assert.equal(ui.elements.get('expected-sha').value,'');assert.equal(ui.evaluate('state.item.hardware'),'Test board');assert.equal(ui.evaluate('state.item.role'),undefined);assert.equal(ui.evaluate('verificationRecord(state.pkg).role'),'common-cli');
  ui.elements.get('expected-sha').value='c'.repeat(64);await assert.rejects(ui.evaluate("loadFirmware('release.zip',outer,catalogItem)"),/SHA-256/);assert.equal(ui.evaluate('state.archive'),null);assert.equal(ui.evaluate('state.pkg'),null);
});

test('unavailable retry storage still closes the failed session and retains the bound in-memory recovery',async()=>{
  const ui=workbench();ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage({architecture:'esp32'});ui.context.record=ui.calls;
  ui.evaluate("state.port=selectedPort;state.pkg=pkg;state.plan={generation:0,port:selectedPort,sha256:pkg.sha256};localStorage.setItem=()=>{throw new Error('storage unavailable');};state.esp={flash:async()=>{const error=new Error('Serial timeout');error.recovery={mac:'aa:bb:cc:dd:ee:ff',sha256:pkg.sha256};throw error;},close:async()=>record.push('closed')};");ui.context.confirm=async()=>true;
  await ui.elements.get('flash').onclick();assert.ok(ui.evaluate('state.espRecovery'));assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.evaluate('state.plan'),null);assert.ok(ui.calls.includes('closed'));assert.match(ui.elements.get('log').textContent,/memory only/);
});

test('our exact-board stable bootloader is selected with version, size and SHA checks before parsing',async()=>{
  for(const failure of [null,'size','hash']){
    const ui=workbench();await Promise.resolve();const name='t1000_e_bootloader-latest_s140_7.3.0.zip',info={version:'2.4.12',profile:'t1000_e',url:'https://github.com/mikecarper/Adafruit_nRF52_Bootloader_OTAFIX/releases/download/v-test/'+name,sha256:'c'.repeat(64),size:64};
    ui.context.item={hardware:'Seeed Studio SenseCAP T1000-E',architecture:'nrf52',name:'t1000e_companion.zip',bootloader:[info.url],bootloaderInfo:info};ui.context.selected=fakePackage({name,kind:'softdevice_bootloader',destructive:true,sha256:info.sha256});ui.evaluate('state.items=[item];');ui.elements.get('artifact').value='0';ui.evaluate('updateDownload();controls();');
    assert.equal(ui.elements.get('bootloader-source').options.length,1);assert.match(ui.elements.get('bootloader-source').options[0].text,/OTAFIX 2.4.12/);assert.match(ui.elements.get('bootloader-detail').textContent,/requires reinstalling/);
    ui.context.boundedFetch=async()=>new Uint8Array(failure==='size'?63:64);ui.context.hash=()=>failure==='hash'?'d'.repeat(64):info.sha256;ui.context.checkedZip=()=>[{name:'manifest.json'},{name:'sd_bl.bin'},{name:'sd_bl.dat'}];let parsed=0;ui.context.inspectFirmware=()=>{parsed++;return ui.context.selected;};
    await ui.elements.get('load-bootloader').onclick();assert.deepEqual(ui.calls,[]);
    if(failure){assert.equal(parsed,0);assert.equal(ui.evaluate('state.pkg'),null);assert.match(ui.elements.get('notice').textContent,failure==='size'?/size does not match/:/SHA-256/);}
    else{assert.equal(parsed,1);assert.equal(ui.evaluate('state.pkg.sha256'),info.sha256);assert.equal(ui.evaluate('state.item.bootloaderInfo.profile'),'t1000_e');assert.equal(ui.elements.get('expected-sha').value,info.sha256);assert.match(ui.elements.get('notice').textContent,/SHA-256 verified/);assert.match(ui.elements.get('image-warning').textContent,/requires reinstalling/);}
  }
});

test('unavailable or unverified nRF52 bootloaders do not expose old upstream recommendations',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.item={name:'pending.zip',architecture:'nrf52',bootloader:['https://flasher.meshcore.io/old-bootloader.zip'],bootloaderUnavailable:'This exact profile is not hardware-qualified; no automatic bootloader recommendation.'};ui.evaluate('state.items=[item];');ui.elements.get('artifact').value='0';ui.evaluate('updateDownload();controls();');assert.equal(ui.elements.get('bootloader-source').options.length,0);assert.equal(ui.elements.get('load-bootloader').disabled,true);assert.match(ui.elements.get('bootloader-detail').textContent,/not hardware-qualified/);
  ui.elements.get('bootloader-source').value=ui.context.item.bootloader[0];await ui.elements.get('load-bootloader').onclick();assert.equal(ui.evaluate('state.pkg'),null);assert.match(ui.elements.get('notice').textContent,/No verified stable bootloader/);assert.deepEqual(ui.calls,[]);
});

test('automatic digests follow their exact file through local download fallback but not a later different application',async()=>{
  const ui=workbench();ui.context.hash=bytes=>bytes.length===64?'a'.repeat(64):'b'.repeat(64);ui.context.checkedZip=()=>[{name:'manifest.json'},{name:'app.bin'},{name:'app.dat'}];ui.context.inspectFirmware=(name,bytes)=>fakePackage({name,sha256:ui.context.hash(bytes)});
  ui.evaluate("setAutomaticSha('a'.repeat(64),'boot.zip');");ui.elements.get('firmware-file').files=[{name:'boot.zip',size:64,arrayBuffer:async()=>new ArrayBuffer(64)}];await ui.elements.get('firmware-file').onchange();assert.equal(ui.elements.get('expected-sha').value,'a'.repeat(64));assert.equal(ui.evaluate('state.pkg.name'),'boot.zip');
  ui.elements.get('firmware-file').files=[{name:'new-app.bin',size:128,arrayBuffer:async()=>new ArrayBuffer(128)}];await ui.elements.get('firmware-file').onchange();assert.equal(ui.elements.get('expected-sha').value,'');assert.equal(ui.evaluate('state.pkg.name'),'new-app.bin');
  ui.elements.get('expected-sha').value='c'.repeat(64);await ui.elements.get('expected-sha').onchange();await ui.elements.get('firmware-file').onchange();assert.equal(ui.elements.get('expected-sha').value,'c'.repeat(64));assert.equal(ui.evaluate('state.pkg'),null);assert.match(ui.elements.get('notice').textContent,/SHA-256/);
});

test('recovery profiles are never automatically selected from physical hardware or a shared installed identity',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.catalog={version:'2.4.12',bundle:{url:'https://example.test/recovery.zip'},profiles:[{id:'xiao_nrf52840_ble',installedIdentity:'XIAO_DFU'},{id:'xiao_nrf52840_ble_sense',installedIdentity:'XIAO_DFU'}]};ui.elements.get('hardware').value='Seeed Studio XIAO nRF52';ui.evaluate("state.device={model:'XIAO_DFU'};state.recoveryCatalog=catalog;updateRecoveryChoices();controls();");
  assert.equal(ui.elements.get('recovery-profile').value,'');assert.equal(ui.elements.get('recovery-profile').options.length,3);assert.equal(ui.elements.get('load-recovery').disabled,true);assert.deepEqual(ui.calls,[]);
  assert.match(ui.elements.get('recovery-profile').options[1].text,/xiao_nrf52840_ble/);assert.match(ui.elements.get('recovery-profile').options[2].text,/xiao_nrf52840_ble_sense/);
});

test('loading the selected installed-identity recovery ZIP is verified but sends no device commands',async()=>{
  const ui=workbench();await Promise.resolve();const name='R_gat562_bootloader-v-test_s140_6.1.1.zip',profile={id:'gat562',installedIdentity:'GAT562_DFU',name,sha256:'c'.repeat(64),size:64};ui.context.catalog={version:'2.4.12',bundle:{url:'https://example.test/recovery.zip',size:128},profiles:[profile]};ui.context.pkg=fakePackage({name,kind:'softdevice_bootloader',destructive:true,sha256:profile.sha256});ui.elements.get('hardware').value='RAK4631';ui.evaluate('state.recoveryCatalog=catalog;updateRecoveryChoices();');ui.elements.get('recovery-profile').value='gat562';ui.context.boundedFetch=async()=>new Uint8Array(128);ui.context.recoveryPackage=(catalog,id,bytes)=>{assert.equal(catalog,ui.context.catalog);assert.equal(id,'gat562');assert.equal(bytes.length,128);return {name,bytes:new Uint8Array(64),profile};};ui.context.hash=()=>profile.sha256;ui.context.checkedZip=()=>[{name:'manifest.json'},{name:'sd_bl.bin'},{name:'sd_bl.dat'}];ui.context.inspectFirmware=()=>ui.context.pkg;
  await ui.elements.get('load-recovery').onclick();assert.equal(ui.evaluate('state.loadedRecovery.id'),'gat562');assert.equal(ui.evaluate('state.pkg.name'),name);assert.match(ui.elements.get('notice').textContent,/installed identity GAT562_DFU/);assert.match(ui.elements.get('image-warning').textContent,/CURRENTLY INSTALLED/);assert.deepEqual(ui.calls,[]);
});

test('every recovery write needs its own typed acknowledgement plus ordinary board and wipe consent',async()=>{
  for(const accepted of [false,true]){
    const ui=workbench();await Promise.resolve();serialMock(ui);const profile={id:'gat562',installedIdentity:'GAT562_DFU',sha256:'a'.repeat(64)};ui.context.catalog={version:'2.4.12',profiles:[profile]};ui.context.pkg=fakePackage({name:'renamed-recovery.zip',kind:'softdevice_bootloader',destructive:true});ui.context.selectedPort=ui.port;ui.evaluate('state.recoveryCatalog=catalog;state.pkg=pkg;state.port=selectedPort;state.plan={generation:0,port:selectedPort,sha256:pkg.sha256};');
    ui.context.confirm=async(_t,_d,_w,token)=>{ui.calls.push(token);return token==='RECOVERY gat562'?accepted:true;};ui.context.assessBoard=()=>({requiresOverride:true,token:'unknown-to-rak4631',payloadFamily:'unknown'});ui.context.flashNrf=async()=>ui.calls.push('DFU-write');
    await ui.elements.get('flash').onclick();assert.ok(ui.calls.includes('RECOVERY gat562'));assert.equal(ui.calls.includes('DFU-write'),accepted);
    if(accepted){assert.ok(ui.calls.includes('unknown-to-rak4631'));assert.ok(ui.calls.includes('WIPE WITHOUT BACKUP'));assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.evaluate('state.handoff'),true);assert.equal(ui.evaluate('state.verification'),null);assert.match(ui.elements.get('notice').textContent,/NORMAL bootloader/);assert.match(ui.elements.get('notice').textContent,/unverified/);}
  }
});

test('failed recovery download or verification cannot leave a previous firmware plan flashable',async()=>{
  for(const invalid of [false,true]){
    const ui=workbench();await Promise.resolve();ui.context.catalog={version:'2.4.12',bundle:{url:'https://example.test/recovery.zip',size:128},profiles:[{id:'gat562'}]};ui.evaluate("state.recoveryCatalog=catalog;state.pkg={name:'old.zip'};state.plan={written:true};updateRecoveryChoices();");ui.elements.get('recovery-profile').value='gat562';ui.context.boundedFetch=async()=>{if(!invalid)throw Error('CORS blocked');return new Uint8Array(128);};ui.context.recoveryPackage=()=>{throw Error('Recovery SHA-256 mismatch');};
    await ui.elements.get('load-recovery').onclick();assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('flash').disabled,true);assert.match(ui.elements.get('notice').textContent,invalid?/SHA-256/:/Download recovery bundle/);assert.deepEqual(ui.calls,[]);
  }
});

// Minimal DOM ancestry for collapsed-panel wiring; no browser is involved.
function collapsedPanels(ui){
  const advanced=ui.elements.get('advanced-options');assert.ok(advanced);advanced.tagName='DETAILS';advanced.open=false;advanced.hidden=false;
  for(const id of ['connection-options','custom-firmware','nrf-actions','migration-options','verification-options','esp-retry-options','image-details']){
    const panel=ui.elements.get(id);assert.ok(panel,id);panel.tagName='DETAILS';panel.open=false;panel.hidden=false;panel.parentElement=advanced;
  }
  for(const id of ['backups','console','capabilities']){const panel=ui.elements.get(id);panel.tagName='DETAILS';panel.open=false;panel.hidden=false;}
  ui.elements.get('archive-picker').tagName='DIV';ui.elements.get('archive-picker').parentElement=ui.elements.get('custom-firmware');
  return advanced;
}

test('revealing a required nested input opens every details ancestor without a hardware operation',async()=>{
  const ui=workbench();await Promise.resolve();const advanced=collapsedPanels(ui),custom=ui.elements.get('custom-firmware'),archive=ui.elements.get('archive-picker');
  advanced.hidden=true;archive.hidden=true;ui.evaluate("revealPanel('archive-picker');");
  assert.equal(archive.hidden,false);assert.equal(custom.open,true);assert.equal(advanced.open,true);assert.equal(advanced.hidden,false);assert.equal(ui.elements.get('connection-options').open,false);assert.deepEqual(ui.calls,[]);
});

test('pending recovery and reset controls reveal themselves but never reset, retry or write automatically',async()=>{
  for(const [state,panel]of [['migration','migration-options'],['needed','migration-options'],['espRecovery','esp-retry-options'],['recovery','nrf-actions'],['written','verification-options']]){
    const ui=workbench();await Promise.resolve();const advanced=collapsedPanels(ui);ui.elements.get(panel).hidden=true;
    ui.context.pendingPanelState=state;ui.evaluate("if(['written','needed'].includes(pendingPanelState))state.plan={[pendingPanelState]:true};else state[pendingPanelState]={};controls();");
    assert.equal(ui.elements.get(panel).open,true,state);assert.equal(ui.elements.get(panel).hidden,false,state);assert.equal(advanced.open,true,state);assert.deepEqual(ui.calls,[],state);
  }
});

test('tool navigation opens known collapsed sections and ignores unrelated fragments without USB activity',async()=>{
  const ui=workbench();await Promise.resolve();
  for(const id of ['firmware-choices','backups','console','capabilities','advanced-options']){
    collapsedPanels(ui);ui.elements.get(id).open=false;ui.context.window.location={hash:'#'+id};ui.evaluate('openLinkedPanel();');assert.equal(ui.elements.get(id).open,true,id);
  }
  collapsedPanels(ui);ui.context.window.location={hash:'#confirm-submit'};ui.evaluate('openLinkedPanel();');
  assert.equal(ui.elements.get('advanced-options').open,false);assert.equal(ui.elements.get('backups').open,false);assert.equal(ui.elements.get('confirm-submit').open,undefined);assert.deepEqual(ui.calls,[]);
});

test('the Web Serial status link opens the bottom console, including a repeated same-fragment click',async()=>{
  const ui=workbench();await Promise.resolve();collapsedPanels(ui);
  for(let i=0;i<2;i++){
    ui.elements.get('console').open=false;
    ui.windowEvents.click({target:{closest(selector){assert.equal(selector,'a[href^="#"]');return {getAttribute:()=> '#console'};}}});
    assert.equal(ui.elements.get('console').open,true);
  }
  assert.deepEqual(ui.calls,[]);
});

test('USB selection lists only the chosen port and its freshly read identity, clearing stale and disconnected labels',async()=>{
  const ui=workbench();await Promise.resolve();assert.equal(ui.elements.get('selected-port').hidden,true);assert.equal(ui.elements.get('selected-port').textContent,'');
  ui.context.chosenPort=ui.port;ui.evaluate('state.port=chosenPort;controls();');
  assert.equal(ui.elements.get('selected-port').textContent,'Selected: USB 303a:1001');assert.match(ui.elements.get('select-port').getAttribute('aria-label'),/Selected: USB 303a:1001/);
  ui.evaluate("state.device={model:'RAK 3401',name:'D4830D16'};state.portLabelEvidence={port:state.port,device:state.device};controls();");
  assert.equal(ui.elements.get('selected-port').textContent,'Selected: RAK 3401 · D4830D16 · USB 303a:1001');
  ui.context.dfuPort={getInfo:()=>({usbVendorId:0x239a,usbProductId:0x002a})};ui.evaluate('state.port=dfuPort;state.handoff=true;controls();');
  assert.equal(ui.elements.get('selected-port').textContent,'Selected: USB 239a:002a · DFU');assert.doesNotMatch(ui.elements.get('select-port').getAttribute('aria-label'),/RAK|D4830D16/);
  ui.serialEvents.disconnect({port:ui.context.dfuPort});assert.equal(ui.elements.get('selected-port').hidden,true);assert.equal(ui.elements.get('selected-port').textContent,'');assert.deepEqual(ui.calls,[]);
});

test('normal default controls keep extras closed and only an explicit visible nRF52 wipe expands its actions',async()=>{
  const ui=workbench();await Promise.resolve();const advanced=collapsedPanels(ui);ui.elements.get('nrf-actions').hidden=true;
  ui.evaluate('controls();');assert.equal(advanced.open,false);assert.equal(ui.elements.get('nrf-actions').open,false);
  ui.context.pkg=fakePackage();ui.evaluate("state.installMode='install';state.pkg=pkg;");ui.elements.get('nrf-actions').hidden=false;ui.evaluate('controls();');
  assert.equal(ui.elements.get('nrf-actions').open,true);assert.equal(advanced.open,true);assert.deepEqual(ui.calls,[]);
});

test('an unresolved automatic connection reveals its override and parent without sending control lines',async()=>{
  const ui=workbench();await Promise.resolve();const advanced=collapsedPanels(ui);ui.elements.get('transport-mode').value='auto';
  ui.context.chooseConnection=()=>({mode:null,reason:'Fixture connection needs manual selection.'});
  assert.throws(()=>ui.evaluate('connectionMode();'),/needs manual selection/);assert.equal(ui.elements.get('connection-options').open,true);assert.equal(advanced.open,true);assert.deepEqual(ui.calls,[]);
});

test('release archives reveal the exact-image chooser while expert components reveal their required top-level offset',async()=>{
  const ui=workbench();await Promise.resolve();const advanced=collapsedPanels(ui);
  ui.context.checkedZip=()=>[{name:'board.bin',length:64},{name:'README.txt',length:12}];
  await ui.evaluate("loadFirmware('release.zip',new Uint8Array(64));");
  assert.equal(ui.elements.get('archive-picker').hidden,false);assert.equal(ui.elements.get('custom-firmware').open,true);assert.equal(advanced.open,true);assert.equal(ui.evaluate('state.pkg'),null);
  advanced.open=false;ui.context.pkg=fakePackage({name:'bootloader.bin',architecture:'esp32',expert:true,destructive:true});ui.context.inspectFirmware=()=>ui.context.pkg;
  await ui.evaluate('loadFirmware(pkg.name,new Uint8Array(64));');assert.equal(ui.elements.get('expert-fields').hidden,false);assert.equal(advanced.open,false);assert.deepEqual(ui.calls,[]);
});

test('blocked migration downloads expose the offline ZIP inputs and exact download link',async()=>{
  const ui=workbench();await Promise.resolve();const advanced=collapsedPanels(ui),url='https://example.test/exact-migration.zip';
  ui.context.pkg=fakePackage({name:'app.bin',architecture:'esp32'});ui.context.selectedPort=ui.port;ui.evaluate('state.pkg=pkg;state.port=selectedPort;');
  ui.context.ensureBackup=async()=>{};ui.context.boundedFetch=async()=>{throw Error('Fixture CORS block');};
  ui.context.EspSession=class{async connect(){ui.calls.push('mock-connect');return{mac:'aa:bb:cc:dd:ee:ff',chip:'ESP32',flashBytes:4<<20};}async prepare(){throw Object.assign(Error('Needs migration artifact'),{download:{url}});}async close(){ui.calls.push('mock-close');}};
  await ui.elements.get('prepare').onclick();
  assert.equal(ui.elements.get('migration-options').open,true);assert.equal(advanced.open,true);assert.equal(ui.elements.get('download-migration').hidden,false);assert.equal(ui.elements.get('download-migration').href,url);
  assert.match(ui.elements.get('notice').textContent,/Could not automatically download.*Fixture CORS block/);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,['mock-connect','mock-close']);
});

test('migration artifact validator errors are not mislabeled as download restrictions',async()=>{
  const ui=workbench();await Promise.resolve();const advanced=collapsedPanels(ui),url='https://example.test/exact-migration.zip';
  ui.elements.get('download-migration').hidden=true;
  ui.context.pkg=fakePackage({name:'app.bin',architecture:'esp32'});ui.context.selectedPort=ui.port;ui.evaluate('state.pkg=pkg;state.port=selectedPort;');
  ui.context.ensureBackup=async()=>{};ui.context.boundedFetch=async()=>new Uint8Array(8);
  ui.context.BrowserPlanner=class{async call(op){assert.equal(op,'download');throw Error('Fixture artifact verification failed');}};
  ui.context.EspSession=class{async connect(){return{mac:'aa:bb:cc:dd:ee:ff',chip:'ESP32',flashBytes:4<<20};}async prepare(){throw Object.assign(Error('Needs migration artifact'),{download:{url}});}async close(){}};
  await ui.elements.get('prepare').onclick();
  assert.match(ui.elements.get('notice').textContent,/Fixture artifact verification failed/);assert.doesNotMatch(ui.elements.get('notice').textContent,/blocked|Download exact|automatically download/);
  assert.equal(ui.elements.get('download-migration').hidden,true);assert.equal(ui.elements.get('migration-options').open,false);assert.equal(advanced.open,false);assert.equal(ui.evaluate('state.plan'),null);
});

test('importing a validated backup reveals restore controls without restoring or opening USB',async()=>{
  const ui=workbench();await Promise.resolve();collapsedPanels(ui);
  const archive={schema:'org.meshfirmware.web-backup/v1',payload:{role:'companion',publicKey:'a'.repeat(64),channels:[],contacts:[]}};
  ui.elements.get('backup-file').files=[{name:'backup.json',size:2,text:async()=>'{}'}];ui.context.parseBackup=async()=>archive;ui.context.verifyBackup=value=>value.payload;
  await ui.elements.get('backup-file').onchange();assert.equal(ui.elements.get('backups').open,true);assert.equal(ui.evaluate('state.restore'),archive);assert.equal(ui.elements.get('restore').disabled,true);assert.deepEqual(ui.calls,[]);
});

async function commonRestoreWorkbench(){
  const ui=workbench();await Promise.resolve();const archive={schema:'org.meshfirmware.web-backup/v1',sha256:'a'.repeat(64),payload:{role:'common-cli',publicKey:'11'.repeat(32),replies:{'get name':'> Restored'}}};
  const preview={operations:[{id:'name',label:'Node name'}],skipped:[{id:'region',label:'Regions',reason:'Unstructured snapshot requires manual review.'}],warnings:['The primary radio tuple does not record preamble length; restoring it selects the firmware’s automatic preamble.'],privateIdentity:true};
  ui.context.parseBackup=async()=>archive;ui.context.verifyBackup=value=>{assert.ok(value);return value.payload;};ui.context.commonCliRestorePreview=()=>preview;ui.context.selectedPort=ui.port;ui.evaluate('state.port=selectedPort;');
  ui.elements.get('backup-file').files=[{name:'saved.json',size:2,text:async()=>'{}'}];await ui.elements.get('backup-file').onchange();return {...ui,archive,preview};
}

test('Import JSON opens only a local file chooser and never opens USB or restores automatically',async()=>{
  const ui=workbench();await Promise.resolve();let picker=0;ui.elements.get('backup-file').click=()=>picker++;
  ui.elements.get('import-backup-json').onclick();assert.equal(picker,1);assert.deepEqual(ui.calls,[]);ui.evaluate('state.busy=true;');ui.elements.get('import-backup-json').onclick();assert.equal(picker,1);
});

test('CommonCLI JSON import previews supported and skipped settings, resets old identity approvals and enables review only',async()=>{
  const ui=await commonRestoreWorkbench();assert.equal(ui.evaluate('state.restore'),ui.archive);assert.equal(ui.elements.get('restore-preview').hidden,false);assert.equal(ui.elements.get('restore').disabled,false);assert.match(ui.elements.get('restore-report').textContent,/Ready: Node name/);assert.match(ui.elements.get('restore-report').textContent,/Skipped: Regions/);assert.match(ui.elements.get('backup-summary').textContent,/serial console.*Nothing uploaded or written/);assert.deepEqual(ui.calls,[]);
  ui.elements.get('new-hardware').checked=true;ui.elements.get('replace-identity').checked=true;await ui.elements.get('backup-file').onchange();assert.equal(ui.elements.get('new-hardware').checked,false);assert.equal(ui.elements.get('replace-identity').checked,false);assert.deepEqual(ui.calls,[]);
});

test('invalid imports cannot leave an older restore ready and unsupported-only JSON cannot authorize writes',async()=>{
  const ui=await commonRestoreWorkbench();ui.context.parseBackup=async()=>{throw Error('Backup digest mismatch');};await ui.elements.get('backup-file').onchange();assert.equal(ui.evaluate('state.restore'),null);assert.equal(ui.evaluate('state.restorePreview'),null);assert.equal(ui.elements.get('restore-preview').hidden,true);assert.equal(ui.elements.get('restore').disabled,true);
  ui.context.parseBackup=async()=>ui.archive;ui.context.commonCliRestorePreview=()=>({operations:[],skipped:[],warnings:[],privateIdentity:false});await ui.elements.get('backup-file').onchange();assert.equal(ui.elements.get('restore').disabled,true);ui.context.confirm=async()=>assert.fail('No supported setting means no write confirmation');await ui.elements.get('restore').onclick();assert.match(ui.elements.get('notice').textContent,/no supported settings/);assert.deepEqual(ui.calls,[]);
});

test('cross-hardware and identity choices refresh the local preview without changing the node',async()=>{
  const ui=await commonRestoreWorkbench();ui.context.commonCliRestorePreview=(_payload,options)=>{assert.equal(options.newHardware,true);return {...ui.preview,operations:[],skipped:[{id:'rxgain',label:'RX gain',reason:'Retained on the new board.'}]};};ui.elements.get('new-hardware').checked=true;ui.elements.get('new-hardware').onchange();assert.match(ui.elements.get('restore-report').textContent,/Retained on the new board/);assert.equal(ui.elements.get('restore').disabled,true);ui.elements.get('replace-identity').checked=true;ui.elements.get('replace-identity').onchange();assert.equal(ui.elements.get('restore').disabled,false);assert.deepEqual(ui.calls,[]);
});

test('restore cancellation retains the old flash proof and includes limitations in the final button confirmation',async()=>{
  const ui=await commonRestoreWorkbench();ui.context.plan={sha256:'b'.repeat(64)};ui.evaluate('state.plan=plan;');ui.context.confirm=async(title,detail,warning,action)=>{assert.match(title,/serial console/);assert.match(detail,/1 serial settings/);assert.match(warning,/automatic preamble/);assert.match(warning,/not atomic/);assert.match(action,/^RESTORE /);return false;};await ui.elements.get('restore').onclick();assert.equal(ui.evaluate('state.plan'),ui.context.plan);assert.deepEqual(ui.calls,[]);
});

test('changed target, imported JSON, flash context or identity choices stop restore before opening serial',async()=>{
  for(const change of ['port','generation','archive','new-hardware','replace-identity','pkg','plan','mode']){
    const ui=await commonRestoreWorkbench();ui.context.confirm=async()=>{if(change==='port')ui.evaluate('state.port=null;');if(change==='generation')ui.evaluate('state.generation++;');if(change==='archive')ui.evaluate('state.restore={};');if(change==='new-hardware'||change==='replace-identity')ui.elements.get(change).checked=true;if(change==='pkg'||change==='plan')ui.evaluate(`state.${change}={};`);if(change==='mode')ui.evaluate("state.installMode='install';");return true;};await ui.elements.get('restore').onclick();assert.match(ui.elements.get('notice').textContent,/changed during confirmation/,change);assert.deepEqual(ui.calls,[],change);
  }
});

test('reviewed CommonCLI restore uses guarded serial settings, invalidates flash approval and reports without logging secrets',async()=>{
  const ui=await commonRestoreWorkbench();ui.context.plan={sha256:'b'.repeat(64)};ui.evaluate('state.plan=plan;state.backupApproved={};state.verification={sha256:"c".repeat(64)};');ui.context.confirm=async()=>true;
  ui.context.SerialLink=class{async open(){ui.calls.push('open');}async close(){ui.calls.push('close');}async command(command){ui.calls.push(command);return 'SECRET_TEST_VALUE';}};
  ui.context.restoreCommonCli=async(link,payload,options,report)=>{assert.equal(payload,ui.archive.payload);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.backupApproved'),null);assert.equal(ui.evaluate('state.verification'),null);options.assertCurrent();assert.equal(await link.command('get name'),'SECRET_TEST_VALUE');await link.command('set name Restored');report(.9,'Node name checked');return {restored:[{id:'name',label:'Node name'}],skipped:ui.preview.skipped,warnings:['Some saved options require a manual restart.']};};
  await ui.elements.get('restore').onclick();assert.deepEqual(ui.calls,['open','get name','set name Restored','close']);assert.match(ui.elements.get('restore-summary').textContent,/1 settings restored; 1 skipped/);assert.match(ui.elements.get('restore-report').textContent,/Restored: Node name/);assert.match(ui.elements.get('notice').textContent,/serial settings restored and checked/);assert.ok(!ui.elements.get('log').textContent.includes('SECRET_TEST_VALUE'));assert.equal(ui.evaluate('state.restore'),ui.archive);
});

test('serial context changes during restore prevent another setter and never claim completion',async()=>{
  const ui=await commonRestoreWorkbench();ui.context.confirm=async()=>true;ui.context.SerialLink=class{async open(){ui.calls.push('open');}async close(){ui.calls.push('close');}async command(command){ui.calls.push(command);ui.evaluate('state.generation++;');return '> value';}};ui.context.restoreCommonCli=async link=>{await link.command('get name');await link.command('set name Do not write');};await ui.elements.get('restore').onclick();assert.deepEqual(ui.calls,['open','get name','close']);assert.match(ui.elements.get('notice').textContent,/Restore stopped/);assert.match(ui.elements.get('restore-summary').textContent,/Restore stopped.*Earlier settings may already have changed/);assert.doesNotMatch(ui.elements.get('notice').textContent,/restored and checked/);
});

test('restore completion distinguishes skipped-only results, saved identity and changes requiring restart',async()=>{
  for(const outcome of ['skipped-only','identity','restart']){
    const ui=await commonRestoreWorkbench();ui.context.confirm=async()=>true;ui.context.SerialLink=class{async open(){}async close(){}};
    ui.context.restoreCommonCli=async()=>({restored:outcome==='restart'?[{id:'wifi.ssid',label:'Wi-Fi SSID'}]:[],skipped:[],warnings:[],identityPendingReboot:outcome==='identity',restartRequired:outcome!=='skipped-only'});
    await ui.elements.get('restore').onclick();const status=ui.elements.get('notice').textContent;
    if(outcome==='skipped-only'){assert.match(status,/No settings were changed/);assert.doesNotMatch(status,/restored and checked/);}else if(outcome==='identity'){assert.match(status,/requires a manual reboot/);assert.match(status,/identity has not yet been verified/);}else assert.match(status,/manual restart is required/);
    assert.deepEqual(ui.calls,[]);
  }
});

test('restore cannot discard active write sessions, reset proofs, migration or recovery records',async()=>{
  for(const field of ['esp','written','migrationApproval','migration','recovery','espRecovery','handoff','dfu','already-bootloader']){
    const ui=await commonRestoreWorkbench();ui.context.protectedState={revoke:()=>assert.fail('A disabled restore must not revoke migration approval')};if(field==='dfu')ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0044});else if(field==='already-bootloader')ui.elements.get(field).checked=true;else if(field==='written')ui.evaluate('state.plan={written:true};');else ui.evaluate(`state.${field}=protectedState;`);ui.evaluate('controls();');assert.equal(ui.elements.get('restore').disabled,true,field);ui.context.confirm=async()=>assert.fail('Blocked restores stop before prompting');await ui.elements.get('restore').onclick();assert.deepEqual(ui.calls,[],field);if(field==='written')assert.equal(ui.evaluate('state.plan.written'),true);else if(!['dfu','already-bootloader'].includes(field))assert.equal(ui.evaluate(`state.${field}`),ui.context.protectedState,field);
  }
});

test('a blocked custom URL download reveals its exact download link and local-file alternative',async()=>{
  const ui=workbench();await Promise.resolve();const advanced=collapsedPanels(ui),url='https://example.test/custom.bin';
  ui.elements.get('custom-url').value=url;ui.context.pkg=fakePackage();ui.evaluate('state.pkg=pkg;state.plan={written:true};');
  ui.context.boundedFetch=async()=>{throw Error('Fixture CORS block');};await ui.elements.get('fetch-custom').onclick();
  assert.equal(ui.elements.get('image-details').open,true);assert.equal(ui.elements.get('custom-firmware').open,true);assert.equal(advanced.open,true);assert.equal(ui.elements.get('download-firmware').href,url);
  assert.match(ui.elements.get('notice').textContent,/Fixture CORS block/);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(ui.calls,[]);
});

test('firmware validation failures after a successful download are not misreported as CORS or network failures',async()=>{
  for(const action of ['fetch-firmware','fetch-custom']){
    const ui=workbench();await Promise.resolve();collapsedPanels(ui);
    ui.context.item={...v4Item,url:'https://firmware.example.test/exact-board.bin',name:'exact-board.bin'};
    ui.evaluate("state.items=[item];state.pkg={name:'old.bin'};state.plan={written:true};");
    ui.elements.get('artifact').value='0';ui.elements.get('custom-url').value=ui.context.item.url;
    ui.context.boundedFetch=async()=>new Uint8Array(64);
    ui.context.inspectFirmware=()=>{throw Error('Firmware checksum rejected after download');};
    await ui.elements.get(action).onclick();
    const message=ui.elements.get('notice').textContent;
    assert.match(message,/Firmware checksum rejected after download/,action);
    assert.doesNotMatch(message,/CORS|network restrictions|could not download|host blocks|choose.*local file/i,action);
    assert.equal(ui.evaluate('state.pkg'),null,action);assert.equal(ui.evaluate('state.plan'),null,action);assert.equal(ui.elements.get('flash').disabled,true,action);assert.deepEqual(ui.calls,[],action);
  }
});

test('a failed catalog download names its host and exposes the exact local-file fallback without claiming CORS is proven',async()=>{
  const ui=workbench();await Promise.resolve();const advanced=collapsedPanels(ui),url='https://firmware.example.test/exact-board.bin';
  ui.context.item={...v4Item,url,name:'exact-board.bin'};ui.evaluate("state.items=[item];state.pkg={name:'old.bin'};state.plan={written:true};");ui.elements.get('artifact').value='0';
  ui.context.boundedFetch=async()=>{throw Error('Failed to fetch');};
  await ui.elements.get('fetch-firmware').onclick();
  const message=ui.elements.get('notice').textContent;
  assert.match(message,/Could not download exact-board\.bin from firmware\.example\.test/i);
  assert.match(message,/Retry the numbered action first/);assert.match(message,/Choose a local firmware file on this page/);assert.match(message,/Keep ZIP files zipped/);assert.match(message,/do not extract or drag folders onto the radio/);
  assert.match(message,/including CORS|CORS.{0,25}(?:can|may)|(?:can|may).{0,25}CORS/i);
  assert.doesNotMatch(message,/CORS (?:caused|blocked)|blocked (?:by|because of) CORS/i);
  assert.equal(ui.elements.get('download-firmware').href,url);assert.equal(ui.elements.get('image-details').open,true);assert.equal(ui.elements.get('custom-firmware').open,true);assert.equal(advanced.open,true);
  assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(ui.calls,[]);
});

test('known HTTP, size and response-body failures preserve their cause without suggesting CORS',async()=>{
  for(const failure of ['http','declared-size','stream-size','body']){
    const ui=workbench();await Promise.resolve();collapsedPanels(ui);let cancelled=0,released=0;
    ui.context.item={...v4Item,name:'exact-board.bin',url:'https://firmware.example.test/exact-board.bin'};ui.evaluate('state.items=[item];');ui.elements.get('artifact').value='0';
    const reader={read:async()=>({value:new Uint8Array((64<<20)+1),done:false}),cancel:async()=>{cancelled++;},releaseLock(){released++;}};
    ui.context.fetch=async()=>({ok:failure!=='http',status:404,headers:{get:()=>failure==='declared-size'?String((64<<20)+1):null},body:failure==='body'?null:{getReader:()=>reader}});
    await ui.elements.get('fetch-firmware').onclick();
    const message=ui.elements.get('notice').textContent;
    assert.match(message,failure==='http'?/HTTP 404/:failure==='body'?/no readable response body/:/exceeds.*(?:64 MiB|permitted size)/,failure);
    assert.doesNotMatch(message,/CORS|network restrictions/i,failure);assert.match(message,/firmware\.example\.test/,failure);
    assert.equal(cancelled,failure==='stream-size'?1:0,failure);assert.equal(released,failure==='stream-size'?1:0,failure);
    assert.equal(ui.evaluate('state.pkg'),null,failure);assert.equal(ui.evaluate('state.plan'),null,failure);assert.deepEqual(ui.calls,[],failure);
  }
});

test('catalog firmware downloads automatically from its verified same-origin mirror without a local file or USB operation',async()=>{
  const ui=workbench();await Promise.resolve();const payload=new Uint8Array(64).fill(7),compressed=gzipSync(payload),sha256=firmwareHash(payload),mirrorBase='https://mikecarper.github.io/meshfirmware/firmware/',url='https://github.com/mikecarper/MeshCore/releases/download/v1/exact-node.zip',requests=[],loaded=[];
  const entry={url,sha256,size:payload.length,gzipSha256:firmwareHash(compressed),gzipSize:compressed.length,path:sha256+'.gz'},index={schemaVersion:1,entries:[entry],warnings:[]};
  ui.context.item={...v4Item,name:'exact-node.zip',url,sha256};ui.evaluate('state.items=[item];state.plan={old:true};');ui.elements.get('artifact').value='0';
  ui.context.fetchFirmwareBytes=(source,options)=>{assert.equal(options.expectedSha256,sha256);return verifiedDownload(source,{...options,mirrorBase,pageOrigin:'https://mikecarper.github.io',fetchImpl:async target=>{requests.push(target);if(target===mirrorBase+'index.json')return new Response(JSON.stringify(index));if(target===mirrorBase+entry.path)return new Response(compressed);throw Error('Original cross-origin source must not be fetched');}});};
  ui.context.loadFirmware=async(name,bytes,item)=>{loaded.push({name,bytes,item});ui.context.downloadedPkg=fakePackage({name,sha256});ui.evaluate('state.pkg=downloadedPkg;');};
  await ui.elements.get('fetch-firmware').onclick();
  assert.deepEqual(requests,[mirrorBase+'index.json',mirrorBase+entry.path]);assert.equal(loaded.length,1);assert.equal(loaded[0].name,'exact-node.zip');assert.deepEqual(loaded[0].bytes,payload);assert.equal(loaded[0].item,ui.context.item);assert.ok(ui.evaluate('state.pkg'));assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('firmware-file').files.length,0);assert.deepEqual(ui.calls,[]);
});

test('corrupt hosted firmware cannot load, switch sources or retain an earlier flash plan',async()=>{
  const ui=workbench();await Promise.resolve();const payload=new Uint8Array(64).fill(7),compressed=gzipSync(payload),sha256=firmwareHash(payload),mirrorBase='https://mikecarper.github.io/meshfirmware/firmware/',url='https://github.com/mikecarper/MeshCore/releases/download/v1/exact-node.zip',requests=[];
  const entry={url,sha256,size:payload.length,gzipSha256:firmwareHash(compressed),gzipSize:compressed.length,path:sha256+'.gz'},index={schemaVersion:1,entries:[entry],warnings:[]},bad=Buffer.from(compressed);bad[12]^=1;
  ui.context.item={...v4Item,name:'exact-node.zip',url,sha256};ui.context.old=fakePackage();ui.evaluate('state.items=[item];state.pkg=old;state.plan={written:true};');ui.elements.get('artifact').value='0';
  ui.context.fetchFirmwareBytes=(source,options)=>verifiedDownload(source,{...options,mirrorBase,pageOrigin:'https://mikecarper.github.io',fetchImpl:async target=>{requests.push(target);if(target===mirrorBase+'index.json')return new Response(JSON.stringify(index));if(target===mirrorBase+entry.path)return new Response(bad);throw Error('No unverified fallback');}});
  ui.context.loadFirmware=async()=>{throw Error('Corrupt bytes must not reach image parsing');};await ui.elements.get('fetch-firmware').onclick();
  assert.deepEqual(requests,[mirrorBase+'index.json',mirrorBase+entry.path]);assert.match(ui.elements.get('notice').textContent,/compressed SHA-256/);assert.doesNotMatch(ui.elements.get('notice').textContent,/CORS|network restrictions/);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(ui.calls,[]);
});

test('a blocked exact-board bootloader download reveals its link and local-file alternative without retaining write proof',async()=>{
  const ui=workbench();await Promise.resolve();const advanced=collapsedPanels(ui),url='https://example.test/board_bootloader.zip';
  ui.context.item={architecture:'nrf52',hardware:'Exact board',bootloader:[url],bootloaderInfo:{url,sha256:'b'.repeat(64),size:64,profile:'exact-board',version:'2.4.12'}};
  ui.elements.get('hardware').value='Exact board';ui.elements.get('bootloader-source').value=url;ui.evaluate("state.items=[item];state.pkg={name:'previous.zip'};state.plan={written:true};");
  ui.context.boundedFetch=async()=>{throw Error('Fixture bootloader CORS block');};await ui.elements.get('load-bootloader').onclick();
  assert.equal(ui.elements.get('image-details').open,true);assert.equal(ui.elements.get('custom-firmware').open,true);assert.equal(advanced.open,true);assert.equal(ui.elements.get('download-firmware').href,url);
  assert.match(ui.elements.get('notice').textContent,/download the bootloader ZIP/);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(ui.calls,[]);
});

test('a blocked erase ZIP download reveals its exact link and local erase input while retaining the final image',async()=>{
  const ui=workbench();await Promise.resolve();const advanced=collapsedPanels(ui),url='https://example.test/exact-erase.zip';
  ui.elements.get('nrf-actions').hidden=true;ui.elements.get('erase-source').value=url;ui.context.pkg=fakePackage({name:'intended-final.zip'});ui.evaluate('state.pkg=pkg;state.plan=null;');
  ui.context.boundedFetch=async()=>{throw Error('Fixture erase CORS block');};await assert.rejects(ui.evaluate('erasePackage();'),/Download the exact erase ZIP/);
  assert.equal(ui.elements.get('image-details').open,true);assert.equal(ui.elements.get('nrf-actions').open,true);assert.equal(ui.elements.get('nrf-actions').hidden,false);assert.equal(advanced.open,true);assert.equal(ui.elements.get('download-firmware').href,url);
  assert.equal(ui.elements.get('custom-firmware').open,false);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,[]);
});

test('erase download diagnostics preserve integrity failures and cannot approve a stale radio or final image',async()=>{
  for(const failure of ['hash','radio','image','source']){
    const ui=workbench();await Promise.resolve();ui.context.pkg=fakePackage({name:'intended-final.zip'});ui.evaluate('state.pkg=pkg;');ui.elements.get('erase-source').value='https://flasher.meshcore.io/firmware/FLASH_ERASE_nrf52_softdevice_v6.zip';let release;
    ui.context.boundedFetch=()=>new Promise((resolve,reject)=>{release=failure==='hash'?()=>reject(Object.assign(Error('Public erase utility pinned SHA-256 mismatch'),{downloadKind:'mirror'})):()=>resolve(new Uint8Array(64));});ui.context.inspectFirmware=()=>{assert.fail('A stale download cannot be parsed or approved');};
    const preparing=ui.evaluate('erasePackage();');if(failure==='radio')ui.evaluate('state.generation++;');if(failure==='image')ui.evaluate('state.pkg={name:"different.zip"};');if(failure==='source')ui.elements.get('erase-source').value='https://example.test/other.zip';release();
    await assert.rejects(preparing,failure==='hash'?/pinned SHA-256 mismatch/:/selected radio, final firmware or erase utility changed/);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,[]);
  }
});

const mergedItem=item=>({...item,action:'flash-wipe',name:item.name.replace(/\.bin$/i,'-merged.bin'),url:item.url.replace(/\.bin$/i,'-merged.bin'),sha256:'d'.repeat(64)});
const artifactChoices=ui=>ui.elements.get('artifact').options.filter(option=>option.value).map(option=>option.value);
function customEspImage({merged=false,expert=false}={}){
  const app=radioDefaultsImage();
  if(expert){app.fill(0,32,36);app[239]=app.subarray(32,224).reduce((checksum,byte)=>checksum^byte,0xef);}
  if(!merged)return app;
  const bytes=new Uint8Array(0x10000+app.length).fill(255),table=Uint8Array.from(migrationFlowFixture().bridgePlan.targetTable);
  const boot=app.slice();boot.fill(0,32,36);boot[239]=boot.subarray(32,224).reduce((checksum,byte)=>checksum^byte,0xef);
  bytes.set(boot);bytes.set(table,0x8000);bytes.set(app,0x10000);return bytes;
}
async function customEspWorkbench(mode='update'){
  const ui=workbench();await Promise.resolve();ui.context.hash=firmwareHash;ui.context.inspectFirmware=inspectFirmwareBytes;ui.context.inventory=[v4Item,mergedItem(v4Item)];ui.context.initialMode=mode;
  ui.evaluate('state.items=inventory;state.installMode=initialMode;syncInstallMode();filterCatalog();');ui.elements.get('hardware').value=v4Item.hardware;return ui;
}

test('Custom firmware is a first-class Firmware choice and exposes local and URL inputs in that section',async()=>{
  const ui=await customEspWorkbench();ui.elements.get('provider').value='Custom';ui.elements.get('auto-detect-board').checked=true;
  await ui.elements.get('provider').onchange();
  assert.equal(ui.elements.get('provider').value,'Custom');assert.equal(ui.evaluate('state.manualSelections.provider'),'Custom');
  assert.equal(ui.elements.get('custom-firmware').hidden,false);assert.equal(ui.elements.get('custom-firmware').open,true);
  assert.equal(ui.elements.get('artifact-field').hidden,true);assert.equal(ui.elements.get('role').disabled,true);assert.equal(ui.elements.get('version').disabled,true);
  assert.deepEqual(artifactChoices(ui),[]);assert.deepEqual(ui.calls,[]);
  ui.elements.get('provider').value='Keymind Cascade';await ui.elements.get('provider').onchange();
  assert.equal(ui.elements.get('custom-firmware').hidden,true);assert.equal(ui.elements.get('artifact-field').hidden,false);
});

test('custom inspection explains detected merged origin and actual app offsets without writing or claiming early expansion success',async()=>{
  const ui=await customEspWorkbench();ui.context.image=customEspImage();ui.elements.get('provider').value='Custom';
  await ui.evaluate('loadFirmware("renamed.bin",image);');ui.evaluate('controls();');
  assert.equal(ui.elements.get('firmware-inspection').hidden,false,ui.evaluate('JSON.stringify({pkg:state.pkg?.name,provider:$("provider").value,summary:$("automatic-summary").textContent})'));assert.match(ui.elements.get('firmware-inspection-summary').textContent,/Application update/);
  assert.match(ui.elements.get('firmware-inspection-layout').textContent,/read from the connected radio/);
  ui.evaluate('state.plan={sha256:state.pkg.sha256,addresses:[0x420000,0x20000]};controls();');
  assert.match(ui.elements.get('firmware-inspection-layout').textContent,/0x420000, 0x20000.*no expansion needed/);
  ui.evaluate('state.plan={sha256:state.pkg.sha256,addresses:[0x10000,0x150000],needed:true};controls();');
  assert.match(ui.elements.get('firmware-inspection-layout').textContent,/expansion required.*bridge.*checked after expansion/i);
  ui.context.image=customEspImage({merged:true});await ui.evaluate('loadFirmware("anything.bin",image);');ui.evaluate('controls();');
  assert.match(ui.elements.get('firmware-inspection-layout').textContent,/write offset 0x0.*no expansion bridge/);assert.deepEqual(ui.calls,[]);
});

test('custom dropdown selection preserves the deliberate local image during automatic device matching',async()=>{
  const ui=await customEspWorkbench();ui.elements.get('auto-detect-board').checked=true;ui.elements.get('provider').value='Custom';ui.context.image=customEspImage();
  await ui.evaluate('loadFirmware("mine.bin",image);');ui.evaluate('state.manualSelections.provider="Custom";state.device={model:"Heltec V4",role:"common-cli"};selectDetectedBoard();');
  assert.equal(ui.elements.get('provider').value,'Custom');assert.equal(ui.evaluate('state.pkg?.name'),'mine.bin',ui.elements.get('automatic-summary').textContent);assert.equal(ui.evaluate('state.pkg.sha256'),firmwareHash(ui.context.image));assert.deepEqual(ui.calls,[]);
});

test('validated custom ESP32 bytes select their installation mode without discarding the image or authorizing a write',async()=>{
  for(const [initial,merged,expected]of [['update',true,'install'],['install',false,'update']]){
    const ui=await customEspWorkbench(initial),image=customEspImage({merged});ui.context.image=image;
    await ui.evaluate('loadFirmware("custom.bin",image);');ui.evaluate('controls();');
    assert.equal(ui.evaluate('state.installMode'),expected);assert.equal(ui.elements.get('install-mode-install').checked,merged);assert.equal(ui.elements.get('install-mode-update').checked,!merged);assert.equal(ui.elements.get('flash-action').value,merged?'wipe':'update');
    assert.equal(ui.evaluate('state.pkg.payload'),image);assert.equal(ui.evaluate('state.pkg.sha256'),firmwareHash(image));assert.equal(ui.evaluate('state.radioDefaults.sourceSha256'),firmwareHash(image));assert.equal(ui.elements.get('image-name').textContent,'custom.bin');
    assert.equal(ui.evaluate('state.item.hardware'),v4Item.hardware);assert.equal(ui.evaluate('state.item.role'),undefined);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.backupApproved'),null);assert.equal(ui.elements.get('skip-backup').checked,false);assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(ui.calls,[]);
    assert.deepEqual(artifactChoices(ui),[merged?'1':'0']);assert.equal(ui.evaluate('installModeSource.kind'),'manual');
    if(!merged)assert.match(ui.elements.get('notice').textContent,/Application-only update.*no whole-chip erase/i);
    ui.elements.get('flash-action').value=merged?'update':'wipe';ui.evaluate('controls();assertInstallModePackage(state.pkg);');assert.equal(ui.elements.get('flash-action').value,merged?'wipe':'update');
  }
});

test('a custom merged image still needs the final destructive-write confirmation after automatic mode selection',async()=>{
  const ui=await customEspWorkbench();ui.context.image=customEspImage({merged:true});ui.context.selectedPort=ui.port;
  await ui.evaluate('loadFirmware("custom.bin",image);');ui.evaluate('state.port=selectedPort;state.plan={generation:state.generation,port:state.port,sha256:state.pkg.sha256,installMode:state.installMode,addresses:[0],mac:"aa:bb:cc:dd:ee:ff"};');
  ui.context.confirm=async(_title,_detail,warning,token)=>{ui.calls.push(token);assert.match(warning,/whole-chip erase|identity|settings/i);return false;};
  await ui.evaluate('flashPreparedFirmware();');assert.deepEqual(ui.calls,['WIPE WITHOUT BACKUP']);assert.equal(ui.evaluate('state.plan.written'),undefined);assert.equal(ui.evaluate('state.pkg.payload'),ui.context.image);
});

test('custom mode inference excludes catalog selections, components, UF2, nRF52 and pending device flows',async()=>{
  for(const catalogSource of ['explicit','local-name']){
    const ui=await customEspWorkbench();ui.context.image=customEspImage({merged:true});ui.context.exact={...mergedItem(v4Item),name:'exact.bin'};ui.evaluate('state.items.push(exact);');
    await ui.evaluate(`loadFirmware(exact.name,image,${catalogSource==='explicit'?'exact':'null'});`);
    assert.equal(ui.evaluate('state.installMode'),'update',catalogSource);assert.equal(ui.evaluate('state.item'),ui.context.exact);assert.throws(()=>ui.evaluate('assertInstallModePackage(state.pkg);'),/merged erase\/new install/);assert.deepEqual(ui.calls,[]);
  }
  for(const pkg of [inspectFirmwareBytes('component.bin',customEspImage({expert:true})),fakePackage({name:'firmware.uf2',architecture:'uf2',kind:'UF2 drive copy',destructive:true}),fakePackage({name:'application.zip'})]){
    const ui=await customEspWorkbench('install');ui.context.selected=pkg;ui.context.inspectFirmware=()=>pkg;ui.context.checkedZip=()=>[{name:'manifest.json'},{name:'app.bin'},{name:'app.dat'}];
    await ui.evaluate('loadFirmware(selected.name,new Uint8Array(64));');assert.equal(ui.evaluate('state.installMode'),'install',pkg.architecture);assert.equal(ui.evaluate('state.pkg'),pkg);assert.deepEqual(ui.calls,[]);
  }
  for(const field of ['handoff','migration','migrationApproval','recovery','espRecovery','verification','plan','flashProgress']){
    const ui=await customEspWorkbench();ui.context.image=customEspImage({merged:true});ui.context.pendingField=field;
    ui.evaluate('state[pendingField]=pendingField==="handoff"?true:pendingField==="plan"?{written:true}:pendingField==="migrationApproval"?{revoke(){}}:{};');
    await ui.evaluate('loadFirmware("custom.bin",image);');assert.equal(ui.evaluate('state.installMode'),'update',field);assert.equal(ui.evaluate('state.pkg.payload'),ui.context.image,field);assert.equal(ui.elements.get('skip-backup').checked,false,field);assert.deepEqual(ui.calls,[],field);
  }
});

test('invalid custom bytes or a published hash mismatch cannot change installation mode',async()=>{
  for(const fault of ['image','hash']){
    const ui=await customEspWorkbench();ui.context.image=fault==='image'?new Uint8Array(64):customEspImage({merged:true});if(fault==='hash')ui.elements.get('expected-sha').value='a'.repeat(64);
    await assert.rejects(ui.evaluate('loadFirmware("custom.bin",image);'),fault==='image'?/validated ESP32 image/:/SHA-256 does not match/);assert.equal(ui.evaluate('state.installMode'),'update');assert.equal(ui.evaluate('state.pkg'),null);assert.deepEqual(ui.calls,[]);
  }
});

test('custom application-only selection cannot silently undo the Meshtastic erase policy',async()=>{
  for(const source of ['device','mode-source']){
    const ui=await customEspWorkbench('install');ui.context.image=customEspImage();
    ui.evaluate(source==='device'?'state.device={firmwareFamily:"meshtastic",role:"meshtastic"};':'installModeSource={kind:"meshtastic",port:state.port};');
    await ui.evaluate('loadFirmware("custom.bin",image);');assert.equal(ui.evaluate('state.installMode'),'install',source);assert.equal(ui.evaluate('state.pkg.payload'),ui.context.image);assert.throws(()=>ui.evaluate('assertInstallModePackage(state.pkg);'),/validated merged ESP32 image/);assert.deepEqual(ui.calls,[]);
  }
  const ui=await customEspWorkbench('update');ui.context.image=customEspImage();ui.evaluate('state.device={firmwareFamily:"meshtastic",role:"meshtastic"};installModeSource={kind:"manual",port:state.port};');
  await ui.evaluate('loadFirmware("custom.bin",image);');assert.equal(ui.evaluate('state.installMode'),'update');ui.evaluate('assertInstallModePackage(state.pkg);');assert.deepEqual(ui.calls,[]);
});

test('custom source handlers retain pre-invalidation mode locks and never let an allowance override a new pending flow',async()=>{
  for(const source of ['file','url'])for(const phase of ['written-plan','approval','new-migration']){
    const ui=await customEspWorkbench(),image=customEspImage({merged:true});ui.context.image=image;
    if(phase==='written-plan')ui.evaluate('state.plan={written:true};');if(phase==='approval')ui.evaluate('state.migrationApproval={revoke(){}};');
    const read=async()=>{if(phase==='new-migration')ui.evaluate('state.migration={phase:"pending"};');return image;};
    if(source==='file'){ui.elements.get('firmware-file').files=[{name:'custom.bin',size:image.length,arrayBuffer:async()=>(await read()).buffer}];await ui.elements.get('firmware-file').onchange();}
    else{ui.elements.get('custom-url').value='https://example.test/custom.bin';ui.context.downloadFirmwareBytes=read;await ui.elements.get('fetch-custom').onclick();}
    assert.equal(ui.evaluate('state.installMode'),'update',`${source}: ${phase}`);assert.equal(ui.evaluate('state.pkg.sha256'),firmwareHash(image));assert.deepEqual(ui.calls,[]);
  }
  for(const blockedBy of ['original-flow','new-flow','explicit-false']){
    const ui=await customEspWorkbench();ui.context.image=customEspImage({merged:true});
    ui.context.checkedZip=(_bytes,options)=>options.directoryOnly?[{name:'nested/custom.bin',length:ui.context.image.length}]:{'nested/custom.bin':ui.context.image};
    if(blockedBy==='original-flow')ui.evaluate('state.plan={written:true};');
    await ui.evaluate(`loadFirmware("bundle.zip",new Uint8Array(64),null,{allowModeSync:${blockedBy!=='explicit-false'}});`);
    assert.equal(ui.evaluate('state.archiveContext.allowModeSync'),blockedBy==='new-flow',blockedBy);
    if(blockedBy==='new-flow')ui.evaluate('state.migration={phase:"pending"};');
    ui.elements.get('archive-entry').value='nested/custom.bin';await ui.elements.get('load-entry').onclick();
    assert.equal(ui.evaluate('state.installMode'),'update',blockedBy);assert.equal(ui.evaluate('state.pkg.payload'),ui.context.image);assert.deepEqual(ui.calls,[]);
  }
});

test('anonymous release archives retain selected-board erase and bootloader hints when an entry is loaded',async()=>{
  const ui=workbench();await Promise.resolve();const entry='nested/custom-app.zip',outer=new Uint8Array(8),inner=new Uint8Array(64),board=xiaoRepeaterItem({erase:['https://example.test/board-erase.zip'],bootloader:['https://example.test/board-bootloader.zip']});
  ui.context.inventory=[board];ui.context.outer=outer;ui.context.selected=fakePackage({name:'custom-app.zip'});ui.context.inspectFirmware=()=>ui.context.selected;
  ui.context.checkedZip=(bytes,options)=>options.directoryOnly?bytes===outer?[{name:entry,length:inner.length}]:[{name:'manifest.json'},{name:'app.bin'},{name:'app.dat'}]:{[entry]:inner};
  ui.evaluate('state.items=inventory;filterCatalog();');await ui.evaluate('loadFirmware("release.zip",outer);');assert.equal(ui.evaluate('state.archiveContext.hardware'),undefined);
  ui.elements.get('hardware').value=board.hardware;ui.elements.get('archive-entry').value=entry;await ui.elements.get('load-entry').onclick();
  assert.equal(ui.evaluate('state.pkg'),ui.context.selected);assert.equal(ui.evaluate('state.item.hardware'),board.hardware);assert.deepEqual(Array.from(ui.evaluate('state.item.erase')),board.erase);assert.deepEqual(Array.from(ui.evaluate('state.item.bootloader')),board.bootloader);assert.equal(ui.evaluate('state.item.role'),undefined);assert.deepEqual(ui.calls,[]);
});

test('local file input resets immediately while its captured file remains readable and can be selected again',async()=>{
  const ui=await customEspWorkbench(),image=customEspImage({merged:true}),input=ui.elements.get('firmware-file');let reads=0;
  const file={name:'custom.bin',size:image.length,arrayBuffer:async()=>{assert.equal(input.value,'');reads++;return image.buffer.slice(0);}};
  for(let attempt=0;attempt<2;attempt++){
    input.files=[file];input.value='C:\\fakepath\\custom.bin';await input.onchange();assert.equal(input.value,'');assert.equal(ui.evaluate('state.pkg.sha256'),firmwareHash(image));assert.equal(ui.evaluate('state.installMode'),'install');
    if(attempt===0)await ui.evaluate("setInstallMode('update');");
  }
  assert.equal(reads,2);assert.deepEqual(ui.calls,[]);
  input.files=[];await input.onchange();assert.equal(ui.evaluate('state.pkg.sha256'),firmwareHash(image));
});

test('Update is the initial mode and an old saved install preference cannot re-enable erasing on a new page',async()=>{
  let resolveCatalog;const catalogPromise=new Promise(resolve=>resolveCatalog=resolve),ui=workbench({productionDefaults:true,catalogPromise});
  ui.context.localStorage.setItem('meshfirmware.selections',JSON.stringify({provider:'MeshCore',hardware:v4Item.hardware,role:v4Item.role,version:v4Item.version,installMode:'install'}));
  resolveCatalog({items:[v4Item,mergedItem(v4Item)],warnings:[],generatedAt:'2026-10-27T00:00:00Z'});await new Promise(resolve=>setImmediate(resolve));
  assert.equal(ui.evaluate('state.installMode'),'update');assert.equal(ui.elements.get('install-mode-update').checked,true);assert.equal(ui.elements.get('install-mode-install').checked,false);assert.equal(ui.elements.get('flash-action').value,'update');
  assert.deepEqual(artifactChoices(ui),['0']);assert.deepEqual(ui.calls,[]);
});

test('mode selection filters application and merged builds even when automatic setup is off',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.inventory=[v4Item,mergedItem(v4Item)];ui.evaluate("state.items=inventory;filterCatalog();");
  assert.deepEqual(artifactChoices(ui),['0']);
  await ui.evaluate("setInstallMode('install');");
  assert.equal(ui.evaluate('state.installMode'),'install');assert.deepEqual(artifactChoices(ui),['1']);assert.equal(ui.elements.get('flash-action').value,'wipe');assert.match(ui.elements.get('install-mode-hint').textContent,/eras|identity|settings/i);
  await ui.evaluate("setInstallMode('update');");
  assert.deepEqual(artifactChoices(ui),['0']);assert.equal(ui.elements.get('flash-action').value,'update');assert.deepEqual(ui.calls,[]);
});

test('mode switch invalidates firmware, archive, backup approval and write proof before selecting the exact paired build',async()=>{
  const ui=workbench();await Promise.resolve();const update={...v4Item,sha256:'c'.repeat(64)},install=mergedItem(update);
  ui.context.inventory=[update,install];ui.context.record=ui.calls;ui.context.pkg=fakePackage({architecture:'esp32',name:update.name});
  ui.evaluate("state.items=inventory;filterCatalog();state.pkg=pkg;state.item=inventory[0];state.plan={prepared:true};state.archive=new Uint8Array(3);state.archiveContext={hardware:'Heltec v4'};state.loadedRecovery={id:'old'};state.directory={name:'old-drive'};state.backupApproved={sha256:pkg.sha256};state.automaticSha='c'.repeat(64);state.automaticShaName=inventory[0].name;state.esp={close:async()=>record.push('close-inspected-session')};");
  ui.elements.get('provider').value='MeshCore';ui.elements.get('hardware').value=v4Item.hardware;ui.elements.get('role').value=v4Item.role;ui.elements.get('version').value=v4Item.version;ui.elements.get('artifact').value='0';ui.elements.get('expected-sha').value='c'.repeat(64);
  const generation=ui.evaluate('state.generation');await ui.evaluate("setInstallMode('install');");
  for(const field of ['pkg','plan','item','archive','archiveContext','loadedRecovery','directory','backupApproved','automaticSha','automaticShaName','esp'])assert.equal(ui.evaluate('state.'+field),null,field);
  assert.ok(ui.evaluate('state.generation')>generation);assert.equal(ui.elements.get('expected-sha').value,'');assert.equal(ui.elements.get('artifact').value,'1');assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(ui.calls,['close-inspected-session']);
  await ui.evaluate("setInstallMode('update');");assert.equal(ui.elements.get('artifact').value,'0');assert.equal(ui.elements.get('hardware').value,v4Item.hardware);assert.equal(ui.elements.get('provider').value,v4Item.provider);assert.deepEqual(ui.calls,['close-inspected-session']);
});

test('paired mode selection never guesses between profiles or files with different safety metadata',async()=>{
  for(const changes of [{name:'heltec_v4_tft_repeater-v1.18.0-merged.bin'},{notice:'Different safety requirement'}]){
    const ui=workbench();await Promise.resolve();const update={...v4Item,notice:'Original safety requirement'},install={...mergedItem(update),...changes};ui.context.inventory=[update,install];
    ui.evaluate('state.items=inventory;filterCatalog();');ui.elements.get('provider').value='MeshCore';ui.elements.get('hardware').value=v4Item.hardware;ui.elements.get('role').value=v4Item.role;ui.elements.get('version').value=v4Item.version;ui.elements.get('artifact').value='0';
    await ui.evaluate("setInstallMode('install');");assert.equal(ui.elements.get('artifact').value,'');assert.equal(ui.evaluate('state.pkg'),null);assert.deepEqual(ui.calls,[]);
  }
  const ui=workbench();await Promise.resolve();const install=mergedItem(v4Item);ui.context.inventory=[v4Item,install,{...install,url:'https://second.test/same-profile-merged.bin',sha256:'e'.repeat(64)}];
  ui.evaluate('state.items=inventory;filterCatalog();');ui.elements.get('artifact').value='0';await ui.evaluate("setInstallMode('install');");assert.equal(ui.elements.get('artifact').value,'');assert.deepEqual(artifactChoices(ui),['1','2']);assert.deepEqual(ui.calls,[]);
});

test('automatic install selection keeps a known headless V4 on its exact base profile and allows a warned downgrade',async()=>{
  const ui=workbench({productionDefaults:true});await Promise.resolve();const update=headlessV4Item({version:'v1.18.0.1'}),install=mergedItem(update),tft=mergedItem(headlessV4Item({name:'heltec_v4_tft_repeater-full-logging-ota-v1.18.0.1.bin',version:'v1.18.0.1',url:'https://example.test/tft.bin',releaseNotes:'EXACT TARGET - heltec_v4_tft_repeater.\nSETUP - https://mikecarper.github.io/MeshCore/firmware_picker/?hardware=heltec_v4_tft'}));
  ui.context.inventory=[update,tft,install];ui.evaluate("state.items=inventory;state.device={model:'Heltec V4.2 none detected',catalogRole:'repeater',version:'v1.18.0.2'};filterCatalog();selectDetectedBoard();");assert.equal(ui.elements.get('artifact').value,'0');
  await ui.evaluate("setInstallMode('install');");assert.equal(ui.elements.get('artifact').value,'2');assert.deepEqual(artifactChoices(ui),['1','2']);assert.match(ui.elements.get('automatic-summary').textContent,/downgrade/i);assert.doesNotMatch(ui.elements.get('automatic-summary').textContent,/Write-only update selected/);assert.deepEqual(ui.calls,[]);
});

test('nRF52 main mode switch and hidden erase-action mirror cannot drift apart',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.inventory=[xiaoRepeaterItem()];ui.evaluate('state.items=inventory;filterCatalog();');
  ui.elements.get('install-mode-install').checked=true;ui.elements.get('install-mode-update').checked=false;await ui.elements.get('install-mode-install').onchange();
  assert.equal(ui.evaluate('state.installMode'),'install');assert.equal(ui.elements.get('flash-action').value,'wipe');assert.deepEqual(artifactChoices(ui),['0']);
  ui.elements.get('flash-action').value='update';ui.evaluate('controls();');assert.equal(ui.elements.get('flash-action').value,'wipe');
  ui.elements.get('install-mode-update').checked=true;ui.elements.get('install-mode-install').checked=false;await ui.elements.get('install-mode-update').onchange();assert.equal(ui.evaluate('state.installMode'),'update');assert.equal(ui.elements.get('flash-action').value,'update');assert.deepEqual(ui.calls,[]);
});

test('pending device workflows lock both mode inputs and reject mode changes without discarding their image or plan',async()=>{
  for(const [field,value]of [['handoff',true],['migration',{sha256:'a'.repeat(64)}],['recovery',{sha256:'a'.repeat(64),eraseComplete:true}],['espRecovery',{sha256:'a'.repeat(64)}],['verification',{sha256:'a'.repeat(64)}],['plan',{written:true}]]){
    const ui=workbench();await Promise.resolve();ui.context.pendingValue=value;ui.context.pkg=fakePackage();ui.evaluate('state.pkg=pkg;state.'+field+'=pendingValue;controls();');
    assert.equal(ui.elements.get('install-mode-update').disabled,true,field);assert.equal(ui.elements.get('install-mode-install').disabled,true,field);
    await assert.rejects(ui.evaluate("setInstallMode('install');"),field==='verification'?/Use Flash a new device.*optionally verify/:/pending|finish|complete|progress|cannot|continue|locked/i);
    assert.equal(ui.evaluate('state.installMode'),'update',field);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg,field);assert.equal(ui.evaluate('state.'+field),value,field);assert.deepEqual(ui.calls,[]);
  }
});

test('actual custom payload and mode mismatches stop before backup, reset, ROM connection or writes',async()=>{
  for(const [mode,pkg]of [['update',fakePackage({name:'renamed.bin',architecture:'esp32',merged:true,destructive:true})],['install',fakePackage({name:'claims-merged.bin',architecture:'esp32',merged:false})],['install',fakePackage({name:'firmware.uf2',architecture:'uf2'})]]){
    const ui=workbench();await Promise.resolve();ui.context.mode=mode;ui.context.pkg=pkg;ui.context.selectedPort=ui.port;ui.evaluate('state.installMode=mode;state.pkg=pkg;state.port=selectedPort;');ui.context.ensureBackup=async()=>ui.calls.push('backup');
    await ui.elements.get('prepare').onclick();assert.equal(ui.evaluate('state.plan'),null);assert.match(ui.elements.get('notice').textContent,/update|install|merged|UF2|support/i);assert.equal(ui.evaluate('state.installMode'),mode);assert.deepEqual(ui.calls,[]);
  }
});

test('normal nRF52 install needs a validated erase package and still stops at the typed wipe acknowledgement',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.pkg=fakePackage();ui.context.selectedPort=ui.port;ui.evaluate("state.installMode='install';state.pkg=pkg;state.port=selectedPort;");ui.elements.get('transport-mode').value='nrf52';ui.elements.get('already-bootloader').checked=true;
  ui.context.ensureBackup=async()=>ui.calls.push('backup');await ui.elements.get('prepare').onclick();assert.equal(ui.evaluate('state.plan'),null);assert.match(ui.elements.get('notice').textContent,/erase ZIP/i);assert.deepEqual(ui.calls,['backup']);
  ui.calls.length=0;ui.context.erase=fakePackage({name:'official-erase.zip',erase:true,destructive:true,eraseEvidence:'official SoftDevice v7 erase payload'});ui.context.erasePackage=async()=>ui.context.erase;
  await ui.elements.get('prepare').onclick();assert.equal(ui.evaluate('state.plan.erasePkg'),ui.context.erase);assert.equal(ui.evaluate('state.plan.installMode'),'install');
  ui.context.confirm=async(_title,_detail,_warning,token)=>{ui.calls.push(token);return false;};ui.context.flashNrf=async()=>ui.calls.push('write');await ui.elements.get('flash').onclick();assert.ok(ui.calls.includes('WIPE WITHOUT BACKUP'));assert.ok(!ui.calls.includes('write'));assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);
});

test('recorded nRF recovery and merged ESP retry restore a locked install display without starting an erase',async()=>{
  for(const pending of [{recovery:{sha256:'a'.repeat(64),name:'final.zip',phase:'erasing',eraseComplete:false}},{espRecovery:{sha256:'a'.repeat(64),mac:'aa:bb:cc:dd:ee:ff',merged:true}}]){
    const ui=workbench(pending);await Promise.resolve();assert.equal(ui.evaluate('state.installMode'),'install');assert.equal(ui.elements.get('install-mode-install').checked,true);assert.equal(ui.elements.get('flash-action').value,'wipe');assert.equal(ui.elements.get('install-mode-install').disabled,true);assert.equal(ui.elements.get('install-mode-update').disabled,true);assert.deepEqual(ui.calls,[]);
  }
});

test('same-mode or unchecked radio changes do not discard a prepared plan and unsupported modes are rejected',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.pkg=fakePackage();ui.context.plan={prepared:true};ui.evaluate('state.pkg=pkg;state.plan=plan;');
  await ui.evaluate("setInstallMode('update');");assert.equal(ui.evaluate('state.plan'),ui.context.plan);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);
  ui.elements.get('install-mode-install').checked=false;await ui.elements.get('install-mode-install').onchange();assert.equal(ui.evaluate('state.installMode'),'update');assert.equal(ui.evaluate('state.plan'),ui.context.plan);
  await assert.rejects(ui.evaluate("setInstallMode('unsupported');"),/Update|install/);assert.equal(ui.evaluate('state.plan'),ui.context.plan);assert.deepEqual(ui.calls,[]);
});

test('a prepared plan bound to another install mode cannot reach confirmation or device writes',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.pkg=fakePackage();ui.context.selectedPort=ui.port;ui.evaluate("state.installMode='install';state.pkg=pkg;state.port=selectedPort;state.plan={installMode:'update',generation:state.generation,port:selectedPort,sha256:pkg.sha256};");
  ui.context.confirm=async()=>{ui.calls.push('confirm');return true;};ui.context.flashNrf=async()=>ui.calls.push('write');await ui.elements.get('flash').onclick();assert.match(ui.elements.get('notice').textContent,/mode|Selection changed|inspect/i);assert.deepEqual(ui.calls,[]);
});

test('standalone nRF52 bootloader and SoftDevice components do not inherit an application erase stage from Install mode',async()=>{
  for(const kind of ['bootloader','softdevice','softdevice_bootloader']){
    const ui=workbench();await Promise.resolve();ui.context.pkg=fakePackage({kind,destructive:true});ui.context.selectedPort=ui.port;ui.evaluate("state.installMode='install';state.pkg=pkg;state.port=selectedPort;");ui.elements.get('transport-mode').value='nrf52';ui.elements.get('already-bootloader').checked=true;
    ui.context.ensureBackup=async()=>ui.calls.push('backup');ui.context.erasePackage=async()=>{ui.calls.push('erase-package');throw Error('An advanced component must not infer an application erase stage');};
    await ui.elements.get('prepare').onclick();assert.equal(ui.evaluate('state.plan?.erasePkg'),null,kind);assert.equal(ui.evaluate('state.plan?.sha256'),ui.context.pkg.sha256,kind);assert.deepEqual(ui.calls,['backup']);
  }
});

test('normal catalogs hide embedded nRF52 bootloaders while retaining legacy application wrappers',async()=>{
  const ui=workbench();await Promise.resolve();const embedded=xiaoRepeaterItem({name:'Xiao_nrf52_repeater-full-ota-with-bootloader-2.4.12-v1.18.0.1.zip'}),wrapper={...v4Item,name:'esp32_repeater-v1.18.0.zip',action:'download'},uf2={...v4Item,architecture:'noflash',name:'pico_repeater-v1.18.0.uf2',action:'download'};
  ui.context.inventory=[embedded,wrapper,uf2,{...embedded,name:'board_bootloader-v0.11.0.zip'},{...embedded,name:'FLASH_ERASE.zip'}];ui.evaluate('state.items=inventory;filterCatalog();');
  assert.deepEqual(artifactChoices(ui),['1','2']);ui.elements.get('artifact').value='1';await ui.elements.get('artifact').onchange();assert.equal(ui.elements.get('artifact').value,'1');assert.equal(ui.evaluate('state.pkg'),null);assert.deepEqual(ui.calls,[]);
  await ui.evaluate("setInstallMode('install');");assert.deepEqual(artifactChoices(ui),[]);assert.equal(ui.elements.get('artifact').value,'');
  ui.elements.get('auto-detect-board').checked=true;ui.evaluate("state.manualSelections={provider:'MeshCore'};state.device={model:'Seeed Xiao-nrf52',catalogRole:'repeater'};selectDetectedBoard();");assert.equal(ui.elements.get('artifact').value,'');assert.deepEqual(artifactChoices(ui),[]);assert.equal(ui.evaluate('state.pkg'),null);assert.deepEqual(ui.calls,[]);
});

test('nRF52 firmware choices contain only the two application profiles in both Update and Install modes',async()=>{
  const full=xiaoRepeaterItem({name:'Xiao_nrf52_repeater-full-ota-v1.18.0.1.zip',sha256:'c'.repeat(64),subtitle:'Full supported sensors + LoRa OTA'}),reduced=xiaoRepeaterItem({name:'Xiao_nrf52_repeater-reduced-ota-v1.18.0.1.zip',url:'https://example.test/xiao-reduced.zip',sha256:'d'.repeat(64),subtitle:'Reduced optional sensors + LoRa OTA'});
  const embedded=[full,reduced].map(item=>({...item,name:item.name.replace('-v1.18','-with-bootloader-2.4.12-v1.18'),url:item.url.replace('.zip','-with-bootloader.zip'),subtitle:item.subtitle+' + OTAFIX 2.4.12 bootloader'}));
  const ui=workbench();await Promise.resolve();ui.context.inventory=[full,reduced,...embedded];ui.evaluate('state.items=inventory;filterCatalog();');
  for(const [id,value]of [['provider','MeshCore'],['hardware',full.hardware],['role','repeater'],['version',full.version]])ui.elements.get(id).value=value;
  for(const mode of ['update','install','update']){
    await ui.evaluate(`setInstallMode('${mode}');`);ui.evaluate('filterCatalog();');
    assert.deepEqual(artifactChoices(ui),['0','1'],mode);assert.equal(ui.elements.get('provider').value,'MeshCore');assert.equal(ui.elements.get('hardware').value,full.hardware);assert.equal(ui.elements.get('role').value,'repeater');assert.equal(ui.elements.get('version').value,full.version);
    assert.equal(ui.evaluate('state.items[0].sha256'),full.sha256);assert.equal(ui.evaluate('state.items[1].url'),reduced.url);assert.ok(!ui.elements.get('artifact').options.some(option=>/with.bootloader/i.test(option.text)));assert.equal(ui.evaluate('state.pkg'),null);
  }
  assert.deepEqual(ui.calls,[]);
});

async function bootloaderOfferWorkbench({reported='0.11.0-OTAFIX2.4.10',role='common-cli',protocol=14,model='Seeed Tracker T1000-E',cached=false}={}){
  const ui=workbench();await Promise.resolve();
  const info={version:'2.4.12',profile:'xiao_nrf52840_ble',hardwareId:'xiao_nrf52',url:'https://example.test/xiao_nrf52840_ble_bootloader-v0.11.0-OTAFIX2.4.12_s140_7.3.0.zip',sha256:'c'.repeat(64),size:64,cached};
  const item=xiaoRepeaterItem({hardware:'Seeed Studio SenseCAP T1000-E',bootloader:[info.url],bootloaderInfo:info});
  ui.context.inventory=[item];ui.context.selectedPort=ui.port;ui.evaluate('state.items=inventory;state.port=selectedPort;filterCatalog();');
  for(const [id,value]of [['provider','MeshCore'],['hardware',item.hardware],['role','repeater'],['version',item.version],['artifact','0']])ui.elements.get(id).value=value;
  ui.evaluate('updateDownload();');
  const device={role,protocol,model,name:'Test XIAO',catalogRole:role==='companion'?'companionFull':'repeater',publicKey:'11'.repeat(32),version:'v1.18.0.2'};
  ui.context.detectMeshCore=async()=>({...device});
  const reply=()=>{if(reported instanceof Error)throw reported;return reported;};
  const link={async command(command,timeout){ui.calls.push('query:'+command);assert.equal(command,'get bootloader.ver');assert.equal(timeout,350);return reply();}};
  ui.context.testLink=link;
  ui.context.MeshCore=class{constructor(selected,options){assert.equal(selected,link);assert.equal(options.timeoutMs,700);}async cli(command){ui.calls.push('binary-query:'+command);assert.equal(command,'get bootloader.ver');return reply();}};
  await ui.evaluate('readApplication(testLink);');ui.evaluate('controls();');
  return {...ui,info,item,device,link};
}

test('the top bootloader action follows step 5, and the separate offer lives under Advanced',()=>{
  assert.ok(html.indexOf('id="verify-app"')<html.indexOf('id="top-bootloader-update"'));
  assert.ok(html.indexOf('id="top-bootloader-update"')<html.indexOf('id="advanced-options"'));
  assert.ok(html.indexOf('id="advanced-options"')<html.indexOf('id="nrf-bootloader-offer"'));
});

test('the top bootloader action is available before USB for a supported exact repeater or room',async()=>{
  const ui=workbench();await Promise.resolve();
  const info={version:'2.4.12',profile:'heltec_t096',url:'https://example.test/t096.zip',sha256:'c'.repeat(64),size:64};
  const repeater=xiaoRepeaterItem({hardware:'Heltec Mesh Node T096',bootloader:[info.url],bootloaderInfo:info});
  const room={...repeater,role:'roomServer'};
  ui.context.inventory=[repeater,room];ui.evaluate('state.items=inventory;filterCatalog();');
  ui.elements.get('provider').value='MeshCore';ui.elements.get('hardware').value=repeater.hardware;
  for(const role of ['repeater','roomServer']){
    ui.elements.get('role').value=role;ui.elements.get('artifact').value='';ui.evaluate('updateDownload();controls();');
    assert.equal(ui.elements.get('top-bootloader-update').hidden,false,role);
    assert.equal(ui.elements.get('top-bootloader-update').disabled,false,role);
    assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.evaluate('state.pkg'),null);
    assert.deepEqual(ui.calls,[]);
  }
  for(const role of ['companionFull','sensor','']){
    ui.elements.get('role').value=role;ui.evaluate('controls();');
    assert.equal(ui.elements.get('top-bootloader-update').hidden,true,role);
  }
  ui.elements.get('role').value='repeater';ui.context.detectedCompanion={role:'companion',catalogRole:'companionFull'};
  ui.evaluate('state.device=detectedCompanion;controls();');
  assert.equal(ui.elements.get('top-bootloader-update').hidden,true);
  ui.evaluate('state.device=null;');ui.elements.get('artifact').value='1';ui.evaluate('controls();');
  assert.equal(ui.elements.get('top-bootloader-update').hidden,true,'a stale room selection cannot supply a repeater bootloader');
});

test('the top bootloader action loads only the selected verified bootloader and never flashes',async()=>{
  const ui=workbench();await Promise.resolve();
  const info={version:'2.4.12',profile:'heltec_t096',url:'https://example.test/t096.zip',sha256:'c'.repeat(64),size:64};
  const item=xiaoRepeaterItem({hardware:'Heltec Mesh Node T096',bootloader:[info.url],bootloaderInfo:info});
  ui.context.inventory=[item];ui.evaluate('state.items=inventory;filterCatalog();');
  ui.elements.get('provider').value='MeshCore';ui.elements.get('hardware').value=item.hardware;ui.elements.get('role').value='repeater';ui.elements.get('artifact').value='';
  ui.context.component=fakePackage({name:'t096.zip',kind:'softdevice_bootloader',destructive:true,sha256:info.sha256});
  ui.context.boundedFetch=async(url,options)=>{ui.calls.push('download:'+url);assert.equal(options.expectedSha256,info.sha256);return new Uint8Array(info.size);};
  ui.context.hash=()=>info.sha256;ui.context.checkedZip=()=>[{name:'manifest.json'},{name:'bootloader.bin'},{name:'bootloader.dat'}];ui.context.inspectFirmware=()=>ui.context.component;
  ui.evaluate('updateDownload();controls();');await ui.elements.get('top-bootloader-update').onclick();
  assert.equal(ui.evaluate('state.pkg.name'),'t096.zip');assert.equal(ui.evaluate('state.item.bootloaderInfo.profile'),'heltec_t096');
  assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,['download:'+info.url]);
});

test('changing the selected role during bootloader download cannot load stale bytes',async()=>{
  const ui=workbench();await Promise.resolve();
  const info={version:'2.4.12',profile:'heltec_t096',url:'https://example.test/t096.zip',sha256:'c'.repeat(64),size:64};
  const item=xiaoRepeaterItem({hardware:'Heltec Mesh Node T096',bootloader:[info.url],bootloaderInfo:info});
  ui.context.inventory=[item];ui.evaluate('state.items=inventory;filterCatalog();');
  ui.elements.get('provider').value='MeshCore';ui.elements.get('hardware').value=item.hardware;ui.elements.get('role').value='repeater';ui.elements.get('artifact').value='';
  let resume;ui.context.boundedFetch=()=>new Promise(resolve=>{resume=resolve;});
  ui.evaluate('updateDownload();controls();');const pending=ui.elements.get('top-bootloader-update').onclick();
  while(!resume)await new Promise(resolve=>setImmediate(resolve));
  ui.elements.get('role').value='companionFull';resume(new Uint8Array(info.size));await pending;
  assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);
  assert.match(ui.elements.get('notice').textContent,/selected radio or bootloader changed/i);
  assert.deepEqual(ui.calls,[]);
});

test('a detected companion never receives the automatic post-startup bootloader prompt',async()=>{
  const ui=await bootloaderOfferWorkbench({role:'companion',protocol:14});
  ui.context.choose=async()=>{ui.calls.push('unexpected-prompt');return 'prepare';};
  await ui.evaluate('offerBootloaderAfterStartup()');
  assert.equal(ui.elements.get('top-bootloader-update').hidden,true);
  assert.ok(!ui.calls.includes('unexpected-prompt'));
  assert.equal(ui.elements.get('nrf-bootloader-offer').hidden,false,'the manual offer stays available under Advanced');
});

test('a read-only nRF52 bootloader query offers the exact board update separately without loading or resetting',async()=>{
  const ui=await bootloaderOfferWorkbench({reported:'\u001b[32m> get bootloader.ver\r\n> 0.11.0-OTAFIX2.4.10\u001b[0m\r\n'});
  assert.equal(ui.evaluate('state.device.bootloaderVersion'),'0.11.0-OTAFIX2.4.10');assert.equal(ui.evaluate('state.device.architecture'),'nrf52');
  assert.equal(ui.elements.get('nrf-bootloader-offer').hidden,false);assert.equal(ui.elements.get('prepare-bootloader-update').hidden,false);assert.equal(ui.elements.get('prepare-bootloader-update').disabled,false);assert.match(ui.elements.get('nrf-bootloader-status').textContent,/2\.4\.10/);assert.match(ui.elements.get('nrf-bootloader-status').textContent,/2\.4\.12.*separate/i);
  assert.equal(ui.elements.get('artifact').value,'0');assert.deepEqual(artifactChoices(ui),['0']);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,['query:get bootloader.ver']);
});

test('XIAO bootloader recommendation follows the connected repeater status, not the shared application image',async()=>{
  const snapshot=xiaoBootloaderSnapshot();
  for(const [board,profile] of [['28860044','xiao_nrf52840_ble'],['28860045','xiao_nrf52840_ble_sense']]){
    const ui=workbench();await Promise.resolve();ui.context.snapshot=snapshot;ui.context.selectedPort=ui.port;
    ui.context.inventory=[xiaoRepeaterItem({bootloaderInfo:{profile:'xiao_nrf52840_ble',url:'https://example.test/base.zip'},bootloader:['https://example.test/base.zip']})];
    ui.evaluate('state.items=inventory;state.port=selectedPort;state.bootloaderCatalog=snapshot;filterCatalog();');ui.elements.get('hardware').value='Seeed Studio Xiao nRF52 WIO';ui.elements.get('artifact').value='0';
    ui.evaluate('updateDownload();');assert.equal(ui.elements.get('bootloader-source').value,'');
    ui.context.detectMeshCore=async()=>({role:'common-cli',model:'Seeed Xiao-nrf52',publicKey:'11'.repeat(32)});
    ui.context.testLink={command:async command=>{ui.calls.push(command);return command==='get bootloader.ver'?'0.11.0-OTAFIX2.4.10':`BL board=${board} target=${board} name=XIAO_DFU crc=6F9BE280 abi=3 caps=0E | staged:none mid=-- hash=--`;}};
    await ui.evaluate('readApplication(testLink);');ui.evaluate('updateDownload();controls();');
    assert.equal(ui.evaluate('bootloaderItem().bootloaderInfo.profile'),profile);assert.match(ui.elements.get('bootloader-detail').textContent,/not proof of the physical module/i);
    assert.equal(ui.elements.get('prepare-bootloader-update').hidden,false);assert.equal(ui.evaluate('state.pkg'),null);assert.deepEqual(ui.calls,['get bootloader.ver','ota bootloader status']);
    ui.evaluate('state.port={getInfo:()=>({})};updateDownload();');assert.equal(ui.elements.get('bootloader-source').value,'');
  }
});

test('unknown, unavailable and recovery XIAO identities never fall back to the base bootloader',async()=>{
  for(const [version,status] of [['0.4.3','unknown command'],['R_0x12345678','BL board=28860044 target=28860044 name=XIAO_DFU crc=6F9BE280 abi=3 caps=0E | staged:none mid=-- hash=--'],['0.4.3','BL board=28860045 target=28860044 name=XIAO_DFU crc=6F9BE280 abi=3 caps=0E | staged:none mid=-- hash=--']]){
    const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.inventory=[xiaoRepeaterItem({bootloaderInfo:{profile:'xiao_nrf52840_ble',url:'https://example.test/base.zip'},bootloader:['https://example.test/base.zip']})];ui.evaluate('state.items=inventory;state.port=selectedPort;filterCatalog();');ui.elements.get('hardware').value='Seeed Studio Xiao nRF52 WIO';ui.elements.get('artifact').value='0';ui.context.detectMeshCore=async()=>({role:'common-cli',model:'Seeed Xiao-nrf52'});ui.context.testLink={command:async command=>command==='get bootloader.ver'?version:status};
    await ui.evaluate('readApplication(testLink);');ui.evaluate('updateDownload();controls();');assert.equal(ui.elements.get('bootloader-source').value,'');assert.equal(ui.elements.get('prepare-bootloader-update').hidden,true);assert.equal(ui.evaluate('state.pkg'),null);
  }
});

test('the selected Sense bootloader is preserved through download and image inspection',async()=>{
  const snapshot=xiaoBootloaderSnapshot(),ui=workbench();await Promise.resolve();ui.context.snapshot=snapshot;ui.context.selectedPort=ui.port;
  ui.context.inventory=[xiaoRepeaterItem({bootloaderInfo:{profile:'xiao_nrf52840_ble',url:'https://example.test/base.zip'},bootloader:['https://example.test/base.zip']})];ui.evaluate('state.items=inventory;state.port=selectedPort;state.bootloaderCatalog=snapshot;filterCatalog();');ui.elements.get('hardware').value='Seeed Studio Xiao nRF52 WIO';ui.elements.get('artifact').value='0';
  ui.context.detectMeshCore=async()=>({role:'common-cli',model:'Seeed Xiao-nrf52',publicKey:'11'.repeat(32)});ui.context.testLink={command:async command=>command==='get bootloader.ver'?'0.11.0-OTAFIX2.4.10':'BL board=28860045 target=28860045 name=XIAO_DFU crc=6F9BE280 abi=3 caps=0E | staged:none mid=-- hash=--'};
  await ui.evaluate('readApplication(testLink);');ui.evaluate('updateDownload();controls();');
  const selected=ui.evaluate('bootloaderItem().bootloaderInfo');ui.context.component=fakePackage({name:new URL(selected.url).pathname.split('/').pop(),kind:'softdevice_bootloader',destructive:true,sha256:selected.sha256});
  ui.context.boundedFetch=async()=>new Uint8Array(selected.size);ui.context.hash=()=>selected.sha256;ui.context.checkedZip=()=>[{name:'manifest.json'},{name:'bootloader.bin'},{name:'bootloader.dat'}];ui.context.inspectFirmware=()=>ui.context.component;
  await ui.elements.get('prepare-bootloader-update').onclick();assert.equal(ui.evaluate('state.item.bootloaderInfo.profile'),'xiao_nrf52840_ble_sense');assert.equal(ui.evaluate('selectedBootloader(state.pkg).profile'),'xiao_nrf52840_ble_sense');assert.equal(ui.evaluate('state.plan'),null);
});

test('the optional INFO_UF2 fallback selects Sense only for the matching current DFU port',async()=>{
  const snapshot=xiaoBootloaderSnapshot(),ui=workbench();await Promise.resolve();ui.context.snapshot=snapshot;ui.context.selectedPort=ui.port;ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0045});
  ui.context.inventory=[xiaoRepeaterItem({bootloaderInfo:{profile:'xiao_nrf52840_ble',url:'https://example.test/base.zip'},bootloader:['https://example.test/base.zip']})];ui.context.info=parseBootloaderInfo('UF2 Bootloader 0.6.2\nModel: Seeed XIAO nRF52840\nBoard-ID: nRF52840-SeeedXiaoSense-v1\n');
  ui.evaluate('state.items=inventory;state.port=selectedPort;state.bootloaderCatalog=snapshot;state.bootloaderInfo={info,port:selectedPort,generation:state.generation};');ui.elements.get('hardware').value='Seeed Studio Xiao nRF52 WIO';ui.elements.get('artifact').value='0';
  assert.equal(ui.evaluate('bootloaderItem().bootloaderInfo.profile'),'xiao_nrf52840_ble_sense');ui.evaluate('state.generation++;');assert.equal(ui.evaluate('bootloaderItem()'),null);
  ui.evaluate('state.bootloaderInfo.generation=state.generation;');ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0044});assert.equal(ui.evaluate('bootloaderItem()'),null);
});

test('companion bootloader version reads use only the supported read-only CLI and older companions stay usable',async()=>{
  for(const protocol of [13,14,15]){
    const ui=await bootloaderOfferWorkbench({role:'companion',protocol});
    assert.deepEqual(ui.calls,protocol>=14?['binary-query:get bootloader.ver']:[]);assert.equal(ui.evaluate('state.device.publicKey'),'11'.repeat(32));assert.equal(ui.elements.get('prepare-bootloader-update').hidden,protocol<14);
    if(protocol<14){assert.equal(ui.evaluate('state.device.bootloaderVersion'),null);assert.match(ui.elements.get('nrf-bootloader-status').textContent,/could not be verified|unknown/i);}
  }
});

test('the detected application labels the selected USB port without claiming an unavailable COM number',async()=>{
  const ui=await bootloaderOfferWorkbench({role:'companion',reported:'> 0.4.3'});
  assert.match(ui.elements.get('selected-port').textContent,/Selected: Seeed Tracker T1000-E · Test XIAO · USB /);
  assert.doesNotMatch(ui.elements.get('selected-port').textContent,/COM\d/);
  assert.equal(ui.evaluate('state.device.bootloaderVersion'),'0.4.3');assert.equal(ui.elements.get('prepare-bootloader-update').hidden,false);
  assert.match(ui.elements.get('nrf-bootloader-status').textContent,/non-OTAFIX bootloader 0\.4\.3/);
  assert.deepEqual(ui.calls,['binary-query:get bootloader.ver']);
});

async function usbModeWorkbench({reply='usb.mode hardware-cdc-jtag',role='common-cli',protocol=14,usbInfo={usbVendorId:0x303a,usbProductId:0x1001},model='Heltec V4.2 none detected',map={schemaVersion:1,builds:[]},version}={}){
  const ui=workbench({productionDefaults:true});await Promise.resolve();ui.context.selectedPort=ui.port;ui.port.getInfo=()=>usbInfo;ui.context.inventory=[headlessV4Item()];ui.context.pkg=fakePackage({architecture:'esp32'});ui.evaluate('state.items=inventory;state.port=selectedPort;state.pkg=pkg;');
  ui.context.usbConnectionMap=map;ui.context.detectMeshCore=async()=>({model,role,protocol,version,publicKey:'11'.repeat(32)});
  ui.context.reply=reply;const response=()=>{if(ui.context.reply instanceof Error)throw ui.context.reply;return ui.context.reply;};
  const link={command:async(command,timeout)=>{ui.calls.push('query:'+command);assert.equal(command,'get usb.mode');assert.equal(timeout,350);return response();}};ui.context.testLink=link;
  ui.context.MeshCore=class{constructor(selected,options){assert.equal(selected,link);assert.equal(options.timeoutMs,700);}async cli(command){ui.calls.push('binary-query:'+command);assert.equal(command,'get usb.mode');return response();}};
  await ui.evaluate('readApplication(testLink);');ui.evaluate('controls();');return ui;
}

test('a V4 firmware USB-mode report selects automatic connection without requesting a manual override',async()=>{
  for(const [reply,usbMode,mode] of [['> get usb.mode\r\n> usb.mode hardware-cdc-jtag\r\n','hardware-cdc-jtag','usb_reset'],['usb.mode tinyusb','tinyusb','tinyusb']]){
    const ui=await usbModeWorkbench({reply});assert.equal(ui.evaluate('state.device.usbMode'),usbMode);assert.equal(ui.evaluate('state.connection.mode'),mode);assert.equal(ui.evaluate('state.connection.source'),'application-report');assert.equal(ui.elements.get('transport-mode').value,'auto');assert.deepEqual(nextHighlight(ui),['prepare']);assert.match(ui.elements.get('connection-summary').textContent,/reports/);assert.deepEqual(ui.calls,['query:get usb.mode']);
  }
});

test('USB-mode reads use only read-only supported companion CLI and gracefully tolerate older firmware',async()=>{
  for(const protocol of [13,14,15]){
    const ui=await usbModeWorkbench({role:'companion',protocol});assert.deepEqual(ui.calls,protocol>=14?['binary-query:get usb.mode']:[]);assert.equal(ui.evaluate('state.device.usbMode'),protocol>=14?'hardware-cdc-jtag':null);assert.equal(ui.evaluate('state.device.publicKey'),'11'.repeat(32));
  }
  for(const reply of ['Unknown command','ERROR: not supported','get usb.mode','usb.mode unknown','usb.mode uart','usb.mode tinyusb extra','usb.mode tinyusb\nusb.mode hardware-cdc-jtag','log line\nusb.mode hardware-cdc-jtag',new Error('Optional CLI timed out')]){
    const ui=await usbModeWorkbench({reply});assert.equal(ui.evaluate('state.connection.mode'),null,String(reply));assert.equal(ui.evaluate('state.device.publicKey'),'11'.repeat(32));assert.deepEqual(ui.calls,['query:get usb.mode']);
  }
});

test('USB-mode queries skip unqualified USB identities and unknown models',async()=>{
  for(const values of [{usbInfo:{usbVendorId:0x1a86,usbProductId:0x7523}},{usbInfo:{usbVendorId:0x303a,usbProductId:0x1002}},{usbInfo:{usbVendorId:0x2886,usbProductId:0x0044}},{model:'Unreviewed board'}]){
    const ui=await usbModeWorkbench(values);assert.deepEqual(ui.calls,[]);assert.equal(ui.evaluate('state.device.usbMode'),null);
  }
});

test('USB-mode reporting cannot retain a previous valid report or stale read evidence',async()=>{
  const ui=await usbModeWorkbench();ui.calls.length=0;ui.context.reply='Unknown command';await ui.evaluate('readApplication(testLink);');assert.equal(ui.evaluate('state.device.usbMode'),null);assert.equal(ui.evaluate('state.connection.mode'),null);assert.deepEqual(ui.calls,['query:get usb.mode']);
  for(const change of ['disconnect','generation']){
    const stale=workbench({productionDefaults:true});await Promise.resolve();stale.context.selectedPort=stale.port;stale.context.inventory=[headlessV4Item()];stale.evaluate('state.items=inventory;state.port=selectedPort;');stale.context.detectMeshCore=async()=>({model:'Heltec V4.2 none detected',role:'common-cli',publicKey:'11'.repeat(32)});
    stale.context.testLink={command:async()=>{if(change==='disconnect')stale.serialEvents.disconnect({port:stale.port});else stale.evaluate('state.generation++;');return 'usb.mode hardware-cdc-jtag';}};
    await assert.rejects(stale.evaluate('readApplication(testLink);'),/changed or disconnected.*USB mode/);assert.equal(stale.evaluate('state.device'),null,change);
  }
});

test('an explicit user connection override remains selected after reading the firmware USB mode',async()=>{
  const ui=await usbModeWorkbench();ui.elements.get('transport-mode').value='tinyusb';await ui.evaluate('readApplication(testLink);');assert.equal(ui.elements.get('transport-mode').value,'tinyusb');assert.equal(ui.evaluate('connectionMode()'),'tinyusb');assert.deepEqual(ui.calls,['query:get usb.mode','query:get usb.mode']);
});

function historicalUsbMap(usbMode='hardware-cdc-jtag'){
  return {schemaVersion:1,builds:[{version:'v1.18.0.1-halo-keymind-cascade-dev-03214a16',source:{repository:'https://github.com/mikecarper/MeshCore',revision:'03214a16df2bd09d3272dfb001d2d322c6740f60'},profiles:[{hardware:'Heltec v4',architecture:'esp32',role:'repeater',usbMode,usbIds:['303a:1001'],targets:['heltec_v4_repeater'],evidence:['variants/heltec_v4/platformio.ini']}]}]};
}

test('reviewed USB history handles unsupported older firmware using the exact running version, not the replacement',async()=>{
  const map=historicalUsbMap(),version=map.builds[0].version+' (Build: 27-Oct-2026)';
  for(const reply of ['Unknown command','ERROR: not supported',new Error('Optional CLI timed out')]){
    const ui=await usbModeWorkbench({map,version,reply});assert.equal(ui.evaluate('state.connection.mode'),'usb_reset');assert.equal(ui.evaluate('state.connection.source'),'firmware-map');assert.deepEqual(nextHighlight(ui),['prepare']);assert.deepEqual(ui.calls,['query:get usb.mode']);
    ui.elements.get('hardware').value='A different selected replacement board';ui.elements.get('provider').value='MeshCore';ui.evaluate('updateConnectionChoice();');assert.equal(ui.evaluate('state.connection.mode'),'usb_reset');
  }
  for(const version of ['v1.18.0.1-halo-keymind-cascade-dev-99999999','v1.18.0.1-halo-keymind-cascade-dev-observer-03214a16','v1.18.0.1-halo-keym',undefined]){
    const ui=await usbModeWorkbench({map,version,reply:'Unknown command'});assert.equal(ui.evaluate('state.connection.mode'),null,String(version));
  }
});

test('live USB reports win history while explicit unknown or malformed reports never silently use history',async()=>{
  const map=historicalUsbMap(),version=map.builds[0].version;
  const live=await usbModeWorkbench({map,version,reply:'usb.mode tinyusb'});assert.equal(live.evaluate('state.connection.mode'),'tinyusb');assert.equal(live.evaluate('state.connection.source'),'application-report');
  for(const reply of ['usb.mode unknown','usb.mode uart','usb.mode tinyusb extra','log line\nusb.mode hardware-cdc-jtag']){
    const ui=await usbModeWorkbench({map,version,reply});assert.equal(ui.evaluate('state.connection.mode'),null,reply);assert.equal(ui.evaluate('state.device.usbModeFallback'),null,reply);
  }
  const invalid=await usbModeWorkbench({map:{schemaVersion:999},version,reply:'Unknown command'});assert.equal(invalid.evaluate('state.connection.mode'),null);
  const noModel=await usbModeWorkbench({map,version,model:'Unreviewed board',reply:'Unknown command'});assert.equal(noModel.evaluate('state.device.usbModeFallback'),null);assert.equal(noModel.evaluate('state.connection.mode'),null);
});

test('companion USB history needs the complete CLI version wrapper, never a truncated DEVICE_INFO field',async()=>{
  const map=historicalUsbMap();map.builds[0].profiles[0].role='companionFull';
  for(const version of ['v1.18.0.1-halo-keym',map.builds[0].version]){
    const ui=await usbModeWorkbench({map,version,role:'companion',protocol:13,reply:'Unknown command'});assert.equal(ui.evaluate('state.connection.mode'),null);assert.deepEqual(ui.calls,[]);
  }
  const version=`Companion ${map.builds[0].version} (protocol 14, build 27-Oct-2026)`;
  const ui=await usbModeWorkbench({map,version,role:'companion',reply:'Unknown command'});assert.equal(ui.evaluate('state.connection.mode'),'usb_reset');assert.equal(ui.evaluate('state.connection.source'),'firmware-map');
});

async function connectionTrialWorkbench({failures=0,disconnect=false,fail=null,mapMode=null,legacyTiny=false}={}){
  const map=mapMode?historicalUsbMap(mapMode):{schemaVersion:1,builds:[]};
  const ui=await usbModeWorkbench({reply:'Unknown command',map,version:map.builds[0]?.version,...(legacyTiny?{usbInfo:{usbVendorId:0x303a,usbProductId:0x0002}}:{})});ui.calls.length=0;
  ui.context.ensureBackup=async()=>ui.calls.push('backup-considered');let count=0;
  ui.context.EspSession=class{
    constructor(port){assert.equal(port,ui.port);}
    async connect(mode,options){ui.calls.push('connect:'+mode);assert.equal(options.singleReset,true);if(fail)throw fail;if(count++<failures)throw Object.assign(Error('No ROM response'),{romHandshakeFailed:true});return {chip:'ESP32-S3',mac:'aa:bb:cc:dd:ee:ff',flashBytes:16<<20};}
    async prepare(){ui.calls.push('prepare');return {sha256:ui.context.pkg.sha256,addresses:[0x10000],mac:'aa:bb:cc:dd:ee:ff'};}
    async close(){ui.calls.push('close');}
  };
  ui.context.touch1200=async(port,kind)=>{assert.equal(port,ui.port);assert.equal(kind,'tinyusb');ui.calls.push('tinyusb-handoff');if(disconnect)ui.serialEvents.disconnect({port:ui.port});};
  return ui;
}

test('unknown native ESP connection prepares with bounded actual tests after backup, retaining the first working method',async()=>{
  for(const [failures,mode,expected] of [[0,'no_reset',['backup-considered','connect:no_reset','prepare']],[1,'usb_reset',['backup-considered','connect:no_reset','close','connect:usb_reset','prepare']],[2,'no_reset',['backup-considered','connect:no_reset','close','connect:usb_reset','close','tinyusb-handoff','connect:no_reset','prepare']]]){
    const ui=await connectionTrialWorkbench({failures});assert.deepEqual(nextHighlight(ui),['prepare']);assert.equal(ui.elements.get('connection-options').open,undefined);
    await ui.elements.get('prepare').onclick();assert.deepEqual(ui.calls,expected);assert.equal(ui.evaluate('state.plan.transportMode'),mode);assert.equal(ui.evaluate('state.plan.port'),ui.port);assert.equal(ui.elements.get('transport-mode').value,'auto');assert.deepEqual(nextHighlight(ui),['flash']);assert.match(ui.elements.get('connection-summary').textContent,/verified by ROM/);
  }
});

test('JSON and legacy native-USB hints are provisional and require actual ROM verification before preparation',async()=>{
  for(const options of [{mapMode:'hardware-cdc-jtag'},{mapMode:'tinyusb'},{legacyTiny:true}]){
    const ui=await connectionTrialWorkbench(options);assert.equal(ui.evaluate('canTryConnectionFallback()'),true);assert.match(ui.elements.get('connection-summary').textContent,/provisional.*real ROM response/);assert.doesNotMatch(ui.elements.get('connection-summary').textContent,/verified by ROM/);assert.equal(ui.evaluate('state.plan'),null);
    await ui.elements.get('prepare').onclick();assert.deepEqual(ui.calls,['backup-considered','connect:no_reset','prepare']);assert.equal(ui.evaluate('state.plan.transportMode'),'no_reset');assert.match(ui.elements.get('connection-summary').textContent,/verified by ROM response \(no_reset\)/);assert.ok(!ui.calls.includes('tinyusb-handoff'));
  }
});

test('an incorrect mapped USB method can fall through to the other proven working method without changing the manual override',async()=>{
  for(const [mapMode,expectedMode,expected] of [
    ['hardware-cdc-jtag','no_reset',['backup-considered','connect:no_reset','close','connect:usb_reset','close','tinyusb-handoff','connect:no_reset','prepare']],
    ['tinyusb','usb_reset',['backup-considered','connect:no_reset','close','tinyusb-handoff','connect:no_reset','close','connect:usb_reset','prepare']],
  ]){
    const ui=await connectionTrialWorkbench({mapMode,failures:2});await ui.elements.get('prepare').onclick();assert.deepEqual(ui.calls,expected);assert.equal(ui.evaluate('state.plan.transportMode'),expectedMode);assert.equal(ui.elements.get('transport-mode').value,'auto');assert.match(ui.elements.get('connection-summary').textContent,/verified by ROM/);assert.deepEqual(nextHighlight(ui),['flash']);
  }
});

test('mapped connection verification cannot enable Flash or claim success while the ROM response is pending',async()=>{
  const ui=await connectionTrialWorkbench({mapMode:'hardware-cdc-jtag'}),Session=ui.context.EspSession;let release;
  ui.context.EspSession=class extends Session{async connect(){ui.calls.push('await-ROM');return new Promise(resolve=>{release=resolve;});}};
  const pending=ui.elements.get('prepare').onclick();while(!release)await Promise.resolve();assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('flash').disabled,true);assert.doesNotMatch(ui.elements.get('connection-summary').textContent,/verified by ROM/);assert.ok(!ui.calls.includes('prepare'));
  release({chip:'ESP32-S3',mac:'aa:bb:cc:dd:ee:ff',flashBytes:16<<20});await pending;assert.ok(ui.evaluate('state.plan'));assert.match(ui.elements.get('connection-summary').textContent,/verified by ROM/);assert.deepEqual(ui.calls,['backup-considered','await-ROM','prepare']);
});

test('failed mapped connection verification ends with manual picking and cannot silently retry its JSON hint',async()=>{
  for(const mapMode of ['hardware-cdc-jtag','tinyusb']){
    const ui=await connectionTrialWorkbench({mapMode,failures:3});await ui.elements.get('prepare').onclick();assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.connection.mode'),null);assert.equal(ui.evaluate('state.connection.source'),'trial-failed');assert.deepEqual(nextHighlight(ui),['transport-mode']);assert.doesNotMatch(ui.elements.get('connection-summary').textContent,/verified by ROM/);const tried=[...ui.calls];
    await ui.elements.get('prepare').onclick();assert.deepEqual(ui.calls,tried);assert.equal(ui.evaluate('state.plan'),null);assert.match(ui.elements.get('notice').textContent,/manually/);
  }
});

test('fresh live USB evidence read during backup supersedes the original JSON hint before any reset',async()=>{
  for(const usbMode of ['hardware-cdc-jtag','tinyusb']){
    const ui=await connectionTrialWorkbench({mapMode:usbMode==='tinyusb'?'hardware-cdc-jtag':'tinyusb'}),Session=ui.context.EspSession;
    ui.context.ensureBackup=async()=>{ui.calls.push('backup-reread');ui.context.liveMode=usbMode;ui.evaluate("state.device.usbMode=liveMode;state.device.usbModeStatus='reported';");};
    ui.context.EspSession=class extends Session{async connect(mode){ui.calls.push('live-connect:'+mode);return {chip:'ESP32-S3',mac:'aa:bb:cc:dd:ee:ff',flashBytes:16<<20};}};
    ui.context.confirm=async()=>{ui.calls.push('live-handoff-confirmation');return true;};
    await ui.elements.get('prepare').onclick();assert.deepEqual(ui.calls,usbMode==='tinyusb'?['backup-reread','live-handoff-confirmation','tinyusb-handoff']:['backup-reread','live-connect:usb_reset','prepare']);
    if(usbMode==='tinyusb')assert.equal(ui.evaluate('state.plan'),null);else assert.equal(ui.evaluate('state.plan.transportMode'),'usb_reset');
  }
});

test('a live USB conflict or newly protected workflow discovered during backup stops before connection testing',async()=>{
  for(const change of ['conflict','migration']){
    const ui=await connectionTrialWorkbench({mapMode:'hardware-cdc-jtag'});ui.context.ensureBackup=async()=>{ui.calls.push('backup-reread');if(change==='conflict')ui.evaluate("state.device.usbMode='uart';state.device.usbModeStatus='reported';");else ui.evaluate('state.migration={uart:false};');};
    await ui.elements.get('prepare').onclick();assert.deepEqual(ui.calls,['backup-reread']);assert.equal(ui.evaluate('state.plan'),null);assert.match(ui.elements.get('notice').textContent,change==='conflict'?/choose.*manually/i:/Pending USB migration/);
  }
});

test('backup refreshes the historical hint ordering rather than retaining an older TinyUSB preference',async()=>{
  const ui=await connectionTrialWorkbench({mapMode:'tinyusb',failures:1});ui.context.ensureBackup=async()=>{ui.calls.push('backup-reread');ui.evaluate("state.device.usbModeFallback.usbMode='hardware-cdc-jtag';");};
  await ui.elements.get('prepare').onclick();assert.deepEqual(ui.calls,['backup-reread','connect:no_reset','close','connect:usb_reset','prepare']);assert.equal(ui.evaluate('state.plan.transportMode'),'usb_reset');
});

test('trial handoff on USB re-enumeration guides selection without another touch, erase or write',async()=>{
  const ui=await connectionTrialWorkbench({failures:2,disconnect:true});await ui.elements.get('prepare').onclick();
  assert.deepEqual(ui.calls,['backup-considered','connect:no_reset','close','connect:usb_reset','close','tinyusb-handoff']);assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('transport-mode').value,'no_reset');assert.equal(ui.elements.get('already-bootloader').checked,true);assert.deepEqual(nextHighlight(ui),['select-port']);assert.match(ui.elements.get('notice').textContent,/Nothing has been erased or written/);
});

test('a final TinyUSB control-line interruption preserves Meshtastic firmware choices through a delayed disconnect and ROM reselection',async()=>{
  for(const timing of ['immediate','delayed']){
    const ui=await connectionTrialWorkbench({failures:2});
    ui.evaluate("state.device={...state.device,firmwareFamily:'meshtastic',role:'meshtastic',version:'2.7.15.567b8ea',publicKey:null,meshtasticHardware:110};state.backupApproved={port:state.port,sha256:pkg.sha256,skipped:true,sourceFirmware:'meshtastic'};");
    const device=ui.evaluate('state.device'),pkg=ui.evaluate('state.pkg'),approval=ui.evaluate('state.backupApproved'),filters=['provider','hardware','role','version','artifact'].map(id=>ui.elements.get(id).value);
    ui.context.touch1200=async()=>{ui.calls.push('tinyusb-handoff');if(timing==='immediate')ui.serialEvents.disconnect({port:ui.port});throw Object.assign(Error("Failed to execute 'setSignals' on 'SerialPort': Failed to set control signals."),{name:'NetworkError',tinyUsbHandoffPending:true});};
    await ui.elements.get('prepare').onclick();
    assert.equal(ui.evaluate('state.handoff'),true);assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.device'),device);assert.equal(ui.evaluate('state.pkg'),pkg);assert.equal(ui.evaluate('state.backupApproved'),approval);assert.equal(ui.elements.get('transport-mode').value,'no_reset');assert.deepEqual(nextHighlight(ui),['select-port']);
    assert.match(ui.elements.get('progress-label').textContent,/handoff requested, not yet verified/);assert.doesNotMatch(ui.elements.get('notice').textContent,/Failed to execute|Automatic connection testing stopped/);assert.ok(!ui.calls.includes('prepare'));assert.equal(ui.calls.filter(call=>call==='connect:no_reset').length,1);assert.equal(ui.calls.filter(call=>call==='tinyusb-handoff').length,1);
    if(timing==='delayed')ui.serialEvents.disconnect({port:ui.port});
    assert.equal(ui.evaluate('state.device'),device);assert.equal(ui.evaluate('state.backupApproved'),approval);assert.deepEqual(['provider','hardware','role','version','artifact'].map(id=>ui.elements.get(id).value),filters);
    const romPort={getInfo:ui.port.getInfo};ui.context.navigator.serial.requestPort=async()=>romPort;ui.context.confirm=async()=>true;
    await ui.elements.get('select-port').onclick();
    assert.equal(ui.evaluate('state.port'),romPort);assert.equal(ui.evaluate('state.pkg'),pkg);assert.equal(ui.evaluate('state.device'),device);assert.equal(ui.evaluate('state.backupApproved.port'),romPort);assert.equal(ui.elements.get('transport-mode').value,'no_reset');assert.deepEqual(['provider','hardware','role','version','artifact'].map(id=>ui.elements.get(id).value),filters);assert.equal(ui.calls.filter(call=>call==='tinyusb-handoff').length,1);
  }
});

test('exhausted or fatal trial errors stop automation and expose the final manual connection choice',async()=>{
  for(const options of [{failures:3},{fail:new Error('Secure boot is enabled')},{fail:Object.assign(new Error('Access denied'),{name:'NotAllowedError'})}]){
    const ui=await connectionTrialWorkbench(options);await ui.elements.get('prepare').onclick();assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.esp'),null);assert.deepEqual(nextHighlight(ui),['transport-mode']);assert.equal(ui.elements.get('connection-options').open,true);assert.equal(ui.evaluate('canTryConnectionFallback()'),false);assert.match(ui.elements.get('progress-label').textContent,/Automatic connection testing stopped:/);
    assert.equal(ui.calls.filter(call=>call==='connect:usb_reset').length,options.fail?0:1);assert.equal(ui.calls.filter(call=>call==='tinyusb-handoff').length,options.fail?0:1);assert.ok(!ui.calls.includes('prepare'));
  }
});

test('a disconnect or changed image during asynchronous ESP preparation cannot rebind a stale trial plan',async()=>{
  for(const change of ['disconnect','generation','image','installation','session']){
    const ui=await connectionTrialWorkbench();const Session=ui.context.EspSession;
    ui.context.EspSession=class extends Session{async prepare(){const plan=await super.prepare();if(change==='disconnect')ui.serialEvents.disconnect({port:ui.port});if(change==='generation')ui.evaluate('state.generation++;');if(change==='image')ui.evaluate('state.pkg={...pkg};');if(change==='installation')ui.evaluate("state.installMode='install';");if(change==='session')ui.evaluate('state.esp=null;');return plan;}};
    await ui.elements.get('prepare').onclick();assert.equal(ui.evaluate('state.plan'),null,change);assert.match(ui.elements.get('notice').textContent,/stale plan|changed during preparation/,change);assert.equal(ui.calls.filter(call=>call.startsWith('connect:')).length,1,change);
  }
});

test('active method trials do not replace live reports, explicit overrides or pending protected flows',async()=>{
  for(const scenario of ['live','manual','uart','unknown-usb','nrf','handoff','already-bootloader','migration','migrationApproval','recovery','espRecovery','verification','plan']){
    const ui=await connectionTrialWorkbench();
    if(scenario==='live')ui.evaluate("state.device.usbMode='tinyusb';state.device.usbModeStatus='reported';");
    if(scenario==='manual')ui.elements.get('transport-mode').value='tinyusb';
    if(scenario==='uart')ui.port.getInfo=()=>({usbVendorId:0x1a86,usbProductId:0x7523});
    if(scenario==='unknown-usb')ui.port.getInfo=()=>({usbVendorId:0x1234,usbProductId:0x5678});
    if(scenario==='nrf')ui.evaluate("state.device.architecture='nrf52';");
    if(scenario==='already-bootloader')ui.elements.get('already-bootloader').checked=true;
    if(scenario==='handoff')ui.evaluate('state.handoff=true;');
    if(['migration','migrationApproval','recovery','espRecovery','verification','plan'].includes(scenario))ui.evaluate(`state.${scenario}={};`);
    assert.equal(ui.evaluate('canTryConnectionFallback()'),false,scenario);assert.deepEqual(ui.calls,[],scenario);
  }
});

test('bootloader reporting distinguishes non-OTAFIX reports from unavailable versions and outdated OTAFIX stable releases',async()=>{
  for(const [reported,pattern,offer]of [
    ['0.11.0-OTAFIX2.4.12',/matches.*2\.4\.12|No bootloader update is needed/i,false],
    ['0.11.0-OTAFIX2.4.13',/newer.*No downgrade/i,false],
    ['OTAFIX2.4.12-custom',/custom.*not treated as.*outdated/i,false],
    ['0.11.0',/non-OTAFIX bootloader 0\.11\.0.*separate board-specific USB update/i,true],
    ['0.4.3',/non-OTAFIX bootloader 0\.4\.3.*version name alone does not authorize/i,true],
    ['unknown command',/could not be verified|unknown/i,false],
    [new Error('Optional CLI unavailable'),/could not be verified|unknown/i,false],
    ['OTAFIX2.4.12-preview.1',/preview.*replace the preview/i,true]
  ]){
    const ui=await bootloaderOfferWorkbench({reported,cached:true});assert.equal(ui.elements.get('nrf-bootloader-offer').hidden,false);assert.equal(ui.elements.get('prepare-bootloader-update').hidden,!offer);assert.match(ui.elements.get('nrf-bootloader-status').textContent,pattern);assert.match(ui.elements.get('nrf-bootloader-status').textContent,/last verified stable/);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.device.publicKey'),'11'.repeat(32));assert.deepEqual(ui.calls,['query:get bootloader.ver']);
  }
});

test('bootloader updates need the exact detected nRF52 board and cannot be offered during another workflow',async()=>{
  for(const scenario of ['other-board','unknown-model','no-version-mapping','no-port','dfu','already-bootloader','handoff','recovery','migration','espRecovery','verification','session','plan','package']){
    const ui=await bootloaderOfferWorkbench();ui.calls.length=0;
    if(scenario==='other-board'){ui.context.other=xiaoRepeaterItem({hardware:'Different nRF52 board',bootloader:[ui.info.url],bootloaderInfo:ui.info});ui.evaluate('state.items.push(other);');ui.elements.get('artifact').value='1';}
    if(scenario==='unknown-model')ui.evaluate("state.device.model='Seeed Xiao-nrf';");
    if(scenario==='no-version-mapping')ui.evaluate('delete state.items[0].bootloaderInfo;');
    if(scenario==='no-port')ui.evaluate('state.port=null;');
    if(scenario==='dfu')ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0044});
    if(scenario==='already-bootloader')ui.elements.get('already-bootloader').checked=true;
    if(scenario==='handoff')ui.evaluate('state.handoff=true;');
    for(const field of ['recovery','migration','espRecovery','verification'])if(scenario===field)ui.evaluate(`state.${field}={sha256:'a'.repeat(64)};`);
    if(scenario==='session')ui.evaluate('state.esp={};');
    if(scenario==='plan')ui.evaluate('state.plan={};');
    if(scenario==='package'){ui.context.pkg=fakePackage({kind:'softdevice_bootloader',destructive:true});ui.evaluate('state.pkg=pkg;');}
    ui.evaluate('controls();');assert.equal(ui.elements.get('prepare-bootloader-update').hidden,true,scenario);assert.equal(ui.elements.get('prepare-bootloader-update').disabled,true,scenario);
    ui.context.loadBootloaderFirmware=async()=>ui.calls.push('unexpected-load');await ui.elements.get('prepare-bootloader-update').onclick();assert.deepEqual(ui.calls,[],scenario);
  }
});

test('non-nRF and bootloader interfaces never receive an application bootloader-version query',async()=>{
  for(const scenario of ['esp32','dfu','already-bootloader']){
    const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.inventory=[scenario==='esp32'?headlessV4Item():xiaoRepeaterItem()];ui.evaluate('state.items=inventory;state.port=selectedPort;');
    if(scenario==='dfu')ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0044});
    if(scenario==='already-bootloader')ui.elements.get('already-bootloader').checked=true;
    ui.context.detectMeshCore=async()=>({role:'common-cli',model:scenario==='esp32'?'Heltec V4.2 none detected':'Seeed Xiao-nrf52',publicKey:'11'.repeat(32)});ui.context.testLink={command:async()=>{throw new Error('An excluded interface must not be probed');}};
    await ui.evaluate('readApplication(testLink);');assert.equal(ui.evaluate('state.device.bootloaderVersion'),null);assert.deepEqual(ui.calls,[]);
  }
});

test('disconnecting during optional bootloader reporting cannot retain version evidence for another port',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.inventory=[xiaoRepeaterItem()];ui.evaluate('state.items=inventory;state.port=selectedPort;');
  ui.context.detectMeshCore=async()=>({role:'common-cli',model:'Seeed Xiao-nrf52',publicKey:'11'.repeat(32)});ui.context.testLink={command:async()=>{ui.serialEvents.disconnect({port:ui.port});return 'OTAFIX2.4.10';}};
  await assert.rejects(ui.evaluate('readApplication(testLink);'),/changed or disconnected.*bootloader/i);assert.equal(ui.evaluate('state.device'),null);assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.elements.get('prepare-bootloader-update').hidden,true);assert.deepEqual(ui.calls,[]);
});

test('preparing a recommended nRF52 bootloader only loads the hash-checked ZIP and preserves the selected application',async()=>{
  const ui=await bootloaderOfferWorkbench();ui.calls.length=0;
  const name=new URL(ui.info.url).pathname.split('/').pop();ui.context.bootPkg=fakePackage({name,kind:'softdevice_bootloader',destructive:true,sha256:ui.info.sha256});
  ui.context.boundedFetch=async url=>{assert.equal(url,ui.info.url);ui.calls.push('download-bootloader');return new Uint8Array(ui.info.size);};ui.context.hash=()=>ui.info.sha256;ui.context.checkedZip=()=>[{name:'manifest.json'},{name:'bootloader.bin'},{name:'bootloader.dat'}];ui.context.inspectFirmware=()=>ui.context.bootPkg;
  await ui.elements.get('prepare-bootloader-update').onclick();
  assert.deepEqual(ui.calls,['download-bootloader']);assert.equal(ui.evaluate('state.pkg'),ui.context.bootPkg);assert.equal(ui.evaluate('state.item.bootloaderInfo.profile'),ui.info.profile);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.port'),ui.port);assert.equal(ui.elements.get('artifact').value,'0');assert.equal(ui.elements.get('expected-sha').value,ui.info.sha256);assert.match(ui.elements.get('image-warning').textContent,/requires reinstalling/);
  assert.equal(ui.elements.get('prepare-bootloader-update').hidden,true);
  serialMock(ui);ui.context.ensureBackup=async()=>ui.calls.push('backup-before-component');ui.elements.get('transport-mode').value='nrf52';ui.elements.get('already-bootloader').checked=true;
  await ui.elements.get('prepare').onclick();assert.equal(ui.evaluate('state.plan.erasePkg'),null);assert.ok(ui.calls.includes('backup-before-component'));
  const confirmations=[];ui.context.confirm=async(_title,_detail,_warning,token)=>{confirmations.push(token);return false;};ui.context.flashNrf=async()=>ui.calls.push('flash-bootloader');await ui.elements.get('flash').onclick();assert.deepEqual(confirmations,['WIPE WITHOUT BACKUP']);assert.ok(!ui.calls.includes('flash-bootloader'));
  ui.context.confirm=async()=>true;await ui.elements.get('flash').onclick();assert.ok(ui.calls.includes('flash-bootloader'));assert.equal(ui.elements.get('artifact').value,'0');assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.evaluate('state.handoff'),true);assert.equal(ui.evaluate('state.device.bootloaderVersion'),null);assert.equal(ui.evaluate('state.verification'),null);assert.match(ui.elements.get('notice').textContent,/application build remains selected|reinstall.*application/i);assert.match(ui.elements.get('notice').textContent,/not yet verified/i);
});

function prepareNrfStartup(ui,{reported='0.11.0-OTAFIX2.4.10',publicKey=ui.device.publicKey}={}){
  ui.context.detectMeshCore=async()=>({...ui.device,role:'common-cli',version:'v1.18.0.2',publicKey});
  ui.context.SerialLink=class{async open(_baud,options){assert.equal(options.application,true);ui.calls.push('application-open');}async close(){ui.calls.push('application-close');}async command(command){ui.calls.push('application-query:'+command);if(command==='get bootloader.ver')return reported;if(command==='ver')return 'MeshCore v1.18.0.2';throw new Error('Unexpected application query '+command);}};
  ui.context.expected={sha256:'a'.repeat(64),architecture:'nrf52',role:'common-cli',model:ui.device.model,publicKey:ui.device.publicKey,version:'v1.18.0.2'};ui.context.appPkg=fakePackage({name:ui.item.name});
  ui.evaluate('state.verification=expected;state.handoff=true;state.pkg=appPkg;');ui.elements.get('already-bootloader').checked=false;ui.calls.length=0;
}

test('after step 5 verifies a repeater, the top bootloader action remains available',async()=>{
  const ui=await bootloaderOfferWorkbench({reported:'unknown command'});
  prepareNrfStartup(ui,{reported:'0.11.0-OTAFIX2.4.12'});
  await ui.evaluate('verifyApplication();');ui.evaluate('controls();');
  assert.equal(ui.evaluate('state.verification'),null);
  assert.equal(ui.elements.get('top-bootloader-update').hidden,false);
  assert.equal(ui.elements.get('top-bootloader-update').disabled,false);
  const name=new URL(ui.info.url).pathname.split('/').pop();ui.context.bootPkg=fakePackage({name,kind:'softdevice_bootloader',destructive:true,sha256:ui.info.sha256});
  ui.context.boundedFetch=async url=>{assert.equal(url,ui.info.url);ui.calls.push('download-bootloader');return new Uint8Array(ui.info.size);};
  ui.context.hash=()=>ui.info.sha256;ui.context.checkedZip=()=>[{name:'manifest.json'},{name:'bootloader.bin'},{name:'bootloader.dat'}];ui.context.inspectFirmware=()=>ui.context.bootPkg;
  await ui.elements.get('top-bootloader-update').onclick();
  assert.ok(ui.calls.includes('download-bootloader'));
  assert.equal(ui.evaluate('state.pkg'),ui.context.bootPkg);
  assert.equal(ui.evaluate('state.plan'),null);
});

test('installing an application that can report bootloader version prompts only after startup is verified',async()=>{
  const ui=await bootloaderOfferWorkbench({reported:'unknown command'});assert.equal(ui.elements.get('prepare-bootloader-update').hidden,true);
  prepareNrfStartup(ui);const prompts=[];
  ui.context.choose=async(title,detail,buttons)=>{prompts.push({title,detail,buttons});ui.calls.push('bootloader-offer');assert.equal(ui.evaluate('state.verification'),null);assert.match(ui.elements.get('notice').textContent,/startup verified/i);return 'later';};
  ui.context.loadBootloaderFirmware=async()=>ui.calls.push('unexpected-component-load');await ui.evaluate('verifyApplication();');
  assert.deepEqual(ui.calls,['application-open','application-query:get bootloader.ver','application-query:ver','application-close','bootloader-offer']);assert.equal(prompts.length,1);assert.match(prompts[0].title,/Bootloader update available/i);assert.match(prompts[0].detail,/2\.4\.10/);assert.match(prompts[0].detail,/2\.4\.12/);assert.match(prompts[0].detail,/application started successfully/i);assert.match(prompts[0].detail,/Backup.*DFU.*confirmation/i);assert.equal(prompts[0].buttons[0][0],'later');assert.equal(prompts[0].buttons[1][0],'prepare');assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.evaluate('state.pkg'),ui.context.appPkg);assert.match(ui.elements.get('notice').textContent,/startup verified/i);
  await ui.evaluate('offerBootloaderAfterStartup();');assert.equal(prompts.length,1,'The same identity/reported version/verified bootloader is only prompted once per page');
});

test('current, unknown, newer and custom bootloaders do not prompt after successful application startup',async()=>{
  for(const reported of ['0.11.0-OTAFIX2.4.12','0.11.0-OTAFIX2.4.13','0.11.0 (base)','unknown command','OTAFIX2.4.12-custom']){
    const ui=await bootloaderOfferWorkbench();prepareNrfStartup(ui,{reported});ui.context.choose=async()=>{ui.calls.push('unexpected-offer');return 'prepare';};ui.context.loadBootloaderFirmware=async()=>ui.calls.push('unexpected-load');await ui.evaluate('verifyApplication();');
    assert.equal(ui.evaluate('state.verification'),null,reported);assert.match(ui.elements.get('notice').textContent,/startup verified/i,reported);assert.deepEqual(ui.calls,['application-open','application-query:get bootloader.ver','application-query:ver','application-close'],reported);
  }
});

test('non-OTAFIX startup reports offer a separate bootloader preparation once, without automatically replacing it',async()=>{
  for(const reported of ['0.4.3','0.11.0','0.9.2-Seeed']){
    const ui=await bootloaderOfferWorkbench();prepareNrfStartup(ui,{reported});
    ui.context.choose=async(_title,detail)=>{assert.ok(detail.includes(reported));ui.calls.push('offer');return 'later';};
    ui.context.loadBootloaderFirmware=async()=>{throw Error('Must not load without approval');};
    await ui.evaluate('verifyApplication();');await ui.evaluate('offerBootloaderAfterStartup();');
    assert.deepEqual(ui.calls,['application-open','application-query:get bootloader.ver','application-query:ver','application-close','offer']);
    assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.evaluate('state.plan'),null);
  }
});

test('the post-startup bootloader prompt only prepares after an explicit choice and retains successful application verification on preparation failure',async()=>{
  for(const failure of [false,true]){
    const ui=await bootloaderOfferWorkbench();prepareNrfStartup(ui);ui.context.choose=async()=>{ui.calls.push('accepted-prepare');return 'prepare';};ui.context.loadBootloaderFirmware=async()=>{ui.calls.push('load-component-only');if(failure)throw Error('Fixture download failure');};
    if(failure)await assert.rejects(ui.evaluate('verifyApplication();'),/Application startup was verified.*bootloader preparation failed.*Fixture download failure/i);else await ui.evaluate('verifyApplication();');
    assert.deepEqual(ui.calls,['application-open','application-query:get bootloader.ver','application-query:ver','application-close','accepted-prepare','load-component-only']);assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.port'),ui.port);assert.equal(ui.elements.get('artifact').value,'0');
  }
});

test('manual startup verification preserves proven application completion on failed component download but never overwrites a newly loaded bootloader',async()=>{
  for(const failure of [false,true]){
    const ui=await bootloaderOfferWorkbench();prepareNrfStartup(ui);ui.context.choose=async()=> 'prepare';
    ui.context.bootPkg=fakePackage({name:'new-bootloader.zip',kind:'softdevice_bootloader',destructive:true,sha256:'c'.repeat(64),warnings:['Separate bootloader compatibility must be checked.']});
    ui.context.checkedZip=()=>[{name:'manifest.json'},{name:'bootloader.bin'},{name:'bootloader.dat'}];ui.context.inspectFirmware=()=>ui.context.bootPkg;
    ui.context.loadBootloaderFirmware=async()=>{
      if(failure){ui.evaluate('invalidateFirmwareSelection();');throw Error('Fixture component download unavailable');}
      await ui.evaluate('loadFirmware(bootPkg.name,new Uint8Array(64));');
    };
    await ui.elements.get('verify-app').onclick();
    assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.port'),ui.port);
    if(failure){
      assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.finishedFirmware.verified'),true);assert.match(ui.elements.get('notice').textContent,/startup was verified.*Separate bootloader preparation failed/i);
      assert.match(ui.elements.get('progress-label').textContent,/Application startup verified/);assert.match(ui.elements.get('automatic-summary').textContent,/Installed firmware startup verified/);assert.equal(ui.elements.get('reconnect-title').textContent,'Firmware verified');assert.equal(ui.elements.get('prepare').disabled,true);
    }else{
      assert.equal(ui.evaluate('state.pkg'),ui.context.bootPkg);assert.equal(ui.evaluate('state.finishedFirmware'),null);assert.match(ui.elements.get('image-warning').textContent,/Separate bootloader compatibility|requires reinstalling/);
      assert.match(ui.elements.get('progress-label').textContent,/Image validated locally/);assert.match(ui.elements.get('automatic-summary').textContent,/new-bootloader\.zip/);assert.doesNotMatch(ui.elements.get('automatic-summary').textContent,/No further flashing is required/);assert.equal(ui.elements.get('prepare').disabled,false);assert.notEqual(ui.elements.get('reconnect-title').textContent,'Firmware verified');
    }
    assert.deepEqual(ui.calls,['application-open','application-query:get bootloader.ver','application-query:ver','application-close']);
  }
});

test('post-startup bootloader preparation rejects changed evidence or a new pending workflow while the prompt is open',async()=>{
  for(const change of ['port','generation','board','sha256','url','sha256-in-place','url-in-place','pending-recovery','component']){
    const ui=await bootloaderOfferWorkbench();prepareNrfStartup(ui);ui.context.choose=async()=>{
      if(change==='port')ui.evaluate('state.port={getInfo:()=>({})};');
      if(change==='generation')ui.evaluate('state.generation++;');
      if(change==='board')ui.evaluate("state.device.model='Different nRF52 board';");
      if(change==='sha256')ui.evaluate("state.items[0]={...state.items[0],bootloaderInfo:{...state.items[0].bootloaderInfo,sha256:'d'.repeat(64)}};");
      if(change==='url')ui.evaluate("state.items[0]={...state.items[0],bootloaderInfo:{...state.items[0].bootloaderInfo,url:'https://example.test/replaced-bootloader.zip'}};");
      if(change==='sha256-in-place')ui.evaluate("state.items[0].bootloaderInfo.sha256='d'.repeat(64);");
      if(change==='url-in-place')ui.evaluate("state.items[0].bootloaderInfo.url='https://example.test/replaced-bootloader.zip';");
      if(change==='pending-recovery')ui.evaluate("state.espRecovery={sha256:'d'.repeat(64),mac:'aa:bb:cc:dd:ee:ff'};");
      if(change==='component'){ui.context.component=fakePackage({kind:'softdevice_bootloader',destructive:true});ui.evaluate('state.pkg=component;');}
      return 'prepare';
    };ui.context.loadBootloaderFirmware=async()=>ui.calls.push('unexpected-component-load');
    await assert.rejects(ui.evaluate('verifyApplication();'),/device or verified bootloader changed/i,change);assert.equal(ui.evaluate('state.verification'),null,change);assert.ok(!ui.calls.includes('unexpected-component-load'),change);assert.equal(ui.evaluate('state.plan'),null,change);
  }
});

test('a pending ESP write blocks stale nRF52 application verification before opening USB or offering another image',async()=>{
  const ui=await bootloaderOfferWorkbench();prepareNrfStartup(ui);ui.context.pendingEsp={sha256:'d'.repeat(64),mac:'aa:bb:cc:dd:ee:ff',name:'interrupted.bin'};ui.evaluate('state.espRecovery=pendingEsp;');
  const originalPackage=ui.evaluate('state.pkg'),originalVerification=ui.evaluate('state.verification');ui.context.choose=async()=>{ui.calls.push('unexpected-offer');return 'prepare';};ui.context.loadBootloaderFirmware=async()=>ui.calls.push('unexpected-image-load');
  await assert.rejects(ui.evaluate('verifyApplication();'),/pending write recovery/i);assert.deepEqual(ui.calls,[]);assert.equal(ui.evaluate('state.verification'),originalVerification);assert.equal(ui.evaluate('state.pkg'),originalPackage);assert.equal(ui.evaluate('state.espRecovery'),ui.context.pendingEsp);assert.equal(ui.evaluate('state.port'),ui.port);
});

test('direct post-startup bootloader offers cannot supersede pending ESP recovery or a loaded component',async()=>{
  for(const scenario of ['esp-recovery','component']){
    const ui=await bootloaderOfferWorkbench();ui.calls.length=0;
    if(scenario==='esp-recovery')ui.evaluate("state.espRecovery={sha256:'d'.repeat(64),mac:'aa:bb:cc:dd:ee:ff'};");
    else{ui.context.component=fakePackage({kind:'softdevice_bootloader',destructive:true});ui.evaluate('state.pkg=component;');}
    const originalPackage=ui.evaluate('state.pkg'),originalRecovery=ui.evaluate('state.espRecovery');ui.context.choose=async()=>{ui.calls.push('unexpected-offer');return 'prepare';};ui.context.loadBootloaderFirmware=async()=>ui.calls.push('unexpected-image-load');
    await ui.evaluate('offerBootloaderAfterStartup();');assert.deepEqual(ui.calls,[],scenario);assert.equal(ui.evaluate('state.pkg'),originalPackage,scenario);assert.equal(ui.evaluate('state.espRecovery'),originalRecovery,scenario);
  }
});

test('an application identity mismatch never reaches the optional bootloader update prompt',async()=>{
  const ui=await bootloaderOfferWorkbench();prepareNrfStartup(ui,{publicKey:'22'.repeat(32)});ui.context.choose=async()=>ui.calls.push('unexpected-offer');ui.context.loadBootloaderFirmware=async()=>ui.calls.push('unexpected-load');
  await assert.rejects(ui.evaluate('verifyApplication();'),/identity differs/i);assert.ok(ui.evaluate('state.verification'));assert.deepEqual(ui.calls,['application-open','application-query:get bootloader.ver','application-close']);
});

test('numbered backup/prepare labels survive control refreshes and install-mode changes without replacing button children',async()=>{
  const ui=workbench();await Promise.resolve();const ariaWrites=[];
  for(const id of ['select-port','prepare','flash'])Object.defineProperty(ui.elements.get(id),'textContent',{configurable:true,get:()=>'',set(){throw Error('Replacing a primary button would delete its step number');}});
  ui.elements.get('prepare').setAttribute=(name,value)=>ariaWrites.push([name,value]);
  ui.evaluate('controls();');assert.match(ui.elements.get('prepare-label').textContent,/Backup\s*&\s*prepare update/i);
  await ui.evaluate("setInstallMode('install');");assert.match(ui.elements.get('prepare-label').textContent,/Backup\s*&\s*prepare install/i);
  await ui.evaluate("setInstallMode('update');");assert.match(ui.elements.get('prepare-label').textContent,/Backup\s*&\s*prepare update/i);
  assert.ok(ariaWrites.some(([name,value])=>name==='aria-label'&&/Step 3: Backup and prepare install/i.test(value)));assert.ok(ariaWrites.some(([name,value])=>name==='aria-label'&&/Step 3: Backup and prepare update/i.test(value)));
  assert.deepEqual(ui.calls,[]);
});

test('step guidance describes the next action from UI state without authorizing USB or claiming backup success',async()=>{
  const cases=[
    {state:'',patterns:[/step\s*1/i]},
    {state:'state.port=selectedPort;',patterns:[/firmware|build/i,/step\s*2/i]},
    {state:'state.port=selectedPort;state.pkg=pkg;',patterns:[/step\s*3/i,/backup|prepare/i]},
    {state:'state.port=selectedPort;state.pkg=pkg;state.plan={prepared:true};',patterns:[/step\s*4/i,/review|flash/i]},
    {state:'state.handoff=true;',patterns:[/step\s*1/i,/step\s*3/i,/same/i]},
    {state:"state.recovery={sha256:pkg.sha256,phase:'reselect-dfu',eraseComplete:true};",patterns:[/step\s*1/i,/step\s*3/i,/same/i]},
    {state:'state.port=selectedPort;state.pkg=pkg;state.verification={sha256:pkg.sha256};',patterns:[/verif|startup|application/i]},
    {state:'state.port=selectedPort;state.pkg=pkg;state.plan={written:true};',patterns:[/verif|start|reset/i]},
    {state:'state.busy=true;',patterns:[/connect|running|working|progress/i]}
  ];
  for(const fixture of cases){
    const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage();ui.evaluate(fixture.state+'controls();');
    const message=ui.elements.get('step-guidance').textContent;for(const pattern of fixture.patterns)assert.match(message,pattern,fixture.state||'initial');
    assert.doesNotMatch(message,/(?:backup|backed\s+up).{0,25}(?:complete|saved|successful)/i,'A numbered label is not proof a backup was saved');assert.deepEqual(ui.calls,[]);
  }
});

test('four-step guidance keeps mode selection at 2, backup at 3 and final confirmation at 4',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage();
  ui.evaluate('state.port=selectedPort;controls();');
  assert.match(ui.elements.get('step-guidance').textContent,/step\s*2/i);
  assert.match(ui.elements.get('step-guidance').textContent,/update|install|installation/i);
  for(const mode of ['update','install']){
    ui.context.mode=mode;ui.evaluate('state.installMode=mode;state.pkg=pkg;state.plan=null;controls();');
    const backup=ui.elements.get('step-guidance').textContent;
    assert.match(backup,/step\s*3/i);assert.match(backup,/backup|prepare/i);assert.doesNotMatch(backup,/step\s*2\s*:\s*backup/i);
    ui.evaluate('state.plan={prepared:true};controls();');
    const flash=ui.elements.get('step-guidance').textContent;
    assert.match(flash,/step\s*4/i);assert.match(flash,/review|flash/i);assert.match(flash,/confirm/i);
  }
  assert.deepEqual(ui.calls,[]);
});

async function skipBackupWorkbench({catalogOnly=false,runtime=false,architecture='nrf52'}={}){
  const ui=workbench();await Promise.resolve();serialMock(ui);ui.context.selectedPort=ui.port;
  ui.context.pkg=fakePackage({name:architecture==='esp32'?'sample.bin':'sample.zip',architecture,kind:'application'});
  ui.context.inventory=[{...v4Item,architecture,name:ui.context.pkg.name,url:'https://example.test/'+ui.context.pkg.name,action:architecture==='esp32'?'flash-update':'flash'}];
  ui.evaluate('state.items=inventory;state.port=selectedPort;state.device={model:"Sample radio",role:"common-cli"};');
  if(catalogOnly){ui.elements.get('artifact').value='0';ui.context.downloadFirmwareBytes=async()=>{ui.calls.push('download');return new Uint8Array(64);};ui.context.checkedZip=()=>[{name:'manifest.json'},{name:'application.bin'},{name:'application.dat'}];ui.context.inspectFirmware=()=>{ui.calls.push('validate-image');return ui.context.pkg;};}
  else ui.evaluate('state.pkg=pkg;');
  ui.elements.get('transport-mode').value=architecture==='esp32'?'no_reset':'nrf52';ui.elements.get('auto-backup').checked=true;ui.elements.get('skip-backup').checked=true;
  if(!runtime&&architecture==='nrf52'){ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0044});ui.elements.get('already-bootloader').checked=true;}
  ui.context.captureBackup=async()=>{throw Error('Explicit skip must not capture a backup');};
  ui.context.confirm=async(_title,_detail,warning,token,options)=>{if(token!=='SAME DEVICE')assert.match(warning,/chose to skip backup/i);ui.calls.push('confirm:'+token);return true;};
  ui.context.flashNrf=async(_link,pkg)=>ui.calls.push(pkg.erase?'write-erase':'write-final');
  ui.context.touch1200=async(port,mode)=>{assert.equal(port,ui.port);assert.equal(mode,'nrf52');ui.calls.push('enter-dfu');};
  if(architecture==='esp32')ui.context.EspSession=class{async connect(mode){assert.equal(mode,'no_reset');ui.calls.push('inspect-chip');return {chip:'ESP32-S3',mac:'aa:bb:cc:dd:ee:ff',flashBytes:4<<20};}async prepare(pkg){ui.calls.push('validate-plan');return {sha256:pkg.sha256,addresses:[0x10000],mac:'aa:bb:cc:dd:ee:ff'};}async flash(){ui.calls.push('write-final');}async close(){ui.calls.push('close-rom');}};
  return ui;
}

async function meshtasticDirectWorkbench(options={}){
  const ui=await skipBackupWorkbench(options);ui.elements.get('skip-backup').checked=false;ui.context.sourceDevice=meshtasticDevice();ui.evaluate('state.device=sourceDevice;controls();');
  ui.context.choose=async()=>{throw Error('No separate backup dialog is needed for Meshtastic');};
  ui.context.confirm=async(_title,_detail,warning,token)=>{if(token!=='SAME DEVICE'){assert.match(warning,/Meshtastic.*not backed up/i);assert.doesNotMatch(warning,/You chose to skip backup/);}ui.calls.push('confirm:'+token);return true;};
  return ui;
}

test('Meshtastic hides unavailable backup controls and highlights step 4 without changing the manual skip preference',async()=>{
  const ui=await meshtasticWorkbench();await ui.elements.get('select-port').onclick();
  assert.equal(ui.elements.get('prepare').hidden,true);assert.equal(ui.elements.get('prepare').disabled,true);assert.equal(ui.elements.get('skip-backup-option').hidden,true);assert.equal(ui.elements.get('skip-backup').checked,false);assert.equal(ui.elements.get('flash').disabled,false);assert.deepEqual(nextHighlight(ui),['flash']);assert.match(ui.elements.get('step-guidance').textContent,/^Step 4:/);assert.doesNotMatch(ui.elements.get('workflow-guidance').textContent,/Step 3|choose.*skip/i);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,['chooser','open','close']);
  await ui.evaluate("setInstallMode('update');");assert.equal(ui.elements.get('prepare').hidden,true);assert.equal(ui.elements.get('flash').disabled,false);assert.deepEqual(nextHighlight(ui),['flash']);
});

test('Meshtastic step 4 downloads and validates before final consent, without an unsupported backup prompt',async()=>{
  for(const architecture of ['nrf52','esp32']){
    const ui=await meshtasticDirectWorkbench({catalogOnly:true,architecture});await ui.elements.get('flash').onclick();
    assert.ok(ui.calls.indexOf('download')<ui.calls.indexOf('validate-image'));assert.ok(ui.calls.indexOf('validate-image')<ui.calls.indexOf('confirm:FLASH'));assert.ok(ui.calls.indexOf('confirm:FLASH')<ui.calls.indexOf('write-final'));assert.equal(ui.calls.filter(call=>call==='write-final').length,1);assert.equal(ui.elements.get('skip-backup').checked,false);assert.equal(ui.evaluate('state.skipBackupForOperation'),false);assert.equal(ui.evaluate('state.backup'),null);
  }
});

test('Meshtastic direct preparation stops on invalid firmware, missing erase utility, board mismatch or declined confirmation',async()=>{
  for(const outcome of ['invalid','erase','board','cancel']){
    const ui=await meshtasticDirectWorkbench({catalogOnly:outcome==='invalid'});
    if(outcome==='invalid')ui.context.inspectFirmware=()=>{throw Error('Invalid firmware');};
    if(outcome==='erase'){ui.evaluate("state.installMode='install';syncInstallMode();");ui.context.erasePackage=async()=>{throw Error('Missing erase utility');};}
    if(outcome==='board')ui.context.assessBoard=()=>({requiresOverride:true,firmwareFamily:'rak4631',deviceFamily:'unknown',token:'unknown-to-rak4631'});
    if(outcome==='board'||outcome==='cancel')ui.context.confirm=async(_title,_detail,warning,token)=>{ui.calls.push('confirm:'+token);return false;};
    await ui.elements.get('flash').onclick();assert.ok(!ui.calls.includes('write-final')&&!ui.calls.includes('write-erase'),outcome);assert.equal(ui.evaluate('state.skipBackupForOperation'),false,outcome);assert.equal(ui.elements.get('skip-backup').checked,false,outcome);
  }
});

test('Meshtastic keeps step 4 across nRF52 runtime-to-DFU handoff without automatically writing',async()=>{
  const ui=await meshtasticDirectWorkbench({runtime:true});await ui.elements.get('flash').onclick();assert.deepEqual(ui.calls,['enter-dfu']);assert.equal(ui.evaluate('state.backupApproved.sourceFirmware'),'meshtastic');assert.equal(ui.evaluate('state.port'),null);assert.match(ui.elements.get('step-guidance').textContent,/Step 1.*step 4/i);assert.equal(ui.elements.get('prepare').hidden,true);
  ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0044});await ui.elements.get('select-port').onclick();assert.equal(ui.elements.get('flash').disabled,false);assert.deepEqual(nextHighlight(ui),['flash']);assert.ok(!ui.calls.includes('write-final'));await ui.elements.get('flash').onclick();assert.equal(ui.calls.filter(call=>call==='write-final').length,1);assert.equal(ui.calls.filter(call=>call==='enter-dfu').length,1);assert.ok(ui.calls.indexOf('confirm:SAME DEVICE')<ui.calls.indexOf('confirm:FLASH'));assert.equal(ui.elements.get('skip-backup').checked,false);
});

test('Meshtastic erase and final application writes each retain consent, with a UI-only recovery-source marker',async()=>{
  const ui=await meshtasticDirectWorkbench();ui.evaluate("state.installMode='install';syncInstallMode();");ui.context.erase=fakePackage({name:'erase.zip',erase:true,destructive:true});ui.context.erasePackage=async()=>ui.context.erase;
  await ui.elements.get('flash').onclick();assert.deepEqual(ui.calls.filter(call=>call.startsWith('write-')),['write-erase']);assert.equal(ui.evaluate('state.recovery.sourceFirmware'),'meshtastic');assert.equal(JSON.parse(ui.context.localStorage.getItem('meshfirmware.nrfRecovery')).sourceFirmware,'meshtastic');assert.equal(ui.elements.get('prepare').hidden,true);assert.equal(ui.elements.get('flash').disabled,true);
  assert.equal(ui.elements.get('flash-progress-title').textContent,'DONE — ERASE STEP ONLY');ui.elements.get('flash-progress-close').onclick();
  await ui.elements.get('select-port').onclick();assert.deepEqual(nextHighlight(ui),['flash']);assert.equal(ui.elements.get('flash').disabled,false);assert.deepEqual(ui.calls.filter(call=>call.startsWith('write-')),['write-erase']);await ui.elements.get('flash').onclick();assert.deepEqual(ui.calls.filter(call=>call.startsWith('write-')),['write-erase','write-final']);assert.equal(ui.calls.filter(call=>call==='confirm:WIPE WITHOUT BACKUP').length,1);assert.equal(ui.calls.filter(call=>call==='confirm:FLASH').length,1);assert.equal(ui.elements.get('skip-backup').checked,false);
});

test('only explicitly marked Meshtastic recovery keeps direct step 4 after reload, never a model-name guess',async()=>{
  for(const marked of [true,false]){
    const recovery={sha256:'a'.repeat(64),name:'sample.zip',deviceModel:'Meshtastic hardware 9',eraseComplete:true,...(marked?{sourceFirmware:'meshtastic'}:{})},ui=workbench({recovery});await Promise.resolve();serialMock(ui);ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage({name:'sample.zip'});ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0044});ui.elements.get('transport-mode').value='nrf52';ui.context.confirm=async()=>true;await ui.elements.get('select-port').onclick();ui.evaluate('state.pkg=pkg;controls();');
    assert.equal(ui.elements.get('prepare').hidden,marked);assert.equal(ui.elements.get('skip-backup-option').hidden,marked);assert.equal(ui.elements.get('flash').disabled,!marked);assert.equal(ui.evaluate('state.device'),null);assert.equal(ui.elements.get('skip-backup').checked,false);assert.deepEqual(ui.calls,['chooser']);
  }
});

test('connecting a MeshCore node after Meshtastic restores the normal backup path',async()=>{
  const ui=await meshtasticWorkbench();await ui.elements.get('select-port').onclick();const nextPort={getInfo:()=>({usbVendorId:0x239a,usbProductId:0x4405})};ui.context.navigator.serial.requestPort=async()=>nextPort;ui.context.detectApplication=async()=>({firmwareFamily:'meshcore',role:'companion',model:'Heltec T114',protocol:13,publicKey:'11'.repeat(32)});await ui.elements.get('select-port').onclick();
  assert.equal(ui.elements.get('prepare').hidden,false);assert.equal(ui.elements.get('prepare').disabled,false);assert.equal(ui.elements.get('skip-backup-option').hidden,false);assert.equal(ui.elements.get('skip-backup').checked,false);assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(nextHighlight(ui),['prepare']);assert.match(ui.elements.get('workflow-guidance').textContent,/Step 3/);assert.equal(ui.evaluate('state.pkg'),null);
});

test('skip backup is opt-in and enables step 4 without requiring step 3',async()=>{
  const ui=await skipBackupWorkbench();ui.elements.get('skip-backup').checked=false;ui.evaluate('controls();');
  assert.equal(ui.elements.get('flash').disabled,true);assert.equal(ui.elements.get('prepare').disabled,false);assert.equal(ui.elements.get('skip-backup-warning').hidden,true);
  ui.elements.get('skip-backup').checked=true;await ui.elements.get('skip-backup').onchange();
  assert.equal(ui.elements.get('flash').disabled,false);assert.equal(ui.elements.get('prepare').disabled,true);assert.equal(ui.elements.get('skip-backup-warning').hidden,false);assert.match(ui.elements.get('step-guidance').textContent,/Step 4.*without backup/);assert.equal(ui.elements.get('auto-backup').checked,true);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,[]);
  const fresh=workbench();assert.equal(fresh.elements.get('skip-backup').checked,false);
});

test('direct step 4 downloads and validates selected firmware before no-backup confirmation and writing',async()=>{
  for(const architecture of ['nrf52','esp32']){
    const ui=await skipBackupWorkbench({catalogOnly:true,architecture});await ui.elements.get('flash').onclick();
    assert.ok(ui.calls.indexOf('download')<ui.calls.indexOf('validate-image'),architecture);assert.ok(ui.calls.indexOf('validate-image')<ui.calls.indexOf('confirm:FLASH'),architecture);assert.ok(ui.calls.indexOf('confirm:FLASH')<ui.calls.indexOf('write-final'),architecture);
    if(architecture==='esp32'){assert.ok(ui.calls.indexOf('inspect-chip')<ui.calls.indexOf('validate-plan'));assert.ok(ui.calls.indexOf('validate-plan')<ui.calls.indexOf('confirm:FLASH'));}
    assert.equal(ui.elements.get('skip-backup').checked,true,architecture);assert.equal(ui.evaluate('state.skipBackupForOperation'),false,architecture);assert.ok(!ui.calls.includes('enter-dfu'),architecture);assert.ok(!ui.elements.get('notice').textContent.includes('JSON backup has been downloaded'),architecture);
  }
});

test('skip backup still requires final confirmation and cleans its operation flag on cancellation or errors',async()=>{
  for(const outcome of ['cancel','invalid-image','hash','missing-target']){
    const ui=await skipBackupWorkbench({catalogOnly:outcome==='invalid-image'});
    if(outcome==='cancel')ui.context.confirm=async(_title,_detail,warning,token)=>{assert.equal(token,'FLASH');assert.match(warning,/No new logical backup was created/);return false;};
    if(outcome==='invalid-image')ui.context.inspectFirmware=()=>{throw Error('Invalid firmware fixture');};
    if(outcome==='hash')ui.elements.get('expected-sha').value='b'.repeat(64);
    if(outcome==='missing-target')ui.evaluate('state.port=null;');
    await ui.elements.get('flash').onclick();assert.ok(!ui.calls.includes('write-final'),outcome);assert.ok(!ui.calls.includes('enter-dfu'),outcome);assert.equal(ui.evaluate('state.skipBackupForOperation'),false,outcome);
  }
});

test('direct step 4 stops at DFU handoff and resumes only after an explicit same-radio selection and click',async()=>{
  const ui=await skipBackupWorkbench({runtime:true});await ui.elements.get('flash').onclick();
  assert.deepEqual(ui.calls,['enter-dfu']);assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.skipBackupForOperation'),false);assert.equal(ui.elements.get('skip-backup').checked,true);assert.match(ui.elements.get('step-guidance').textContent,/Step 1.*Step 4/i);
  ui.port.getInfo=()=>({usbVendorId:0x2886,usbProductId:0x0044});await ui.elements.get('select-port').onclick();
  assert.equal(ui.elements.get('skip-backup').checked,true);assert.equal(ui.elements.get('flash').disabled,false);assert.ok(!ui.calls.includes('write-final'));
  await ui.elements.get('flash').onclick();assert.equal(ui.calls.filter(call=>call==='enter-dfu').length,1);assert.equal(ui.calls.filter(call=>call==='write-final').length,1);assert.ok(ui.calls.indexOf('confirm:SAME DEVICE')<ui.calls.indexOf('confirm:FLASH'));assert.equal(ui.evaluate('state.skipBackupForOperation'),false);
});

test('direct erase without backup preserves wipe acknowledgement and erase/reselect/final-write boundaries',async()=>{
  const ui=await skipBackupWorkbench();ui.evaluate("state.installMode='install';");ui.context.erase=fakePackage({name:'erase.zip',erase:true,destructive:true});ui.context.erasePackage=async()=>ui.context.erase;
  await ui.elements.get('flash').onclick();assert.ok(ui.calls.includes('confirm:WIPE WITHOUT BACKUP'));assert.deepEqual(ui.calls.filter(call=>call.startsWith('write-')),['write-erase']);assert.equal(ui.evaluate('state.recovery.phase'),'reselect-dfu');assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('flash').disabled,true);
  await ui.elements.get('select-port').onclick();assert.equal(ui.evaluate('state.recovery.phase'),'final');assert.equal(ui.elements.get('skip-backup').checked,true);await ui.elements.get('flash').onclick();
  assert.deepEqual(ui.calls.filter(call=>call.startsWith('write-')),['write-erase','write-final']);assert.equal(ui.calls.filter(call=>call==='confirm:WIPE WITHOUT BACKUP').length,1);assert.equal(ui.calls.filter(call=>call==='confirm:FLASH').length,1);
});

test('skip backup never rebuilds a stale plan or bypasses mode and board overrides',async()=>{
  for(const scenario of ['stale','mode','board']){
    const ui=await skipBackupWorkbench();
    if(scenario==='stale'){ui.evaluate('state.plan={generation:-1,port:state.port,sha256:state.pkg.sha256};');ui.context.prepareSelectedFirmware=async()=>{throw Error('A stale plan must not be silently rebuilt');};}
    if(scenario==='mode'){ui.context.pkg=fakePackage({architecture:'esp32',merged:true,destructive:true});ui.evaluate('state.pkg=pkg;');}
    if(scenario==='board'){ui.context.assessBoard=()=>({requiresOverride:true,firmwareFamily:'rak4631',deviceFamily:'unknown',token:'unknown-to-rak4631'});ui.context.confirm=async(_title,_detail,_warning,token)=>{assert.equal(token,'unknown-to-rak4631');ui.calls.push('board-override');return false;};}
    await ui.elements.get('flash').onclick();assert.ok(!ui.calls.includes('write-final'),scenario);assert.ok(!ui.calls.includes('enter-dfu'),scenario);assert.equal(ui.evaluate('state.skipBackupForOperation'),false,scenario);
    if(scenario==='stale')assert.match(ui.elements.get('notice').textContent,/Selection changed/);
  }
});

test('unrelated radio, image and installation selections clear skip intent but internal downloads preserve it',async()=>{
  for(const change of ['radio','image','mode','application']){
    const ui=await skipBackupWorkbench();
    if(change==='radio')await ui.elements.get('select-port').onclick();
    if(change==='image')await ui.evaluate('clearFirmwareSelection();');
    if(change==='mode')await ui.evaluate("setInstallMode('install');");
    if(change==='application')ui.evaluate('invalidateApplicationEvidence();');
    assert.equal(ui.elements.get('skip-backup').checked,false,change);
  }
});

test('without skip opt-in step 4 cannot prepare or download an unprepared image',async()=>{
  const ui=await skipBackupWorkbench({catalogOnly:true});ui.elements.get('skip-backup').checked=false;await ui.elements.get('flash').onclick();assert.deepEqual(ui.calls,[]);assert.match(ui.elements.get('notice').textContent,/Selection changed/);assert.equal(ui.evaluate('state.skipBackupForOperation'),false);
});

test('changing the skip choice invalidates an old preparation without resetting the radio',async()=>{
  const ui=await skipBackupWorkbench();ui.context.record=ui.calls;ui.evaluate('state.plan={generation:state.generation,port:state.port,sha256:state.pkg.sha256};state.backupApproved={sha256:state.pkg.sha256,port:state.port};state.esp={close:async()=>record.push("close-inspection")};');
  ui.elements.get('skip-backup').checked=false;await ui.elements.get('skip-backup').onchange();assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.evaluate('state.backupApproved'),null);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);assert.equal(ui.elements.get('flash').disabled,true);assert.equal(ui.elements.get('prepare').disabled,false);assert.deepEqual(ui.calls,['close-inspection']);
});

test('unfinished preparation returns and failed writes cannot leak skip scope or repeat a transferred plan',async()=>{
  for(const outcome of ['no-plan','throw','written']){
    const ui=await skipBackupWorkbench();
    if(outcome==='no-plan')ui.context.prepareSelectedFirmware=async()=>{ui.calls.push('prepare-only');};
    if(outcome==='throw')ui.context.flashNrf=async()=>{ui.calls.push('write-attempt');throw Error('Transport interrupted');};
    if(outcome==='written')ui.evaluate('state.plan={generation:state.generation,port:state.port,sha256:state.pkg.sha256,written:true};');
    await ui.elements.get('flash').onclick();assert.equal(ui.evaluate('state.skipBackupForOperation'),false,outcome);assert.ok(!ui.calls.includes('write-final'),outcome);
    if(outcome==='no-plan')assert.deepEqual(ui.calls,['prepare-only']);
    if(outcome==='written'){assert.deepEqual(ui.calls,[]);assert.match(ui.elements.get('notice').textContent,/already been transferred/);}
  }
});

test('reselecting a radio shows a prominent existing USB action without opening a chooser or resetting',async()=>{
  for(const pending of ['handoff','recovery','esp-recovery','verification','migration','waiting-rom','waiting-application']){
    const ui=workbench();await Promise.resolve();ui.context.pkg=fakePackage({architecture:'nrf52'});const styles=[],aria=[];
    ui.elements.get('flasher').classList.toggle=(name,value)=>styles.push([name,value]);ui.elements.get('select-port').setAttribute=(name,value)=>aria.push([name,value]);
    if(pending==='handoff')ui.evaluate('state.handoff=true;state.pkg=pkg;');
    if(pending==='recovery')ui.evaluate("state.recovery={phase:'reselect-dfu'};");
    if(pending==='esp-recovery')ui.evaluate('state.espRecovery={};');
    if(pending==='verification')ui.evaluate('state.verification={};');
    if(pending==='migration')ui.evaluate('state.migration={};');
    if(pending.startsWith('waiting-')){ui.context.phase=pending;ui.evaluate('state.migrationApproval={phase};');}
    ui.evaluate('controls();');
    assert.deepEqual(styles.filter(([name])=>name==='reconnect-needed').at(-1),['reconnect-needed',pending!=='verification'],pending);assert.equal(ui.elements.get('reconnect-callout').hidden,false,pending);assert.equal(ui.elements.get('select-port-label').textContent,pending==='verification'?'Verify previous device (optional)':pending==='waiting-application'?'Reconnect to verify firmware':'Select the same radio again',pending);
    if(pending==='verification')assert.deepEqual(nextHighlight(ui),['start-new-radio']);else assert.ok(aria.some(([name,value])=>name==='aria-describedby'&&value==='reconnect-detail'),pending);
    const detail=ui.elements.get('reconnect-detail').textContent;assert.match(detail,/same radio/i,pending);
    if(['handoff','recovery'].includes(pending))assert.match(detail,/DFU/,pending);
    if(['verification','waiting-application'].includes(pending))assert.match(detail,/application USB port/,pending);
    assert.deepEqual(ui.calls,[],pending);assert.equal(ui.evaluate('state.port'),null,pending);
  }
});

test('initial pages, active operations and a selected returning port keep the compact USB action',async()=>{
  for(const scenario of ['initial','busy','connected']){
    const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;const styles=[],removed=[];
    ui.elements.get('flasher').classList.toggle=(name,value)=>styles.push([name,value]);ui.elements.get('select-port').removeAttribute=name=>removed.push(name);
    if(scenario==='busy')ui.evaluate('state.handoff=true;state.busy=true;');
    if(scenario==='connected')ui.evaluate('state.handoff=true;state.port=selectedPort;');
    ui.evaluate('controls();');assert.deepEqual(styles.filter(([name])=>name==='reconnect-needed').at(-1),['reconnect-needed',false],scenario);assert.equal(ui.elements.get('reconnect-callout').hidden,true,scenario);assert.equal(ui.elements.get('select-port-label').textContent,'Choose USB port',scenario);assert.ok(removed.includes('aria-describedby'),scenario);assert.deepEqual(ui.calls,[],scenario);
  }
});

test('a required firmware-build choice is highlighted and revealed without choosing, focusing or opening USB',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.inventory=[v4Item];
  const highlights=[],aria=[];ui.elements.get('artifact-field').classList.toggle=(name,value)=>highlights.push([name,value]);ui.elements.get('artifact').setAttribute=(name,value)=>aria.push([name,value]);
  ui.elements.get('artifact').focus=()=>{throw Error('A required choice must not steal keyboard focus');};
  ui.evaluate('state.items=inventory;state.port=selectedPort;filterCatalog();');ui.elements.get('hardware').value=v4Item.hardware;ui.elements.get('firmware-choices').open=false;ui.evaluate('controls();');
  assert.deepEqual(highlights.at(-1),['choice-required',true]);assert.ok(aria.some(([name,value])=>name==='aria-required'&&value==='true'));assert.equal(ui.elements.get('artifact-required').hidden,false);assert.equal(ui.elements.get('artifact-choice-hint').hidden,false);assert.equal(ui.elements.get('firmware-choices').open,true);
  assert.ok(aria.some(([name,value])=>name==='aria-label'&&value==='Step 2.5: Firmware build'));assert.match(ui.elements.get('step-guidance').textContent,/^Step 2\.5:/);
  assert.equal(ui.elements.get('artifact').value,'');assert.equal(ui.elements.get('prepare').disabled,true);assert.deepEqual(ui.calls,[]);
});

test('selecting a firmware build clears the highlight immediately and clearing the choice restores it',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.inventory=[v4Item];ui.evaluate('state.items=inventory;state.port=selectedPort;filterCatalog();');
  ui.elements.get('hardware').value=v4Item.hardware;
  const highlights=[],aria=[],removed=[];ui.elements.get('artifact-field').classList.toggle=(name,value)=>highlights.push([name,value]);ui.elements.get('artifact').setAttribute=(name,value)=>aria.push([name,value]);ui.elements.get('artifact').removeAttribute=name=>removed.push(name);
  ui.elements.get('artifact').value='0';await ui.elements.get('artifact').onchange();
  assert.deepEqual(highlights.at(-1),['choice-required',false]);assert.deepEqual(aria.at(-1),['aria-required','false']);assert.equal(ui.elements.get('artifact-choice-hint').hidden,true);assert.equal(ui.elements.get('artifact-required').hidden,true);assert.equal(ui.elements.get('prepare').disabled,false);
  assert.ok(removed.includes('aria-label'));assert.match(ui.elements.get('step-guidance').textContent,/^Step 3:/);assert.doesNotMatch(ui.elements.get('step-guidance').textContent,/Step 2\.5/);
  ui.elements.get('artifact').value='';await ui.elements.get('artifact').onchange();assert.deepEqual(highlights.at(-1),['choice-required',true]);assert.match(ui.elements.get('step-guidance').textContent,/^Step 2\.5:/);assert.equal(ui.elements.get('prepare').disabled,true);assert.deepEqual(ui.calls,[]);
});

test('build highlights do not claim a choice is needed for custom images, idle pages or pending device flows',async()=>{
  for(const scenario of ['disconnected','busy','custom','empty','migration','recovery','esp-recovery','verification','handoff','approval']){
    const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.inventory=[v4Item];ui.context.pkg=fakePackage();ui.evaluate('state.items=inventory;state.port=selectedPort;filterCatalog();');
    if(scenario==='disconnected')ui.evaluate('state.port=null;');
    if(scenario==='busy')ui.evaluate('state.busy=true;');
    if(scenario==='custom')ui.evaluate('state.pkg=pkg;');
    if(scenario==='empty')ui.elements.get('artifact').options=[new ui.context.Option('No files','')];
    if(scenario==='migration')ui.evaluate('state.migration={};');
    if(scenario==='recovery')ui.evaluate('state.recovery={};');
    if(scenario==='esp-recovery')ui.evaluate('state.espRecovery={};');
    if(scenario==='verification')ui.evaluate('state.verification={};');
    if(scenario==='handoff')ui.evaluate('state.handoff=true;');
    if(scenario==='approval')ui.evaluate('state.migrationApproval={};');
    const highlights=[];ui.elements.get('artifact-field').classList.toggle=(name,value)=>highlights.push([name,value]);ui.elements.get('firmware-choices').open=false;ui.evaluate('updateArtifactChoiceHighlight();');
    assert.deepEqual(highlights.at(-1),['choice-required',false],scenario);assert.equal(ui.elements.get('artifact-choice-hint').hidden,true,scenario);assert.equal(ui.elements.get('artifact-required').hidden,true,scenario);assert.equal(ui.elements.get('firmware-choices').open,false,scenario);assert.deepEqual(ui.calls,[],scenario);
  }
});

// Real immutable byte/table proofs, with all USB and timers supplied by mocks.
function migrationFlowFixture({uart=false}={}){
  const chip=uart?0:9,flashBytes=(uart?4:16)<<20,board=uart?'heltec_v2':'heltec_v4',target=board+'_repeater',targetApp1=uart?0x200000:0x650000,targetAppSize=uart?0x1f0000:0x640000;
  const payload=new Uint8Array(64),header=new DataView(payload.buffer);payload[0]=0xe9;payload[1]=1;payload[12]=chip;payload[3]=(Math.log2(flashBytes)-20)<<4;header.setUint32(28,16,true);header.setUint32(32,0xabcd5432,true);
  let checksum=0xef;for(const value of payload.subarray(32,48))checksum^=value;payload[63]=checksum;
  const pkg=fakePackage({name:target+'-v1.18.0.bin',architecture:'esp32',chipId:chip,payload,sha256:firmwareHash(payload),payloadHash:firmwareHash(payload),merged:false,expert:false});
  const targetTable=new Uint8Array(4096).fill(255),view=new DataView(targetTable.buffer),encode=value=>new TextEncoder().encode(value);
  for(const [i,type,subtype,offset,size,name]of [[0,1,2,0x9000,0x5000,'nvs'],[1,1,0,0xe000,0x2000,'otadata'],[2,0,0x10,0x10000,targetAppSize,'app0'],[3,0,0x11,targetApp1,targetAppSize,'app1']]){
    const at=i*32;targetTable.fill(0,at,at+32);view.setUint16(at,0x50aa,true);targetTable[at+2]=type;targetTable[at+3]=subtype;view.setUint32(at+4,offset,true);view.setUint32(at+8,size,true);targetTable.set(encode(name),at+12);
  }
  view.setUint16(128,0xebeb,true);targetTable.set(Uint8Array.from(md5hex(targetTable.subarray(0,128)).match(/../g),byte=>parseInt(byte,16)),144);
  const bridge=payload.slice();bridge[40]^=1;bridge[63]^=1;
  const mac='aa:bb:cc:dd:ee:ff',sourceHash='c'.repeat(64),targetHash=firmwareHash(targetTable),bridgeHash=firmwareHash(bridge),sourceOffsets=[0x150000,0x10000];
  const sourceParts=[{type:1,subtype:2,offset:0x9000,size:0x5000,label:'nvs',flags:0},{type:1,subtype:0,offset:0xe000,size:0x2000,label:'otadata',flags:0},{type:0,subtype:0x10,offset:0x10000,size:0x140000,label:'app0',flags:0},{type:0,subtype:0x11,offset:0x150000,size:0x140000,label:'app1',flags:0}];
  const bridgePlan={format:'meshcore-usb-partition-expansion-v2',ok:true,needed:true,resume:false,started:false,completed:false,verified:false,usb_safe:true,mac,device_mac:'AABBCCDDEEFF',sha256:pkg.sha256,payloadHash:pkg.payloadHash,firmware_sha256:pkg.sha256,chip,flash_bytes:flashBytes,board,target,hardware_id:board,target_id:target,firmware_version:'v1.18.0',artifact_sha256:'f'.repeat(64),bridge:Array.from(bridge),bridge_bytes:bridge.length,bridge_sha256:bridgeHash,bridge_offsets:sourceOffsets,app_offsets:sourceOffsets,addresses:sourceOffsets,active_offset:0x10000,parts:sourceParts,source_table_sha256:sourceHash,target_table_sha256:targetHash,targetTable:Array.from(targetTable),uart_completion_status:uart,automatic_rom_return:!uart,merged:false,expert:false,requiresRevisionOverride:false,chunkedRecovery:false,revisionProof:'e'.repeat(64),compatibilityWarnings:[]};
  const finalPlan={needed:false,verified:true,identity_restored:true,configuration_restored:true,mac,sha256:pkg.sha256,payloadHash:pkg.payloadHash,firmware_sha256:pkg.sha256,target:bridgePlan.target,flash_bytes:flashBytes,app_offsets:[targetApp1,0x10000],addresses:[targetApp1,0x10000],active_offset:0x10000,parts:parsePartitionTable(targetTable,flashBytes),completed_bridge_sha256:bridgeHash,completed_source_table_sha256:sourceHash,completed_target_table_sha256:targetHash,completed_bridge_segments:sourceOffsets.map(address=>({address,sourceOffset:0,length:bridge.length,payloadHash:bridgeHash})),merged:false,expert:false,requiresRevisionOverride:false,chunkedRecovery:false,revisionProof:'e'.repeat(64),compatibilityWarnings:[]};
  return {pkg,mac,flashBytes,bridgePlan,finalPlan};
}

async function migrationWorkbench({uart=true,externalUart=false,accepted=true,publicKey='11'.repeat(32),autoFinish=false}={}){
  const fixture=migrationFlowFixture({uart}),ui=workbench();await Promise.resolve();
  const prompts=[],sessions=[],faults={},device={name:'Test radio',model:uart?'Heltec V2':'Heltec V4 OLED',role:'common-cli',catalogRole:'repeater',version:'v1.18.0',...(publicKey?{publicKey}:{})};
  let stage='bridge';
  ui.context.hash=firmwareHash;ui.context.pkg=fixture.pkg;ui.context.selectedPort=ui.port;ui.context.originalDevice=device;
  ui.port.getInfo=()=>uart||externalUart?{usbVendorId:0x10c4,usbProductId:0xea60}:{usbVendorId:0x303a,usbProductId:0x1001};
  ui.elements.get('transport-mode').value=uart||externalUart?'default_reset':'no_reset';ui.elements.get('auto-finish').checked=autoFinish;
  ui.evaluate('state.pkg=pkg;state.port=selectedPort;state.device=originalDevice;');
  ui.context.choose=async()=>{ui.calls.push('backup-considered');return 'skip';};
  ui.context.confirm=async(title,detail,warning,token)=>{prompts.push({title,detail,warning,token});ui.calls.push('confirm:'+token);return accepted;};
  ui.context.waitForMigration=async(_link,mac)=>{assert.equal(mac,fixture.mac);ui.calls.push('uart-settled');if(faults.wait)throw faults.wait;};
  ui.context.detectMeshCore=async()=>{ui.calls.push('detect-application');return faults.device||device;};
  ui.context.SerialLink=class{
    constructor(port){this.port=port;}
    async open(_baud,options){this.application=!!options?.application;ui.calls.push(options?.application?'application-open':'uart-open');const error=typeof faults.applicationOpen==='function'?faults.applicationOpen():faults.applicationOpen;if(error&&options?.application)throw error;}
    async command(command){ui.calls.push(command);return command==='get storage.layout'?faults.layout??'> int:esp32=16384K ext:none; app0*@0x10000+6400K,app1@0x650000+6400K':faults.version??'MeshCore v1.18.0';}
    async close(){ui.calls.push('serial-close');await faults.duringSerialClose?.({application:this.application,port:this.port});}
  };
  ui.context.EspSession=class{
    constructor(port){this.port=port;this.stage=stage;sessions.push(this);ui.calls.push('rom-open:'+this.stage);}
    async connect(mode,options){this.connectMode=mode;this.connectOptions=options;assert.equal(options?.singleReset,this.stage==='final'&&mode==='default_reset','Only an approved original-UART continuation may consume one reset attempt');ui.calls.push('connect:'+mode);const error=typeof faults.connect==='function'?faults.connect(this.stage,mode):faults.connect;if(error)throw error;return {chip:uart?'ESP32':'ESP32-S3',chipId:fixture.bridgePlan.chip,mac:this.stage==='final'&&faults.mac||fixture.mac,flashBytes:fixture.flashBytes};}
    async prepare(pkg,args){assert.equal(pkg,fixture.pkg);ui.calls.push('prepare:'+this.stage);if(faults.prepare)throw faults.prepare;const plan=this.stage==='bridge'?fixture.bridgePlan:fixture.finalPlan;this.plan={...plan};if(this.stage==='final'&&faults.finalPlan)Object.assign(this.plan,faults.finalPlan);return this.plan;}
    async flash(pkg){assert.equal(pkg,fixture.pkg);ui.calls.push('write:'+this.stage);if(faults.write)throw faults.write;await faults.duringWrite?.(this.stage);}
    async finish(nativeUsb){ui.calls.push('finish:'+this.stage);if(faults.finish)throw faults.finish;await faults.duringFinish?.(this.stage);if(this.stage==='bridge')stage='final';return nativeUsb;}
    async close(){ui.calls.push('rom-close:'+this.stage);}
  };
  return {...ui,...fixture,prompts,sessions,faults,device};
}

test('automatic migration UI fixtures use the real two-stage immutable proof guard',()=>{
  const {pkg,bridgePlan,finalPlan}=migrationFlowFixture(),approval=new MigrationApproval(pkg,bridgePlan);
  assert.equal(approval.phase,'bridge-ready');approval.beginBridge(pkg,bridgePlan).bridgeVerified(pkg,bridgePlan).beginFinal(pkg,finalPlan).finalVerified(pkg,finalPlan).complete();assert.equal(approval.phase,'complete');
});

test('a saved migration marker never recreates automatic write or reset permission after reload',async()=>{
  const {pkg,mac}=migrationFlowFixture(),pending={mac,sha256:pkg.sha256,uart:true,settled:true,phase:'running',migrationApproval:{phase:'waiting-rom'}};
  const ui=workbench({pending});await Promise.resolve();assert.equal(ui.evaluate('state.migrationApproval'),null);assert.equal(ui.elements.get('stop-migration-auto').hidden,true);assert.deepEqual(ui.calls,[]);assert.ok(ui.evaluate("localStorage.getItem('meshfirmware.pendingMigration')"));
});

test('one migration acknowledgement completes UART bridge, final firmware and startup without more buttons',async()=>{
  const ui=await migrationWorkbench({uart:true,autoFinish:false});
  await ui.elements.get('prepare').onclick();assert.equal(ui.evaluate('state.plan.needed'),true);assert.deepEqual(ui.calls.filter(call=>call.startsWith('write:')),[]);
  await ui.elements.get('flash').onclick();
  assert.deepEqual(ui.prompts.map(prompt=>prompt.token),['EXPAND AND FLASH']);
  for(const value of [ui.mac,ui.pkg.sha256,ui.bridgePlan.bridge_sha256,ui.bridgePlan.target_table_sha256])assert.ok(ui.prompts[0].detail.includes(value),value);
  assert.match(ui.prompts[0].warning,/power loss|physical recovery/i);assert.match(ui.prompts[0].warning,/restarts|automatic finish is off/i);
  assert.deepEqual(ui.calls.filter(call=>/^(write|finish):/.test(call)),['write:bridge','finish:bridge','write:final','finish:final']);
  assert.ok(ui.calls.indexOf('uart-settled')<ui.calls.indexOf('prepare:final'));assert.ok(ui.calls.indexOf('prepare:final')<ui.calls.indexOf('write:final'));
  assert.equal(ui.calls.filter(call=>call==='backup-considered').length,1);assert.ok(!ui.calls.includes('chooser'));assert.equal(ui.evaluate('state.migrationApproval'),null);assert.equal(ui.evaluate('state.migration'),null);assert.equal(ui.evaluate('state.verification'),null);assert.match(ui.elements.get('notice').textContent,/startup verified/i);assert.match(ui.elements.get('notice').textContent,/public identity matches/i);
});

test('native USB migration waits for browser port permission and resumes both remaining steps after selection',async()=>{
  const ui=await migrationWorkbench({uart:false});await ui.elements.get('prepare').onclick();await ui.elements.get('flash').onclick();
  assert.equal(ui.evaluate('state.migrationApproval.phase'),'waiting-rom');assert.equal(ui.evaluate('state.port'),null);assert.deepEqual(ui.calls.filter(call=>call.startsWith('write:')),['write:bridge']);assert.ok(!ui.calls.includes('chooser'));
  for(const id of ['prepare','flash','finish','transport-mode','hardware','restore','send-command'])assert.equal(ui.elements.get(id).disabled,true,id);
  assert.equal(ui.elements.get('select-port').disabled,false);assert.equal(ui.elements.get('stop-migration-auto').hidden,false);
  const selected={getInfo:ui.port.getInfo};ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');return selected;};
  const before=ui.calls.length;await ui.elements.get('select-port').onclick();assert.equal(ui.calls[before],'chooser');
  assert.deepEqual(ui.calls.filter(call=>/^(write|finish):/.test(call)),['write:bridge','finish:bridge','write:final','finish:final']);assert.equal(ui.evaluate('state.migrationApproval.phase'),'waiting-application');assert.ok(ui.evaluate('state.verification'));assert.deepEqual(ui.prompts.map(prompt=>prompt.token),['EXPAND AND FLASH']);
  await ui.elements.get('select-port').onclick();assert.equal(ui.evaluate('state.migrationApproval'),null);assert.equal(ui.evaluate('state.verification'),null);assert.match(ui.elements.get('notice').textContent,/startup verified/i);assert.deepEqual(ui.prompts.map(prompt=>prompt.token),['EXPAND AND FLASH']);assert.equal(ui.calls.filter(call=>call==='backup-considered').length,1);
});

test('only the same already granted USB object can automatically resume an approved migration',async()=>{
  const ui=await migrationWorkbench({uart:false});await ui.elements.get('prepare').onclick();await ui.elements.get('flash').onclick();
  ui.serialEvents.connect({port:{getInfo:ui.port.getInfo}});await new Promise(resolve=>setImmediate(resolve));assert.deepEqual(ui.calls.filter(call=>call.startsWith('write:')),['write:bridge']);
  ui.serialEvents.connect({port:ui.port});await new Promise(resolve=>setImmediate(resolve));assert.deepEqual(ui.calls.filter(call=>call.startsWith('write:')),['write:bridge','write:final']);assert.equal(ui.evaluate('state.migrationApproval.phase'),'waiting-application');
  ui.serialEvents.connect({port:ui.port});await new Promise(resolve=>setImmediate(resolve));assert.equal(ui.evaluate('state.migrationApproval'),null);assert.equal(ui.evaluate('state.verification'),null);assert.ok(!ui.calls.includes('chooser'));assert.deepEqual(ui.prompts.map(prompt=>prompt.token),['EXPAND AND FLASH']);
});

test('cancelling the single expansion acknowledgement leaves both bridge and final unwritten',async()=>{
  const ui=await migrationWorkbench({accepted:false});await ui.elements.get('prepare').onclick();await ui.elements.get('flash').onclick();
  assert.deepEqual(ui.prompts.map(prompt=>prompt.token),['EXPAND AND FLASH']);assert.deepEqual(ui.calls.filter(call=>/^(write|finish):/.test(call)),[]);assert.equal(ui.evaluate('state.migrationApproval'),null);assert.equal(ui.evaluate('state.migration'),null);assert.ok(ui.evaluate('state.plan'));assert.equal(ui.evaluate("localStorage.getItem('meshfirmware.pendingMigration')"),undefined);
});

test('automatic final writes stop on changed chip, image, restoration or migration provenance',async()=>{
  for(const [name,patch]of [
    ['mac',{mac:'00:11:22:33:44:55'}],
    ['firmware hash',{finalPlan:{sha256:'a'.repeat(64)}}],
    ['payload hash',{finalPlan:{payloadHash:'a'.repeat(64)}}],
    ['restored identity',{finalPlan:{identity_restored:false}}],
    ['restored configuration',{finalPlan:{configuration_restored:false}}],
    ['bridge hash',{finalPlan:{completed_bridge_sha256:'a'.repeat(64)}}],
    ['source table hash',{finalPlan:{completed_source_table_sha256:'a'.repeat(64)}}],
    ['target table hash',{finalPlan:{completed_target_table_sha256:'a'.repeat(64)}}],
    ['bridge write geometry',{finalPlan:{completed_bridge_segments:[]}}],
    ['target firmware profile',{finalPlan:{target:'different_board_repeater'}}],
    ['final write geometry',{finalPlan:{addresses:[0x660000,0x10000],app_offsets:[0x660000,0x10000]}}],
    ['unverified completion',{finalPlan:{verified:false}}],
    ['unapproved revision override',{finalPlan:{requiresRevisionOverride:true}}],
    ['unapproved interrupted recovery',{finalPlan:{chunkedRecovery:true}}]
  ]){
    const ui=await migrationWorkbench();await ui.elements.get('prepare').onclick();Object.assign(ui.faults,patch);await ui.elements.get('flash').onclick();
    assert.deepEqual(ui.calls.filter(call=>/^(write|finish):/.test(call)),['write:bridge','finish:bridge'],name);assert.equal(ui.evaluate('state.migrationApproval'),null,name);assert.ok(ui.evaluate('state.migration'),name);assert.ok(ui.evaluate("localStorage.getItem('meshfirmware.pendingMigration')"),name);assert.deepEqual(ui.prompts.map(prompt=>prompt.token),['EXPAND AND FLASH'],name);assert.match(ui.elements.get('log').textContent,/revoked|Stopped:/i,name);
  }
});

test('stopping during a physical bridge write finishes that write without sending the next reset',async()=>{
  const ui=await migrationWorkbench();await ui.elements.get('prepare').onclick();let approval;
  ui.faults.duringWrite=async stage=>{assert.equal(stage,'bridge');approval=ui.evaluate('state.migrationApproval');assert.equal(approval.phase,'bridge-writing');assert.equal(ui.elements.get('flash-progress-dialog').open,true);assert.equal(ui.elements.get('flash-stop-auto').hidden,false);assert.equal(ui.elements.get('flash-stop-auto').disabled,false);ui.elements.get('flash-stop-auto').onclick();assert.equal(ui.elements.get('flash-progress-dialog').open,true);assert.ok(ui.evaluate('state.flashProgress'));assert.equal(ui.elements.get('flash-stop-auto').hidden,true);};
  await ui.elements.get('flash').onclick();assert.equal(approval.phase,'revoked');assert.equal(ui.evaluate('state.migrationApproval'),null);assert.equal(ui.evaluate('state.migration.phase'),'written');assert.equal(ui.evaluate('state.plan.written'),true);assert.deepEqual(ui.calls.filter(call=>/^(write|finish):/.test(call)),['write:bridge']);assert.match(ui.elements.get('notice').textContent,/stopped|no next reset/i);
});

test('automatic migration closes only the intermediate bridge window and leaves final DONE open without another click',async()=>{
  const ui=await migrationWorkbench();await ui.elements.get('prepare').onclick();const dialog=ui.elements.get('flash-progress-dialog');let opened=0,closed=0;
  dialog.showModal=()=>{assert.ok(!dialog.open,'The previous write window must already be closed');dialog.open=true;opened++;};dialog.close=()=>{assert.equal(dialog.open,true);assert.equal(ui.elements.get('flash-progress-percent').textContent,'100%');dialog.open=false;closed++;};
  ui.faults.duringWrite=async()=>{assert.equal(dialog.open,true);ui.evaluate("progress(.5,'Writing + verifying bridge or application');");assert.equal(ui.elements.get('flash-progress-percent').textContent,'50%');};ui.faults.duringFinish=async stage=>{assert.equal(ui.evaluate('state.flashProgress'),null,'Reset is outside the active write');assert.equal(dialog.open,stage==='final');if(stage==='final')assert.equal(ui.elements.get('flash-progress-title').textContent,'DONE');};
  await ui.elements.get('flash').onclick();assert.equal(opened,2);assert.equal(closed,1);assert.equal(dialog.open,true);assert.equal(ui.evaluate('state.flashProgress'),null);assert.equal(ui.evaluate('state.migrationApproval'),null);assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.elements.get('flash-progress-title').textContent,'DONE');ui.elements.get('flash-progress-close').onclick();assert.equal(closed,2);assert.equal(dialog.open,false);
});

test('migration errors retain recovery markers and never retry a write or reset automatically',async()=>{
  for(const failure of ['write','finish','wait']){
    const ui=await migrationWorkbench();await ui.elements.get('prepare').onclick();ui.faults[failure]=new Error(failure+' failed');await ui.elements.get('flash').onclick();
    assert.equal(ui.evaluate('state.migrationApproval'),null,failure);assert.ok(ui.evaluate('state.migration'),failure);assert.ok(ui.evaluate("localStorage.getItem('meshfirmware.pendingMigration')"),failure);assert.equal(ui.calls.filter(call=>call==='write:bridge').length,1,failure);assert.ok(!ui.calls.includes('write:final'),failure);assert.ok(ui.calls.filter(call=>call==='finish:bridge').length<=1,failure);assert.ok(!ui.calls.includes('finish:final'),failure);assert.match(ui.elements.get('notice').textContent,/failed/i,failure);
  }
});

test('automatic startup without a prior public key is explicit about its limited identity proof',async()=>{
  const ui=await migrationWorkbench({publicKey:null});await ui.elements.get('prepare').onclick();await ui.elements.get('flash').onclick();
  assert.deepEqual(ui.prompts.map(prompt=>prompt.token),['EXPAND AND FLASH']);assert.match(ui.prompts[0].warning,/identity cannot be independently proven/i);assert.equal(ui.evaluate('state.migrationApproval'),null);assert.equal(ui.evaluate('state.verification'),null);assert.match(ui.elements.get('notice').textContent,/startup verified/i);assert.match(ui.elements.get('notice').textContent,/identity could not be independently verified/i);assert.doesNotMatch(ui.elements.get('notice').textContent,/public identity matches/i);
});

test('a responding application with the wrong identity stops immediately without startup retries',async()=>{
  const ui=await migrationWorkbench();await ui.elements.get('prepare').onclick();ui.faults.device={...ui.device,publicKey:'22'.repeat(32)};await ui.elements.get('flash').onclick();
  assert.equal(ui.evaluate('state.migrationApproval'),null);assert.ok(ui.evaluate('state.verification'));assert.equal(ui.calls.filter(call=>call==='application-open').length,1);assert.equal(ui.calls.filter(call=>call==='detect-application').length,1);assert.match(ui.elements.get('notice').textContent,/identity differs/i);assert.deepEqual(ui.calls.filter(call=>/^(write|finish):/.test(call)),['write:bridge','finish:bridge','write:final','finish:final']);
});

test('queued same-object reconnects cannot reenter active writes or duplicate either reset',async()=>{
  const ui=await migrationWorkbench({uart:false});await ui.elements.get('prepare').onclick();
  ui.faults.duringWrite=async()=>{await ui.elements.get('flash').onclick();await ui.elements.get('prepare').onclick();await ui.elements.get('select-port').onclick();};
  ui.faults.duringFinish=async()=>{ui.serialEvents.disconnect({port:ui.port});ui.serialEvents.connect({port:ui.port});ui.serialEvents.connect({port:ui.port});};
  await ui.elements.get('flash').onclick();await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(ui.calls.filter(call=>/^(write|finish):/.test(call)),['write:bridge','finish:bridge','write:final','finish:final']);assert.equal(ui.evaluate('state.migrationApproval'),null);assert.equal(ui.evaluate('state.verification'),null);assert.ok(!ui.calls.includes('chooser'));assert.deepEqual(ui.prompts.map(prompt=>prompt.token),['EXPAND AND FLASH']);
});

test('an unexpected disconnect during a write revokes future automation without a reset retry',async()=>{
  const ui=await migrationWorkbench();await ui.elements.get('prepare').onclick();ui.faults.duringWrite=async()=>ui.serialEvents.disconnect({port:ui.port});await ui.elements.get('flash').onclick();
  assert.deepEqual(ui.calls.filter(call=>/^(write|finish):/.test(call)),['write:bridge']);assert.equal(ui.evaluate('state.migrationApproval'),null);assert.ok(ui.evaluate('state.migration'));assert.ok(ui.evaluate("localStorage.getItem('meshfirmware.pendingMigration')"));assert.equal(ui.evaluate('state.port'),null);assert.match(ui.elements.get('notice').textContent,/No verified write|disconnect|changed/i);
});

test('closing a migration session retains scope but replacing firmware revokes it without device commands',async()=>{
  const ui=await migrationWorkbench({uart:false});await ui.elements.get('prepare').onclick();await ui.elements.get('flash').onclick();const approval=ui.evaluate('state.migrationApproval');
  const before=ui.calls.length;await ui.evaluate('closeEsp()');assert.equal(ui.evaluate('state.migrationApproval'),approval);assert.equal(approval.phase,'waiting-rom');ui.evaluate('invalidateFirmwareSelection();');assert.equal(approval.phase,'revoked');assert.equal(ui.evaluate('state.migrationApproval'),null);assert.ok(ui.evaluate('state.migration'));assert.deepEqual(ui.calls.slice(before),[]);
});

test('automatic migration retains required storage proof when firmware explicitly lacks the capability',async()=>{
  const ui=await migrationWorkbench();ui.faults.layout='Unknown command';await ui.elements.get('prepare').onclick();await ui.elements.get('flash').onclick();
  assert.equal(ui.calls.filter(call=>call==='application-open').length,1);assert.equal(ui.evaluate('state.migrationApproval'),null);assert.equal(ui.evaluate('state.migration'),null);assert.equal(ui.evaluate('state.verification.requiresStorageLayout'),true);assert.equal(JSON.parse(ui.context.localStorage.getItem('meshfirmware.verifyApplication')).requiresStorageLayout,true);assert.equal(ui.evaluate('state.finishedFirmware'),null);assert.match(ui.elements.get('notice').textContent,/storage-layout verification is unavailable or invalid/);
});

test('manual final migration captures layout requirements before clearing its migration marker',async()=>{
  const ui=await migrationWorkbench();ui.evaluate('continueApprovedMigration=async()=>{};');await ui.elements.get('prepare').onclick();await ui.elements.get('flash').onclick();ui.elements.get('stop-migration-auto').onclick();
  assert.ok(ui.evaluate('state.migration'));assert.equal(ui.evaluate('state.migrationApproval'),null);ui.elements.get('already-bootloader').checked=true;ui.elements.get('transport-mode').value='no_reset';await ui.elements.get('prepare').onclick();assert.ok(ui.evaluate('state.plan'),ui.elements.get('notice').textContent);assert.equal(ui.evaluate('state.plan.verified'),true);await ui.elements.get('flash').onclick();
  assert.equal(ui.evaluate('state.migration'),null);assert.equal(ui.evaluate('state.verification.requiresStorageLayout'),true);assert.equal(JSON.parse(ui.context.localStorage.getItem('meshfirmware.verifyApplication')).requiresStorageLayout,true);
  await ui.elements.get('finish').onclick();ui.faults.layout='Unknown command';await ui.elements.get('verify-app').onclick();assert.equal(ui.evaluate('state.verification.requiresStorageLayout'),true);assert.equal(ui.evaluate('state.finishedFirmware'),null);assert.match(ui.elements.get('notice').textContent,/storage-layout verification is unavailable or invalid/);
});

test('read-only startup readiness can retry, but permission failures and failed proofs never do',async()=>{
  {
    const ui=await migrationWorkbench();let attempts=0;ui.faults.applicationOpen=()=>++attempts===1?new Error('No response while application starts'):null;
    ui.evaluate('const originalStartupCheck=verifyApprovedStartup;verifyApprovedStartup=approval=>originalStartupCheck(approval,{timeoutMs:1000,retryMs:0});');await ui.elements.get('prepare').onclick();await ui.elements.get('flash').onclick();
    assert.equal(attempts,2);assert.equal(ui.evaluate('state.migrationApproval'),null);assert.equal(ui.evaluate('state.verification'),null);assert.match(ui.elements.get('notice').textContent,/startup verified/i);assert.deepEqual(ui.calls.filter(call=>/^(write|finish):/.test(call)),['write:bridge','finish:bridge','write:final','finish:final']);
  }
  for(const failure of ['permission','layout','model','role','version','timeout']){
    const ui=await migrationWorkbench();
    if(failure==='permission')ui.faults.applicationOpen=Object.assign(new Error('Access is denied'),{name:'NotAllowedError'});
    if(failure==='timeout'){ui.faults.applicationOpen=new Error('No response');ui.evaluate('const originalStartupCheck=verifyApprovedStartup;verifyApprovedStartup=approval=>originalStartupCheck(approval,{timeoutMs:0,retryMs:0});');}
    if(failure==='layout')ui.faults.layout='layout unavailable';
    if(failure==='model')ui.faults.device={...ui.device,model:'Different board'};
    if(failure==='role')ui.faults.device={...ui.device,role:'companion'};
    if(failure==='version'){ui.context.endfIdentity=()=>({versionText:'v1.18.0'});ui.faults.version='MeshCore v1.17.0';}
    await ui.elements.get('prepare').onclick();await ui.elements.get('flash').onclick();assert.equal(ui.calls.filter(call=>call==='application-open').length,1,failure);assert.equal(ui.evaluate('state.migrationApproval'),null,failure);assert.ok(ui.evaluate('state.verification'),failure);assert.deepEqual(ui.calls.filter(call=>/^(write|finish):/.test(call)),['write:bridge','finish:bridge','write:final','finish:final'],failure);
  }
});

test('a newly selected UART object is never reset before its matching MAC is checked',async()=>{
  for(const sameMac of [true,false]){
    const ui=await migrationWorkbench();await ui.elements.get('prepare').onclick();
    // Pause exactly where a disconnect/new browser interface needs step 1;
    // the actual first bridge write, readback, reset and settled read still run.
    ui.evaluate('const originalMigrationContinuation=continueApprovedMigration;continueApprovedMigration=async()=>{};');await ui.elements.get('flash').onclick();
    assert.equal(ui.evaluate('state.migrationApproval.phase'),'waiting-rom');assert.equal(ui.evaluate('state.migration.settled'),true);assert.equal(ui.evaluate('state.approvalResetPort'),ui.port);
    ui.evaluate('continueApprovedMigration=originalMigrationContinuation;state.port=null;state.generation++;');
    const newPort={getInfo:ui.port.getInfo};ui.context.navigator.serial.requestPort=async()=>{ui.calls.push('chooser');return newPort;};if(!sameMac)ui.faults.mac='00:11:22:33:44:55';
    const before=ui.calls.length;await ui.elements.get('select-port').onclick();assert.equal(ui.calls[before],'chooser');assert.ok(ui.calls.slice(before).includes('connect:no_reset'));assert.ok(!ui.calls.slice(before).includes('connect:default_reset'));
    if(sameMac){assert.deepEqual(ui.calls.filter(call=>/^(write|finish):/.test(call)),['write:bridge','finish:bridge','write:final','finish:final']);assert.equal(ui.evaluate('state.verification'),null);assert.match(ui.elements.get('notice').textContent,/startup verified/i);}
    else{assert.deepEqual(ui.calls.filter(call=>/^(write|finish):/.test(call)),['write:bridge','finish:bridge']);assert.ok(ui.evaluate('state.migration'));assert.match(ui.elements.get('notice').textContent,/same physical chip|different|pending/i);}
    assert.equal(ui.evaluate('state.migrationApproval'),null);assert.deepEqual(ui.prompts.map(prompt=>prompt.token),['EXPAND AND FLASH']);
  }
});

test('S3 behind an external UART adapter waits for automatic ROM return without needing a reconnect event',async()=>{
  const ui=await migrationWorkbench({uart:false,externalUart:true});assert.equal(ui.bridgePlan.chip,9);assert.equal(ui.bridgePlan.uart_completion_status,false);assert.equal(ui.bridgePlan.automatic_rom_return,true);
  await ui.elements.get('prepare').onclick();await ui.elements.get('flash').onclick();
  assert.deepEqual(ui.calls.filter(call=>call.startsWith('connect:')),['connect:default_reset','connect:no_reset']);assert.deepEqual(ui.calls.filter(call=>/^(write|finish):/.test(call)),['write:bridge','finish:bridge','write:final','finish:final']);assert.ok(!ui.calls.includes('uart-settled'));assert.ok(!ui.calls.includes('chooser'));assert.equal(ui.evaluate('state.migrationApproval'),null);assert.equal(ui.evaluate('state.verification'),null);assert.match(ui.elements.get('notice').textContent,/startup verified/i);
});

test('only read-only no-reset ROM readiness can retry during automatic expansion',async()=>{
  {
    const ui=await migrationWorkbench({uart:false,externalUart:true});await ui.elements.get('prepare').onclick();let attempts=0;
    ui.faults.connect=stage=>stage==='final'&&++attempts===1?new Error('Timed out waiting for ROM sync'):null;
    ui.evaluate('const originalPrepareApprovedFinal=prepareApprovedFinal;prepareApprovedFinal=approval=>originalPrepareApprovedFinal(approval,{timeoutMs:1000,retryMs:0});');await ui.elements.get('flash').onclick();
    assert.equal(attempts,2);assert.deepEqual(ui.calls.filter(call=>call.startsWith('connect:')),['connect:default_reset','connect:no_reset','connect:no_reset']);assert.equal(ui.evaluate('state.migrationApproval'),null);assert.equal(ui.evaluate('state.verification'),null);assert.deepEqual(ui.calls.filter(call=>/^(write|finish):/.test(call)),['write:bridge','finish:bridge','write:final','finish:final']);
  }
  for(const failure of ['permission','security','wrong MAC','proof','classic-reset-timeout','ROM deadline']){
    const ui=await migrationWorkbench({uart:failure==='classic-reset-timeout',externalUart:true});await ui.elements.get('prepare').onclick();
    if(failure==='permission')ui.faults.connect=Object.assign(new Error('Access is denied'),{name:'NotAllowedError'});
    if(failure==='security')ui.faults.connect=new Error('Flash encryption security check refused');
    if(failure==='wrong MAC')ui.faults.mac='00:11:22:33:44:55';
    if(failure==='proof')ui.faults.finalPlan={completed_target_table_sha256:'a'.repeat(64)};
    if(failure==='classic-reset-timeout'||failure==='ROM deadline')ui.faults.connect=new Error('Timed out waiting for ROM sync');
    if(failure==='ROM deadline')ui.evaluate('const originalPrepareApprovedFinal=prepareApprovedFinal;prepareApprovedFinal=approval=>originalPrepareApprovedFinal(approval,{timeoutMs:0,retryMs:0});');
    const before=ui.calls.length;await ui.elements.get('flash').onclick();const connects=ui.calls.slice(before).filter(call=>call.startsWith('connect:'));
    assert.deepEqual(connects,[failure==='classic-reset-timeout'?'connect:default_reset':'connect:no_reset'],failure);assert.deepEqual(ui.calls.filter(call=>/^(write|finish):/.test(call)),['write:bridge','finish:bridge'],failure);assert.equal(ui.evaluate('state.migrationApproval'),null,failure);assert.ok(ui.evaluate('state.migration'),failure);assert.ok(ui.evaluate("localStorage.getItem('meshfirmware.pendingMigration')"),failure);
  }
});

test('known native USB reset transport can poll its granted ROM port without another prepare or flash press',async()=>{
  const ui=await migrationWorkbench({uart:false});ui.elements.get('transport-mode').value='usb_reset';await ui.elements.get('prepare').onclick();await ui.elements.get('flash').onclick();
  assert.deepEqual(ui.calls.filter(call=>call.startsWith('connect:')),['connect:usb_reset','connect:no_reset']);assert.deepEqual(ui.calls.filter(call=>/^(write|finish):/.test(call)),['write:bridge','finish:bridge','write:final','finish:final']);assert.equal(ui.evaluate('state.migrationApproval.phase'),'waiting-application');assert.ok(!ui.calls.includes('chooser'));
  ui.serialEvents.connect({port:ui.port});await new Promise(resolve=>setImmediate(resolve));assert.equal(ui.evaluate('state.migrationApproval'),null);assert.equal(ui.evaluate('state.verification'),null);assert.deepEqual(ui.prompts.map(prompt=>prompt.token),['EXPAND AND FLASH']);
});

test('a queued ROM-return event cannot be reused as application readiness after the migration phase changes',async()=>{
  const ui=await migrationWorkbench({uart:false});ui.elements.get('transport-mode').value='usb_reset';await ui.elements.get('prepare').onclick();
  ui.faults.duringFinish=async stage=>{if(stage==='bridge'){ui.serialEvents.connect({port:ui.port});assert.equal(ui.evaluate('state.approvalResumeRequested.phase'),'waiting-rom');}};
  await ui.elements.get('flash').onclick();await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(ui.calls.filter(call=>/^(write|finish):/.test(call)),['write:bridge','finish:bridge','write:final','finish:final']);assert.equal(ui.evaluate('state.migrationApproval.phase'),'waiting-application');assert.equal(ui.evaluate('state.approvalResumeRequested'),null);assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.calls.filter(call=>call==='application-open').length,0);assert.ok(ui.evaluate('state.verification'));
  ui.serialEvents.connect({port:ui.port});await new Promise(resolve=>setImmediate(resolve));assert.equal(ui.calls.filter(call=>call==='application-open').length,1);assert.equal(ui.evaluate('state.migrationApproval'),null);assert.equal(ui.evaluate('state.verification'),null);
});

test('stopping while the application link closes retains startup verification for a manual check',async()=>{
  const ui=await migrationWorkbench();await ui.elements.get('prepare').onclick();let approval,applicationCloses=0;
  ui.faults.duringSerialClose=async({application})=>{if(application){applicationCloses++;approval=ui.evaluate('state.migrationApproval');assert.equal(approval.phase,'waiting-application');ui.elements.get('stop-migration-auto').onclick();}};
  await ui.elements.get('flash').onclick();assert.equal(applicationCloses,1);assert.equal(approval.phase,'revoked');assert.equal(ui.evaluate('state.migrationApproval'),null);assert.ok(ui.evaluate('state.verification'));assert.ok(ui.evaluate("localStorage.getItem('meshfirmware.verifyApplication')"));assert.match(ui.elements.get('notice').textContent,/stopped/i);assert.doesNotMatch(ui.elements.get('notice').textContent,/startup verified/i);assert.deepEqual(ui.calls.filter(call=>/^(write|finish):/.test(call)),['write:bridge','finish:bridge','write:final','finish:final']);
});

async function boardWarningWorkbench(architecture='nrf52'){
  const ui=workbench();await Promise.resolve();ui.context.pkg=fakePackage({architecture});ui.context.selectedPort=ui.port;
  ui.elements.get('hardware').value='Heltec T114';
  ui.evaluate('state.pkg=pkg;state.port=selectedPort;state.plan={generation:state.generation,port:state.port,sha256:pkg.sha256,installMode:state.installMode,addresses:[0x10000]};');
  ui.context.assessFirmwareBoard=()=>({status:'mismatch',requiresOverride:true,reason:'Image targets T1000-E, not the selected T114.'});
  return ui;
}
test('main inspection shows mismatched and unverified board warnings without claiming a match',async()=>{
  const ui=await boardWarningWorkbench();ui.evaluate('updateFirmwareInspection();');
  assert.match(ui.elements.get('firmware-inspection-board').textContent,/Board mismatch:.*T1000-E.*acknowledging/);
  assert.equal(ui.elements.get('firmware-inspection').classList.contains('board-warning'),true);
  ui.context.assessFirmwareBoard=()=>({status:'unknown',requiresOverride:true,reason:'This file has no verified board identity.'});ui.evaluate('updateFirmwareInspection();');
  assert.match(ui.elements.get('firmware-inspection-board').textContent,/Board not verified:.*no verified board identity/);assert.deepEqual(ui.calls,[]);
});
test('board mismatches can be overridden on nRF52, ESP32 and UF2 but still need final write confirmation',async()=>{
  for(const architecture of ['nrf52','esp32','uf2']){
    const ui=await boardWarningWorkbench(architecture);
    ui.context.confirm=async(title,detail,warning,token)=>{ui.calls.push(token);if(token==='FLASH MISMATCHED BOARD'){assert.match(title,/mismatch/);assert.match(detail,/T1000-E.*T114/);assert.match(warning,/continue anyway.*SWD.*chip-family/s);return true;}assert.match(detail,/Board check:.*T1000-E/);return false;};
    await ui.evaluate('flashPreparedFirmware();');assert.deepEqual(ui.calls,['FLASH MISMATCHED BOARD','FLASH'],architecture);
  }
});
test('cancelling an unknown-board acknowledgement stops before any hardware operation',async()=>{
  const ui=await boardWarningWorkbench();ui.context.assessFirmwareBoard=()=>({status:'unknown',requiresOverride:true,reason:'No embedded board identity.'});
  ui.context.confirm=async(_title,_detail,_warning,token)=>{ui.calls.push(token);return false;};
  await assert.rejects(ui.evaluate('flashPreparedFirmware();'),/Board override cancelled/);assert.deepEqual(ui.calls,['FLASH UNVERIFIED BOARD']);
});
test('a board override is revoked if the radio, image, board or runtime evidence changes while warning is open',async()=>{
  for(const change of ['state.generation++','state.port={getInfo:()=>({})}','state.pkg={...state.pkg}','$("hardware").value="Other board"','state.device={model:"Changed"}','state.installMode="install"']){
    const ui=await boardWarningWorkbench();ui.context.confirm=async(_title,_detail,_warning,token)=>{ui.calls.push(token);ui.evaluate(change);return true;};
    await assert.rejects(ui.evaluate('flashPreparedFirmware();'),/changed during confirmation/,change);assert.deepEqual(ui.calls,['FLASH MISMATCHED BOARD']);
  }
});
test('board evidence is checked again after the final write dialog, not only after the mismatch warning',async()=>{
  const ui=await boardWarningWorkbench();ui.context.confirm=async(_title,_detail,_warning,token)=>{ui.calls.push(token);if(token==='FLASH')ui.evaluate('state.device={model:"Changed during final prompt"}');return true;};
  await assert.rejects(ui.evaluate('flashPreparedFirmware();'),/changed during confirmation/);assert.deepEqual(ui.calls,['FLASH MISMATCHED BOARD','FLASH']);
});
test('a UF2 board override cannot be carried to another mounted drive or edited drive identity',async()=>{
  for(const change of ['state.directory={name:"Different drive"}','state.plan.uf2Info="Board-ID: Changed"']){
    const ui=await boardWarningWorkbench('uf2');ui.evaluate('state.directory={name:"Original drive"};state.plan.uf2Info="Board-ID: Original";');
    ui.context.confirm=async(_title,_detail,_warning,token)=>{ui.calls.push(token);ui.evaluate(change);return true;};
    await assert.rejects(ui.evaluate('flashPreparedFirmware();'),/changed during confirmation/);assert.deepEqual(ui.calls,['FLASH MISMATCHED BOARD']);
  }
});
test('a generic-board match cannot waive the protected RAK board warning',async()=>{
  const ui=await boardWarningWorkbench();ui.context.assessFirmwareBoard=()=>({status:'match',requiresOverride:false,reason:'Generic board match.'});
  ui.context.assessBoard=()=>({requiresOverride:true,payloadFamily:'rak4631',deviceFamily:'rak3401',reason:'Protected RAK target conflicts.'});
  ui.context.confirm=async(_title,detail,_warning,token)=>{ui.calls.push(token);assert.match(detail,/Protected RAK target conflicts/);return false;};
  await assert.rejects(ui.evaluate('flashPreparedFirmware();'),/Board override cancelled/);assert.deepEqual(ui.calls,['FLASH MISMATCHED BOARD']);
});
test('a board-specific non-RAK erase ZIP also receives its own overridable board check',async()=>{
  const ui=await boardWarningWorkbench();ui.context.erase=fakePackage({name:'other-board-formatter.zip',erase:true,destructive:true});ui.evaluate('state.plan.erasePkg=erase;');
  ui.context.assessFirmwareBoard=({pkg})=>pkg===ui.context.erase?{status:'mismatch',requiresOverride:true,reason:'The formatter targets a different board.'}:{status:'match',requiresOverride:false,reason:'Final image matches.'};
  ui.context.confirm=async(_title,detail,_warning,token)=>{ui.calls.push(token);assert.match(detail,/formatter targets.*other-board-formatter/s);return false;};
  await assert.rejects(ui.evaluate('flashPreparedFirmware();'),/Board override cancelled/);assert.deepEqual(ui.calls,['FLASH MISMATCHED BOARD']);
});
test('real custom inspection wires the byte-level unknown-board assessment into the final flash warning',async()=>{
  const ui=await customEspWorkbench();ui.context.image=customEspImage();ui.context.selectedPort=ui.port;
  await ui.evaluate('loadFirmware("custom.bin",image);');ui.context.assessFirmwareBoard=assessFirmwareBoard;
  ui.evaluate('state.port=selectedPort;state.plan={generation:state.generation,port:state.port,sha256:state.pkg.sha256,installMode:state.installMode,addresses:[0x10000]};controls();');
  assert.match(ui.elements.get('firmware-inspection-board').textContent,/Board not verified:.*does not expose/);
  ui.context.confirm=async(_title,detail,_warning,token)=>{ui.calls.push(token);assert.match(detail,/filename.*do not prove/);return false;};
  await assert.rejects(ui.evaluate('flashPreparedFirmware();'),/Board override cancelled/);assert.deepEqual(ui.calls,['FLASH UNVERIFIED BOARD']);
});

const wadaItem=(merged=false)=>({...v4Item,provider:'Wadamesh TAK',role:'gui',version:'tak-beta_103.1',action:merged?'flash-wipe':'flash-update',name:`wadamesh-heltec-v4${merged?'-merged':''}.bin`,url:`https://github.com/jade-on-mesh/wadamesh-tak/releases/download/tak-beta_103.1/wadamesh-heltec-v4${merged?'-merged':''}.bin`,requiredDisplay:'tft',wadameshBuild:'heltec-v4',title:'Wadamesh TAK · standalone',size:merged?5000000:4934464,...(!merged?{requiresExistingProvider:'Wadamesh TAK'}:{})});
const takDefaultItems=(hardware='LilyGo T-Deck')=>[
  {...v4Item,provider:'Keymind Cascade',hardware,role:'companionFull',...(hardware==='Heltec v4'?{releaseNotes:'SETUP - https://mikecarper.github.io/MeshCore/firmware_picker/?hardware=heltec_v4'}:{})},
  {...v4Item,provider:'Keymind Cascade',hardware,role:'companionFull',action:'flash-wipe',name:'keymind-board-merged.bin'},
  ...[false,true].map(merged=>({...wadaItem(merged),hardware,requiredDisplay:hardware.startsWith('Heltec v4')?'tft':undefined}))
];
test('detected supported hardware defaults to Wadamesh merged install instead of preserving the old MeshCore role',async()=>{
  const ui=workbench({productionDefaults:true,catalogPromise:Promise.resolve(linkedCatalog(takDefaultItems()))});await new Promise(resolve=>setImmediate(resolve));
  assert.equal(ui.elements.get('provider').value,'Keymind Cascade');assert.equal(ui.evaluate('state.manualSelections.provider'),undefined);
  ui.evaluate('state.device={model:"LilyGo T-Deck",catalogRole:"repeater",version:"v1.18.0"};selectDetectedBoard();');
  assert.equal(ui.elements.get('provider').value,'Wadamesh TAK');assert.equal(ui.elements.get('role').value,'gui');assert.equal(ui.elements.get('artifact').value,'3');assert.equal(ui.evaluate('state.installMode'),'install');assert.equal(ui.evaluate('installModeSource.kind'),'provider');
  assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(JSON.parse(ui.context.localStorage.getItem('meshfirmware.selections')).providerExplicit,false);assert.deepEqual(ui.calls,[]);
});
test('implicit provider hardware menu includes Wadamesh-only boards and switches provider even with automatic artifact selection off',async()=>{
  const hardware='Elecrow CrowPanel Advance 3.5',items=[...takDefaultItems().slice(0,2),...takDefaultItems(hardware).slice(2)],ui=workbench({catalogPromise:Promise.resolve(linkedCatalog(items))});await new Promise(resolve=>setImmediate(resolve));
  assert.ok(ui.elements.get('hardware').options.some(option=>option.value===hardware));
  ui.elements.get('hardware').value=hardware;await ui.elements.get('hardware').onchange();
  assert.equal(ui.elements.get('provider').value,'Wadamesh TAK');assert.equal(ui.elements.get('hardware').value,hardware);assert.equal(ui.evaluate('state.installMode'),'install');assert.deepEqual(artifactChoices(ui),['3']);assert.equal(ui.elements.get('artifact').value,'');assert.deepEqual(ui.calls,[]);
});
test('a newly detected ESP32 board refreshes a prior nRF52 provider scope before selecting Wadamesh install',async()=>{
  const items=[linkedT114Item,...takDefaultItems()],ui=workbench({catalogPromise:Promise.resolve(linkedCatalog(items))});await new Promise(resolve=>setImmediate(resolve));ui.context.selectedPort=ui.port;
  ui.evaluate('state.port=selectedPort;state.device={architecture:"nrf52"};filterCatalog();');assert.ok(!ui.elements.get('provider').options.some(option=>option.value==='Wadamesh TAK'));
  ui.evaluate('state.device={architecture:"esp32",model:"LilyGo T-Deck",catalogRole:"companionFull"};selectDetectedBoard();');
  assert.equal(ui.elements.get('provider').value,'Wadamesh TAK');assert.equal(ui.evaluate('state.installMode'),'install');assert.equal(ui.evaluate('state.manualSelections.provider'),undefined);assert.deepEqual(artifactChoices(ui),['4']);assert.deepEqual(ui.calls,[]);
});
test('V4 automatic provider exception permits only a positively reported R8 TFT',async()=>{
  for(const [model,hardware,wada] of [
    ['Heltec V4 OLED','Heltec v4',false],['Heltec v4','Heltec v4',false],
    ['Heltec v4 R8','Heltec v4 R8',false],['Heltec V4.3 R8 OLED','Heltec v4 R8',false],
    ['Heltec V4.3 R8 TFT','Heltec v4 R8',true]
  ]){
    const ui=workbench({productionDefaults:true,catalogPromise:Promise.resolve(linkedCatalog(takDefaultItems(hardware)))});await new Promise(resolve=>setImmediate(resolve));
    ui.context.model=model;ui.evaluate('state.device={model,catalogRole:"companionFull"};selectDetectedBoard();');
    assert.equal(ui.elements.get('provider').value,wada?'Wadamesh TAK':'Keymind Cascade',model);assert.equal(ui.evaluate('state.installMode'),wada?'install':'update',model);assert.equal(ui.elements.get('artifact').value,wada?'3':'0',model);assert.deepEqual(ui.calls,[]);
  }
});
test('explicit Keymind choices and shared provider/update links override the automatic Wadamesh preference',async()=>{
  for(const kind of ['manual','saved','link']){
    const options=kind==='saved'?{savedSelections:{provider:'Keymind Cascade',providerExplicit:true}}:kind==='link'?{search:'?provider=Keymind+Cascade&mode=update'}:{};
    const ui=workbench({...options,productionDefaults:true,catalogPromise:Promise.resolve(linkedCatalog(takDefaultItems()))});await new Promise(resolve=>setImmediate(resolve));
    if(kind==='manual'){ui.elements.get('provider').value='Keymind Cascade';await ui.elements.get('provider').onchange();}
    ui.evaluate('state.device={model:"LilyGo T-Deck",catalogRole:"companionFull"};selectDetectedBoard();');
    assert.equal(ui.elements.get('provider').value,'Keymind Cascade',kind);assert.equal(ui.elements.get('artifact').value,'0',kind);assert.equal(ui.evaluate('state.installMode'),'update',kind);assert.equal(JSON.parse(ui.context.localStorage.getItem('meshfirmware.selections')).providerExplicit,true);assert.deepEqual(ui.calls,[]);
  }
});
test('an explicitly saved Keymind version is preserved when Wadamesh also supports that board',async()=>{
  const items=takDefaultItems(),item=items[0],savedSelections={provider:item.provider,providerExplicit:false,hardware:item.hardware,role:item.role,version:item.version,versionExplicit:true};
  const ui=workbench({productionDefaults:true,savedSelections,catalogPromise:Promise.resolve(linkedCatalog(items))});await new Promise(resolve=>setImmediate(resolve));
  ui.evaluate('state.device={model:"LilyGo T-Deck",catalogRole:"companionFull"};selectDetectedBoard();');
  assert.equal(ui.elements.get('provider').value,'Keymind Cascade');assert.equal(ui.elements.get('artifact').value,'0');assert.equal(ui.elements.get('version').value,item.version);assert.equal(ui.evaluate('state.installMode'),'update');
  const saved=JSON.parse(ui.context.localStorage.getItem('meshfirmware.selections'));assert.equal(saved.versionExplicit,true);assert.equal(saved.providerExplicit,false);assert.deepEqual(ui.calls,[]);
});
test('an explicit older Wadamesh version survives the temporary Keymind default until R8 TFT is detected',async()=>{
  const items=takDefaultItems('Heltec v4 R8'),old={...items[3],version:'tak-beta_103.0',name:'wadamesh-old-merged.bin',url:'https://example.test/wadamesh-old-merged.bin'};
  const savedSelections={provider:old.provider,providerExplicit:false,hardware:old.hardware,role:old.role,version:old.version,versionExplicit:true};
  const ui=workbench({productionDefaults:true,savedSelections,catalogPromise:Promise.resolve(linkedCatalog([...items,old]))});await new Promise(resolve=>setImmediate(resolve));
  assert.equal(ui.elements.get('provider').value,'Keymind Cascade');assert.equal(ui.evaluate('state.manualSelections.version'),old.version);assert.equal(ui.elements.get('artifact').value,'');
  ui.evaluate('state.device={model:"Heltec V4.3 R8 TFT",catalogRole:"companionFull"};selectDetectedBoard();');
  assert.equal(ui.elements.get('provider').value,'Wadamesh TAK');assert.equal(ui.elements.get('artifact').value,'4');assert.equal(ui.elements.get('version').value,old.version);assert.equal(ui.evaluate('state.installMode'),'install');assert.deepEqual(ui.calls,[]);
});
test('remembered defaults do not become explicit provider choices on the next load',async()=>{
  for(const provider of ['Keymind Cascade','Wadamesh TAK']){
    const ui=workbench({savedSelections:{provider,providerExplicit:false,hardware:'LilyGo T-Deck'},catalogPromise:Promise.resolve(linkedCatalog(takDefaultItems()))});await new Promise(resolve=>setImmediate(resolve));
    assert.equal(ui.elements.get('provider').value,'Wadamesh TAK');assert.equal(ui.evaluate('state.installMode'),'install');assert.equal(ui.evaluate('state.manualSelections.provider'),undefined);assert.equal(JSON.parse(ui.context.localStorage.getItem('meshfirmware.selections')).providerExplicit,false);assert.deepEqual(ui.calls,[]);
  }
});
test('unavailable explicit providers never turn into an automatic Wadamesh installation',async()=>{
  for(const options of [{savedSelections:{provider:'MeshCore',providerExplicit:true,hardware:'LilyGo T-Deck'}},{search:'?provider=MeshCore&hardware=LilyGo+T-Deck'}]){
    const ui=workbench({...options,productionDefaults:true,catalogPromise:Promise.resolve(linkedCatalog(takDefaultItems()))});await new Promise(resolve=>setImmediate(resolve));
    ui.evaluate('applyAutomaticSelections();');assert.equal(ui.evaluate('state.manualSelections.provider'),'MeshCore');assert.equal(ui.elements.get('provider').value,'');assert.equal(ui.elements.get('artifact').value,'');assert.equal(ui.evaluate('state.installMode'),'update');assert.match(ui.elements.get('automatic-summary').textContent,/No write-only/);assert.deepEqual(ui.calls,[]);
  }
});
test('unfinished device workflows retain their saved firmware instead of adopting a new provider default',async()=>{
  for(const flow of [{pending:{mac:'aa:bb:cc:dd:ee:ff',sha256:'a'.repeat(64)}},{recovery:{sha256:'a'.repeat(64),name:'final.zip',eraseComplete:true}},{espRecovery:{sha256:'a'.repeat(64),mac:'aa:bb:cc:dd:ee:ff',merged:true}},{verification:{sha256:'a'.repeat(64),name:'final.bin'}}]){
    const items=takDefaultItems(),ui=workbench({...flow,savedSelections:{...items[0],providerExplicit:false},catalogPromise:Promise.resolve(linkedCatalog(items))});
    const mode=ui.evaluate('state.installMode');await new Promise(resolve=>setImmediate(resolve));
    assert.equal(ui.evaluate('continuingDeviceFlow()'),true);assert.equal(ui.evaluate('state.installMode'),mode);
    for(const id of ['provider','hardware','role','version'])assert.equal(ui.elements.get(id).value,items[0][id],id);
    assert.equal(ui.evaluate('state.migrationApproval'),null);assert.deepEqual(ui.calls,[]);
  }
});
test('switching away from automatic Wadamesh resets only its default erase mode, not a deliberate installation choice',async()=>{
  for(const explicitMode of [false,true]){
    const ui=workbench({productionDefaults:true,catalogPromise:Promise.resolve(linkedCatalog(takDefaultItems()))});await new Promise(resolve=>setImmediate(resolve));
    ui.evaluate('state.device={model:"LilyGo T-Deck",catalogRole:"companionFull"};selectDetectedBoard();');assert.equal(ui.evaluate('state.installMode'),'install');
    if(explicitMode)await ui.evaluate('setInstallMode("install");');
    ui.elements.get('provider').value='Keymind Cascade';await ui.elements.get('provider').onchange();
    assert.equal(ui.evaluate('state.installMode'),explicitMode?'install':'update');assert.equal(ui.elements.get('artifact').value,explicitMode?'1':'0');assert.deepEqual(ui.calls,[]);
  }
});
test('legacy automatic Keymind preference follows the board and explicit Update remains authoritative',async()=>{
  const ui=workbench({productionDefaults:true,savedSelections:{provider:'Keymind Cascade',hardware:'LilyGo T-Deck'},search:'?hardware=LilyGo+T-Deck&mode=update',catalogPromise:Promise.resolve(linkedCatalog(takDefaultItems()))});await new Promise(resolve=>setImmediate(resolve));
  ui.evaluate('applyAutomaticSelections();');assert.equal(ui.elements.get('provider').value,'Wadamesh TAK');assert.equal(ui.evaluate('state.installMode'),'update');assert.equal(ui.elements.get('artifact').value,'2');assert.equal(ui.evaluate('state.manualSelections.provider'),undefined);assert.deepEqual(ui.calls,[]);
});
test('partial selection links resolve their exact build provider before applying the automatic default',async()=>{
  for(const index of [0,3]){
    const items=takDefaultItems(),item=items[index],search='?'+new URLSearchParams({hardware:item.hardware,role:item.role,version:item.version,build:item.name,mode:index===3?'install':'update'});
    const ui=workbench({search,catalogPromise:Promise.resolve(linkedCatalog(items))});await new Promise(resolve=>setImmediate(resolve));
    assert.equal(ui.elements.get('provider').value,item.provider);assert.equal(ui.elements.get('artifact').value,String(index));assert.equal(ui.evaluate('state.manualSelections.provider'),item.provider);assert.deepEqual(ui.calls,[]);
  }
});
test('partial role/version links apply compatible Wadamesh filters before choosing the build',async()=>{
  const items=takDefaultItems(),item=items[3],search='?'+new URLSearchParams({hardware:item.hardware,role:item.role,version:item.version});
  const ui=workbench({search,catalogPromise:Promise.resolve(linkedCatalog(items))});await new Promise(resolve=>setImmediate(resolve));
  assert.equal(ui.elements.get('provider').value,'Wadamesh TAK');assert.equal(ui.elements.get('role').value,'gui');assert.equal(ui.elements.get('version').value,item.version);assert.equal(ui.evaluate('state.installMode'),'install');assert.deepEqual(artifactChoices(ui),['3']);assert.equal(ui.evaluate('state.manualSelections.provider'),undefined);assert.deepEqual(ui.calls,[]);
});
test('a new non-Wadamesh radio resets an implicit Wadamesh install default instead of inheriting an erase',async()=>{
  const items=[...takDefaultItems(),{...v4Item,provider:'Keymind Cascade',role:'companionFull',releaseNotes:'SETUP - https://mikecarper.github.io/MeshCore/firmware_picker/?hardware=heltec_v4'}],ui=workbench({productionDefaults:true,catalogPromise:Promise.resolve(linkedCatalog(items))});await new Promise(resolve=>setImmediate(resolve));serialMock(ui);
  ui.context.previousPort={getInfo:()=>({usbVendorId:0x303a,usbProductId:0x0002})};
  ui.evaluate('state.port=previousPort;state.device={model:"LilyGo T-Deck",catalogRole:"companionFull"};selectDetectedBoard();');
  assert.equal(ui.evaluate('state.installMode'),'install');ui.context.detectMeshCore=async()=>({model:'Heltec V4 OLED',catalogRole:'companionFull'});await ui.elements.get('select-port').onclick();
  assert.equal(ui.elements.get('provider').value,'Keymind Cascade');assert.equal(ui.evaluate('state.installMode'),'update');assert.notEqual(ui.evaluate('installModeSource?.kind'),'manual');assert.equal(ui.elements.get('artifact').value,'4');assert.deepEqual(ui.calls,['chooser','open','close']);
});
test('selecting Wadamesh defaults to merged installation and displays its limits without loading firmware or touching USB',async()=>{
  const ui=workbench({catalogPromise:Promise.resolve(linkedCatalog([v4Item,{...v4Item,provider:'Keymind Cascade'},wadaItem(),wadaItem(true)]))});await new Promise(resolve=>setImmediate(resolve));
  assert.equal(ui.elements.get('provider').value,'Keymind Cascade');ui.elements.get('provider').value='Wadamesh TAK';await ui.elements.get('provider').onchange();
  assert.equal(ui.evaluate('state.installMode'),'install');assert.equal(ui.elements.get('install-mode-install').checked,true);assert.equal(ui.elements.get('wadamesh-info').hidden,false);assert.equal(ui.elements.get('radio-defaults').hidden,true);
  assert.match(ui.elements.get('workflow-guidance').textContent,/No Keymind expansion or post-flash settings/);assert.match(ui.elements.get('install-mode-hint').textContent,/Wadamesh first install.*whole-chip erase/);
  assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,[]);
});
test('a saved Wadamesh provider defaults to first install while an explicit Update selection link is honored',async()=>{
  for(const linked of [false,true]){
    const ui=workbench({savedSelections:{provider:'Wadamesh TAK'},search:linked?'?provider=Wadamesh+TAK&mode=update':'',catalogPromise:Promise.resolve(linkedCatalog([wadaItem(),wadaItem(true)]))});await new Promise(resolve=>setImmediate(resolve));
    assert.equal(ui.elements.get('provider').value,'Wadamesh TAK');assert.equal(ui.evaluate('state.installMode'),linked?'update':'install');assert.deepEqual(ui.calls,[]);
  }
});
test('Wadamesh mode switching pairs only the exact same board/build despite differing size and app-only requirements',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.inventory=[wadaItem(),wadaItem(true),{...wadaItem(true),wadameshBuild:'heltec-v4-r8',hardware:'Heltec v4 R8'}];
  ui.evaluate('state.items=inventory;filterCatalog();$("provider").value="Wadamesh TAK";filterCatalog("provider");$("hardware").value=inventory[0].hardware;filterCatalog("hardware");$("role").value="gui";filterCatalog("role");$("artifact").value="0";');
  await ui.evaluate('setInstallMode("install");');assert.equal(ui.elements.get('artifact').value,'1');assert.deepEqual(ui.calls,[]);
});
test('Wadamesh manual OLED-to-TFT selection retains a clear overridable display warning',async()=>{
  const ui=await customEspWorkbench('install');ui.context.image=customEspImage({merged:true});ui.context.wada=wadaItem(true);ui.context.selectedPort=ui.port;
  await ui.evaluate('loadFirmware(wada.name,image,wada);');ui.evaluate('state.port=selectedPort;state.device={model:"Heltec V4.3 OLED"};state.plan={generation:state.generation,port:state.port,sha256:state.pkg.sha256,installMode:state.installMode,addresses:[0]};controls();');
  assert.match(ui.elements.get('firmware-inspection-board').textContent,/Board mismatch:.*requires a TFT.*OLED/);
  ui.context.confirm=async(_title,detail,_warning,token)=>{ui.calls.push(token);assert.match(detail,/requires a TFT.*OLED/);return false;};
  await assert.rejects(ui.evaluate('flashPreparedFirmware();'),/Board override cancelled/);assert.deepEqual(ui.calls,['FLASH MISMATCHED BOARD']);
});
test('a generic board match cannot claim the Wadamesh TFT requirement was verified',async()=>{
  const ui=await customEspWorkbench('install');ui.context.image=customEspImage({merged:true});ui.context.wada=wadaItem(true);
  await ui.evaluate('loadFirmware(wada.name,image,wada);');ui.evaluate('state.device={model:"Heltec v4"};controls();');
  assert.match(ui.elements.get('firmware-inspection-board').textContent,/Board not verified:.*requires the TFT.*not been identified/);
  assert.equal(ui.evaluate('firmwareBoardAssessment().requiresOverride'),true);assert.deepEqual(ui.calls,[]);
});
test('a renamed byte-identical Wadamesh file retains TFT warnings and does not gain MeshCore settings',async()=>{
  const ui=await customEspWorkbench('install');ui.context.image=customEspImage({merged:true});
  await ui.evaluate('loadFirmware("renamed.bin",image);');ui.context.known={...wadaItem(true),sha256:firmwareHash(ui.context.image)};
  ui.evaluate('state.items.push(known);state.item=null;$("provider").value="Custom";state.device={model:"Heltec V4.3 OLED"};controls();');
  assert.match(ui.elements.get('firmware-inspection-board').textContent,/Board mismatch:.*requires a TFT.*OLED/);assert.equal(ui.evaluate('radioSettingsAvailable()'),false);assert.equal(ui.elements.get('radio-defaults').hidden,true);
  ui.evaluate('queueVerification(state.pkg);');assert.equal(ui.evaluate('state.verification'),null);assert.deepEqual(ui.calls,[]);
});
test('selecting a different USB radio restores the Wadamesh first-install default without probing it',async()=>{
  const ui=workbench({catalogPromise:Promise.resolve(linkedCatalog([wadaItem(),wadaItem(true)]))});await new Promise(resolve=>setImmediate(resolve));
  ui.elements.get('auto-detect-board').checked=false;ui.elements.get('provider').value='Wadamesh TAK';ui.context.previousPort={getInfo:()=>({})};
  ui.evaluate('state.port=previousPort;state.manualSelections={provider:"Wadamesh TAK"};state.installMode="update";installModeSource={kind:"manual",port:previousPort};');
  await ui.elements.get('select-port').onclick();assert.equal(ui.evaluate('state.port'),ui.port);assert.equal(ui.evaluate('state.installMode'),'install');assert.deepEqual(ui.calls,['chooser']);
});
test('starting another radio with a retained Wadamesh provider restores its merged-install default',async()=>{
  const ui=workbench({catalogPromise:Promise.resolve(linkedCatalog([wadaItem(),wadaItem(true)]))});await new Promise(resolve=>setImmediate(resolve));
  ui.elements.get('provider').value='Wadamesh TAK';ui.evaluate('state.manualSelections={provider:"Wadamesh TAK"};state.verification={name:"previous.bin",sha256:"a".repeat(64)};');ui.context.confirm=async()=>true;
  await ui.evaluate('startNewRadio();');assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.elements.get('provider').value,'Wadamesh TAK');assert.equal(ui.evaluate('state.installMode'),'install');assert.deepEqual(ui.calls,[]);
});
test('standalone firmware does not queue MeshCore USB settings or claim MeshCore startup verification',async()=>{
  const ui=await customEspWorkbench('install');ui.context.image=customEspImage({merged:true});ui.context.wada=wadaItem(true);
  await ui.evaluate('loadFirmware(wada.name,image,wada);');ui.evaluate('state.radioDefaults.inspection={supported:false};queueVerification(state.pkg);');
  assert.equal(ui.evaluate('radioSettingsAvailable()'),false);assert.equal(ui.evaluate('state.verification'),null);
  await assert.rejects(ui.evaluate('inspectSelectedRadioDefaults();'),/Configure Wadamesh TAK.*on the device/);assert.deepEqual(ui.calls,[]);
  ui.evaluate('state.esp={port:{getInfo:()=>({})},finish:async()=>{},close:async()=>{}};state.plan={written:true,sha256:state.pkg.sha256,transportMode:"no_reset"};');
  await ui.evaluate('finishVerifiedEsp();');assert.equal(ui.evaluate('state.finishedFirmware.provider'),'Wadamesh TAK');assert.equal(ui.evaluate('state.finishedFirmware.verified'),false);assert.equal(ui.evaluate('state.verification'),null);
  assert.match(ui.elements.get('notice').textContent,/not verified.*No MeshCore startup check or settings commands/s);assert.deepEqual(ui.calls,[]);
});

test('an opened USB port with an unsupported application is informational and requires an exact manual board',async()=>{
  const ui=await meshtasticWorkbench();ui.port.getInfo=()=>({usbVendorId:0x303a,usbProductId:0x1001});
  const original=Object.assign(Error('USB serial communication is available, but no supported MeshCore or Meshtastic application answered.'),{code:'APPLICATION_UNIDENTIFIED',usbSerialAvailable:true});
  ui.context.detectApplication=async()=>{throw original;};
  ui.evaluate('$("hardware").value="Heltec T114";filterCatalog("hardware");$("role").value="companionFull";filterCatalog("role");$("artifact").value="0";');
  await ui.elements.get('select-port').onclick();
  assert.equal(ui.elements.get('notice').textContent,original.message);assert.equal(ui.elements.get('notice').classList.contains('error'),false);
  assert.equal(ui.elements.get('device-name').textContent,'USB connected · 303a:1001');assert.equal(ui.elements.get('port-status').textContent,'Application unknown');
  assert.match(ui.elements.get('device-meta').textContent,/serial port opened.*firmware was not identified.*Standalone firmware such as Ripple Ultra may not expose.*exact hardware manually.*no board or firmware was guessed/s);
  for(const id of ['device-name','device-meta','automatic-summary','notice'])assert.doesNotMatch(ui.elements.get(id).textContent,/(?:Ripple Ultra|T-Deck) (?:detected|identified)|Detected (?:Ripple|T-Deck)/i,id);
  assert.match(ui.elements.get('automatic-summary').textContent,/USB serial is available.*unidentified.*exact hardware manually.*no previous board or firmware selection/s);
  assert.match(ui.elements.get('log').textContent,/USB open; application unidentified:/);assert.doesNotMatch(ui.elements.get('log').textContent,/Stopped:/);
  assert.equal(ui.evaluate('state.port'),ui.port);assert.equal(ui.evaluate('state.applicationProbeFailed'),true);assert.equal(ui.evaluate('state.boardDetected'),false);
  for(const field of ['device','detectedHardware','pkg','plan','backupApproved'])assert.equal(ui.evaluate('state.'+field),null,field);
  assert.equal(ui.elements.get('hardware').value,'');assert.equal(ui.elements.get('artifact').value,'');assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(nextHighlight(ui),['hardware']);
  assert.deepEqual(ui.calls,['chooser','open','close']);
});

test('transport and permission failures do not become informational unsupported-application results',async()=>{
  for(const name of ['NetworkError','NotAllowedError','SecurityError']){
    const ui=await meshtasticWorkbench();ui.port.getInfo=()=>({usbVendorId:0x303a,usbProductId:0x1001});
    const original=Object.assign(Error('The USB port could not be read.'),{name});ui.context.detectApplication=async()=>{throw original;};
    await ui.elements.get('select-port').onclick();
    assert.equal(ui.elements.get('notice').textContent,original.message,name);assert.equal(ui.elements.get('notice').classList.contains('error'),true,name);
    assert.match(ui.elements.get('log').textContent,/Stopped: The USB port could not be read/);assert.doesNotMatch(ui.elements.get('log').textContent,/USB open; application unidentified/);
    assert.notEqual(ui.elements.get('port-status').textContent,'Application unknown');assert.doesNotMatch(ui.elements.get('device-meta').textContent,/Ripple|running firmware was not identified/);
    assert.equal(ui.evaluate('state.applicationProbeFailed'),false);assert.equal(ui.evaluate('state.device'),null);assert.equal(ui.evaluate('state.boardDetected'),false);
    assert.equal(Object.hasOwn(original,'usbSerialAvailable'),false);assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(ui.calls,['chooser','open','close']);
  }
});

test('the unsupported-application information path requires both its exact code and affirmative USB diagnostic',async()=>{
  for(const metadata of [{code:'APPLICATION_UNIDENTIFIED'},{code:'APPLICATION_UNIDENTIFIED',usbSerialAvailable:false},{code:'NETWORK_ERROR',usbSerialAvailable:true}]){
    const ui=await meshtasticWorkbench(),original=Object.assign(Error('Identity was not available.'),metadata);ui.context.detectApplication=async()=>{throw original;};
    await ui.elements.get('select-port').onclick();
    assert.equal(ui.elements.get('notice').classList.contains('error'),true,JSON.stringify(metadata));assert.notEqual(ui.elements.get('port-status').textContent,'Application unknown');
    assert.match(ui.elements.get('log').textContent,/Stopped: Identity was not available/);assert.doesNotMatch(ui.elements.get('log').textContent,/USB open; application unidentified/);assert.deepEqual(ui.calls,['chooser','open','close']);
  }
});

test('single-slot startup records retain the inspected physical partition label and geometry',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.pkg=fakePackage({architecture:'esp32'});
  ui.evaluate('state.plan={sha256:pkg.sha256,slotSelection:"a",addresses:[0x210000],parts:[{type:0,subtype:0x10,label:"custom_a",offset:0x210000,size:0x100000},{type:0,subtype:0x11,label:"custom_b",offset:0x10000,size:0x200000}]};');
  assert.deepEqual(JSON.parse(ui.evaluate('JSON.stringify(verificationRecord(pkg).espSlot)')),{selection:'a',label:'custom_a',offset:0x210000,size:0x100000});
  ui.evaluate('state.plan.slotSelection="b";state.plan.addresses=[0x10000];');
  assert.deepEqual(JSON.parse(ui.evaluate('JSON.stringify(verificationRecord(pkg).espSlot)')),{selection:'b',label:'custom_b',offset:0x10000,size:0x200000});
  ui.evaluate('state.plan.slotSelection="both";');assert.equal(ui.evaluate('verificationRecord(pkg).espSlot'),undefined);
});
test('malformed single-slot metadata remains explicitly unverified instead of silently becoming a Both record',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.pkg=fakePackage({architecture:'esp32'});
  for(const plan of [{slotSelection:'a',addresses:[0x10000],parts:null},{slotSelection:'b',addresses:[0x10000],parts:{}},{slotSelection:'a',addresses:[0x110000],parts:[{type:0,subtype:0x10,label:'app0',offset:0x10000,size:0x100000}]}]){
    ui.context.plan=plan;ui.evaluate('state.plan={sha256:pkg.sha256,...plan};');const record=ui.evaluate('verificationRecord(pkg)');assert.equal(record.espSlot.selection,plan.slotSelection);assert.equal(record.espSlot.label,null);assert.equal(record.espSlot.offset,null);assert.equal(record.espSlot.size,null);
  }
});
function interceptBootSlotReply(ui,reply,{during=null}={}){
  for(const [Type,method]of [[ui.context.SerialLink,'command'],[ui.context.MeshCore,'cli']]){
    const original=Type.prototype[method];Type.prototype[method]=async function(command,...args){if(command!=='get boot.slot')return original.call(this,command,...args);ui.calls.push(command);during?.();return reply;};
  }
}
test('single-slot startup checks the actual running custom label before applying settings on CommonCLI and Companion',async()=>{
  for(const role of ['common-cli','companion'])for(const selection of ['a','b']){
    const ui=await storageVerificationWorkbench(role,'int:esp32=8192K'),label=selection==='a'?'custom_a':'custom_b';
    ui.context.expected.espSlot={selection,label,offset:selection==='a'?0x210000:0x10000,size:selection==='a'?0x100000:0x200000};
    interceptBootSlotReply(ui,`> get boot.slot\r\n> running=${label} next=${label} app0=1024K app1=2048K`);ui.context.applyQueuedRadioSettings=async()=>ui.calls.push('settings-write');
    await ui.evaluate('verifyApplication();');assert.equal(ui.evaluate('state.finishedFirmware.verified'),true);assert.equal(ui.evaluate('state.verification'),null);assert.equal(ui.calls.filter(call=>call==='get boot.slot').length,1);assert.ok(ui.calls.indexOf('get boot.slot')<ui.calls.indexOf('settings-write'));
  }
});
test('the same version running from the untouched slot cannot verify a single-slot write or authorize settings',async()=>{
  for(const role of ['common-cli','companion']){
    const ui=await queuedSettingsVerificationWorkbench();if(role==='companion')ui.context.detectMeshCore=async()=>({role,model:ui.context.expected.model,publicKey:ui.context.expected.publicKey,protocol:14,version:'v1.18.0.1'});
    ui.context.expected.role=role;ui.context.expected.espSlot={selection:'a',label:'app0',offset:0x10000,size:0x100000};interceptBootSlotReply(ui,'> running=app1 next=app0 app0=1024K app1=1024K');
    await assert.rejects(ui.evaluate('verifyApplication();'),/running app1, not the written slot A.*single-slot application startup remains unverified/);assert.equal(ui.evaluate('state.finishedFirmware'),null);assert.ok(ui.evaluate('state.verification'));assert.equal(ui.evaluate('state.postFlashSettingsApproval.attempted'),false);assert.ok(!ui.calls.some(call=>call.startsWith('set ')));assert.equal(ui.calls.at(-1),'application-close');
  }
});
test('unsupported, incomplete, duplicate or changed-layout slot replies leave startup unverified and send no settings',async()=>{
  for(const reply of ['Unknown command','Error: unsupported','> running=app0 next=app0 app0=missing app1=1024K','> running=app0 next=app0 app0=2048K app1=1024K','> running=app0 next=app0 app0=1024K','> running=app0 next=app0 app0=1024K app1=1024K\n> running=app1 next=app1 app0=1024K app1=1024K']){
    const ui=await queuedSettingsVerificationWorkbench();ui.context.expected.espSlot={selection:'a',label:'app0',offset:0x10000,size:0x100000};interceptBootSlotReply(ui,reply);
    await assert.rejects(ui.evaluate('verifyApplication();'),/single-slot application startup remains unverified/);assert.equal(ui.evaluate('state.finishedFirmware'),null);assert.ok(ui.evaluate('state.verification'));assert.equal(ui.evaluate('state.postFlashSettingsApproval.attempted'),false);assert.ok(!ui.calls.some(call=>call.startsWith('set ')),reply);
  }
});
test('older Companion single-slot writes stay startup-unverified without sending unsupported CLI or settings',async()=>{
  const ui=await storageVerificationWorkbench('companion','Unknown command');ui.context.expected.espSlot={selection:'a',label:'app0',offset:0x10000,size:0x100000};
  ui.context.detectMeshCore=async()=>({role:'companion',model:ui.context.expected.model,publicKey:ui.context.expected.publicKey,protocol:13,version:'v1.18.0.1'});ui.context.applyQueuedRadioSettings=async()=>ui.calls.push('settings-write');
  await assert.rejects(ui.evaluate('verifyApplication();'),/older Companion.*single-slot application startup remains unverified/);assert.equal(ui.evaluate('state.finishedFirmware'),null);assert.ok(ui.evaluate('state.verification'));assert.deepEqual(ui.calls,['application-open','application-close']);
});
test('a changed single-slot target during its getter cannot authorize startup or queued settings',async()=>{
  const ui=await storageVerificationWorkbench('common-cli','int:esp32=8192K');ui.context.expected.espSlot={selection:'a',label:'app0',offset:0x10000,size:0x100000};
  interceptBootSlotReply(ui,'> running=app0 next=app0 app0=1024K app1=1024K',{during:()=>{ui.context.expected.espSlot.label='app1';}});ui.context.applyQueuedRadioSettings=async()=>ui.calls.push('settings-write');
  await assert.rejects(ui.evaluate('verifyApplication();'),/Single-slot verification target changed/);assert.equal(ui.evaluate('state.finishedFirmware'),null);assert.ok(!ui.calls.includes('settings-write'));
});
test('duplicate application labels cannot identify the written slot and retain an invalid verification marker',async()=>{
  const ui=workbench();await Promise.resolve();ui.context.pkg=fakePackage({architecture:'esp32'});
  for(const subtype of [0,0x11]){
    ui.context.otherSubtype=subtype;ui.evaluate('state.plan={sha256:pkg.sha256,slotSelection:"a",addresses:[0x10000],parts:[{type:0,subtype:0x10,label:"shared",offset:0x10000,size:0x100000},{type:0,subtype:otherSubtype,label:"shared",offset:0x110000,size:0x100000}]};');
    const record=ui.evaluate('verificationRecord(pkg)');assert.equal(record.espSlot.selection,'a');assert.equal(record.espSlot.label,null);assert.equal(record.espSlot.offset,null);assert.equal(record.espSlot.size,null);
    const verify=await storageVerificationWorkbench('common-cli','int:esp32=8192K');verify.context.expected.espSlot=record.espSlot;interceptBootSlotReply(verify,'> running=shared next=shared app0=1024K app1=1024K');verify.context.applyQueuedRadioSettings=async()=>verify.calls.push('settings-write');
    await assert.rejects(verify.evaluate('verifyApplication();'),/single-slot identity is missing or invalid/);assert.equal(verify.evaluate('state.finishedFirmware'),null);assert.ok(!verify.calls.includes('get boot.slot'));assert.ok(!verify.calls.includes('settings-write'));
  }
});
test('removing or changing the slot target during storage-layout reading cannot bypass the slot proof',async()=>{
  for(const mutate of [expected=>{delete expected.espSlot;},expected=>{expected.espSlot.label='app1';}]){
    const ui=await queuedSettingsVerificationWorkbench();ui.context.expected.espSlot={selection:'a',label:'app0',offset:0x10000,size:0x100000};const original=ui.context.SerialLink.prototype.command;
    ui.context.SerialLink.prototype.command=async function(command,...args){const reply=await original.call(this,command,...args);if(command==='get storage.layout')mutate(ui.context.expected);return reply;};
    await assert.rejects(ui.evaluate('verifyApplication();'),/Single-slot verification target changed/);assert.equal(ui.evaluate('state.finishedFirmware'),null);assert.ok(ui.evaluate('state.verification'));assert.equal(ui.evaluate('state.postFlashSettingsApproval.attempted'),false);assert.ok(!ui.calls.some(call=>call.startsWith('set ')));assert.ok(!ui.calls.includes('get boot.slot'));
  }
});
