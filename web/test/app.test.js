// DOM wiring unit tests, not browser/hardware automation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import {detectBoard,detectRecoveryProfile} from '../src/board-detection.js';
import {chooseFirmware,firmwareVersionWarning} from '../src/automatic.js';
import {chooseConnection} from '../src/connection-choice.js';
import {catalogProvider} from '../src/catalog.js';
const html=await readFile(new URL('../index.html',import.meta.url),'utf8');
const source=(await readFile(new URL('../src/app.js',import.meta.url),'utf8')).replace(/^import .*;\r?$/gm,'');
const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);
function workbench({pending=null,recovery=null,espRecovery=null,catalogPromise=null,productionDefaults=false}={}) {
  const calls=[],elements=new Map(),serialEvents={};
  class Option {constructor(text,value){this.text=text;this.value=value;}}
  for(const id of ids)elements.set(id,{value:'',disabled:false,hidden:false,textContent:'',files:[],options:[],checked:false,classList:{toggle(){}},replaceChildren(...options){this.options=options;this.value=options[0]?.value||'';},removeAttribute(){},setAttribute(){},addEventListener(){},showModal(){},scrollHeight:0});
  elements.get('project').value='MeshCore';elements.get('transport-mode').value='no_reset';elements.get('backup-role').value='companion';
  if(productionDefaults){for(const id of ['auto-detect-board','auto-backup','auto-finish'])elements.get(id).checked=true;elements.get('transport-mode').value='auto';elements.get('backup-role').value='auto';}
  const port={getInfo:()=>({usbVendorId:0x303a,usbProductId:0x1001})};
  const storage=new Map(pending?[['meshfirmware.pendingMigration',JSON.stringify(pending)]]:[]);
  if(recovery)storage.set('meshfirmware.nrfRecovery',JSON.stringify(recovery));
  if(espRecovery)storage.set('meshfirmware.espRecovery',JSON.stringify(espRecovery));
  const context=vm.createContext({document:{getElementById:id=>{assert.ok(elements.has(id),`Missing HTML id ${id}`);return elements.get(id);},querySelectorAll:()=>[...elements.values()]},navigator:{serial:{requestPort:async()=>{calls.push('chooser');return port;},getPorts(){throw new Error('must not enumerate automatically');},addEventListener(type,handler){serialEvents[type]=handler;}}},window:{addEventListener(){}},localStorage:{getItem:k=>storage.get(k),setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},Option,URL,Blob,Uint8Array,TextEncoder,TextDecoder,console,setTimeout,clearTimeout,AbortSignal,Date,
    fail(message){throw new Error(message);},text:b=>new TextDecoder().decode(b),hash:()=>'',getCatalog:async()=>catalogPromise||({items:[],warnings:[],generatedAt:new Date().toISOString()}),catalogProvider,httpsUrl:value=>value,compareVersions:(a,b)=>b.localeCompare(a),detectBoard,detectRecoveryProfile,chooseFirmware,firmwareVersionWarning,chooseConnection,assessBoard:()=>({requiresOverride:false,payloadFamily:'unknown'}),endfIdentity:()=>null,rakFamily:value=>/rak4631/i.test(value)?'rak4631':'unknown',detectMeshCore(){},exportNativeBackup(){},backupSummary:()=>({complete:true,privateIdentity:true,reasons:[]}),
    SerialLink:class{constructor(){calls.push('serial');throw new Error('Unexpected serial open');}},EspSession:class{constructor(){calls.push('rom');throw new Error('Unexpected ROM session');}},validateEspWriteRecovery:value=>value,MeshCore:class{},BrowserPlanner:class{},inspectFirmware(){throw new Error('Bad image');},checkedZip(){return [];},recoveryPackage(){throw new Error('No verified recovery package');},verifyBackup(){},parseBackup(){},enterCompanionBinary(){},backupCommonCli(){},touch1200(){},flashNrf(){},waitForMigration(){}
  });
  vm.runInContext(source,context);
  return {context,elements,calls,port,serialEvents,evaluate:code=>vm.runInContext(code,context)};
}
test('every UI id exists once and all wired controls have matching HTML',()=>{
  assert.equal(new Set(ids).size,ids.length);
  for(const match of source.matchAll(/\$\('([^']+)'\)/g))assert.ok(ids.includes(match[1]),match[1]);
});

test('reconnect guidance warns about VM USB capture without promising a timed return or an administrator CLI',()=>{
  assert.match(html,/pause VMs configured for USB auto-capture/);assert.match(html,/do not assume it will be returned after 30 seconds/);assert.match(html,/No administrator CLI command is part of the browser workflow/);assert.match(html,/Never interrupt an active partition-migration bridge/);
});

const v4Item={project:'MeshCore',provider:'MeshCore',hardware:'Heltec v4',architecture:'esp32',role:'repeater',version:'v1.18.0',name:'heltec_v4_repeater-v1.18.0.bin',action:'flash-update',url:'https://example.test/v4.bin'};
test('provider picker shows Keymind Cascade and stock and restores a saved historical Logging choice',async()=>{
  let resolveCatalog;const catalogPromise=new Promise(resolve=>resolveCatalog=resolve),ui=workbench({catalogPromise});
  ui.context.localStorage.setItem('meshfirmware.selections',JSON.stringify({provider:'Keymind Cascade Logging',hardware:v4Item.hardware,role:v4Item.role,version:v4Item.version}));
  resolveCatalog({items:[v4Item,{...v4Item,provider:'Keymind Cascade'}],warnings:[],generatedAt:'2026-10-27T00:00:00Z'});
  await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(ui.elements.get('provider').options.map(option=>[option.text,option.value]),[['All providers',''],['Keymind Cascade','Keymind Cascade'],['MeshCore (stock)','MeshCore']]);
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

test('connecting a reviewed screenless V4 automatically selects exact hardware and matching safe firmware, not USB reset mode',async()=>{
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
    assert.deepEqual(ui.calls,['chooser','open','detect','close']);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('flash').disabled,true);
    assert.equal(ui.evaluate('state.connection.mode'),null);assert.match(ui.elements.get('connection-summary').textContent,/needs a manual choice/); // Shared 303a:1001 is not a reset-protocol proof.
  }
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
  assert.equal(ui.evaluate('state.device.architecture'),'nrf52');assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(ui.calls,['chooser','open','close','chooser','open','close']);
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

test('handoff recovery migration and verification re-selection retain the exact in-progress firmware image',async()=>{
  for(const mode of ['handoff','recovery','migration','espRecovery','verification']){
    const ui=workbench({productionDefaults:true});await Promise.resolve();
    ui.context.pkg=fakePackage({name:'in-progress.bin',architecture:mode==='recovery'?'nrf52':'esp32'});ui.context.selectedPort=ui.port;ui.evaluate('state.pkg=pkg;state.port=selectedPort;');
    ui.context.confirm=async()=>{ui.calls.push('same-device');return true;};
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

test('Prepare update loads the automatic artifact and requests guarded TinyUSB handoff, never flashes',async()=>{
  const ui=workbench({productionDefaults:true});await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage({architecture:'esp32'});ui.evaluate("state.port=selectedPort;state.device={model:'Heltec V4 OLED',architecture:'esp32'};");ui.port.getInfo=()=>({usbVendorId:0x303a,usbProductId:0x0002});ui.elements.get('artifact').value='0';ui.context.fetchSelectedFirmware=async()=>{ui.calls.push('fetch');ui.evaluate('state.pkg=pkg;');};ui.context.ensureBackup=async()=>ui.calls.push('backup');ui.context.confirm=async(_t,_d,_w,token)=>{ui.calls.push(token);return true;};ui.context.touch1200=async(_port,kind)=>ui.calls.push(kind);
  await ui.elements.get('prepare').onclick();assert.deepEqual(ui.calls,['fetch','backup','ENTER BOOTLOADER','tinyusb']);assert.equal(ui.evaluate('state.port'),null);assert.equal(ui.elements.get('transport-mode').value,'no_reset');assert.equal(ui.elements.get('already-bootloader').checked,true);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);
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
  const ui=workbench();await Promise.resolve();serialMock(ui);ui.context.selectedPort=ui.port;ui.evaluate('state.port=selectedPort;');ui.elements.get('hardware').value='Manual board';ui.context.detectMeshCore=async()=>({role:'companion',model:'Station G3 ESP'});
  await ui.elements.get('probe').onclick();assert.deepEqual(ui.calls,['open','close']);assert.equal(ui.elements.get('hardware').value,'Manual board');assert.match(ui.elements.get('board-detection').textContent,/No complete exact/);
});

test('DFU detection checks hints without probing or treating USB as physical board proof',async()=>{
  const ui=workbench();await Promise.resolve();ui.port.getInfo=()=>({usbVendorId:0x239a,usbProductId:0x0029});ui.elements.get('auto-detect-board').checked=true;ui.elements.get('hardware').value='Physical RAK';
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
  const ui=workbench();await Promise.resolve();serialMock(ui);ui.context.selectedPort=ui.port;ui.evaluate('state.port=selectedPort;');ui.elements.get('hardware').value='Manual';
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
test('default backup flow finishes and acknowledges the saved archive before ROM entry',async()=>{
  const ui=workbench();serialMock(ui);ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage({name:'app.bin',architecture:'esp32'});ui.evaluate('state.port=selectedPort;state.pkg=pkg;');ui.elements.get('backup-role').value='auto';
  ui.context.choose=async title=>{ui.calls.push(title);return title.startsWith('Back up')?'backup':'saved';};
  ui.context.detectMeshCore=async()=>({role:'companion',publicKey:'11'.repeat(32),model:'test',name:'test'});
  ui.context.MeshCore=class{async backup(){ui.calls.push('backup');return {payload:{role:'companion'}};}};
  ui.context.exportNativeBackup=async()=>({schema:'native'});ui.context.download=()=>ui.calls.push('download');
  ui.context.EspSession=class{async connect(){ui.calls.push('enter-rom');return {chip:'ESP32-S3',mac:'aa:bb:cc:dd:ee:ff',flashBytes:4<<20};}async prepare(){return {addresses:[0x10000],sha256:ui.context.pkg.sha256};}async close(){}};
  await ui.elements.get('prepare').onclick();
  assert.ok(ui.calls.indexOf('backup')<ui.calls.indexOf('enter-rom'));assert.ok(ui.calls.indexOf('Confirm your backup download')<ui.calls.indexOf('enter-rom'));assert.equal(ui.evaluate('state.plan.sha256'),ui.context.pkg.sha256);
});
test('cancelling the backup offer prevents all reset and ROM operations',async()=>{
  const ui=workbench();ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage({architecture:'esp32'});ui.evaluate('state.port=selectedPort;state.pkg=pkg;');ui.context.choose=async()=> 'cancel';
  await ui.elements.get('prepare').onclick();assert.deepEqual(ui.calls,[]);assert.match(ui.elements.get('notice').textContent,/Cancelled before reset/);
});
test('explicit ROM/DFU skips application backup without probing the port',async()=>{
  const ui=workbench();ui.context.selectedPort=ui.port;ui.context.pkg=fakePackage();ui.evaluate('state.port=selectedPort;state.pkg=pkg;');ui.elements.get('transport-mode').value='nrf52';ui.elements.get('already-bootloader').checked=true;
  ui.context.choose=async title=>{assert.match(title,/cannot be done/);return 'skip';};
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
  const ui=workbench();ui.context.pkg=fakePackage();ui.context.selectedPort=ui.port;ui.evaluate('state.pkg=pkg;state.port=selectedPort;');ui.elements.get('transport-mode').value='nrf52';ui.elements.get('already-bootloader').checked=true;ui.elements.get('flash-action').value='wipe';ui.context.choose=async()=> 'skip';
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
  const ui=workbench();ui.context.pkg=fakePackage();ui.context.selectedPort=ui.port;ui.evaluate('state.pkg=pkg;state.port=selectedPort;');ui.elements.get('transport-mode').value='nrf52';ui.elements.get('already-bootloader').checked=true;ui.elements.get('flash-action').value='wipe';ui.context.choose=async()=> 'skip';
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

test('failed downloads and local reads clear the old firmware and write proof before failure',async()=>{
  for(const action of ['fetch-firmware','fetch-custom','load-bootloader','local-read','local-size','load-entry']){
    const ui=workbench();await Promise.resolve();ui.context.selectedPort=ui.port;ui.context.record=ui.calls;
    ui.evaluate("state.port=selectedPort;state.pkg={name:'old.bin',sha256:'a'.repeat(64)};state.plan={sha256:state.pkg.sha256,generation:0,port:selectedPort};state.esp={close:async()=>record.push('closed-old-session')};state.items=[{name:'new.bin',hardware:'test',url:'https://example.test/new.bin'}];state.archive=new Uint8Array(8);");
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

test('pending recovery and verification controls reveal themselves but never reset, retry or write automatically',async()=>{
  for(const [state,panel]of [['migration','migration-options'],['needed','migration-options'],['espRecovery','esp-retry-options'],['recovery','nrf-actions'],['verification','verification-options'],['written','verification-options']]){
    const ui=workbench();await Promise.resolve();const advanced=collapsedPanels(ui);ui.elements.get(panel).hidden=true;
    ui.context.pendingPanelState=state;ui.evaluate("if(['written','needed'].includes(pendingPanelState))state.plan={[pendingPanelState]:true};else state[pendingPanelState]={};controls();");
    assert.equal(ui.elements.get(panel).open,true,state);assert.equal(ui.elements.get(panel).hidden,false,state);assert.equal(advanced.open,true,state);assert.deepEqual(ui.calls,[],state);
  }
});

test('tool navigation opens known collapsed sections and ignores unrelated fragments without USB activity',async()=>{
  const ui=workbench();await Promise.resolve();
  for(const id of ['backups','console','capabilities','advanced-options']){
    collapsedPanels(ui);ui.context.window.location={hash:'#'+id};ui.evaluate('openLinkedPanel();');assert.equal(ui.elements.get(id).open,true,id);
  }
  collapsedPanels(ui);ui.context.window.location={hash:'#confirm-submit'};ui.evaluate('openLinkedPanel();');
  assert.equal(ui.elements.get('advanced-options').open,false);assert.equal(ui.elements.get('backups').open,false);assert.equal(ui.elements.get('confirm-submit').open,undefined);assert.deepEqual(ui.calls,[]);
});

test('normal default controls keep extras closed and only an explicit visible nRF52 wipe expands its actions',async()=>{
  const ui=workbench();await Promise.resolve();const advanced=collapsedPanels(ui);ui.elements.get('nrf-actions').hidden=true;
  ui.evaluate('controls();');assert.equal(advanced.open,false);assert.equal(ui.elements.get('nrf-actions').open,false);
  ui.context.pkg=fakePackage();ui.evaluate('state.pkg=pkg;');ui.elements.get('nrf-actions').hidden=false;ui.elements.get('flash-action').value='wipe';ui.evaluate('controls();');
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
  assert.match(ui.elements.get('notice').textContent,/migration host blocked/);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,['mock-connect','mock-close']);
});

test('importing a validated backup reveals restore controls without restoring or opening USB',async()=>{
  const ui=workbench();await Promise.resolve();collapsedPanels(ui);
  const archive={schema:'org.meshfirmware.web-backup/v1',payload:{role:'companion',publicKey:'a'.repeat(64),channels:[],contacts:[]}};
  ui.elements.get('backup-file').files=[{name:'backup.json',size:2,text:async()=>'{}'}];ui.context.parseBackup=async()=>archive;ui.context.verifyBackup=value=>value.payload;
  await ui.elements.get('backup-file').onchange();assert.equal(ui.elements.get('backups').open,true);assert.equal(ui.evaluate('state.restore'),archive);assert.equal(ui.elements.get('restore').disabled,true);assert.deepEqual(ui.calls,[]);
});

test('a blocked custom URL download reveals its exact download link and local-file alternative',async()=>{
  const ui=workbench();await Promise.resolve();const advanced=collapsedPanels(ui),url='https://example.test/custom.bin';
  ui.elements.get('custom-url').value=url;ui.context.pkg=fakePackage();ui.evaluate('state.pkg=pkg;state.plan={written:true};');
  ui.context.boundedFetch=async()=>{throw Error('Fixture CORS block');};await ui.elements.get('fetch-custom').onclick();
  assert.equal(ui.elements.get('image-details').open,true);assert.equal(ui.elements.get('custom-firmware').open,true);assert.equal(advanced.open,true);assert.equal(ui.elements.get('download-firmware').href,url);
  assert.match(ui.elements.get('notice').textContent,/Fixture CORS block/);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(ui.calls,[]);
});

test('a blocked exact-board bootloader download reveals its link and local-file alternative without retaining write proof',async()=>{
  const ui=workbench();await Promise.resolve();const advanced=collapsedPanels(ui),url='https://example.test/board_bootloader.zip';
  ui.context.item={architecture:'nrf52',hardware:'Exact board',bootloader:[url],bootloaderInfo:{url,sha256:'b'.repeat(64),size:64,profile:'exact-board',version:'2.4.12'}};
  ui.elements.get('hardware').value='Exact board';ui.elements.get('bootloader-source').value=url;ui.evaluate("state.items=[item];state.pkg={name:'previous.zip'};state.plan={written:true};");
  ui.context.boundedFetch=async()=>{throw Error('Fixture bootloader CORS block');};await ui.elements.get('load-bootloader').onclick();
  assert.equal(ui.elements.get('image-details').open,true);assert.equal(ui.elements.get('custom-firmware').open,true);assert.equal(advanced.open,true);assert.equal(ui.elements.get('download-firmware').href,url);
  assert.match(ui.elements.get('notice').textContent,/download this exact bootloader ZIP/);assert.equal(ui.evaluate('state.pkg'),null);assert.equal(ui.evaluate('state.plan'),null);assert.equal(ui.elements.get('flash').disabled,true);assert.deepEqual(ui.calls,[]);
});

test('a blocked erase ZIP download reveals its exact link and local erase input while retaining the final image',async()=>{
  const ui=workbench();await Promise.resolve();const advanced=collapsedPanels(ui),url='https://example.test/exact-erase.zip';
  ui.elements.get('nrf-actions').hidden=true;ui.elements.get('erase-source').value=url;ui.context.pkg=fakePackage({name:'intended-final.zip'});ui.evaluate('state.pkg=pkg;state.plan=null;');
  ui.context.boundedFetch=async()=>{throw Error('Fixture erase CORS block');};await assert.rejects(ui.evaluate('erasePackage();'),/Download the exact erase ZIP/);
  assert.equal(ui.elements.get('image-details').open,true);assert.equal(ui.elements.get('nrf-actions').open,true);assert.equal(ui.elements.get('nrf-actions').hidden,false);assert.equal(advanced.open,true);assert.equal(ui.elements.get('download-firmware').href,url);
  assert.equal(ui.elements.get('custom-firmware').open,false);assert.equal(ui.evaluate('state.pkg'),ui.context.pkg);assert.equal(ui.evaluate('state.plan'),null);assert.deepEqual(ui.calls,[]);
});
