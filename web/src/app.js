import './style.css';
import { inspectFirmware, checkedZip, hash, fail, text } from './firmware.js';
import { SerialLink, flashNrf, touch1200 } from './serial.js';
import { EspSession } from './esp.js';
import { getCatalog, httpsUrl } from './catalog.js';
import { MeshCore, backupCommonCli, verifyBackup, parseBackup, enterCompanionBinary } from './meshcore.js';
import { BrowserPlanner } from './planner.js';
import { waitForMigration } from './migration.js';

const $ = id => document.getElementById(id);
const state = { port: null, pkg: null, esp: null, plan: null, generation: 0, busy: false, items: [], restore: null, directory: null, archive:null, planner:null, migration:null, downloaded:new Set() };
try { const pending=JSON.parse(localStorage.getItem('meshfirmware.pendingMigration') || 'null'); if(pending && /^[a-f0-9:]{17}$/i.test(pending.mac) && /^[a-f0-9]{64}$/.test(pending.sha256)) state.migration=pending; } catch { /* The worker still fails closed on any actual NVS migration state. */ }
// Exact bootloader IDs shared with the native classifier. Never match a broad
// vendor/product range: nearby application IDs must still be probed normally.
const dfuIds = new Set(['2886:0044','2886:0045','2886:0057','2886:1667','239a:0029','239a:002a','239a:0071','239a:00b3','239a:00da']);
const portId = port => { const info = port?.getInfo() || {}; return info.usbVendorId === undefined ? 'USB serial' : [info.usbVendorId,info.usbProductId].map(n => n.toString(16).padStart(4,'0')).join(':'); };
const size = bytes => `${(bytes / (1 << 20)).toFixed(2)} MiB`;
function log(message) { $('log').textContent = ($('log').textContent + '\n' + String(message).replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'')).slice(-100000); $('log').scrollTop = $('log').scrollHeight; }
function notice(message, error = false) { $('notice').textContent = message; $('notice').classList.toggle('error',error); }
function progress(value, message) { $('progress').value = value; $('progress-label').textContent = message; }
function controls() {
  document.querySelectorAll('[data-lock]').forEach(el => { el.disabled = state.busy; });
  $('select-port').disabled ||= !('serial' in navigator);
  $('prepare').disabled ||= !state.pkg || (!state.port && state.pkg.architecture !== 'uf2');
  $('flash').disabled ||= !state.plan;
  $('finish').disabled ||= !state.esp || !state.plan?.written;
  $('wait-migration').disabled ||= !state.port || !state.migration?.uart || state.migration?.settled;
  $('recover-bridge').disabled ||= !state.port || !state.pkg || !state.migration;
  $('restore').disabled ||= !state.restore || !state.port || state.restore.schema !== 'org.meshfirmware.web-backup/v1' || state.restore.payload.role !== 'companion';
  for (const id of ['touch','probe','backup','send-command','binary-mode']) $(id).disabled ||= !state.port;
  $('fetch-firmware').disabled ||= !$('artifact').value;
}
async function closeEsp() { if (state.esp) { await state.esp.close(); state.esp = null; } state.plan = null; }
async function operation(callback) {
  if (state.busy) return; state.busy = true; controls();
  try { await callback(); }
  catch (error) { notice(error.message || String(error),true); log(`Stopped: ${error.message || error}`); }
  finally { state.busy = false; controls(); }
}
async function linkOperation(callback) {
  if(state.migration) fail('A partition migration is pending. Application commands and backups are blocked until its final firmware write is verified.');
  if (!state.port) fail('Choose a USB port first.');
  if (dfuIds.has(portId(state.port))) fail('This port is in DFU. Logical backups and application commands cannot run in a bootloader.');
  await closeEsp(); const link = new SerialLink(state.port);
  try { await link.open(); return await callback(link); } finally { await link.close(); }
}
function confirm(title, detail, warning, token) {
  $('confirm-title').textContent = title; $('confirm-detail').textContent = detail; $('confirm-warning').textContent = warning; $('token-label').textContent = token; $('confirm-token').value = ''; $('confirm-submit').disabled = true;
  $('confirm-token').oninput = () => { $('confirm-submit').disabled = $('confirm-token').value !== token; };
  const dialog = $('confirm-dialog'); dialog.returnValue = ''; dialog.showModal();
  return new Promise(resolve => dialog.addEventListener('close',() => resolve(dialog.returnValue === 'confirm' && $('confirm-token').value === token),{once:true}));
}
function download(name, bytes, type = 'application/octet-stream') { const url = URL.createObjectURL(new Blob([bytes],{type})); const a = document.createElement('a'); a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url),30000); }
async function loadFirmware(name, bytes) {
  await closeEsp(); state.pkg = null; state.generation++;
  $('image-name').textContent = 'No image loaded'; $('image-kind').textContent = '—'; $('image-size').textContent = '—'; $('image-sha').textContent = ''; $('expert-fields').hidden = true;
  if (/\.zip$/i.test(name)) {
    const entries = checkedZip(bytes,{maxEntries:8192,maxExpanded:512<<20,directoryOnly:true});
    if (!entries.some(e=>e.name==='manifest.json') || entries.length!==3) {
      const candidates=entries.filter(e=>/\.(?:bin|zip|uf2)$/i.test(e.name) && e.length>0 && e.length<(32<<20));
      if (!candidates.length) fail('No firmware images in this release archive.');
      state.archive=bytes; $('archive-entry').replaceChildren(...candidates.map(e=>new Option(e.name,e.name))); $('archive-picker').hidden=false;
      notice('Release ZIP indexed without expanding every board. Select the exact image for your board.'); return;
    }
  }
  const pkg = inspectFirmware(name,bytes), expected = $('expected-sha').value.trim().toLowerCase();
  if (expected && (!/^[a-f0-9]{64}$/.test(expected) || expected !== pkg.sha256)) fail('Published SHA-256 does not match the selected bytes.');
  state.pkg = pkg; $('image-name').textContent = pkg.name; $('image-kind').textContent = pkg.kind; $('image-size').textContent = size(bytes.length); $('image-sha').textContent = pkg.sha256; $('image-warning').textContent = pkg.warnings.join(' ');
  $('expert-fields').hidden = !pkg.expert;
  progress(0,'Image validated locally. Inspect the device before confirmation.'); notice('Firmware loaded. No device data has been written.');
}
function options(id, values, placeholder) { const select = $(id), prior = select.value; select.replaceChildren(new Option(placeholder,''),...Array.from(new Set(values)).filter(Boolean).sort().map(v => new Option(v,v))); if ([...select.options].some(o => o.value === prior)) select.value = prior; }
function filterCatalog(changed = 'project') {
  let items = state.items.filter(i => i.project === $('project').value);
  for (const id of ['provider','hardware','role','version']) { if (['project','provider','hardware','role','version'].indexOf(id) > ['project','provider','hardware','role','version'].indexOf(changed)) options(id,items.map(i => i[id]),`All ${id === 'hardware' ? 'boards' : id + 's'}`); if ($(id).value) items = items.filter(i => i[id] === $(id).value); }
  $('artifact').replaceChildren(new Option(`${items.length} artifacts · choose a file`,''),...items.slice(0,3000).map(item => new Option(`${item.name} · ${item.action}`,String(state.items.indexOf(item)))));
  updateDownload(); controls();
}
function updateDownload() { const item = state.items[Number($('artifact').value)]; if ($('artifact').value && item) { $('download-firmware').href = item.url; $('download-firmware').removeAttribute('aria-disabled'); } else { $('download-firmware').removeAttribute('href'); $('download-firmware').setAttribute('aria-disabled','true'); } }
async function boundedFetch(url) {
  const response = await fetch(httpsUrl(url),{signal:AbortSignal.timeout(120000),credentials:'omit'});
  if (!response.ok || Number(response.headers.get('Content-Length')) > (64 << 20)) fail('Firmware download failed or exceeds 64 MiB.');
  const reader = response.body.getReader(), chunks = []; let total = 0;
  try { while (true) { const {value,done} = await reader.read(); if (done) break; total += value.length; if (total > (64 << 20)) fail('Firmware download exceeds 64 MiB.'); chunks.push(value); } }
  finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
  const result = new Uint8Array(total); let offset = 0; for (const c of chunks) { result.set(c,offset); offset += c.length; } return result;
}

$('select-port').onclick = () => operation(async () => {
  const port = await navigator.serial.requestPort(); // Must remain the first awaited browser operation after the click.
  await closeEsp(); state.port = port; state.generation++;
  $('device-name').textContent = `Selected USB ${portId(port)}`; $('device-meta').textContent = 'Port permission granted. Firmware and board identity are not yet verified.'; $('port-status').textContent = dfuIds.has(portId(port)) ? 'DFU port' : 'Port selected';
  if (dfuIds.has(portId(port))) $('transport-mode').value = 'nrf52';
  notice('Port selected. No reset, flash or application probe was sent.');
});
$('transport-mode').onchange = () => operation(async () => { await closeEsp(); state.generation++; });
for (const id of ['expert-offset','migration-package','usb-set']) $(id).onchange = () => operation(async()=>{await closeEsp();state.generation++;});
$('expected-sha').onchange = () => operation(async () => { await closeEsp(); state.generation++; if (state.pkg && $('expected-sha').value.trim() && $('expected-sha').value.trim().toLowerCase() !== state.pkg.sha256) fail('SHA-256 mismatch. Flash plan invalidated.'); });
$('firmware-file').onchange = () => operation(async () => { const file = $('firmware-file').files[0]; if (!file) return; if (file.size > 64 << 20) fail('Firmware exceeds 64 MiB.'); await loadFirmware(file.name,new Uint8Array(await file.arrayBuffer())); });
$('load-entry').onclick = () => operation(async () => { const entry=$('archive-entry').value; if(!state.archive || !entry) fail('Select an archive entry.'); const files=checkedZip(state.archive,{maxEntries:8192,maxExpanded:512<<20,select:name=>name===entry}); await loadFirmware(entry.split('/').pop(),files[entry]); });
$('fetch-custom').onclick = () => operation(async () => { const url=httpsUrl($('custom-url').value); $('download-firmware').href=url; try { await loadFirmware(new URL(url).pathname.split('/').pop(),await boundedFetch(url)); } catch(error) { throw new Error(`${error.message} If this host blocks browser fetches, download it and select the local file.`); } });
$('artifact').onchange = () => { updateDownload(); controls(); };
for (const id of ['project','provider','hardware','role','version']) $(id).onchange = () => filterCatalog(id);
$('fetch-firmware').onclick = () => operation(async () => {
  const item = state.items[Number($('artifact').value)]; if (!item) fail('Choose an artifact.');
  notice('Downloading firmware into browser memory…');
  try { await loadFirmware(item.name,await boundedFetch(item.url)); }
  catch (error) { throw new Error(`${error.message} If the firmware host blocks browser downloads (CORS), use Download and then choose that local file. No proxy or helper is used.`); }
});
$('touch').onclick = () => operation(async () => {
  if(state.migration) fail('A migration is pending. Do not reset the bridge. Complete or recover its verified migration first.');
  const mode = $('transport-mode').value;
  if (!['tinyusb','nrf52'].includes(mode)) fail('Use this only for TinyUSB applications or nRF52 runtime. Other modes enter ROM during inspection.');
  if (dfuIds.has(portId(state.port))) fail('Already a known DFU port; no 1200-baud touch is needed.');
  if (!await confirm('Enter USB bootloader?','This resets the selected application USB interface. A new port may appear.','Bluetooth may disconnect. Select the same physical device again after the touch.','ENTER BOOTLOADER')) return;
  await closeEsp(); try { await touch1200(state.port,mode); } catch (error) { log(`The touch was interrupted (${error.message}). Delivery is uncertain; no second touch was sent.`); }
  state.port = null; state.generation++; $('port-status').textContent = 'Select bootloader port'; $('device-name').textContent = 'USB handoff requested'; notice('Choose USB port again for the same device. Set ESP32 to already in ROM, or select the nRF52 DFU port.');
  if (mode === 'tinyusb') $('transport-mode').value = 'no_reset';
});
$('probe').onclick = () => operation(async () => {
  if(state.migration) fail('Complete the pending migration before application queries.');
  await linkOperation(async link => {
    if($('backup-role').value==='common-cli') {const identity=await link.command('get public.key'), key=/(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])/i.exec(identity)?.[0];if(!key)fail('No CommonCLI public identity response. DFU/ROM cannot answer application commands.');const version=await link.command('ver');$('device-name').textContent='MeshCore CommonCLI';$('device-meta').textContent=`Public identity ${key.slice(0,12)}`;log(version);notice('CommonCLI answered. No settings changed.');return;}
    const mc = new MeshCore(link), self = await mc.self(), info = await mc.info(); $('device-name').textContent = text(self.subarray(58)).replace(/\0/g,''); $('device-meta').textContent = `${text(info.subarray(20,60)).replace(/\0/g,'')} · ${text(info.subarray(60,80)).replace(/\0/g,'')} · public identity ${Array.from(self.subarray(4,10),b => b.toString(16).padStart(2,'0')).join('')}`; log(await mc.cli('version')); notice('MeshCore application answered. No settings changed.');
  });
});
$('binary-mode').onclick=()=>operation(async()=>{
  if(!await confirm('Enter Full Companion binary mode?','Only use this for MeshCore Full Companion text mode.','This may persistently turn USB logging off so binary commands can work. It does not flash or reboot the radio.','BINARY MODE')) return;
  await linkOperation(link=>enterCompanionBinary(link,{allowLoggingChange:true}));
  notice('Binary mode confirmed. USB logging is off; it will not be re-enabled automatically. Read the running node or create a backup.');
});
$('prepare').onclick = () => operation(async () => {
  const pkg = state.pkg; if (!pkg) fail('Load firmware first.'); await closeEsp();
  if(state.migration && (pkg.architecture!=='esp32' || state.migration.sha256!==pkg.sha256)) fail('Select the original ESP32 firmware for the pending migration. No reset is permitted for another image.');
  if ($('expected-sha').value.trim() && $('expected-sha').value.trim().toLowerCase() !== pkg.sha256) fail('SHA-256 mismatch.');
  if (pkg.architecture === 'uf2') {
    if($('transport-mode').value==='nrf52') fail('nRF52 uses serial DFU ZIPs, not a mounted drive. Select the matching DFU ZIP.');
    if (!window.showDirectoryPicker) fail('This browser has no directory picker. Download the UF2 and copy it to the bootloader drive manually.');
    const directory=await window.showDirectoryPicker({mode:'readwrite'}), infoFile=await directory.getFileHandle('INFO_UF2.TXT'), info=await (await infoFile.getFile()).text();
    if(/nrf52|nrf528|nordic/i.test(info)) fail('This is an nRF52 bootloader. Use its serial DFU port and a matching DFU ZIP; drive copying is disabled for nRF52.');
    if (!/UF2 Bootloader|Board-ID:/i.test(info)) fail('This directory has no recognized UF2 bootloader identity.');
    state.directory=directory; state.plan={generation:state.generation,sha256:pkg.sha256,port:state.port,uf2Info:info.slice(0,2048)}; $('device-name').textContent=directory.name; $('device-meta').textContent=info.slice(0,250); notice('UF2 drive identity read. Confirm board compatibility before copying.'); return;
  }
  if (pkg.architecture === 'nrf52') {
    if ($('transport-mode').value !== 'nrf52') fail('Select nRF52 DFU mode and its bootloader port.');
    state.plan = { generation:state.generation,port:state.port,sha256:pkg.sha256 }; notice('DFU ZIP validated. Browser USB metadata cannot prove the physical board; review the target before writing.'); return;
  }
  const mode = $('transport-mode').value;
  if(state.migration && !state.migration.uart && mode!=='no_reset') fail('Pending USB migration: use already in ROM / no reset. A reset could interrupt the bridge.');
  if (!['no_reset','usb_reset','default_reset'].includes(mode)) fail('Enter the ESP32 bootloader first, then explicitly select its ROM port.');
  if(state.migration?.uart && !state.migration.settled) fail('The UART migration must report settled state before any ROM reset. Use Wait for migration; keep power connected.');
  const expertText = $('expert-offset').value.trim();
  const expertOffset = pkg.expert && /^(?:0x[0-9a-f]+|[0-9]+)$/i.test(expertText) ? Number(expertText) : undefined;
  if(pkg.expert && !Number.isSafeInteger(expertOffset)) fail('Enter the explicit flash offset for this component. No offset is guessed.');
  const esp = new EspSession(state.port,log); state.esp = esp;
  try {
    const info = await esp.connect(mode);
    if(state.migration && (state.migration.sha256!==pkg.sha256 || state.migration.mac!==info.mac)) fail('A migration is pending. Select its original firmware and the same physical chip.');
    const planner = pkg.merged || pkg.expert ? null : (state.planner ||= new BrowserPlanner());
    const packageFile=$('migration-package').files[0],setFile=$('usb-set').files[0];
    if((packageFile?.size||0)>(32<<20) || (setFile?.size||0)>(32<<20)) fail('Migration artifact exceeds 32 MiB.');
    const args={planner,packageBytes:packageFile?new Uint8Array(await packageFile.arrayBuffer()):null,usbSetBytes:setFile?new Uint8Array(await setFile.arrayBuffer()):null,resume:!!state.migration,expertOffset};
    let prepared;
    for(let attempt=0;attempt<5;attempt++) {
      try { prepared=await esp.prepare(pkg,args);break; }
      catch(error) {
        if(!error.download) throw error;
        const {url}=error.download;
        $('download-firmware').href=httpsUrl(url);
        try { await planner.call('download',{url,bytes:await boundedFetch(url)}); }
        catch { fail('The migration host blocked the browser download. Use the Download link, select the exact migration ZIP / pinned USB set under Partition migration artifacts, and inspect again.'); }
      }
    }
    if(!prepared) fail('Could not resolve all exact migration artifacts.');
    state.plan = { ...prepared,generation:state.generation,port:state.port };
    $('device-name').textContent = `${info.chip} · ${info.mac}`; $('device-meta').textContent = `${size(info.flashBytes)} physical flash · ROM security checks passed`;
    if(prepared.needed) { $('migration-status').textContent=`Verified USB migration for ${prepared.board}; exact firmware ${prepared.firmware_version}. Keep this tab open until final verification.`; notice('Partition expansion is needed. Review & flash writes the verified USB bridge first. No application or bridge has been written yet.'); }
    else notice(`Read-only plan ready for ${info.mac}. Offsets: ${state.plan.addresses.map(n => '0x' + n.toString(16)).join(', ')}.`);
  }
  catch (error) { await closeEsp(); throw error; }
});
$('flash').onclick = () => operation(async () => {
  const plan = state.plan, pkg = state.pkg;
  if (!plan || plan.generation !== state.generation || plan.port !== state.port || plan.sha256 !== pkg.sha256) fail('Selection changed; inspect again.');
  const rak = pkg.architecture === 'nrf52' && /rak.?4631|wismesh/i.test(pkg.name), token = pkg.expert ? `WRITE 0x${plan.addresses[0].toString(16)}` : rak ? 'unknown-to-rak4631' : pkg.destructive ? 'WIPE WITHOUT BACKUP' : 'FLASH';
  const detail = `${pkg.name}\nSHA-256 ${pkg.sha256}\n${plan.mac ? 'Verified chip MAC ' + plan.mac : plan.uf2Info || 'Board identity unknown to this browser. Confirm the selected nRF52 board yourself.'}`;
  if(plan.needed && !plan.verified && !await confirm('Run USB partition expansion first?',`${plan.board} · ${plan.firmware_version} · ${plan.mac}`,'The verified middle firmware preserves supported identity/settings, not all logs or optional files. Power loss during partition-table replacement can require physical recovery. Keep this tab open and re-select the same chip when asked.','EXPAND PARTITIONS')) return;
  if (!await confirm('Write this firmware?',detail,pkg.warnings.join(' ') + ' Logical backups are not complete flash images. Keep power connected. Wrong bootloader firmware may require SWD recovery.',token)) return;
  if (plan.generation !== state.generation || plan.port !== state.port) fail('Device disconnected or selection changed during confirmation.');
  if (pkg.architecture === 'uf2') {
    if (hash(pkg.payload)!==pkg.payloadHash) fail('UF2 changed after validation.');
    const liveInfo=await (await (await state.directory.getFileHandle('INFO_UF2.TXT')).getFile()).text(); if(liveInfo.slice(0,2048)!==plan.uf2Info) fail('UF2 drive identity changed.');
    const handle=await state.directory.getFileHandle('MESHFW.UF2',{create:true}), stream=await handle.createWritable(); try { await stream.write(pkg.payload); await stream.close(); } catch(error) { await stream.abort().catch(()=>{}); throw error; }
    progress(1,'UF2 copy completed. Bootloader activation and application startup remain unverified.'); state.plan=null; notice('UF2 copy completed. A disappearing drive can indicate reboot; it is not proof the intended firmware started.');
  } else if (pkg.architecture === 'esp32') {
    if(plan.needed && !plan.verified) { state.migration={mac:plan.mac,sha256:pkg.sha256,uart:!!plan.uart_completion_status,settled:false,phase:'writing'}; localStorage.setItem('meshfirmware.pendingMigration',JSON.stringify(state.migration)); }
    await state.esp.flash(pkg,progress); plan.written = true;
    if(plan.needed && !plan.verified) {state.migration.phase='written';localStorage.setItem('meshfirmware.pendingMigration',JSON.stringify(state.migration));}
    notice(plan.needed && !plan.verified?'USB bridge write verified. Reset verified ESP32 to run the migration, wait for automatic ROM return, select the same device, then inspect again before the final firmware write.':'Target flash MD5 verified. Use Reset verified ESP32, then check application startup.');
    if(plan.verified) { state.migration=null; localStorage.removeItem('meshfirmware.pendingMigration'); }
  }
  else { const link = new SerialLink(state.port); try { await link.open(); await flashNrf(link,pkg,progress); notice('DFU transfer completed. Installed firmware / bootloader and application startup remain unverified.'); } finally { await link.close(); state.plan = null; } }
});
async function waitUartMigration() {
  if(!state.migration?.uart || state.migration.settled) fail('No unsettled UART migration is pending.');
  await closeEsp();
  notice('Waiting for the USB-UART bridge to finish restoring settings. No reset will be sent while waiting. Keep power connected.');
  const link=new SerialLink(state.port);
  try { await link.open(); await waitForMigration(link,state.migration.mac); }
  finally { await link.close(); }
  state.migration.settled=true; localStorage.setItem('meshfirmware.pendingMigration',JSON.stringify(state.migration));
  notice('Bridge reports settled. Inspect the same chip again to verify the physical partition table, NVS restoration flags and OTA state before the final write.');
}
$('wait-migration').onclick = ()=>operation(waitUartMigration);
$('recover-bridge').onclick=()=>operation(async()=>{
  if(!state.migration || state.pkg?.architecture!=='esp32' || state.pkg.sha256!==state.migration.sha256) fail('Select the original final firmware for this pending migration.');
  if($('transport-mode').value!=='no_reset') fail('Bridge recovery must connect to an already waiting ROM without any reset. Do not interrupt a running bridge.');
  await closeEsp();const esp=new EspSession(state.port,log);state.esp=esp;
  try {
    const info=await esp.connect('no_reset');if(info.mac!==state.migration.mac)fail('Different physical chip.');
    const recovered=await esp.recoverBridge(state.pkg,{planner:state.planner ||=new BrowserPlanner()});
    state.plan={...recovered,generation:state.generation,port:state.port,written:true};
    notice('Original USB bridge bytes match every target slot. Reset verified ESP32 is available once to start/restart that verified bridge. Final firmware still requires full migration proof.');
  } catch(error) {await closeEsp();throw error;}
});
$('finish').onclick = () => operation(async () => {
  if (!state.plan?.written) fail('No verified write to finish.');
  const bridge=state.plan.needed && !state.plan.verified;
  if(bridge) {state.migration.phase='running';localStorage.setItem('meshfirmware.pendingMigration',JSON.stringify(state.migration));}
  await state.esp.finish($('transport-mode').value !== 'default_reset'); await closeEsp();
  if(bridge && state.migration?.uart) await waitUartMigration();
  else if(bridge) {state.port=null;state.generation++;$('transport-mode').value='no_reset';$('port-status').textContent='Wait for ROM return';notice('Migration bridge started. Keep power connected, wait for its automatic ROM return, then choose the same USB device and inspect again without resetting it.');}
  else notice('Reset requested after verified writes. Re-select the application port and use Read running node to verify startup.');
});
$('backup').onclick = () => operation(async () => {
  if(state.migration) fail('Complete the pending partition migration before opening application USB APIs.');
  const backup=await linkOperation(async link=>$('backup-role').value === 'common-cli' ? backupCommonCli(link,progress) : new MeshCore(link).backup(progress));verifyBackup(backup);
  const filename=`mc.config_backup.web.${new Date().toISOString().replace(/[:.]/g,'-')}.json`;
  download(filename,JSON.stringify(backup,null,2),'application/json');$('backup-summary').textContent=`Downloaded ${filename}. Contains private settings when exposed. Logical backup only; not wipe-safe.`;notice('Backup integrity verified in browser memory and download requested. Confirm it was saved before wiping.');
});
$('backup-file').onchange = () => operation(async () => {
  state.restore=null;const file=$('backup-file').files[0];if(!file)return;if(file.size>(8<<20))fail('Backup exceeds 8 MiB.');
  const raw=await file.text();
  notice('Validating backup integrity locally…');
  const archive=await parseBackup(raw,{validatePython:args=>(state.planner ||=new BrowserPlanner()).call('validateBackup',args)}),p=verifyBackup(archive);state.restore=archive;
  $('backup-summary').textContent=p.role==='companion'?`Verified local archive: ${p.publicKey.slice(0,12)} · ${p.channels.length} channels · ${p.contacts.length} contacts. Nothing uploaded or restored.`:'Verified partial CommonCLI capture. Automatic restore is unavailable.';
});
$('restore').onclick = () => operation(async () => {
  const archive = state.restore, generation = state.generation, p = verifyBackup(archive);
  if (p.role !== 'companion') fail('Partial CommonCLI captures cannot be automatically restored.');
  if (!await confirm('Restore companion settings?',`Backup identity ${p.publicKey}. Different hardware: ${$('new-hardware').checked ? 'YES' : 'NO'}. Replace identity: ${$('replace-identity').checked ? 'YES' : 'NO'}.`,'This writes identity, channels, contacts and core settings. Firmware versions are diagnostic only and are never restored.',`RESTORE ${p.publicKey.slice(0,8)}`)) return;
  if (state.generation !== generation) fail('Selected device changed during confirmation.');
  await linkOperation(async link => new MeshCore(link).restore(archive,{newHardware:$('new-hardware').checked,replaceIdentity:$('replace-identity').checked},progress)); notice('Supported companion settings restored and read back. Review optional CLI snapshots separately.');
});
$('send-command').onclick = () => operation(async () => linkOperation(async link => { const command = $('command').value.trim(); if (!command || /[\r\n\x00]/.test(command)) fail('Enter one command.'); log($('backup-role').value === 'common-cli' ? await link.command(command) : await new MeshCore(link).cli(command)); }));
$('clear-log').onclick = () => { $('log').textContent = 'Log cleared locally.'; };
window.addEventListener('beforeunload',event => { if (state.busy) { event.preventDefault(); event.returnValue = ''; } });
if(state.migration) notice('A partition migration is pending in this browser. Keep power connected, select its original firmware and the same device. Application commands are blocked until final verification.');
if ('serial' in navigator) {
  $('browser-status').textContent = 'Web Serial available';
  navigator.serial.addEventListener('disconnect',event => { if (event.target === state.port || event.port === state.port) { state.generation++; state.plan = null; $('port-status').textContent = 'Disconnected'; log('Selected USB port disconnected. No different port will be substituted.'); controls(); } });
} else { $('browser-status').textContent = 'Web Serial unavailable'; notice('Use a browser with Web Serial support (typically desktop Chrome or Edge). Catalog browsing and local file inspection still work.',true); }
getCatalog().then(catalog => { state.items = catalog.items; $('catalog-status').textContent = `${state.items.length.toLocaleString()} artifacts · snapshot ${new Date(catalog.generatedAt).toLocaleString()} · ${catalog.warnings.length} provider warnings`; filterCatalog(); }).catch(error => { $('artifact').replaceChildren(new Option('Catalog unavailable · choose local firmware','')); $('catalog-status').textContent = error.message; controls(); });
controls();
