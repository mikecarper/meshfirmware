import './style.css';
import { inspectFirmware, checkedZip, hash, fail, text } from './firmware.js';
import { SerialLink, flashNrf, touch1200 } from './serial.js';
import { EspSession, validateEspWriteRecovery } from './esp.js';
import { getCatalog, httpsUrl, compareVersions } from './catalog.js';
import { MeshCore, backupCommonCli, verifyBackup, parseBackup, enterCompanionBinary, detectMeshCore, backupSummary } from './meshcore.js';
import { exportNativeBackup } from './backup-native.js';
import { assessBoard, rakFamily, endfIdentity } from './board-safety.js';
import { BrowserPlanner } from './planner.js';
import { waitForMigration } from './migration.js';

const $ = id => document.getElementById(id);
const state = { port: null, pkg: null, esp: null, plan: null, generation: 0, busy: false, items: [], restore: null, directory: null, archive:null, archiveContext:null, automaticSha:null, automaticShaName:null, planner:null, migration:null, downloaded:new Set(),item:null,device:null,backupApproved:null,backup:null,recovery:null,espRecovery:null,verification:null,handoff:false };
try { const pending=JSON.parse(localStorage.getItem('meshfirmware.pendingMigration') || 'null'); if(pending && /^[a-f0-9:]{17}$/i.test(pending.mac) && /^[a-f0-9]{64}$/.test(pending.sha256)) state.migration=pending; } catch { /* The worker still fails closed on any actual NVS migration state. */ }
for(const [key,field] of [['meshfirmware.nrfRecovery','recovery'],['meshfirmware.verifyApplication','verification']])try{const saved=JSON.parse(localStorage.getItem(key)||'null');if(saved&&/^[a-f0-9]{64}$/.test(saved.sha256))state[field]=field==='recovery'?{...saved,phase:'reselect-dfu',eraseComplete:saved.eraseComplete===true}:saved;}catch{}
try{const saved=JSON.parse(localStorage.getItem('meshfirmware.espRecovery')||'null');if(saved)state.espRecovery=validateEspWriteRecovery(saved);}catch{/* Invalid retry state never authorizes a write. */}
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
  $('flash').disabled ||= !state.plan || state.recovery?.phase==='reselect-dfu';
  $('finish').disabled ||= !state.esp || !state.plan?.written;
  $('wait-migration').disabled ||= !state.port || !state.migration?.uart || state.migration?.settled;
  $('recover-bridge').disabled ||= !state.port || !state.pkg || !state.migration;
  $('discard-esp-recovery').disabled ||= !state.espRecovery;
  $('restore').disabled ||= !state.restore || !state.port || state.restore.schema !== 'org.meshfirmware.web-backup/v1' || state.restore.payload.role !== 'companion';
  for (const id of ['touch','probe','backup','send-command','binary-mode','verify-app']) $(id).disabled ||= !state.port;
  $('verify-app').disabled ||= !state.verification;
  $('fetch-firmware').disabled ||= !$('artifact').value;
  $('load-bootloader').disabled ||= !$('bootloader-source').value;
  $('retry').disabled ||= !state.port||!state.pkg;
}
async function closeEsp() { const esp=state.esp;state.esp=null;state.plan=null;if(esp)await esp.close(); }
async function operation(callback) {
  if (state.busy) return; state.busy = true; controls();
  try { await callback(); }
  catch (error) {
    let retry=null;if(error.recovery)try{retry=validateEspWriteRecovery(error.recovery);}catch{}
    if(retry){
      state.espRecovery=retry;persistEspRecovery();
      try{await closeEsp();}catch(closeError){log(`Serial close: ${closeError.message}`);}
      state.port=null;state.generation++;$('transport-mode').value='no_reset';$('already-bootloader').checked=true;$('port-status').textContent='Select same ROM radio';
      const fresh=retry.attempts>=3||(retry.merged&&!retry.eraseComplete);
      notice(`${error.message} `+(fresh?'Chunked retry cannot continue: use Discard ESP retry record, then explicitly inspect and authorize a fresh write/wipe. Any partition migration remains pending.':"Select the SAME physical radio's waiting ROM port without resetting, inspect the original image, then acknowledge a bounded chunked retry."),true);
    }else notice(error.message || String(error),true);
    log(`Stopped: ${error.message || error}`);
  }
  finally { state.busy = false; controls(); }
}
async function linkOperation(callback) {
  if(state.migration) fail('A partition migration is pending. Application commands and backups are blocked until its final firmware write is verified.');
  if(state.recovery) fail('Finish the pending nRF52 recovery before opening application commands.');
  if(state.espRecovery) fail('An ESP32 write retry is pending. Re-select the same ROM radio and finish or explicitly discard its retry record before application commands.');
  if (!state.port) fail('Choose a USB port first.');
  if (dfuIds.has(portId(state.port)) || $('already-bootloader').checked) fail('Backup/application commands cannot run in DFU/ROM. Select the application port and clear Already in bootloader.');
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
function choose(title,detail,buttons) {
  $('question-title').textContent=title;$('question-detail').textContent=detail;
  const form=$('question-actions');form.replaceChildren(...buttons.map(([value,label])=>{const button=document.createElement('button');button.value=value;button.textContent=label;button.className=value==='backup'?'primary':'secondary';return button;}));
  const dialog=$('question-dialog');dialog.returnValue='cancel';dialog.showModal();return new Promise(resolve=>dialog.addEventListener('close',()=>resolve(dialog.returnValue),{once:true}));
}
function persistFlow(field,key) { if(state[field])localStorage.setItem(key,JSON.stringify(state[field]));else localStorage.removeItem(key); }
function persistEspRecovery(){try{persistFlow('espRecovery','meshfirmware.espRecovery');}catch{log(state.espRecovery?'ESP retry state could not be saved in browser storage. It remains in memory only; keep this page open until recovery finishes.':'The old ESP retry record could not be removed from browser storage and may reappear after reload. Keep this page open and review any stale retry record before another operation.');}}
function invalidateApplicationEvidence(){state.backupApproved=null;state.backup=null;state.device=null;state.handoff=false;}
function clearVerification(){state.verification=null;persistFlow('verification','meshfirmware.verifyApplication');}
const summaryText=s=>`${s.complete?'Complete exposed-API snapshot':'Partial backup'}; ${s.privateIdentity?'private identity included':'private identity unavailable'}. ${(s.reasons||[]).join(' ')}`;
async function readApplication(link) {
  const device=await detectMeshCore(link);state.device=device;
  $('device-name').textContent=device.name||device.model||'MeshCore';$('device-meta').textContent=`${device.model||device.role} · ${device.version||'version not reported'} · identity ${(device.publicKey||'').slice(0,12)}`;
  return device;
}
async function captureBackup() {
  const archive=await linkOperation(async link=>{
    const device=$('backup-role').value==='auto'?await readApplication(link):null;
    if(!device && !state.device) { try {await readApplication(link);}catch{/* Explicit interface choice is still attempted and independently validates identity. */} }
    return (device?.role||$('backup-role').value)==='common-cli'?backupCommonCli(link,progress):new MeshCore(link).backup(progress);
  });
  const info=state.port.getInfo(),native=await exportNativeBackup(archive,{usbIdentity:{vendor_id:info.usbVendorId??null,product_id:info.usbProductId??null},deviceHint:state.device?.model||$('hardware').value,sealNative:args=>(state.planner ||=new BrowserPlanner()).call('sealBackup',args)});
  const summary=backupSummary(archive),completeness=native.payload?.completeness;if(completeness){summary.complete=completeness.status==='api-snapshot-complete';summary.reasons=[...new Set([...summary.reasons,...(completeness.missing_required||[]).map(n=>'Missing '+n),...(completeness.optional_errors||[]).map(n=>'Query failed: '+n)])];}
  const filename=`mc.config_backup.web.${new Date().toISOString().replace(/[:.]/g,'-')}.json`;
  download(filename,JSON.stringify(native,null,2),'application/json');state.backup={archive,summary,filename,port:state.port};
  $('backup-summary').textContent=`Downloaded ${filename}. ${summaryText(summary)} Logical backup only; not wipe-safe. Confirm the download was saved.`;
  notice('Native-compatible archive validated locally; download requested. No backup or secret was uploaded.');return state.backup;
}
async function ensureBackup() {
  if(state.migration||state.recovery||state.espRecovery||(state.backupApproved?.sha256===state.pkg?.sha256&&state.backupApproved?.port===state.port))return;
  const bootloader=dfuIds.has(portId(state.port))||$('already-bootloader').checked;
  if(bootloader) {
    const answer=await choose('Backup cannot be done in ROM/DFU','The application is not running on this interface. Return to application firmware for a logical backup, or explicitly continue without one.',[['cancel','Cancel'],['skip','Continue without backup']]);
    if(answer!=='skip')fail('Cancelled before bootloader commands.');
  } else {
    const answer=await choose('Back up before entering the bootloader?','Recommended: export and validate the running MeshCore node before any reset, ROM entry or flash. Logical backups contain secrets and are not whole-flash images.',[['backup','Back up first'],['skip','Continue without backup'],['cancel','Cancel']]);
    if(answer==='cancel')fail('Cancelled before reset or flash.');
    if(answer==='backup') {
      let result;try{result=await captureBackup();}catch(error){if(!await confirm('Backup did not complete',error.message,'No reset or write has occurred. Continue only if you accept having no complete backup.','CONTINUE WITHOUT BACKUP'))throw error;}
      if(result){const saved=await choose('Confirm your backup download',`${result.filename}. ${summaryText(result.summary)} The browser cannot confirm the file reached disk.`,[['cancel','Cancel'],['saved','I saved the archive']]);if(saved!=='saved')fail('Backup save was not acknowledged.');
        if(result.summary.complete===false&&!await confirm('Continue with a partial backup?',summaryText(result.summary),'A partial logical archive cannot authorize a wipe.','CONTINUE WITH PARTIAL BACKUP'))fail('Partial-backup continuation cancelled.');}
    } else if(answer!=='skip')fail('Cancelled before reset or flash.');
    if(!state.device)try{await linkOperation(readApplication);}catch(error){log(`Application identity unavailable: ${error.message}`);}
  }
  state.backupApproved={sha256:state.pkg?.sha256||'touch',port:state.port,publicKey:state.device?.publicKey||null};
}
function selectedHardware(){return state.item?.hardware||$('hardware').value||state.recovery?.hardware||'';}
function boardAssessment(pkg){return assessBoard(pkg,{selectedHardware:selectedHardware(),deviceModel:state.device?.model||state.recovery?.deviceModel||''});}
async function acknowledgeBoard(pkg) {
  const check=boardAssessment(pkg);
  if(check.requiresOverride&&!await confirm('nRF52 board safety override',`Payload ${check.firmwareFamily}; connected ${check.deviceFamily}. ${check.reason}`,'A wrong board image or bootloader may need SWD recovery. This token authorizes only this write and this selected interface.',check.token))fail('Board override cancelled before writing.');
  return check;
}
async function erasePackage() {
  const file=$('erase-file').files[0];let name,bytes;
  if(file){if(file.size>(4<<20))fail('Erase ZIP exceeds 4 MiB.');name=file.name;bytes=new Uint8Array(await file.arrayBuffer());}
  else {const url=$('erase-source').value;if(!url)fail('Select this board’s erase ZIP, or choose its exact local erase ZIP. The final firmware has not been written.');name=new URL(url).pathname.split('/').pop();try{bytes=await boundedFetch(url);}catch{ $('download-firmware').href=httpsUrl(url);fail('Download the exact erase ZIP using Download, choose it under Erase ZIP, then inspect again.');}}
  const pkg=inspectFirmware(name,bytes);if(pkg.architecture!=='nrf52'||pkg.kind!=='application'||!pkg.erase)fail('Guided erase requires an application erase ZIP, never a bootloader/SoftDevice component. Load component replacements separately.');
  if(!/^official (?:SoftDevice v[67] erase payload|QSPI formatter payload\b)/.test(pkg.eraseEvidence||'')&&!await confirm('Custom erase application',`${pkg.name}\nPayload SHA-256 ${pkg.payloadHash}`,'Only the name marks this as an erase application. It is not one of the known official utilities. This permission does not waive board checks or the separate wipe acknowledgement.','CUSTOM ERASE'))fail('Custom erase cancelled.');return pkg;
}
function verificationRecord(pkg) {
  let identity=pkg.architecture==='nrf52'?pkg.firmwareIdentity:endfIdentity(pkg.payload);
  if(!identity&&pkg.merged){for(const part of state.esp?.plan?.parts||[]){if(part.type!==0||part.offset>=pkg.payload.length)continue;let end=Math.min(part.offset+part.size,pkg.payload.length);while(end>part.offset&&pkg.payload[end-1]===255)end--;identity=endfIdentity(pkg.payload.subarray(part.offset,end));if(identity)break;}}
  const family=pkg.architecture==='nrf52'?boardAssessment(pkg).payloadFamily:'unknown',model=state.device?.model||state.recovery?.deviceModel||null,roleText=state.item?.role||pkg.name,role=/companion/i.test(roleText)?'companion':/repeater|room|sensor/i.test(roleText)?'common-cli':null;
  return {sha256:pkg.sha256,name:pkg.name,architecture:pkg.architecture,publicKey:!pkg.destructive&&!state.recovery?state.device?.publicKey||null:null,model:['rak4631','rak3401'].includes(family)&&rakFamily(model)!==family?null:model,family,role,version:identity?.versionText||null};
}
function queueVerification(pkg){state.verification=verificationRecord(pkg);persistFlow('verification','meshfirmware.verifyApplication');}
function completeNrfTransfer(pkg){
  if(pkg.erase){notice('Erase transfer completed; no application startup is claimed. Select the intended final firmware.');return;}
  if(pkg.kind==='application'){queueVerification(pkg);notice('DFU transfer completed. Choose the application port: the page will verify role, identity, protected board family and payload version when available.');}
  else{clearVerification();notice('DFU component transfer completed. Installed bootloader/SoftDevice startup remains unverified; the completed recovery is released so you can select the application ZIP next.');}
  state.recovery=null;persistFlow('recovery','meshfirmware.nrfRecovery');state.handoff=false;state.backupApproved=null;
}
async function verifyApplication() {
  const expected=state.verification;if(!expected)fail('No flashed application is awaiting verification.');
  if(state.migration||state.recovery||dfuIds.has(portId(state.port)))fail('Choose the running application interface, not ROM/DFU.');
  await closeEsp();const link=new SerialLink(state.port);let device,version,layout;
  try {await link.open();device=await readApplication(link);if(expected.role&&expected.role!==device.role)fail('Running MeshCore interface does not match the selected firmware role.');if(expected.publicKey&&device.publicKey!==expected.publicKey)fail('Running application public identity differs from the pre-flash node. Startup verification failed.');
    if(expected.model&&device.model&&expected.model.toLowerCase()!==device.model.toLowerCase())fail('Running application model differs from the pre-flash device.');
    if(['rak4631','rak3401'].includes(expected.family)&&rakFamily(device.model)!==expected.family)fail('Running protected board family does not match the flashed payload.');
    const mc=device.role==='companion'?new MeshCore(link):null;
    version=mc?await mc.cli('version'):await link.command('ver',700);
    if(expected.version){const actual=/\bv?(\d+\.\d+\.\d+(?:\.\d+)?)/i.exec(version)?.[1],normalize=s=>s.replace(/^v/,'').replace(/(?:\.0)+$/,'');if(!actual||normalize(actual)!==normalize(expected.version))fail('Running firmware version does not match the verified payload.');}
    if(expected.architecture==='esp32'){layout=mc?await mc.cli('get storage.layout'):await link.command('get storage.layout',700);if(!/\bint:esp32-\d+K\b/i.test(layout))fail('Application answered, but storage-layout verification is unavailable or invalid. Flash transfer is verified; application verification remains incomplete.');}
  }finally{await link.close();}
  state.verification=null;state.handoff=false;state.backupApproved=null;persistFlow('verification','meshfirmware.verifyApplication');$('already-bootloader').checked=false;
  notice(`Application startup verified: ${device.name||device.model||device.role}. ${layout?'Storage layout answered. ':''}Physical USB serial is not exposed by Web Serial; the port was explicitly reselected.`);log(version);
}
async function clearFirmwareSelection() {
  // Invalidate before fetch, file I/O or validation can fail. A failed attempt
  // to replace an image must never leave the preceding write plan usable.
  state.pkg=null;state.plan=null;state.item=null;state.archive=null;state.archiveContext=null;state.directory=null;state.backupApproved=null;state.generation++;
  $('image-name').textContent='No image loaded';$('image-kind').textContent='—';$('image-size').textContent='—';$('image-sha').textContent='';$('image-warning').textContent='';
  for(const id of ['expert-fields','archive-picker','nrf-actions'])$(id).hidden=true;
  $('erase-source').replaceChildren();
  await closeEsp();
}
async function loadFirmware(name, bytes, item = null) {
  await clearFirmwareSelection();
  const exact=item?.name===name?item:state.items.find(i=>i.hardware===$('hardware').value&&i.name===name),hints=item||exact||state.items.find(i=>i.hardware===$('hardware').value);
  // Board-wide erase/bootloader hints may be reused for a custom file, never
  // the first catalog entry's unrelated role, variant, version or provider.
  const bootloaderInfo=hints?.bootloaderInfo&&new URL(hints.bootloaderInfo.url).pathname.split('/').pop()===name?hints.bootloaderInfo:null;
  item=exact|| (hints?{hardware:hints.hardware,erase:hints.erase||[],bootloader:hints.bootloader||[],...(bootloaderInfo?{bootloaderInfo}:{})}:null);
  const expected=$('expected-sha').value.trim().toLowerCase();
  if(expected&&(!/^[a-f0-9]{64}$/.test(expected)||expected!==hash(bytes)))fail('Published SHA-256 does not match the selected bytes.');
  $('image-name').textContent = 'No image loaded'; $('image-kind').textContent = '—'; $('image-size').textContent = '—'; $('image-sha').textContent = ''; $('expert-fields').hidden = true;
  if (/\.zip$/i.test(name)) {
    const entries = checkedZip(bytes,{maxEntries:8192,maxExpanded:512<<20,directoryOnly:true});
    if (!entries.some(e=>e.name==='manifest.json') || entries.length!==3) {
      const candidates=entries.filter(e=>/\.(?:bin|zip|uf2)$/i.test(e.name) && e.length>0 && e.length<(32<<20));
      if (!candidates.length) fail('No firmware images in this release archive.');
      state.archive=bytes;state.archiveContext=item?{hardware:item.hardware,erase:item.erase||[],bootloader:item.bootloader||[]}:null; $('archive-entry').replaceChildren(...candidates.map(e=>new Option(e.name,e.name))); $('archive-picker').hidden=false;
      notice('Release ZIP indexed without expanding every board. Select the exact image for your board.'); return;
    }
  }
  const pkg = inspectFirmware(name,bytes);
  state.pkg = pkg;state.item=item;state.backupApproved=null; $('image-name').textContent = pkg.name; $('image-kind').textContent = pkg.kind; $('image-size').textContent = size(bytes.length); $('image-sha').textContent = pkg.sha256; $('image-warning').textContent = [...pkg.warnings,...(selectedBootloader(pkg)?[bootloaderReinstallWarning]:[])].join(' ');
  $('nrf-actions').hidden=pkg.architecture!=='nrf52';$('erase-source').replaceChildren(...(item?.erase||state.recovery?.eraseUrls||[]).map(url=>new Option(new URL(url).pathname.split('/').pop(),url)));
  if(pkg.architecture==='nrf52')$('transport-mode').value='nrf52';
  $('expert-fields').hidden = !pkg.expert;
  progress(0,'Image validated locally. Inspect the device before confirmation.'); notice('Firmware loaded. No device data has been written.');
}
function options(id, values, placeholder) { const select = $(id), prior = select.value; select.replaceChildren(new Option(placeholder,''),...Array.from(new Set(values)).filter(Boolean).sort(id==='version'?compareVersions:undefined).map(v => new Option(v,v))); if ([...select.options].some(o => o.value === prior)) select.value = prior; }
function filterCatalog(changed = 'project') {
  let items = state.items.filter(i => i.project === $('project').value);
  for (const id of ['provider','hardware','role','version']) { if (['project','provider','hardware','role','version'].indexOf(id) > ['project','provider','hardware','role','version'].indexOf(changed)) options(id,items.map(i => i[id]),`All ${id === 'hardware' ? 'boards' : id + 's'}`); if ($(id).value) items = items.filter(i => i[id] === $(id).value); }
  items.sort((a,b)=>compareVersions(a.version,b.version));
  $('artifact').replaceChildren(new Option(`${items.length} artifacts · choose a file`,''),...items.map(item => new Option(`${[item.title,item.subtitle].filter(Boolean).join(' / ')} · ${item.name} · ${item.action}`,String(state.items.indexOf(item)))));
  try{localStorage.setItem('meshfirmware.selections',JSON.stringify(Object.fromEntries(['provider','hardware','role','version'].map(id=>[id,$(id).value]))));}catch{}
  updateDownload(); controls();
}
const bootloaderReinstallWarning='This combined SoftDevice/bootloader DFU ZIP requires reinstalling the exact compatible application afterward. Application-owned data is not guaranteed; make a backup before entering DFU.';
function selectedBootloader(pkg){const info=state.item?.bootloaderInfo;return info&&pkg.kind!=='application'&&pkg.sha256===info.sha256&&pkg.name===new URL(info.url).pathname.split('/').pop()?info:null;}
function setAutomaticSha(value,name=null){$('expected-sha').value=value||'';state.automaticSha=value||null;state.automaticShaName=value?name:null;}
function clearAutomaticSha(name=null){if(name&&name===state.automaticShaName)return;if(state.automaticSha&&$('expected-sha').value.trim().toLowerCase()===state.automaticSha)$('expected-sha').value='';state.automaticSha=null;state.automaticShaName=null;}
function updateDownload() { const item = $('artifact').value?state.items[Number($('artifact').value)]:null,info=item?.bootloaderInfo,urls=item?.architecture==='nrf52'?(info?[info.url]:[]):item?.bootloader||[];$('bootloader-source').replaceChildren(...urls.map(url=>new Option(`${info?(info.cached?'Last verified ':'')+'OTAFIX '+info.version+' · ':''}${new URL(url).pathname.split('/').pop()}`,url)));$('bootloader-detail').textContent=info?`${info.cached?'Latest release could not be checked; using our last verified stable':'Our stable'} OTAFIX ${info.version} · ${info.profile}. SHA-256 is checked before loading. ${bootloaderReinstallWarning}`:item?.bootloaderUnavailable||'Select a firmware artifact for its exact board-specific bootloader recommendation.';if (item) { $('download-firmware').href = item.url; $('download-firmware').removeAttribute('aria-disabled');$('catalog-detail').textContent=[item.subtitle,item.notice,item.releaseNotes,item.bootloaderUnavailable].filter(Boolean).join('\n'); } else { $('download-firmware').removeAttribute('href'); $('download-firmware').setAttribute('aria-disabled','true');$('catalog-detail').textContent=''; } }
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
  const previousApproval=state.backupApproved;await closeEsp();state.backupApproved=null;if(!state.handoff&&!state.recovery)state.device=null;state.port = port; state.generation++;
  $('device-name').textContent = `Selected USB ${portId(port)}`; $('device-meta').textContent = 'Port permission granted. Firmware and board identity are not yet verified.'; $('port-status').textContent = dfuIds.has(portId(port)) ? 'DFU port' : 'Port selected';
  if (dfuIds.has(portId(port))) $('transport-mode').value = 'nrf52';
  $('already-bootloader').checked=dfuIds.has(portId(port));
  if(state.recovery){if(!await confirm('Re-select the erased radio',state.recovery.name,'Confirm this selected serial DFU interface is the SAME physical radio. Every recovery port change needs a new acknowledgement.','SAME DEVICE')){state.port=null;fail('Recovery port confirmation cancelled.');}state.recovery.phase='final';persistFlow('recovery','meshfirmware.nrfRecovery');$('transport-mode').value='nrf52';notice(state.recovery.eraseComplete?'Original final firmware retained. Inspect this DFU port, then review the final write.':'Erase completion is uncertain. Inspect to retry the validated erase step before the final image; it will not be silently skipped.');return;}
  if(state.espRecovery){if(!await confirm('Re-select the interrupted ESP32',`${state.espRecovery.mac}\nOriginal image SHA-256 ${state.espRecovery.sha256}`,'Select the SAME physical radio already waiting in ROM. No reset or write is performed by this selection; its MAC and exact plan will be checked again.','SAME DEVICE')){state.port=null;fail('ESP retry port confirmation cancelled.');}$('transport-mode').value='no_reset';$('already-bootloader').checked=true;notice('Waiting ROM port selected. Load the original exact image and inspect; any chunked retry needs a separate acknowledgement.');return;}
  if(state.handoff&&!state.recovery&&!await confirm('Confirm bootloader handoff',state.device?.model||'Previously selected application','Web Serial does not expose the USB serial number. Confirm this is the same physical radio before reusing its pre-reset board evidence.','SAME DEVICE')){state.port=null;fail('Bootloader handoff confirmation cancelled.');}
  if(state.handoff&&previousApproval)state.backupApproved={...previousApproval,port};
  if(state.verification){state.backupApproved=null;if(!state.verification.publicKey&&!await confirm('Confirm application interface',state.verification.name,'The previous write may have replaced the node identity. Confirm this is the same physical device; Web Serial cannot read its USB serial.','SAME DEVICE')){state.port=null;fail('Application verification port confirmation cancelled.');}$('already-bootloader').checked=false;notice('Application port selected. Verifying running firmware without resetting it…');await verifyApplication();return;}
  notice('Port selected. No reset, flash or application probe was sent.');
});
$('transport-mode').onchange = () => operation(async () => { await closeEsp(); state.generation++; });
for (const id of ['expert-offset','migration-package','usb-set','flash-action','erase-source','erase-file']) $(id).onchange = () => operation(async()=>{await closeEsp();state.generation++;});
$('expected-sha').onchange = () => operation(async () => { state.automaticSha=null;state.automaticShaName=null;await closeEsp(); state.generation++; if (state.pkg && $('expected-sha').value.trim() && $('expected-sha').value.trim().toLowerCase() !== state.pkg.sha256) fail('SHA-256 mismatch. Flash plan invalidated.'); });
$('firmware-file').onchange = () => operation(async () => { const file = $('firmware-file').files[0]; if (!file) return; clearAutomaticSha(file.name);await clearFirmwareSelection();if (file.size > 64 << 20) fail('Firmware exceeds 64 MiB.'); await loadFirmware(file.name,new Uint8Array(await file.arrayBuffer())); });
$('load-entry').onclick = () => operation(async () => { const entry=$('archive-entry').value,archive=state.archive,item=state.archiveContext;await clearFirmwareSelection();if(!archive || !entry) fail('Select an archive entry.');const expected=$('expected-sha').value.trim().toLowerCase();if(expected&&(!/^[a-f0-9]{64}$/.test(expected)||hash(archive)!==expected))fail('Release ZIP SHA-256 does not match.');const files=checkedZip(archive,{maxEntries:8192,maxExpanded:512<<20,select:name=>name===entry});$('expected-sha').value='';await loadFirmware(entry.split('/').pop(),files[entry],item); });
$('fetch-custom').onclick = () => operation(async () => { clearAutomaticSha();await clearFirmwareSelection();const url=httpsUrl($('custom-url').value); $('download-firmware').href=url; try { await loadFirmware(new URL(url).pathname.split('/').pop(),await boundedFetch(url)); } catch(error) { throw new Error(`${error.message} If this host blocks browser fetches, download it and select the local file.`); } });
$('artifact').onchange = () => { updateDownload(); controls(); };
$('bootloader-source').onchange=controls;
$('load-bootloader').onclick=()=>operation(async()=>{const url=$('bootloader-source').value,item=$('artifact').value?state.items[Number($('artifact').value)]:null,info=item?.bootloaderInfo;await clearFirmwareSelection();if(!url||!item)fail('Choose an explicit board firmware artifact and its bootloader ZIP.');if(item.architecture==='nrf52'&&(!info||info.url!==url||!item.bootloader?.includes(url)))fail('No verified stable bootloader from our fork is available for this exact hardware. Select a custom ZIP manually if you intend a recovery.');$('download-firmware').href=httpsUrl(url);try{setAutomaticSha(info?.sha256||'',new URL(url).pathname.split('/').pop());const bytes=await boundedFetch(url);if(info&&bytes.length!==info.size)fail('Published bootloader size does not match the downloaded ZIP.');await loadFirmware(new URL(url).pathname.split('/').pop(),bytes,item);if(info)notice(`Our stable OTAFIX ${info.version} loaded and SHA-256 verified. ${bootloaderReinstallWarning}`);}catch(error){throw new Error(error.message+' If the host blocks fetching, download this exact bootloader ZIP and choose it locally.');}});
for (const id of ['project','provider','hardware','role','version']) $(id).onchange = () => filterCatalog(id);
$('fetch-firmware').onclick = () => operation(async () => {
  const item = $('artifact').value?state.items[Number($('artifact').value)]:null; if (!item) fail('Choose an artifact.');
  await clearFirmwareSelection();
  notice('Downloading firmware into browser memory…');
  try { setAutomaticSha(item.sha256||'',item.name);await loadFirmware(item.name,await boundedFetch(item.url),item); }
  catch (error) { throw new Error(`${error.message} If the firmware host blocks browser downloads (CORS), use Download and then choose that local file. No proxy or helper is used.`); }
});
$('touch').onclick = () => operation(async () => {
  if(state.migration) fail('A migration is pending. Do not reset the bridge. Complete or recover its verified migration first.');
  if(state.espRecovery)fail('An interrupted ESP32 write is pending. Select its waiting ROM port without another reset.');
  const mode = $('transport-mode').value;
  if (!['tinyusb','nrf52'].includes(mode)) fail('Use this only for TinyUSB applications or nRF52 runtime. Other modes enter ROM during inspection.');
  if (dfuIds.has(portId(state.port))) fail('Already a known DFU port; no 1200-baud touch is needed.');
  await ensureBackup();
  if (!await confirm('Enter USB bootloader?','This resets the selected application USB interface. A new port may appear.','Bluetooth may disconnect. Select the same physical device again after the touch.','ENTER BOOTLOADER')) return;
  await closeEsp();state.handoff=true; try { await touch1200(state.port,mode); } catch (error) { log(`The touch was interrupted (${error.message}). Delivery is uncertain; no second touch was sent.`); }
  state.handoff=true;state.port = null; state.generation++; $('port-status').textContent = 'Select bootloader port'; $('device-name').textContent = 'USB handoff requested'; notice('Choose USB port again for the same device. Set ESP32 to already in ROM, or select the nRF52 DFU port.');
  if (mode === 'tinyusb') $('transport-mode').value = 'no_reset';
});
$('probe').onclick = () => operation(async () => {
  if(state.migration) fail('Complete the pending migration before application queries.');
  await linkOperation(readApplication);notice('MeshCore interface, role and identity detected. No settings changed.');
});
$('verify-app').onclick=()=>operation(verifyApplication);
$('retry').onclick=()=>{if(state.esp)$('transport-mode').value='no_reset';return $('prepare').onclick();};
$('binary-mode').onclick=()=>operation(async()=>{
  if(!await confirm('Enter Full Companion binary mode?','Only use this for MeshCore Full Companion text mode.','This may persistently turn USB logging off so binary commands can work. It does not flash or reboot the radio.','BINARY MODE')) return;
  invalidateApplicationEvidence();await linkOperation(link=>enterCompanionBinary(link,{allowLoggingChange:true}));
  notice('Binary mode confirmed. USB logging is off; it will not be re-enabled automatically. Read the running node or create a backup.');
});
$('prepare').onclick = () => operation(async () => {
  const pkg = state.pkg; if (!pkg) fail('Load firmware first.'); await closeEsp();
  if(state.recovery&&state.recovery.sha256!==pkg.sha256)fail('nRF52 recovery is pending. Select its original final firmware; another image will not be substituted.');
  if(state.recovery&&state.recovery.phase!=='final')fail('Erase requires an explicit selection of the same radio’s newly enumerated DFU port.');
  if(state.migration && (pkg.architecture!=='esp32' || state.migration.sha256!==pkg.sha256)) fail('Select the original ESP32 firmware for the pending migration. No reset is permitted for another image.');
  if(state.espRecovery&&(pkg.architecture!=='esp32'||state.espRecovery.sha256!==pkg.sha256))fail('Select the original exact ESP32 firmware for this pending write retry.');
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
    await ensureBackup();
    if(!state.recovery&&!dfuIds.has(portId(state.port))&&!$('already-bootloader').checked){
      if(!await confirm('Enter nRF52 serial DFU?',state.device?.model||'Selected application interface','Backup was considered before this reset. Choose the same radio’s DFU serial port when it re-enumerates; no drive is used.','ENTER BOOTLOADER'))return;
      state.handoff=true;await touch1200(state.port,'nrf52');state.port=null;state.generation++;$('port-status').textContent='Select DFU port';notice('Choose the same radio’s DFU serial port, then inspect again. For an unlisted bootloader, check Already in bootloader.');return;
    }
    const wipe=!pkg.erase&&(state.recovery?!state.recovery.eraseComplete:$('flash-action').value==='wipe'),erasePkg=wipe?await erasePackage():null;
    state.plan = { generation:state.generation,port:state.port,sha256:pkg.sha256,erasePkg };notice(erasePkg?'Both final firmware and destructive erase ZIP validated. Review & flash runs erase first, retains the final image, and requires reselecting the same DFU radio before final write.':'DFU ZIP validated. Board identity and any directional override will be checked immediately before this write.'); return;
  }
  const mode = $('transport-mode').value;
  if(state.migration && !state.migration.uart && mode!=='no_reset') fail('Pending USB migration: use already in ROM / no reset. A reset could interrupt the bridge.');
  if(state.espRecovery&&mode!=='no_reset')fail('ESP32 write recovery must use the waiting ROM port without resetting it.');
  if (!['no_reset','usb_reset','default_reset'].includes(mode)) fail('Enter the ESP32 bootloader first, then explicitly select its ROM port.');
  if(state.migration?.uart&&!state.migration.settled){
    const beforeStart=['writing','written'].includes(state.migration.phase);
    if(!beforeStart||mode!=='no_reset')fail('The UART migration must report settled state before any ROM reset. Use Wait for migration; a pre-start write retry can only inspect an already waiting ROM without resetting it.');
  }
  const expertText = $('expert-offset').value.trim();
  const expertOffset = pkg.expert && /^(?:0x[0-9a-f]+|[0-9]+)$/i.test(expertText) ? Number(expertText) : undefined;
  if(pkg.expert && !Number.isSafeInteger(expertOffset)) fail('Enter the explicit flash offset for this component. No offset is guessed.');
  await ensureBackup();
  state.handoff=true;
  const esp = new EspSession(state.port,log); state.esp = esp;
  try {
    const info = await esp.connect(mode);
    if(state.migration && (state.migration.sha256!==pkg.sha256 || state.migration.mac!==info.mac)) fail('A migration is pending. Select its original firmware and the same physical chip.');
    if(state.espRecovery&&info.mac!==state.espRecovery.mac)fail('Different physical ESP32 chip: the interrupted write belongs to another MAC.');
    const planner = pkg.merged || pkg.expert ? null : (state.planner ||= new BrowserPlanner());
    const packageFile=$('migration-package').files[0],setFile=$('usb-set').files[0];
    if((packageFile?.size||0)>(32<<20) || (setFile?.size||0)>(32<<20)) fail('Migration artifact exceeds 32 MiB.');
    const args={planner,packageBytes:packageFile?new Uint8Array(await packageFile.arrayBuffer()):null,usbSetBytes:setFile?new Uint8Array(await setFile.arrayBuffer()):null,resume:!!state.migration,expertOffset,recovery:state.espRecovery};
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
    if(prepared.recoveryResolved){state.espRecovery=null;persistEspRecovery();}
    state.plan = { ...prepared,generation:state.generation,port:state.port };
    if(prepared.compatibilityWarnings?.length)log(prepared.compatibilityWarnings.join('\n'));
    $('device-name').textContent = `${info.chip} · ${info.mac}`; $('device-meta').textContent = `${size(info.flashBytes)} physical flash · ROM security checks passed`;
    if(prepared.chunkedRecovery)notice('Exact ESP32 write recovery plan verified for this MAC and image. Review & flash offers separately acknowledged 16 KiB writes with independent readback; no whole-chip erase is repeated.');
    else if(prepared.needed) { $('migration-status').textContent=`Verified USB migration for ${prepared.board}; exact firmware ${prepared.firmware_version}. Keep this tab open until final verification.`; notice(prepared.resume===false&&state.migration?'Original source layout verified. The partial bridge can be rewritten safely before it is started; review and acknowledge the migration again.':'Partition expansion is needed. Review & flash writes the verified USB bridge first. No application or bridge has been written yet.'); }
    else notice(`Read-only plan ready for ${info.mac}. Offsets: ${state.plan.addresses.map(n => '0x' + n.toString(16)).join(', ')}.${prepared.mirroredSlots?' Missing fallback slots will be populated and independently verified.':''}`);
  }
  catch (error) { await closeEsp(); throw error; }
});
$('flash').onclick = () => operation(async () => {
  const plan = state.plan, pkg = state.pkg;
  if (!plan || plan.generation !== state.generation || plan.port !== state.port || plan.sha256 !== pkg.sha256) fail('Selection changed; inspect again.');
  if(pkg.architecture==='nrf52')await acknowledgeBoard(pkg);
  if(plan.erasePkg)await acknowledgeBoard(plan.erasePkg);
  const token = pkg.expert ? `WRITE 0x${plan.addresses[0].toString(16)}` : pkg.destructive||plan.erasePkg ? 'WIPE WITHOUT BACKUP' : 'FLASH';
  const detail = `${pkg.name}\nSHA-256 ${pkg.sha256}\n${plan.mac ? 'Verified chip MAC ' + plan.mac : plan.uf2Info || 'Board identity unknown to this browser. Confirm the selected nRF52 board yourself.'}${selectedBootloader(pkg)?'\nOur OTAFIX '+selectedBootloader(pkg).version+' · '+selectedBootloader(pkg).profile+'\n'+bootloaderReinstallWarning:''}${plan.erasePkg?'\nERASE FIRST: '+plan.erasePkg.name+'\nSHA-256 '+plan.erasePkg.sha256+'\n'+plan.erasePkg.warnings.join(' '):''}`;
  let allowRevisionMismatch=false;
  if(plan.requiresRevisionOverride){if(!await confirm('ESP silicon-revision mismatch',detail+'\n'+(plan.compatibilityWarnings||[]).join('\n'),'The image is not compatible with the verified chip revision, or the constrained revision could not be verified. Force only if you accept that it may not boot. This does not override security, chip-family or flash bounds checks.',plan.revisionOverrideToken||'FORCE CHIP REVISION'))return;allowRevisionMismatch=true;}
  if(plan.chunkedRecovery&&!await confirm('Retry this exact ESP32 write in bounded chunks?',detail,'This retries only the verified same chip/image/addresses, in independent 16 KiB operations with readback. No automatic reconnect, reset or repeated whole-chip erase. At most three user-reselected recovery rounds are allowed.','RETRY IN CHUNKS'))return;
  if(plan.needed && !plan.verified && !await confirm('Run USB partition expansion first?',`${plan.board} · ${plan.firmware_version} · ${plan.mac}`,'The verified middle firmware preserves supported identity/settings, not all logs or optional files. Power loss during partition-table replacement can require physical recovery. Keep this tab open and re-select the same chip when asked.','EXPAND PARTITIONS')) return;
  if (!await confirm('Write this firmware?',detail,[...pkg.warnings,...(plan.compatibilityWarnings||[])].join(' ') + ' Logical backups are not complete flash images. Keep power connected. Wrong bootloader firmware may require SWD recovery.',token)) return;
  if (plan.generation !== state.generation || plan.port !== state.port) fail('Device disconnected or selection changed during confirmation.');
  clearVerification();
  if(plan.erasePkg){
    state.recovery={sha256:pkg.sha256,name:pkg.name,hardware:selectedHardware(),deviceModel:state.device?.model||null,eraseUrls:state.item?.erase||state.recovery?.eraseUrls||[],phase:'erasing',eraseComplete:false};persistFlow('recovery','meshfirmware.nrfRecovery');
    const link=new SerialLink(state.port);try{await link.open();await flashNrf(link,plan.erasePkg,progress);state.recovery.eraseComplete=true;}finally{await link.close();state.recovery.phase='reselect-dfu';persistFlow('recovery','meshfirmware.nrfRecovery');state.port=null;state.plan=null;state.generation++;$('port-status').textContent='Select same DFU radio';}
    notice('Erase transfer completed. The original final ZIP remains loaded. Choose the SAME radio’s new DFU serial interface, inspect, then confirm its final firmware write.');return;
  }
  if (pkg.architecture === 'uf2') {
    if (hash(pkg.payload)!==pkg.payloadHash) fail('UF2 changed after validation.');
    const liveInfo=await (await (await state.directory.getFileHandle('INFO_UF2.TXT')).getFile()).text(); if(liveInfo.slice(0,2048)!==plan.uf2Info) fail('UF2 drive identity changed.');
    const handle=await state.directory.getFileHandle('MESHFW.UF2',{create:true}), stream=await handle.createWritable(); try { await stream.write(pkg.payload); await stream.close(); } catch(error) { await stream.abort().catch(()=>{}); throw error; }
    progress(1,'UF2 copy completed. Bootloader activation and application startup remain unverified.'); state.plan=null; notice('UF2 copy completed. A disappearing drive can indicate reboot; it is not proof the intended firmware started.');
  } else if (pkg.architecture === 'esp32') {
    if(plan.needed && !plan.verified) { state.migration={mac:plan.mac,sha256:pkg.sha256,uart:!!plan.uart_completion_status,settled:false,phase:'writing'}; localStorage.setItem('meshfirmware.pendingMigration',JSON.stringify(state.migration)); }
    await state.esp.flash(pkg,progress,{allowRevisionMismatch,chunkedRecovery:!!plan.chunkedRecovery}); plan.written = true;
    state.espRecovery=null;persistEspRecovery();
    if(plan.needed && !plan.verified) {state.migration.phase='written';localStorage.setItem('meshfirmware.pendingMigration',JSON.stringify(state.migration));}
    notice(plan.needed && !plan.verified?'USB bridge write verified. Reset verified ESP32 to run the migration, wait for automatic ROM return, select the same device, then inspect again before the final firmware write.':'Target flash MD5 verified. Use Reset verified ESP32, then check application startup.');
    if(plan.verified) { state.migration=null; localStorage.removeItem('meshfirmware.pendingMigration'); }
    if(!plan.needed||plan.verified)queueVerification(pkg);
  }
  else { const link = new SerialLink(state.port); try { await link.open(); await flashNrf(link,pkg,progress);completeNrfTransfer(pkg); } finally { await link.close(); state.plan = null; } }
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
$('discard-esp-recovery').onclick=()=>operation(async()=>{
  if(!state.espRecovery)fail('No ESP32 retry record is pending.');
  if(!await confirm('Discard the interrupted-write retry record?',`${state.espRecovery.mac}\nImage SHA-256 ${state.espRecovery.sha256}`,'This only discards the browser retry record, not on-device data. It does not undo a partial write. A fresh write requires a new inspection and confirmation. Pending partition-migration state is retained and still must be completed safely.','DISCARD RETRY STATE'))return;
  state.espRecovery=null;persistEspRecovery();await closeEsp();state.port=null;state.generation++;
  notice('ESP retry record discarded; no device commands were sent. Re-select and inspect before a fresh write. '+(state.migration?'The partition migration remains pending; use its original image and a no-reset ROM connection.':''));
});
$('finish').onclick = () => operation(async () => {
  if (!state.plan?.written) fail('No verified write to finish.');
  const bridge=state.plan.needed && !state.plan.verified;
  if(bridge) {state.migration.phase='running';localStorage.setItem('meshfirmware.pendingMigration',JSON.stringify(state.migration));}
  await state.esp.finish($('transport-mode').value !== 'default_reset'); await closeEsp();
  if(bridge && state.migration?.uart) await waitUartMigration();
  else if(bridge) {state.port=null;state.generation++;$('transport-mode').value='no_reset';$('port-status').textContent='Wait for ROM return';notice('Migration bridge started. Keep power connected, wait for its automatic ROM return, then choose the same USB device and inspect again without resetting it.');}
  else {state.port=null;state.generation++;$('already-bootloader').checked=false;notice('Reset requested after verified writes. Choose the application port; startup and storage layout will be verified automatically.');}
});
$('backup').onclick = () => operation(async () => {
  await captureBackup();
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
  invalidateApplicationEvidence();const result=await linkOperation(async link => new MeshCore(link).restore(archive,{newHardware:$('new-hardware').checked,replaceIdentity:$('replace-identity').checked},progress));
  if(result?.warnings?.length)log(result.warnings.join('\n'));
  notice('Supported companion settings restored and read back. '+(result?.warnings?.length?result.warnings.join(' ')+' ':'')+'Review optional CLI snapshots separately.');
});
$('send-command').onclick = () => operation(async () => {const command=$('command').value.trim();if(!command||/[\r\n\x00]/.test(command))fail('Enter one command.');invalidateApplicationEvidence();try{await linkOperation(async link=>{const role=$('backup-role').value==='auto'?(await readApplication(link)).role:$('backup-role').value;log(role==='common-cli'?await link.command(command):await new MeshCore(link).cli(command));});}finally{invalidateApplicationEvidence();}});
$('clear-log').onclick = () => { $('log').textContent = 'Log cleared locally.'; };
window.addEventListener('beforeunload',event => { if (state.busy) { event.preventDefault(); event.returnValue = ''; } });
if(state.migration) notice('A partition migration is pending in this browser. Keep power connected, select its original firmware and the same device. Application commands are blocked until final verification.');
if(state.recovery)notice('An nRF52 erase/recovery is pending. Select its original final ZIP and explicitly choose the same radio’s DFU port.');
if(state.espRecovery)notice('An interrupted ESP32 write is pending. Select its original exact image and the same radio’s waiting ROM port without resetting it.');
if ('serial' in navigator) {
  $('browser-status').textContent = 'Web Serial available';
  navigator.serial.addEventListener('disconnect',event => { if (event.target === state.port || event.port === state.port) { state.generation++; state.plan = null;if(!state.handoff&&!state.recovery&&!state.migration){state.device=null;state.backupApproved=null;} $('port-status').textContent = 'Disconnected'; log('Selected USB port disconnected. No different port will be substituted.'); controls(); } });
} else { $('browser-status').textContent = 'Web Serial unavailable'; notice('Use a browser with Web Serial support (typically desktop Chrome or Edge). Catalog browsing and local file inspection still work.',true); }
getCatalog().then(catalog => { state.items = catalog.items; $('catalog-status').textContent = `${state.items.length.toLocaleString()} artifacts · snapshot ${new Date(catalog.generatedAt).toLocaleString()} · ${catalog.warnings.length} provider warnings${catalog.cached?' · cached':''}`;let saved={};try{saved=JSON.parse(localStorage.getItem('meshfirmware.selections')||'{}');}catch{}filterCatalog();for(const id of ['provider','hardware','role','version']){if([...$(id).options].some(o=>o.value===saved[id])){$(id).value=saved[id];filterCatalog(id);}} }).catch(error => { $('artifact').replaceChildren(new Option('Catalog unavailable · choose local firmware','')); $('catalog-status').textContent = error.message; controls(); });
controls();
