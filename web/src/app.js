import './style.css';
import { inspectFirmware, checkedZip, hash, fail, text } from './firmware.js';
import { SerialLink, flashNrf, touch1200 } from './serial.js';
import { EspSession, validateEspWriteRecovery } from './esp.js';
import { getCatalog, catalogProvider, catalogItemKey, httpsUrl, compareVersions } from './catalog.js';
import { MeshCore, backupCommonCli, verifyBackup, parseBackup, enterCompanionBinary, detectMeshCore, backupSummary, cleanCliReply } from './meshcore.js';
import { exportNativeBackup } from './backup-native.js';
import { assessBoard, rakFamily, endfIdentity } from './board-safety.js';
import { BrowserPlanner } from './planner.js';
import { waitForMigration } from './migration.js';
import { recoveryPackage } from './bootloader-recovery.js';
import { detectBoard, detectRecoveryProfile } from './board-detection.js';
import { chooseFirmware, firmwareVersionWarning, matchesCatalogInstallMode } from './automatic.js';
import { chooseConnection } from './connection-choice.js';
import { MigrationApproval } from './migration-approval.js';
import { assessBootloaderVersion } from './bootloader-version.js';
import { fetchFirmwareBytes } from './downloads.js';

const $ = id => document.getElementById(id);
const state = { installMode:'update', port: null, pkg: null, esp: null, plan: null, generation: 0, busy: false, items: [], restore: null, directory: null, archive:null, archiveContext:null, automaticSha:null, automaticShaName:null, recoveryCatalog:null,loadedRecovery:null,planner:null, migration:null, downloaded:new Set(),item:null,device:null,manualSelections:{},detectedHardware:null,connection:null,boardDetected:false,recoveryManual:false,recoveryDetectionRequested:false,backupApproved:null,backup:null,recovery:null,espRecovery:null,verification:null,handoff:false };
// This write authorization is deliberately never saved in browser storage.
state.migrationApproval=null;state.approvalPort=null;state.approvalResetPort=null;state.approvalResumeRequested=null;
state.backupTextGeneration=0;
const bootloaderOffersShown=new Set();
try { const pending=JSON.parse(localStorage.getItem('meshfirmware.pendingMigration') || 'null'); if(pending && /^[a-f0-9:]{17}$/i.test(pending.mac) && /^[a-f0-9]{64}$/.test(pending.sha256)) state.migration=pending; } catch { /* The worker still fails closed on any actual NVS migration state. */ }
for(const [key,field] of [['meshfirmware.nrfRecovery','recovery'],['meshfirmware.verifyApplication','verification']])try{const saved=JSON.parse(localStorage.getItem(key)||'null');if(saved&&/^[a-f0-9]{64}$/.test(saved.sha256))state[field]=field==='recovery'?{...saved,phase:'reselect-dfu',eraseComplete:saved.eraseComplete===true}:saved;}catch{}
try{const saved=JSON.parse(localStorage.getItem('meshfirmware.espRecovery')||'null');if(saved)state.espRecovery=validateEspWriteRecovery(saved);}catch{/* Invalid retry state never authorizes a write. */}
// Restore only an already pending, hash-bound recovery's display mode, never a
// general erase preference. Every new page otherwise starts in Update.
if(state.recovery||state.espRecovery?.merged)state.installMode='install';
// Exact bootloader IDs shared with the native classifier. Never match a broad
// vendor/product range: nearby application IDs must still be probed normally.
const dfuIds = new Set(['2886:0044','2886:0045','2886:0057','2886:1667','239a:0029','239a:002a','239a:0071','239a:00b3','239a:00da']);
const portId = port => { const info = port?.getInfo() || {}; return info.usbVendorId === undefined ? 'USB serial' : [info.usbVendorId,info.usbProductId].map(n => n.toString(16).padStart(4,'0')).join(':'); };
const size = bytes => `${(bytes / (1 << 20)).toFixed(2)} MiB`;
function log(message) { $('log').textContent = ($('log').textContent + '\n' + String(message).replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'')).slice(-100000); $('log').scrollTop = $('log').scrollHeight; }
function notice(message, error = false) { $('notice').textContent = message; $('notice').classList.toggle('error',error); }
function progress(value, message) { $('progress').value = value; $('progress-label').textContent = message; }
const readinessError=error=>!/permission|denied|not.?allowed|security/i.test(`${error.name} ${error.message}`)&&/timeout|timed out|no response|did not|disconnect|not.?found|network|not open|unavailable|failed to connect|no serial data|invalid head of packet/i.test(`${error.name} ${error.message}`);
function revokeMigrationAutomation(reason=''){
  const approval=state.migrationApproval;if(approval)approval.revoke();
  state.migrationApproval=null;state.approvalPort=null;state.approvalResetPort=null;state.approvalResumeRequested=null;
  if(approval&&reason)log(reason);
}
function revealPanel(id) {
  const target=$(id);
  for(let panel=target;panel;panel=panel.parentElement)if(panel===target||panel.tagName==='DETAILS'){panel.hidden=false;panel.open=true;}
}
function openLinkedPanel() {
  const id=window.location?.hash?.slice(1);
  // Only known tool links are expanded; arbitrary fragments are not selectors.
  if(['backups','console','capabilities','advanced-options'].includes(id))revealPanel(id);
}
function installModeLocked(){
  return !!(state.migrationApproval||state.migration||state.recovery||state.espRecovery||state.verification||state.plan?.written||(state.handoff&&!state.esp));
}
function syncInstallMode(){
  $('install-mode-update').checked=state.installMode==='update';$('install-mode-install').checked=state.installMode==='install';
  $('flash-action').value=state.installMode==='install'?'wipe':'update';
  const modeLabel=state.installMode==='install'?'install':'update';
  $('prepare-label').textContent=`Backup & prepare ${modeLabel}`;
  $('prepare').setAttribute('aria-label',`Step 3: Backup and prepare ${modeLabel}`);
  const locked=installModeLocked();for(const id of ['install-mode-update','install-mode-install'])$(id).disabled=state.busy||locked;
  const component=state.pkg&&(state.pkg.expert||(state.pkg.architecture==='nrf52'&&(state.pkg.kind!=='application'||state.pkg.erase)));
  $('install-mode-hint').textContent=locked?'Finish the pending USB handoff, recovery, migration or verification before changing the installation mode. The original image and recovery checks are retained.':component?'Advanced component/recovery file loaded. Its own board, offset and destructive-write checks still apply; this switch filters application builds.':state.installMode==='install'?'Erase & new install deletes node identity and settings. ESP32 uses a merged image; nRF52 validates an erase ZIP first, then writes the application after you reselect the same radio.':'Update writes the application without a whole-chip erase. Required partition migration is checked separately.';
  $('install-mode-hint').classList.toggle('mode-warning',state.installMode==='install'||!!component);
}
function modePairKey(item){
  return catalogItemKey({...item,name:item.name.replace(/-merged(?=\.bin$)/i,''),url:'',sha256:undefined,action:'',artifactTitle:''});
}
async function setInstallMode(mode){
  if(!['update','install'].includes(mode))fail('Choose Update or Erase & new install.');
  if(mode===state.installMode)return;
  if(installModeLocked())fail('Finish the pending handoff, recovery, migration or verification before changing installation mode.');
  const previous=$('artifact').value?state.items[Number($('artifact').value)]:state.item?.role?state.item:null;
  clearAutomaticSha();await clearFirmwareSelection();state.handoff=false;state.installMode=mode;syncInstallMode();filterCatalog();
  const pairs=previous?state.items.map((item,index)=>({item,index})).filter(({item})=>matchesCatalogInstallMode(item,mode)&&modePairKey(item)===modePairKey(previous)):[];
  if(pairs.length===1&&[...$('artifact').options].some(option=>option.value===String(pairs[0].index))){
    $('artifact').value=String(pairs[0].index);updateDownload();updateFirmwareSelectionSummary({item:pairs[0].item});
  }else if(!previous&&$('auto-detect-board').checked)applyAutomaticSelections();
  else updateFirmwareSelectionSummary({item:null,reason:'Choose the exact build for this installation mode. No different screen, radio or storage profile was substituted.'});
  controls();
}
function assertInstallModePackage(pkg){
  // Existing continuation checks bind these flows to their original image.
  // Their recorded eraseComplete state, not a fresh mode choice, controls retry.
  if(state.recovery||state.migration||state.espRecovery)return;
  if(pkg.architecture==='esp32'&&!pkg.expert){
    if(pkg.merged&&state.installMode!=='install')fail('This is a merged erase/new install image. Select Erase & new install and load the matching build before preparing. No reset or write was sent.');
    if(!pkg.merged&&state.installMode==='install')fail('Erase & new install requires a validated merged ESP32 image, not an application-only update. Choose the matching merged build. No reset or write was sent.');
  }
  if(pkg.architecture==='uf2'&&state.installMode==='install')fail('Erase & new install is not supported by the UF2 drive-copy path. No erase is implied; use the board-specific recovery procedure.');
}
function updateStepGuidance(buildChoiceNeeded=false){
  let message;
  if(state.migrationApproval)message=state.busy?'Automatically completing the approved expansion and final firmware. Keep USB and power connected.':'Automatic completion is waiting for the same radio. Its granted USB port resumes automatically; if it does not return, use step 1 to select it. No Prepare/Flash presses are needed.';
  else if(state.busy)message='Follow the current prompt. Keep the radio connected and power stable.';
  else if(state.verification)message=state.port?'Follow the verification controls to restart verified firmware, then use step 1 for its application port and startup check.':'Step 1 again: choose the same radio’s application port to check that the new firmware started.';
  else if(state.plan?.written)message='Transfer finished; startup is not yet verified. Follow the verification controls before starting another update.';
  else if(state.recovery?.phase==='reselect-dfu'||(state.handoff&&!state.port))message='Step 1 again: choose the same radio’s requested USB port. Then repeat step 3: Backup & prepare before step 4: Flash.';
  else if(!state.port)message='Step 1: Choose your radio’s USB port. Then step 2: choose Update or Erase & new install and check the firmware.';
  else if(state.plan)message='Step 4: Review & flash. Check the warning and confirm the exact operation; nothing is written before confirmation.';
  else if(buildChoiceNeeded)message='Step 2.5: Choose a firmware build. Then step 3: Backup & prepare.';
  else if(!state.pkg&&!$('artifact').value)message='Step 2: Choose Update or Erase & new install and check the firmware build. Then step 3: Backup & prepare.';
  else message='Step 3: Backup & prepare. Follow the backup prompts and USB-port instructions; step 4 flashes only after confirmation.';
  $('step-guidance').textContent=message;
}
function updateArtifactChoiceHighlight(){
  const picker=$('artifact'),hasChoices=[...picker.options].some(option=>option.value!==''&&!option.disabled);
  const needed=!!state.port&&!state.busy&&!state.pkg&&!picker.value&&hasChoices&&!continuingDeviceFlow();
  $('artifact-field').classList.toggle('choice-required',needed);
  $('artifact-required').hidden=!needed;$('artifact-choice-hint').hidden=!needed;
  if(needed)picker.setAttribute('aria-label','Step 2.5: Firmware build');else picker.removeAttribute('aria-label');
  picker.setAttribute('aria-required',String(needed));
  if(needed)$('firmware-choices').open=true;
  return needed;
}
function controls() {
  document.querySelectorAll('[data-lock]').forEach(el => { el.disabled = state.busy; });
  $('select-port').disabled ||= !('serial' in navigator);
  $('prepare').disabled ||= (!state.pkg&&!$('artifact').value) || (!state.port && state.pkg?.architecture !== 'uf2');
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
  $('load-recovery').disabled ||= !state.recoveryCatalog||!$('recovery-profile').value;
  $('retry').disabled ||= !state.port||!state.pkg;
  syncInstallMode();
  updateStepGuidance(updateArtifactChoiceHighlight());
  updateBootloaderOffer();
  // Extras stay collapsed for ordinary updates, but never conceal a required
  // recovery/migration step or a deliberately selected destructive action.
  if(state.espRecovery)revealPanel('esp-retry-options');
  if(state.migration||state.plan?.needed)revealPanel('migration-options');
  if(state.recovery||(!$('nrf-actions').hidden&&$('flash-action').value==='wipe'))revealPanel('nrf-actions');
  if(state.verification||state.plan?.written)revealPanel('verification-options');
  if(state.migrationApproval){
    document.querySelectorAll('[data-lock]').forEach(el=>{el.disabled=true;});
    $('select-port').disabled=state.busy||!('serial'in navigator)||!['waiting-rom','waiting-application'].includes(state.migrationApproval.phase);
  }
  $('stop-migration-auto').hidden=!state.migrationApproval;
  $('stop-migration-auto').disabled=!state.migrationApproval;
  $('stop-migration-auto').textContent=state.busy?'Stop after the current step':'Stop automatic continuation';
}
async function closeEsp() { const esp=state.esp;state.esp=null;state.plan=null;if(esp)await esp.close(); }
async function operation(callback) {
  if (state.busy) return; state.busy = true; controls();
  try { await callback(); }
  catch (error) {
    revokeMigrationAutomation('Automatic migration approval revoked after an error. No automatic write or reset retry is permitted.');
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
  finally {
    state.busy=false;controls();
    const pending=state.approvalResumeRequested;state.approvalResumeRequested=null;
    if(pending&&state.migrationApproval?.phase===pending.phase)void operation(()=>resumeApprovedPort(pending.port));
  }
}
async function linkOperation(callback) {
  if(state.migration) fail('A partition migration is pending. Application commands and backups are blocked until its final firmware write is verified.');
  if(state.recovery) fail('Finish the pending nRF52 recovery before opening application commands.');
  if(state.espRecovery) fail('An ESP32 write retry is pending. Re-select the same ROM radio and finish or explicitly discard its retry record before application commands.');
  if (!state.port) fail('Choose a USB port first.');
  if (dfuIds.has(portId(state.port)) || $('already-bootloader').checked) fail('Backup/application commands cannot run in DFU/ROM. Select the application port and clear Already in bootloader.');
  await closeEsp(); const link = new SerialLink(state.port);
  try { await link.open(115200,{application:true}); return await callback(link); } finally { await link.close(); }
}
function confirm(title, detail, warning, token) {
  $('confirm-title').textContent = title; $('confirm-detail').textContent = detail; $('confirm-warning').textContent = warning; $('token-label').textContent = token; $('confirm-token').value = ''; $('confirm-submit').disabled = true;
  $('confirm-token').oninput = () => { $('confirm-submit').disabled = $('confirm-token').value !== token; };
  const dialog = $('confirm-dialog'); dialog.returnValue = ''; dialog.showModal();
  return new Promise(resolve => dialog.addEventListener('close',() => resolve(dialog.returnValue === 'confirm' && $('confirm-token').value === token),{once:true}));
}
function download(name, bytes, type = 'application/octet-stream') { const url = URL.createObjectURL(new Blob([bytes],{type})); const a = document.createElement('a'); a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url),30000); }
function choose(title,detail,buttons,{backupJson=null,backupWarning=''}={}) {
  $('question-title').textContent=title;$('question-detail').textContent=backupJson?'':detail;$('question-detail').hidden=!!backupJson;
  state.backupTextGeneration++;
  $('question-backup-json-view').hidden=!backupJson;$('question-backup-json').value=backupJson||'';$('question-backup-json-status').textContent='';
  $('question-backup-summary').textContent=backupJson?backupWarning:'';$('question-backup-summary').hidden=!backupJson||!backupWarning;
  const form=$('question-actions');form.replaceChildren(...buttons.map(([value,label])=>{const button=document.createElement('button');button.value=value;button.textContent=label;button.className=['backup','continue'].includes(value)?'primary':'secondary';return button;}));
  const dialog=$('question-dialog');dialog.returnValue='cancel';dialog.showModal();return new Promise(resolve=>dialog.addEventListener('close',()=>{state.backupTextGeneration++;$('question-backup-json').value='';$('question-backup-json-view').hidden=true;$('question-backup-summary').textContent='';$('question-backup-summary').hidden=true;resolve(dialog.returnValue);},{once:true}));
}
function persistFlow(field,key) { if(state[field])localStorage.setItem(key,JSON.stringify(state[field]));else localStorage.removeItem(key); }
function persistEspRecovery(){try{persistFlow('espRecovery','meshfirmware.espRecovery');}catch{log(state.espRecovery?'ESP retry state could not be saved in browser storage. It remains in memory only; keep this page open until recovery finishes.':'The old ESP retry record could not be removed from browser storage and may reappear after reload. Keep this page open and review any stale retry record before another operation.');}}
function invalidateApplicationEvidence(){clearBackupJson();state.backupApproved=null;state.backup=null;state.device=null;state.boardDetected=false;state.handoff=false;}
function clearVerification(){state.verification=null;persistFlow('verification','meshfirmware.verifyApplication');}
const summaryText=s=>`${s.complete?'Complete exposed-API snapshot':'Partial backup'}; ${s.privateIdentity?'private identity included':'private identity unavailable'}. ${(s.reasons||[]).join(' ')}`;
async function readApplication(link) {
  const port=state.port,generation=state.generation,device=await detectMeshCore(link);
  if(state.port!==port||state.generation!==generation)fail('Selected port changed or disconnected while reading the node. Re-select and detect again.');
  const board=detectBoard({items:state.items,deviceModel:device.model,usbInfo:port?.getInfo()||{}});
  const architectures=new Set(state.items.filter(i=>i.hardware===board.hardware).map(i=>i.architecture));
  if(board.hardware&&architectures.size===1)device.architecture=[...architectures][0];
  device.bootloaderVersion=null;
  if(device.architecture==='nrf52'&&!dfuIds.has(portId(port))&&!$('already-bootloader').checked){
    try{
      const command='get bootloader.ver';
      const reply=device.role==='common-cli'?await link.command(command,350):device.role==='companion'&&device.protocol>=14?await new MeshCore(link,{timeoutMs:700}).cli(command):null;
      device.bootloaderVersion=reply===null?null:cleanCliReply(reply,command);
    }catch{/* Optional read-only version reporting must never block application updates. */}
    if(state.port!==port||state.generation!==generation)fail('Selected port changed or disconnected while checking the bootloader. Re-select and detect again.');
  }
  state.device=device;
  refreshFirmwareWarnings();
  $('device-name').textContent=device.name||device.model||'MeshCore';$('device-meta').textContent=`${device.model||device.role} · ${device.version||'version not reported'} · identity ${(device.publicKey||'').slice(0,12)}`;
  return device;
}
function selectDetectedBoard() {
  const result=detectBoard({items:state.items,deviceModel:state.device?.model||'',usbInfo:state.port?.getInfo()||{}});
  if(result.hardware){
    state.detectedHardware=result.hardware;
    const architectures=new Set(state.items.filter(i=>i.hardware===result.hardware).map(i=>i.architecture));
    if(architectures.size===1&&state.device)state.device.architecture=[...architectures][0];
    const provider=$('provider').value;
    if(provider&&!state.items.some(i=>i.provider===provider&&i.hardware===result.hardware))$('provider').value='';
    if($('hardware').value!==result.hardware){$('role').value='';$('version').value='';}
    $('hardware').value='';filterCatalog('provider');$('hardware').value=result.hardware;filterCatalog('hardware');
  }else if($('auto-detect-board').checked){
    const previousAutomaticHardware=state.detectedHardware&&!Object.hasOwn(state.manualSelections,'hardware');
    state.detectedHardware=null;
    if(previousAutomaticHardware&&!continuingDeviceFlow())resetAutomaticBoardSelection(result.reason);
    else {
      if(state.pkg&&state.item?.role&&!continuingDeviceFlow())invalidateFirmwareSelection();
      updateFirmwareSelectionSummary({reason:result.reason+(state.pkg?` Manual file ${state.pkg.name} remains loaded; review it explicitly.`:' Choose the exact hardware manually.')});
    }
    $('firmware-choices').open=true;
  }
  $('board-detection').textContent=result.hardware?`Selected ${result.hardware} from the running firmware's model. Check the physical board before writing; an incorrectly installed firmware can report the wrong model. No image was loaded.`:`${result.reason}${result.candidates.length?' Candidates: '+result.candidates.join(', ')+'.':''}`;
  if($('auto-detect-board').checked&&result.hardware)applyAutomaticSelections();
  else if(!$('auto-detect-board').checked)updateFirmwareSelectionSummary();
  updateConnectionChoice();
  return result;
}
function applyAutomaticSelections(){
  if(!$('auto-detect-board').checked)return;
  const result=chooseFirmware({items:state.items,device:state.device||{},hardware:$('hardware').value,...state.manualSelections,installMode:state.installMode});
  const selected=result.artifactIndex===null?null:state.items[result.artifactIndex];
  if(state.pkg&&(!selected||state.item?.name!==selected.name||state.item?.url!==selected.url)){
    if(state.esp)fail('Close the current inspected session before changing the automatic firmware selection.');
    invalidateFirmwareSelection();
  }
  for(const id of ['provider','hardware','role','version']){
    const value=result.selections[id];$(id).value=[...$(id).options].some(o=>o.value===value)?value:'';
    filterCatalog(id);
  }
  if(result.artifactIndex!==null&&[...$('artifact').options].some(o=>o.value===String(result.artifactIndex)))$('artifact').value=String(result.artifactIndex);
  const item=result.artifactIndex===null?null:state.items[result.artifactIndex];
  updateFirmwareSelectionSummary({item,automatic:true,reason:result.reason});
  if(!item)$('firmware-choices').open=true;
  updateDownload();controls();return result;
}
function updateFirmwareSelectionSummary({item,automatic=false,reason=''}={}) {
  if(item===undefined)item=$('artifact').value?state.items[Number($('artifact').value)]:null;
  const hardware=$('hardware').value,fields=['hardware','provider','role','version'].map(id=>$(id).value).filter(Boolean);
  const mismatch=state.port&&state.device&&state.detectedHardware&&hardware&&hardware!==state.detectedHardware
    ?`The connected node reports ${state.detectedHardware}; the selected firmware target is ${hardware}. Changing Hardware does not change the USB port. Choose the other radio's USB port to switch connected devices.`:'';
  const detail=item?`${item.hardware} · ${item.provider} · ${item.title||item.role} · ${item.version}\n${item.name}\n${state.installMode==='install'?'Erase & new install selected.':automatic?'Write-only update selected.':'Manual firmware selection.'} Prepare ${state.installMode==='install'?'install':'update'} downloads, validates and offers backup before bootloader entry. Nothing is flashed until you confirm.`
    :[fields.length?`Firmware target: ${fields.join(' · ')}.`:'',reason||'Choose hardware, role and a firmware artifact. No image has been loaded or written.'].filter(Boolean).join('\n');
  $('automatic-summary').textContent=[item&&!state.pkg?firmwareDowngradeWarning(null,item):'',mismatch,detail].filter(Boolean).join('\n');
}
function continuingDeviceFlow(){return !!(state.migrationApproval||state.handoff||state.recovery||state.espRecovery||state.migration||state.verification);}
function resetAutomaticBoardSelection(message) {
  // A deliberately loaded custom file is not an automatic board match. Keep
  // it labelled as manual, but discard a prior board's catalog image/plan.
  const manualFile=state.pkg&&!state.item?.role?state.pkg.name:'';
  if(!manualFile)invalidateFirmwareSelection();
  clearAutomaticSha();
  for(const id of ['provider','hardware','role','version'])$(id).value='';
  filterCatalog();
  const provider=state.manualSelections.provider;
  if(provider&&[...$('provider').options].some(o=>o.value===provider)){$('provider').value=provider;filterCatalog('provider');}
  $('automatic-summary').textContent=message+(manualFile?` Manual file ${manualFile} remains loaded; review it explicitly against this radio.`:'');
}
function updateConnectionChoice(){
  const result=chooseConnection({usbInfo:state.port?.getInfo()||{},device:state.device,alreadyBootloader:$('already-bootloader').checked,handoff:state.handoff,packageArchitecture:state.pkg?.architecture});
  state.connection=result;$('connection-summary').textContent=$('transport-mode').value==='auto'?`Automatic connection: ${result.mode||'needs a manual choice'}. ${result.reason}`:'Manual connection override selected.';
  return result;
}
function connectionMode(){
  if($('transport-mode').value!=='auto')return $('transport-mode').value;
  const result=updateConnectionChoice();if(!result.mode){revealPanel('connection-options');fail(result.reason);}return result.mode;
}
function matchInstalledRecovery(installedIdentity='') {
  state.recoveryDetectionRequested=true;
  const result=detectRecoveryProfile({profiles:state.recoveryCatalog?.profiles||[],tag:state.recoveryCatalog?.tag||'',installedIdentity,usbInfo:state.port?.getInfo()||{}});
  state.recoveryManual=false;$('recovery-profile').value=result.profile||'';
  $('recovery-detection').textContent=result.profile?`Selected R_${result.profile} from ${result.source==='usb'?'a unique reviewed USB ID':'the supplied installed identity'}. This is an installed-bootloader hint, NOT proof of the physical board or bootloader version. Review it before loading.`:`${result.reason}${result.candidates.length?' Candidates: '+result.candidates.join(', ')+'.':''}`;
  controls();return result;
}
async function detectSelectedBoard() {
  if(!state.port)fail('Choose a USB port first.');
  if(state.migration||state.recovery||state.espRecovery)fail('Finish the pending write or migration before board detection.');
  if(dfuIds.has(portId(state.port))||$('already-bootloader').checked){
    selectDetectedBoard();matchInstalledRecovery($('installed-identity').value.trim());
    notice('Bootloader hints checked without sending DFU or application commands. Review any recovery match; the physical board is not identified by its DFU USB ID.');return;
  }
  const port=state.port,generation=state.generation;state.device=null;state.boardDetected=false;state.backupApproved=null;
  try { await linkOperation(readApplication); }
  catch(error){
    if(state.port===port&&state.generation===generation){
      if($('auto-detect-board').checked)resetAutomaticBoardSelection('The selected USB device could not be identified. Choose hardware manually or detect again; no previous board selection was reused.');
      else updateFirmwareSelectionSummary({reason:'The selected USB device could not be identified. Review the manual firmware target before writing.'});
      updateConnectionChoice();
    }
    throw error;
  }
  if(state.port!==port||state.generation!==generation){state.device=null;fail('Selected port changed or disconnected during detection. Re-select and detect again.');}
  state.boardDetected=true;selectDetectedBoard();notice('Running MeshCore model read and matching catalog hardware selected when unambiguous. No reset, settings change or firmware write was sent.');
}
function clearBackupJson(){
  state.backupTextGeneration++;
  for(const prefix of ['backup','question-backup']){$(`${prefix}-json`).value='';$(`${prefix}-json-view`).hidden=true;$(`${prefix}-json-status`).textContent='';}
  $('question-backup-summary').textContent='';$('question-backup-summary').hidden=true;
  if(state.backup)delete state.backup.json;
}
async function copyBackupJson(prefix){
  const field=$(`${prefix}-json`),status=$(`${prefix}-json-status`),value=field.value,generation=state.backupTextGeneration;
  if(!value){status.textContent='No backup JSON is available to copy.';return;}
  if(!navigator.clipboard?.writeText){field.focus?.();field.select?.();status.textContent='Clipboard access is unavailable. Select the JSON and copy it manually.';return;}
  try{await navigator.clipboard.writeText(value);if(generation===state.backupTextGeneration&&field.value===value)status.textContent='Copied. Keep it private.';}
  catch{if(generation!==state.backupTextGeneration||field.value!==value)return;field.focus?.();field.select?.();status.textContent='Clipboard permission was not granted. Select the JSON and copy it manually.';}
}
for(const prefix of ['backup','question-backup']){
  $(`copy-${prefix}-json`).onclick=()=>copyBackupJson(prefix);
}
$('clear-backup-json').onclick=()=>{clearBackupJson();notice('Backup JSON boxes cleared. Existing downloaded files and your clipboard were not changed.');};
async function captureBackup() {
  clearBackupJson();state.backup=null;state.backupApproved=null;
  const port=state.port,generation=state.generation;
  const archive=await linkOperation(async link=>{
    const device=$('backup-role').value==='auto'?await readApplication(link):null;
    if(!device && !state.device) { try {await readApplication(link);}catch{/* Explicit interface choice is still attempted and independently validates identity. */} }
    return (device?.role||$('backup-role').value)==='common-cli'?backupCommonCli(link,progress):new MeshCore(link).backup(progress);
  });
  const info=port.getInfo(),native=await exportNativeBackup(archive,{usbIdentity:{vendor_id:info.usbVendorId??null,product_id:info.usbProductId??null},deviceHint:state.device?.model||$('hardware').value,sealNative:args=>(state.planner ||=new BrowserPlanner()).call('sealBackup',args)});
  if(state.port!==port||state.generation!==generation)fail('Selected port changed during backup. No saved-backup approval was retained; select and back up the intended radio again.');
  const summary=backupSummary(archive),completeness=native.payload?.completeness;if(completeness){summary.complete=completeness.status==='api-snapshot-complete';summary.reasons=[...new Set([...summary.reasons,...(completeness.missing_required||[]).map(n=>'Missing '+n),...(completeness.optional_errors||[]).map(n=>'Query failed: '+n)])];}
  const filename=`mc.config_backup.web.${new Date().toISOString().replace(/[:.]/g,'-')}.json`;
  const json=JSON.stringify(native,null,2);state.backup={archive,summary,filename,port,json};
  $('backup-json').value=json;$('backup-json-view').hidden=false;
  download(filename,json,'application/json');
  $('backup-summary').textContent=`Download requested: ${filename}. ${summary.complete?'Complete exposed-API snapshot.':'Partial backup; automatic restore is unavailable.'} Keep it private.`;
  notice('Backup ready. Keep it private.');return state.backup;
}
async function ensureBackup() {
  if(state.migration||state.recovery||state.espRecovery||(state.backupApproved?.sha256===state.pkg?.sha256&&state.backupApproved?.port===state.port))return;
  const bootloader=dfuIds.has(portId(state.port))||$('already-bootloader').checked;
  if(bootloader) {
    const answer=await choose('Backup cannot be done in ROM/DFU','The application is not running on this interface. Return to application firmware for a logical backup, or explicitly continue without one.',[['cancel','Cancel'],['skip','Continue without backup']]);
    if(answer!=='skip')fail('Cancelled before bootloader commands.');
  } else {
    const answer=$('auto-backup').checked?'backup':await choose('Back up before entering the bootloader?','Recommended: export and validate the running MeshCore node before any reset, ROM entry or flash. Logical backups contain secrets and are not whole-flash images.',[['backup','Back up first'],['skip','Continue without backup'],['cancel','Cancel']]);
    if(answer==='cancel')fail('Cancelled before reset or flash.');
    if(answer==='backup') {
      let result;try{result=await captureBackup();}catch(error){if(!await confirm('Backup did not complete',error.message,'No reset or write has occurred. Continue only if you accept having no complete backup.','CONTINUE WITHOUT BACKUP'))throw error;}
      if(result){
        const port=state.port,generation=state.generation,pkg=state.pkg;
        const answer=await choose('Backup JSON','',[['stop','Stop'],['continue','Continue with flashing']],{backupJson:result.json,backupWarning:result.summary.complete===false?'Partial backup: automatic restore is unavailable. An erase is not protected by this backup.':''});
        if(answer!=='continue')fail('Backup stopped. Preparation cancelled before reset or flash.');
        if(state.backup!==result||result.port!==state.port||state.port!==port||state.generation!==generation||state.pkg!==pkg)fail('Selected device or firmware changed while the backup window was open. Prepare again.');
      }
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
  else {const url=$('erase-source').value;if(!url)fail('Select this board’s erase ZIP, or choose its exact local erase ZIP. The final firmware has not been written.');name=new URL(url).pathname.split('/').pop();try{bytes=await boundedFetch(url);}catch{ $('download-firmware').href=httpsUrl(url);revealPanel('image-details');revealPanel('nrf-actions');fail('Download the exact erase ZIP using Download, choose it under Erase ZIP, then inspect again.');}}
  const pkg=inspectFirmware(name,bytes);if(pkg.architecture!=='nrf52'||pkg.kind!=='application'||!pkg.erase)fail('Guided erase requires an application erase ZIP, never a bootloader/SoftDevice component. Load component replacements separately.');
  if(!/^official (?:SoftDevice v[67] erase payload|QSPI formatter payload\b)/.test(pkg.eraseEvidence||'')&&!await confirm('Custom erase application',`${pkg.name}\nPayload SHA-256 ${pkg.payloadHash}`,'Only the name marks this as an erase application. It is not one of the known official utilities. This permission does not waive board checks or the separate wipe acknowledgement.','CUSTOM ERASE'))fail('Custom erase cancelled.');return pkg;
}
function payloadFirmwareIdentity(pkg) {
  let identity=pkg.architecture==='nrf52'?pkg.firmwareIdentity:endfIdentity(pkg.payload);
  if(!identity&&pkg.merged){for(const part of state.esp?.plan?.parts||[]){if(part.type!==0||part.offset>=pkg.payload.length)continue;let end=Math.min(part.offset+part.size,pkg.payload.length);while(end>part.offset&&pkg.payload[end-1]===255)end--;identity=endfIdentity(pkg.payload.subarray(part.offset,end));if(identity)break;}}
  return identity;
}
function firmwareDowngradeWarning(pkg=state.pkg,item=state.item) {
  if(pkg&&(pkg.expert||pkg.erase||(pkg.architecture==='nrf52'&&pkg.kind!=='application')))return '';
  const identity=pkg?payloadFirmwareIdentity(pkg):null,name=pkg?.name||item?.name||'';
  // Bootloader/SoftDevice versions are not application versions. A verified
  // application identity outranks either a catalog label or a custom filename.
  if(!identity&&(/(?:^|[_.\s-])(?:bootloader|softdevice|erase|formatter|format)(?:[_.\s-]|$)|^R_/i.test(name)))return '';
  const filenameVersion=/(?:^|[^A-Za-z0-9])(v\d+(?:\.\d+){1,3})(?!\d|\.\d)/i.exec(name)?.[1];
  return firmwareVersionWarning(state.device?.version,identity?.versionText||item?.version||filenameVersion);
}
function refreshFirmwareWarnings() {
  const pkg=state.pkg;
  $('image-warning').textContent=pkg?[...pkg.warnings,firmwareDowngradeWarning(pkg),...(selectedBootloader(pkg)?[bootloaderReinstallWarning]:[]),...(selectedRecovery(pkg)?[recoveryWarning]:[])].filter(Boolean).join(' '):'';
}
function verificationRecord(pkg) {
  const identity=payloadFirmwareIdentity(pkg);
  const family=pkg.architecture==='nrf52'?boardAssessment(pkg).payloadFamily:'unknown',model=state.device?.model||state.recovery?.deviceModel||null,roleText=state.item?.role||pkg.name,role=/companion/i.test(roleText)?'companion':/repeater|room|sensor/i.test(roleText)?'common-cli':null;
  return {sha256:pkg.sha256,name:pkg.name,architecture:pkg.architecture,publicKey:!pkg.destructive&&!state.recovery?state.device?.publicKey||null:null,model:['rak4631','rak3401'].includes(family)&&rakFamily(model)!==family?null:model,family,role,version:identity?.versionText||null};
}
function queueVerification(pkg){state.verification=verificationRecord(pkg);persistFlow('verification','meshfirmware.verifyApplication');}
function completeNrfTransfer(pkg){
  if(pkg.erase){notice('Erase transfer completed; no application startup is claimed. Select the intended final firmware.');return;}
  const applicationIndex=$('artifact').value?Number($('artifact').value):-1,application=state.items[applicationIndex],normalBootloader=selectedBootloader(pkg);
  const returnToApplication=normalBootloader&&application?.architecture==='nrf52'&&application.hardware===state.item?.hardware&&matchesCatalogInstallMode(application,state.installMode);
  const temporary=selectedRecovery(pkg);
  if(temporary){
    clearVerification();state.recovery=null;persistFlow('recovery','meshfirmware.nrfRecovery');state.handoff=true;state.backupApproved=null;state.port=null;state.plan=null;state.generation++;$('port-status').textContent='Select same recovery DFU radio';
    notice(`Temporary R_${temporary.id} transfer completed; activation and installed identity remain unverified. Re-select the SAME radio's DFU port, then install the NORMAL bootloader for its actual physical board and reinstall the compatible application. Do not leave the allow-all recovery bridge installed.`);return;
  }
  if(pkg.kind==='application'){queueVerification(pkg);notice('DFU transfer completed. Choose the application port: the page will verify role, identity, protected board family and payload version when available.');}
  else{clearVerification();if(state.device)state.device.bootloaderVersion=null;notice('DFU component transfer completed. Installed bootloader/SoftDevice startup remains unverified; the completed recovery is released so you can select the application ZIP next.');}
  state.recovery=null;persistFlow('recovery','meshfirmware.nrfRecovery');state.handoff=false;state.backupApproved=null;
  if(returnToApplication){
    clearAutomaticSha();invalidateFirmwareSelection();$('artifact').value=String(applicationIndex);updateDownload();updateFirmwareSelectionSummary({item:application});
    state.port=null;state.handoff=true;$('port-status').textContent='Select same DFU radio';
    notice('Bootloader DFU transfer completed; the installed version is not yet verified. Your application build remains selected. Use step 1 to choose the SAME radio’s DFU port, then step 3 and step 4 to reinstall its application. Nothing is flashed automatically.');
  }
}
async function verifyApplication({automaticApproval=null}={}) {
  const expected=state.verification;if(!expected)fail('No flashed application is awaiting verification.');
  if(state.migration||state.recovery||state.espRecovery||dfuIds.has(portId(state.port)))fail('Finish any pending write recovery and choose the running application interface, not ROM/DFU.');
  await closeEsp();const port=state.port,generation=state.generation,link=new SerialLink(port);let device,version,layout;
  try {
    try{await link.open(115200,{application:true});device=await readApplication(link);}
    catch(error){
      // Only read-only startup readiness may be retried. Never retry an access
      // denial, a reset/write, or a responding application's failed proof.
      if(readinessError(error))error.applicationNotReady=true;
      throw error;
    }
    if(expected.role&&expected.role!==device.role)fail('Running MeshCore interface does not match the selected firmware role.');if(expected.publicKey&&device.publicKey!==expected.publicKey)fail('Running application public identity differs from the pre-flash node. Startup verification failed.');
    if(expected.model&&device.model&&expected.model.toLowerCase()!==device.model.toLowerCase())fail('Running application model differs from the pre-flash device.');
    if(['rak4631','rak3401'].includes(expected.family)&&rakFamily(device.model)!==expected.family)fail('Running protected board family does not match the flashed payload.');
    const mc=device.role==='companion'?new MeshCore(link):null;
    version=mc?await mc.cli('version'):await link.command('ver',700);
    if(expected.version){const actual=/\bv?(\d+\.\d+\.\d+(?:\.\d+)?)/i.exec(version)?.[1],normalize=s=>s.replace(/^v/,'').replace(/(?:\.0)+$/,'');if(!actual||normalize(actual)!==normalize(expected.version))fail('Running firmware version does not match the verified payload.');}
    if(expected.architecture==='esp32'){layout=mc?await mc.cli('get storage.layout'):await link.command('get storage.layout',700);if(!/\bint:esp32-\d+K\b/i.test(layout))fail('Application answered, but storage-layout verification is unavailable or invalid. Flash transfer is verified; application verification remains incomplete.');}
    if(state.port!==port||state.generation!==generation||state.verification!==expected)fail('Application port changed during verification.');
  }finally{await link.close();}
  if(automaticApproval&&state.migrationApproval!==automaticApproval)fail('Automatic continuation was stopped; startup verification remains available manually.');
  state.verification=null;state.handoff=false;state.backupApproved=null;persistFlow('verification','meshfirmware.verifyApplication');$('already-bootloader').checked=false;
  notice(`Application startup verified: ${device.name||device.model||device.role}. ${layout?'Storage layout answered. ':''}${automaticApproval?(expected.publicKey?'Pre-flash public identity matches.':'No pre-flash public identity was available; physical device identity could not be independently verified.'):'Physical USB serial is not exposed by Web Serial; the port was explicitly reselected.'}`);log(version);
  if(expected.architecture==='nrf52')await offerBootloaderAfterStartup();
}
function invalidateFirmwareSelection() {
  // Invalidate before fetch, file I/O or validation can fail. A failed attempt
  // to replace an image must never leave the preceding write plan usable.
  revokeMigrationAutomation('Automatic migration approval revoked because the selected firmware changed.');
  state.pkg=null;state.plan=null;state.item=null;state.archive=null;state.archiveContext=null;state.loadedRecovery=null;state.directory=null;state.backupApproved=null;state.generation++;
  $('image-name').textContent='No image loaded';$('image-kind').textContent='—';$('image-size').textContent='—';$('image-sha').textContent='';$('image-warning').textContent='';
  for(const id of ['expert-fields','archive-picker','nrf-actions'])$(id).hidden=true;
  $('erase-source').replaceChildren();
}
async function clearFirmwareSelection() {
  invalidateFirmwareSelection();
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
      revealPanel('custom-firmware');
      notice('Release ZIP indexed without expanding every board. Select the exact image for your board.'); return;
    }
  }
  const pkg = inspectFirmware(name,bytes);
  state.pkg = pkg;state.item=item;state.backupApproved=null; $('image-name').textContent = pkg.name; $('image-kind').textContent = pkg.kind; $('image-size').textContent = size(bytes.length); $('image-sha').textContent = pkg.sha256;refreshFirmwareWarnings();
  $('nrf-actions').hidden=pkg.architecture!=='nrf52';$('erase-source').replaceChildren(...(item?.erase||state.recovery?.eraseUrls||[]).map(url=>new Option(new URL(url).pathname.split('/').pop(),url)));
  if(pkg.architecture==='nrf52'&&$('transport-mode').value!=='auto')$('transport-mode').value='nrf52';
  $('expert-fields').hidden = !pkg.expert;
  progress(0,'Image validated locally. Inspect the device before confirmation.'); notice('Firmware loaded. No device data has been written.');
}
function options(id, values, placeholder) {
  const select = $(id), prior = select.value;
  // A detected physical target remains visible even when the chosen provider
  // has no build for it. In that case no firmware artifact is selected.
  if(id==='hardware'&&state.detectedHardware)values=[...values,state.detectedHardware];
  select.replaceChildren(new Option(placeholder,''),...Array.from(new Set(values)).filter(Boolean).sort(id==='version'?compareVersions:undefined).map(v => new Option(id==='provider'&&v==='MeshCore'?'MeshCore (stock)':v,v)));
  if ([...select.options].some(o => o.value === prior)) select.value = prior;
}
function filterCatalog(changed = 'project') {
  let items = state.items.filter(i => i.project === $('project').value);
  for (const id of ['provider','hardware','role','version']) { if (['project','provider','hardware','role','version'].indexOf(id) > ['project','provider','hardware','role','version'].indexOf(changed)) options(id,items.map(i => i[id]),`All ${id === 'hardware' ? 'boards' : id + 's'}`); if ($(id).value) items = items.filter(i => i[id] === $(id).value); }
  items=items.filter(item=>matchesCatalogInstallMode(item,state.installMode));
  items.sort((a,b)=>compareVersions(a.version,b.version));
  $('artifact').replaceChildren(new Option(`${items.length} artifacts · choose a file`,''),...items.map(item => new Option(`${[item.title,item.subtitle].filter(Boolean).join(' / ')} · ${item.name} · ${item.action}`,String(state.items.indexOf(item)))));
  try{localStorage.setItem('meshfirmware.selections',JSON.stringify(Object.fromEntries(['provider','hardware','role','version'].map(id=>[id,$(id).value]))));}catch{}
  updateDownload(); controls();
}
const bootloaderReinstallWarning='This combined SoftDevice/bootloader DFU ZIP requires reinstalling the exact compatible application afterward. Application-owned data is not guaranteed; make a backup before entering DFU.';
const recoveryWarning='Temporary allow-all recovery bridge: choose the CURRENTLY INSTALLED bootloader profile, not the physical target board. It retains that installed identity and relaxes board/version checks. Install the normal bootloader for the actual physical board next, then its compatible application. Plan for application/settings loss; do not leave this bridge installed.';
function selectedBootloader(pkg){const info=state.item?.bootloaderInfo;return info&&pkg.kind!=='application'&&pkg.sha256===info.sha256&&pkg.name===new URL(info.url).pathname.split('/').pop()?info:null;}
function selectedRecovery(pkg){if(!pkg||pkg.architecture!=='nrf52'||pkg.kind==='application')return null;if(state.loadedRecovery?.sha256===pkg.sha256)return state.loadedRecovery;const profile=state.recoveryCatalog?.profiles.find(p=>p.sha256===pkg.sha256);return profile?{...profile,version:state.recoveryCatalog.version}:null;}
function updateRecoveryChoices(){const catalog=state.recoveryCatalog,prior=$('recovery-profile').value;$('recovery-profile').replaceChildren(new Option('Choose the CURRENTLY INSTALLED bootloader profile',''),...(catalog?.profiles||[]).map(p=>new Option(`R_${p.id} · installed identity ${p.installedIdentity}`,p.id)));if(state.recoveryManual&&catalog?.profiles.some(p=>p.id===prior))$('recovery-profile').value=prior;$('recovery-detail').textContent=catalog?`${catalog.cached?'Latest recovery could not be checked; last verified':'Our stable'} OTAFIX ${catalog.version} · ${catalog.profiles.length} temporary recovery profiles. ${recoveryWarning}`:'Recovery catalog unavailable. Normal bootloader/application choices remain usable; a custom recovery ZIP may be chosen manually.';if(catalog){$('download-recovery').href=catalog.bundle.url;$('download-recovery').removeAttribute('aria-disabled');}else{$('download-recovery').removeAttribute('href');$('download-recovery').setAttribute('aria-disabled','true');}}
function setAutomaticSha(value,name=null){$('expected-sha').value=value||'';state.automaticSha=value||null;state.automaticShaName=value?name:null;}
function clearAutomaticSha(name=null){if(name&&name===state.automaticShaName)return;if(state.automaticSha&&$('expected-sha').value.trim().toLowerCase()===state.automaticSha)$('expected-sha').value='';state.automaticSha=null;state.automaticShaName=null;}
function bootloaderItem(){
  if($('artifact').value)return state.items[Number($('artifact').value)]||null;
  if(!$('hardware').value)return null;
  const items=state.items.filter(i=>i.hardware===$('hardware').value&&(!$('provider').value||i.provider===$('provider').value)),choices=new Map();
  for(const item of items)if(item.architecture==='nrf52'&&item.bootloaderInfo)choices.set(item.bootloaderInfo.url,item);
  if(choices.size!==1||items.some(i=>i.architecture!=='nrf52'||!i.bootloaderInfo))return null;
  const item=[...choices.values()][0];return {hardware:item.hardware,architecture:item.architecture,bootloader:item.bootloader,bootloaderInfo:item.bootloaderInfo};
}
function bootloaderUpdateContext(){
  const board=bootloaderItem(),device=state.device,info=board?.bootloaderInfo;
  if(!state.port||device?.architecture!=='nrf52'||!info||board.architecture!=='nrf52'||dfuIds.has(portId(state.port))||$('already-bootloader').checked)return null;
  const detected=detectBoard({items:state.items,deviceModel:device.model||'',usbInfo:state.port.getInfo()});
  // Only an exact running model can bind this advisory to the selected board.
  // Shared USB IDs and a manually selected different board never offer a ZIP.
  if(!detected.hardware||detected.hardware!==board.hardware)return null;
  return {board,info,assessment:assessBootloaderVersion(device.bootloaderVersion,info.version)};
}
function canPrepareBootloaderUpdate(context){return !!context?.assessment.offerUpdate&&!continuingDeviceFlow()&&!state.esp&&!state.plan&&(!state.pkg||state.pkg.architecture==='nrf52'&&state.pkg.kind==='application'&&!state.pkg.erase);}
function updateBootloaderOffer(){
  const context=bootloaderUpdateContext(),panel=$('nrf-bootloader-offer'),button=$('prepare-bootloader-update');
  panel.hidden=!context;button.hidden=true;button.disabled=true;if(!context)return;
  const {info,assessment:a}=context,reference=`${info.cached?'last verified stable':'stable'} OTAFIX ${info.version}`;
  let message;
  if(a.status==='current')message=`Reported bootloader ${a.reported} matches our ${reference}. No bootloader update is needed.`;
  else if(a.status==='older')message=`Reported bootloader ${a.reported}; ${reference} is available as a separate board-specific update.`;
  else if(a.status==='preview')message=`Reported preview bootloader ${a.reported}; ${reference} is available if you want to replace the preview.`;
  else if(a.status==='newer')message=`Reported bootloader ${a.reported} is newer than our ${reference}. No downgrade is suggested.`;
  else if(a.status==='custom')message=`Reported custom bootloader ${a.reported}; our ${reference} is available in advanced options. It is not treated as an outdated stable release.`;
  else message=`The installed bootloader version could not be verified. Our ${reference} is available in advanced options; an unknown version is not assumed outdated. Application updates can continue.`;
  $('nrf-bootloader-status').textContent=message;
  const canOffer=canPrepareBootloaderUpdate(context);
  button.hidden=!canOffer;button.disabled=state.busy||!canOffer;button.textContent=`Prepare OTAFIX ${info.version} bootloader update`;
  $('nrf-bootloader-warning').hidden=!canOffer;
}
async function offerBootloaderAfterStartup(){
  const context=bootloaderUpdateContext();if(!canPrepareBootloaderUpdate(context))return;
  const {info,assessment}=context,port=state.port,generation=state.generation,key=JSON.stringify([state.device.publicKey||state.device.model,assessment.reported,info.sha256]);
  const approved={sha256:info.sha256,url:info.url,version:info.version,hardware:context.board.hardware,reported:assessment.reported,publicKey:state.device.publicKey,model:state.device.model};
  if(bootloaderOffersShown.has(key))return;bootloaderOffersShown.add(key);
  const answer=await choose('Bootloader update available',`The application started successfully. It reports ${assessment.reported}; our ${info.cached?'last verified':'latest verified'} stable is OTAFIX ${info.version}. ${bootloaderReinstallWarning} Preparing downloads and validates the separate ZIP only. Backup, DFU handoff and write confirmation still apply.`,[['later','Keep current bootloader'],['prepare','Prepare bootloader update']]);
  if(answer!=='prepare')return;
  const live=bootloaderUpdateContext();
  if(state.port!==port||state.generation!==generation||!canPrepareBootloaderUpdate(live)||live.info.sha256!==approved.sha256||live.info.url!==approved.url||live.info.version!==approved.version||live.board.hardware!==approved.hardware||live.assessment.reported!==approved.reported||state.device.publicKey!==approved.publicKey||state.device.model!==approved.model)fail('The selected device or verified bootloader changed. Review the bootloader offer again; nothing was reset or written.');
  updateDownload();$('bootloader-source').value=approved.url;revealPanel('bootloader-options');
  try{await loadBootloaderFirmware();}catch(error){throw new Error(`Application startup was verified. Separate bootloader preparation failed: ${error.message}`);}
}
function updateDownload() { const item = $('artifact').value?state.items[Number($('artifact').value)]:null,board=bootloaderItem(),info=board?.bootloaderInfo,urls=board?.architecture==='nrf52'?(info?[info.url]:[]):board?.bootloader||[];$('bootloader-source').replaceChildren(...urls.map(url=>new Option(`${info?(info.cached?'Last verified ':'')+'OTAFIX '+info.version+' · ':''}${new URL(url).pathname.split('/').pop()}`,url)));$('bootloader-detail').textContent=info?`${info.cached?'Latest release could not be checked; using our last verified stable':'Our stable'} OTAFIX ${info.version} · ${info.profile}. SHA-256 is checked before loading. ${bootloaderReinstallWarning}`:item?.bootloaderUnavailable||'Select exact hardware or a firmware artifact for its board-specific bootloader recommendation; conflicting profiles require an explicit artifact.';if (item) { $('download-firmware').href = item.url; $('download-firmware').removeAttribute('aria-disabled');$('catalog-detail').textContent=[firmwareDowngradeWarning(null,item),item.subtitle,item.notice,item.releaseNotes,item.bootloaderUnavailable].filter(Boolean).join('\n'); } else { $('download-firmware').removeAttribute('href'); $('download-firmware').setAttribute('aria-disabled','true');$('catalog-detail').textContent=''; } }
async function boundedFetch(url,{expectedSha256=''}={}) {
  return fetchFirmwareBytes(httpsUrl(url),{expectedSha256,fetchImpl:fetch});
}
async function downloadFirmwareBytes(url,name,expectedSha256=''){
  const source=httpsUrl(url);
  try{return await boundedFetch(source,{expectedSha256});}
  catch(error){
    $('download-firmware').href=source;revealPanel('firmware-choices');revealPanel('image-details');revealPanel('custom-firmware');
    const reason=error.downloadKind?'':' Browser or network restrictions, including CORS, can block access; this page cannot determine which from a failed fetch.';
    throw new Error(`Could not download ${name} from ${new URL(source).hostname}. ${error.message}${reason} Open Download firmware, then choose that exact local file. No reset or write was sent.`);
  }
}

$('select-port').onclick = () => operation(async () => {
  const port = await navigator.serial.requestPort(); // Must remain the first awaited browser operation after the click.
  const previousApproval=state.backupApproved,continuation=continuingDeviceFlow();
  // A first DFU selection cannot identify physical hardware. Preserve a
  // deliberately preselected manual target, never a prior detected board.
  const manualDfuSelection=dfuIds.has(portId(port))&&!state.device&&!state.detectedHardware&&!state.boardDetected;
  await closeEsp();state.backupApproved=null;
  if(!continuation){
    const provider=state.manualSelections.provider;
    clearBackupJson();state.device=null;state.detectedHardware=null;state.manualSelections=provider?{provider}:{};state.backup=null;$('backup-summary').textContent='';
    if($('auto-detect-board').checked&&!manualDfuSelection)resetAutomaticBoardSelection('Reading the selected USB device. Previous automatic firmware choices were cleared; no image is ready to flash.');
    else updateFirmwareSelectionSummary({reason:'New USB port selected. Review the manual firmware target against this radio.'});
  }
  state.port = port; state.generation++;
  $('device-name').textContent = `Selected USB ${portId(port)}`; $('device-meta').textContent = 'Port permission granted. Firmware and board identity are not yet verified.'; $('port-status').textContent = dfuIds.has(portId(port)) ? 'DFU port' : 'Port selected';
  if (dfuIds.has(portId(port))&&$('transport-mode').value!=='auto') $('transport-mode').value = 'nrf52';
  $('already-bootloader').checked=dfuIds.has(portId(port));
  state.boardDetected=false;state.recoveryManual=false;state.recoveryDetectionRequested=false;$('board-detection').textContent='Board not detected for this port. Use Detect board & select, or choose hardware manually.';$('recovery-detection').textContent='';$('recovery-profile').value='';$('installed-identity').value='';
  if(state.migrationApproval){state.approvalPort=port;await continueApprovedMigration();return;}
  if(state.recovery){if(!await confirm('Re-select the erased radio',state.recovery.name,'Confirm this selected serial DFU interface is the SAME physical radio. Every recovery port change needs a new acknowledgement.','SAME DEVICE')){state.port=null;fail('Recovery port confirmation cancelled.');}state.recovery.phase='final';persistFlow('recovery','meshfirmware.nrfRecovery');$('transport-mode').value='nrf52';notice(state.recovery.eraseComplete?'Original final firmware retained. Inspect this DFU port, then review the final write.':'Erase completion is uncertain. Inspect to retry the validated erase step before the final image; it will not be silently skipped.');return;}
  if(state.espRecovery){if(!await confirm('Re-select the interrupted ESP32',`${state.espRecovery.mac}\nOriginal image SHA-256 ${state.espRecovery.sha256}`,'Select the SAME physical radio already waiting in ROM. No reset or write is performed by this selection; its MAC and exact plan will be checked again.','SAME DEVICE')){state.port=null;fail('ESP retry port confirmation cancelled.');}$('transport-mode').value='no_reset';$('already-bootloader').checked=true;notice('Waiting ROM port selected. Load the original exact image and inspect; any chunked retry needs a separate acknowledgement.');return;}
  if(state.handoff&&!state.recovery&&!await confirm('Confirm bootloader handoff',state.device?.model||'Previously selected application','Web Serial does not expose the USB serial number. Confirm this is the same physical radio before reusing its pre-reset board evidence.','SAME DEVICE')){state.port=null;fail('Bootloader handoff confirmation cancelled.');}
  if(state.handoff&&previousApproval)state.backupApproved={...previousApproval,port};
  if(state.verification){state.backupApproved=null;if(!state.verification.publicKey&&!await confirm('Confirm application interface',state.verification.name,'The previous write may have replaced the node identity. Confirm this is the same physical device; Web Serial cannot read its USB serial.','SAME DEVICE')){state.port=null;fail('Application verification port confirmation cancelled.');}$('already-bootloader').checked=false;notice('Application port selected. Verifying running firmware without resetting it…');await verifyApplication();return;}
  updateConnectionChoice();
  if($('auto-detect-board').checked&&!state.handoff&&!state.migration){await detectSelectedBoard();return;}
  notice('Port selected. No reset, flash or application probe was sent.');
});
$('transport-mode').onchange = () => operation(async () => { await closeEsp(); state.generation++;updateConnectionChoice(); });
$('already-bootloader').onchange=()=>operation(async()=>{await closeEsp();state.generation++;updateConnectionChoice();});
$('auto-detect-board').onchange=()=>operation(async()=>{state.manualSelections={};if($('auto-detect-board').checked&&state.port)await detectSelectedBoard();else updateFirmwareSelectionSummary();});
for (const id of ['expert-offset','migration-package','usb-set','erase-source','erase-file']) $(id).onchange = () => operation(async()=>{await closeEsp();state.generation++;});
$('expected-sha').onchange = () => operation(async () => { state.automaticSha=null;state.automaticShaName=null;await closeEsp(); state.generation++; if (state.pkg && $('expected-sha').value.trim() && $('expected-sha').value.trim().toLowerCase() !== state.pkg.sha256) fail('SHA-256 mismatch. Flash plan invalidated.'); });
$('firmware-file').onchange = () => operation(async () => { const file = $('firmware-file').files[0]; if (!file) return; clearAutomaticSha(file.name);await clearFirmwareSelection();if (file.size > 64 << 20) fail('Firmware exceeds 64 MiB.'); await loadFirmware(file.name,new Uint8Array(await file.arrayBuffer())); });
$('load-entry').onclick = () => operation(async () => { const entry=$('archive-entry').value,archive=state.archive,item=state.archiveContext;await clearFirmwareSelection();if(!archive || !entry) fail('Select an archive entry.');const expected=$('expected-sha').value.trim().toLowerCase();if(expected&&(!/^[a-f0-9]{64}$/.test(expected)||hash(archive)!==expected))fail('Release ZIP SHA-256 does not match.');const files=checkedZip(archive,{maxEntries:8192,maxExpanded:512<<20,select:name=>name===entry});$('expected-sha').value='';await loadFirmware(entry.split('/').pop(),files[entry],item); });
$('fetch-custom').onclick = () => operation(async () => { clearAutomaticSha();await clearFirmwareSelection();const url=httpsUrl($('custom-url').value),name=new URL(url).pathname.split('/').pop();$('download-firmware').href=url;const bytes=await downloadFirmwareBytes(url,name);await loadFirmware(name,bytes); });
$('artifact').onchange = () => operation(async()=>{await clearFirmwareSelection();updateDownload();updateFirmwareSelectionSummary();controls();});
$('bootloader-source').onchange=controls;
async function loadBootloaderFirmware(){
  const url=$('bootloader-source').value,source=bootloaderItem(),item=source?{...source,bootloader:[...(source.bootloader||[])],...(source.bootloaderInfo?{bootloaderInfo:{...source.bootloaderInfo}}:{})}:null,info=item?.bootloaderInfo;
  await clearFirmwareSelection();
  if(!url||!item)fail('Choose exact hardware or an explicit board firmware artifact and its bootloader ZIP.');
  if(item.architecture==='nrf52'&&(!info||info.url!==url||!item.bootloader?.includes(url)))fail('No verified stable bootloader from our fork is available for this exact hardware. Select a custom ZIP manually if you intend a recovery.');
  $('download-firmware').href=httpsUrl(url);
  try{
    setAutomaticSha(info?.sha256||'',new URL(url).pathname.split('/').pop());
    const bytes=await boundedFetch(url,{expectedSha256:info?.sha256||''});
    if(info&&bytes.length!==info.size)fail('Published bootloader size does not match the downloaded ZIP.');
    await loadFirmware(new URL(url).pathname.split('/').pop(),bytes,item);
    if(info)notice(`Our stable OTAFIX ${info.version} loaded and SHA-256 verified. ${bootloaderReinstallWarning}`);
  }catch(error){revealPanel('image-details');revealPanel('custom-firmware');throw new Error(error.message+' If this exact build is not hosted and the source blocks fetching, download the bootloader ZIP and choose it locally.');}
}
$('load-bootloader').onclick=()=>operation(loadBootloaderFirmware);
$('prepare-bootloader-update').onclick=()=>operation(async()=>{
  const context=bootloaderUpdateContext();
  if(!canPrepareBootloaderUpdate(context))fail('No separate bootloader update is currently recommended for this connected board.');
  updateDownload();$('bootloader-source').value=context.info.url;revealPanel('bootloader-options');
  await loadBootloaderFirmware();
});
$('recovery-profile').onchange=()=>{state.recoveryManual=true;$('recovery-detection').textContent=$('recovery-profile').value?`Manual choice R_${$('recovery-profile').value}; confirm it matches the currently installed bootloader, not the physical target board.`:'';controls();};
$('match-recovery').onclick=()=>operation(async()=>{if(state.migration||state.recovery||state.espRecovery)fail('Finish the pending write or migration before selecting a different recovery profile.');matchInstalledRecovery($('installed-identity').value.trim());});
$('load-recovery').onclick=()=>operation(async()=>{
  const catalog=state.recoveryCatalog,id=$('recovery-profile').value,file=$('recovery-bundle').files[0];await clearFirmwareSelection();
  if(!catalog||!id||!catalog.profiles.some(p=>p.id===id))fail('Choose the exact CURRENTLY INSTALLED bootloader profile. Ambiguous hints require manual selection; the physical target board does not choose its recovery bridge.');
  let bundle;try{if(file){if(file.size!==catalog.bundle.size)fail('Recovery bundle size does not match the verified release.');bundle=new Uint8Array(await file.arrayBuffer());}else bundle=await boundedFetch(catalog.bundle.url,{expectedSha256:catalog.bundle.sha256||''});}catch(error){throw new Error(`${error.message} Use Download recovery bundle, select that exact local bundle here, then load the selected profile again.`);}
  const loaded=recoveryPackage(catalog,id,bundle);setAutomaticSha(loaded.profile.sha256,loaded.name);await loadFirmware(loaded.name,loaded.bytes);state.loadedRecovery={...loaded.profile,version:catalog.version};$('image-warning').textContent=[...state.pkg.warnings,recoveryWarning].join(' ');
  notice(`Verified OTAFIX ${catalog.version} R_${id} ZIP loaded for installed identity ${loaded.profile.installedIdentity}. No device commands were sent. ${recoveryWarning}`);
});
for (const id of ['project','provider','hardware','role','version']) $(id).onchange = () => operation(async()=>{await clearFirmwareSelection();state.manualSelections[id]=$(id).value;for(const next of ['hardware','role','version'].slice(['provider','hardware','role','version'].indexOf(id)))delete state.manualSelections[next];filterCatalog(id);if($('auto-detect-board').checked)applyAutomaticSelections();else updateFirmwareSelectionSummary();});
for(const [id,mode]of [['install-mode-update','update'],['install-mode-install','install']])$(id).onchange=()=>$(id).checked?operation(()=>setInstallMode(mode)):undefined;
async function fetchSelectedFirmware(){
  const item = $('artifact').value?state.items[Number($('artifact').value)]:null; if (!item) fail('Choose an artifact.');
  await clearFirmwareSelection();
  notice('Downloading firmware into browser memory…');
  setAutomaticSha(item.sha256||'',item.name);
  const bytes=await downloadFirmwareBytes(item.url,item.name,item.sha256||'');
  // Validation errors are not network/CORS errors. Keep their exact cause.
  await loadFirmware(item.name,bytes,item);
}
$('fetch-firmware').onclick=()=>operation(fetchSelectedFirmware);
$('touch').onclick = () => operation(async () => {
  if(state.migration) fail('A migration is pending. Do not reset the bridge. Complete or recover its verified migration first.');
  if(state.espRecovery)fail('An interrupted ESP32 write is pending. Select its waiting ROM port without another reset.');
  const mode = connectionMode();
  if (!['tinyusb','nrf52'].includes(mode)) fail('Use this only for TinyUSB applications or nRF52 runtime. Other modes enter ROM during inspection.');
  if (dfuIds.has(portId(state.port))) fail('Already a known DFU port; no 1200-baud touch is needed.');
  await ensureBackup();
  if (mode!=='nrf52'&&!await confirm('Enter USB bootloader?','This resets the selected application USB interface. A new port may appear.','Bluetooth may disconnect. Select the same physical device again after the touch.','ENTER BOOTLOADER')) return;
  await closeEsp();state.handoff=true; try { await touch1200(state.port,mode); } catch (error) { log(`The touch was interrupted (${error.message}). Delivery is uncertain; no second touch was sent.`); }
  state.handoff=true;state.port = null; state.generation++; $('port-status').textContent = 'Select bootloader port'; $('device-name').textContent = 'USB handoff requested'; notice('Choose USB port again for the same device. Set ESP32 to already in ROM, or select the nRF52 DFU port. If a VM captures the reconnect, pause its USB auto-capture before retrying.');
  if (mode === 'tinyusb') $('transport-mode').value = 'no_reset';
});
$('probe').onclick = () => operation(detectSelectedBoard);
$('verify-app').onclick=()=>operation(verifyApplication);
$('retry').onclick=()=>{if(state.esp)$('transport-mode').value='no_reset';return $('prepare').onclick();};
$('binary-mode').onclick=()=>operation(async()=>{
  if(!await confirm('Enter Full Companion binary mode?','Only use this for MeshCore Full Companion text mode.','This may persistently turn USB logging off so binary commands can work. It does not flash or reboot the radio.','BINARY MODE')) return;
  invalidateApplicationEvidence();await linkOperation(link=>enterCompanionBinary(link,{allowLoggingChange:true}));
  notice('Binary mode confirmed. USB logging is off; it will not be re-enabled automatically. Read the running node or create a backup.');
});
async function prepareSelectedFirmware({waitForRom=false}={}) {
  if(!state.pkg&&$('artifact').value)await fetchSelectedFirmware();
  const pkg = state.pkg; if (!pkg) fail('Select an exact firmware build first.'); await closeEsp();
  if(state.recovery&&state.recovery.sha256!==pkg.sha256)fail('nRF52 recovery is pending. Select its original final firmware; another image will not be substituted.');
  if(state.recovery&&state.recovery.phase!=='final')fail('Erase requires an explicit selection of the same radio’s newly enumerated DFU port.');
  if(state.migration && (pkg.architecture!=='esp32' || state.migration.sha256!==pkg.sha256)) fail('Select the original ESP32 firmware for the pending migration. No reset is permitted for another image.');
  if(state.espRecovery&&(pkg.architecture!=='esp32'||state.espRecovery.sha256!==pkg.sha256))fail('Select the original exact ESP32 firmware for this pending write retry.');
  assertInstallModePackage(pkg);
  if ($('expected-sha').value.trim() && $('expected-sha').value.trim().toLowerCase() !== pkg.sha256) fail('SHA-256 mismatch.');
  if (pkg.architecture === 'uf2') {
    if($('transport-mode').value==='nrf52') fail('nRF52 uses serial DFU ZIPs, not a mounted drive. Select the matching DFU ZIP.');
    if (!window.showDirectoryPicker) fail('This browser has no directory picker. Download the UF2 and copy it to the bootloader drive manually.');
    const directory=await window.showDirectoryPicker({mode:'readwrite'}), infoFile=await directory.getFileHandle('INFO_UF2.TXT'), info=await (await infoFile.getFile()).text();
    if(/nrf52|nrf528|nordic/i.test(info)) fail('This is an nRF52 bootloader. Use its serial DFU port and a matching DFU ZIP; drive copying is disabled for nRF52.');
    if (!/UF2 Bootloader|Board-ID:/i.test(info)) fail('This directory has no recognized UF2 bootloader identity.');
    state.directory=directory; state.plan={installMode:state.installMode,generation:state.generation,sha256:pkg.sha256,port:state.port,uf2Info:info.slice(0,2048)}; $('device-name').textContent=directory.name; $('device-meta').textContent=info.slice(0,250); notice('UF2 drive identity read. Confirm board compatibility before copying.'); return;
  }
  if (pkg.architecture === 'nrf52') {
    if (connectionMode() !== 'nrf52') fail('Select nRF52 DFU mode and its bootloader port.');
    await ensureBackup();
    if(!state.recovery&&!dfuIds.has(portId(state.port))&&!$('already-bootloader').checked){
      state.handoff=true;await touch1200(state.port,'nrf52');state.port=null;state.generation++;$('port-status').textContent='Select DFU port';notice('Choose the same radio’s DFU serial port, then inspect again. For an unlisted bootloader, check Already in bootloader.');return;
    }
    const wipe=!pkg.erase&&(state.recovery?!state.recovery.eraseComplete:pkg.kind==='application'&&$('flash-action').value==='wipe'),erasePkg=wipe?await erasePackage():null;
    state.plan = { installMode:state.installMode,generation:state.generation,port:state.port,sha256:pkg.sha256,erasePkg };notice(erasePkg?'Both final firmware and destructive erase ZIP validated. Review & flash runs erase first, retains the final image, and requires reselecting the same DFU radio before final write.':'DFU ZIP validated. Board identity and any directional override will be checked immediately before this write.'); return;
  }
  const mode = connectionMode();
  if(mode==='tinyusb'){
    await ensureBackup();
    if(!await confirm('Enter the detected USB bootloader?',state.device?.model||'Selected TinyUSB application','Backup was considered first. This resets only the selected radio, without flashing it. Then choose that SAME radio’s ROM port to continue.','ENTER BOOTLOADER'))return;
    state.handoff=true;try{await touch1200(state.port,'tinyusb');}catch(error){log(`Bootloader entry was interrupted (${error.message}); no second touch was sent.`);}
    state.port=null;state.generation++;$('transport-mode').value='no_reset';$('already-bootloader').checked=true;$('port-status').textContent='Choose same ROM radio';notice('Bootloader entry requested, not yet verified. Choose the same radio’s ROM port; its connection strategy is already set. Then Prepare update verifies chip and partitions. If the device disappears, pause VMs with USB auto-capture before retrying; do not assume a 30-second return.');return;
  }
  if(state.migration && !state.migration.uart && mode!=='no_reset') fail('Pending USB migration: use already in ROM / no reset. A reset could interrupt the bridge.');
  if(state.migrationApproval&&mode!=='no_reset'&&state.port!==state.approvalResetPort)fail('A newly selected interface cannot use the original port’s automatic reset permission. Select an already waiting ROM port without resetting, or stop automatic continuation and inspect manually.');
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
    let info;
    try{info=await esp.connect(mode,{singleReset:!!state.migrationApproval&&mode!=='no_reset'});}
    catch(error){if(waitForRom&&mode==='no_reset'&&readinessError(error))error.romNotReady=true;throw error;}
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
        try { await planner.call('download',{url,bytes:await boundedFetch(url)}); }
        catch { $('download-migration').href=httpsUrl(url);$('download-migration').hidden=false;revealPanel('migration-options');fail('The migration host blocked the browser download. Use the Download exact migration artifact link, select the exact migration ZIP / pinned USB set under Partition migration artifacts, and inspect again.'); }
      }
    }
    if(!prepared) fail('Could not resolve all exact migration artifacts.');
    if(prepared.recoveryResolved){state.espRecovery=null;persistEspRecovery();}
    state.plan = { ...prepared,installMode:state.installMode,generation:state.generation,port:state.port,transportMode:mode };
    if(prepared.compatibilityWarnings?.length)log(prepared.compatibilityWarnings.join('\n'));
    $('device-name').textContent = `${info.chip} · ${info.mac}`; $('device-meta').textContent = `${size(info.flashBytes)} physical flash · ROM security checks passed`;
    if(prepared.chunkedRecovery)notice('Exact ESP32 write recovery plan verified for this MAC and image. Review & flash offers separately acknowledged 16 KiB writes with independent readback; no whole-chip erase is repeated.');
    else if(prepared.needed) { $('migration-status').textContent=`Verified USB migration for ${prepared.board}; exact firmware ${prepared.firmware_version}. Keep this tab open until final verification.`; notice(prepared.resume===false&&state.migration?'Original source layout verified. The partial bridge can be rewritten safely before it is started; review and acknowledge the migration again.':'Partition expansion is needed. Review & flash writes the verified USB bridge first. No application or bridge has been written yet.'); }
    else notice(`Read-only plan ready for ${info.mac}. Offsets: ${state.plan.addresses.map(n => '0x' + n.toString(16)).join(', ')}.${prepared.mirroredSlots?' Missing fallback slots will be populated and independently verified.':''}`);
  }
  catch (error) { try{await closeEsp();}catch(closeError){log(`Serial close: ${closeError.message}`);}throw error; }
}
$('prepare').onclick = () => operation(prepareSelectedFirmware);
async function flashPreparedFirmware() {
  const plan = state.plan, pkg = state.pkg;
  if (!plan || plan.generation !== state.generation || plan.port !== state.port || plan.sha256 !== pkg.sha256) fail('Selection changed; inspect again.');
  if(plan.installMode!==undefined&&plan.installMode!==state.installMode)fail('Installation mode changed; prepare the selected build again before writing.');
  assertInstallModePackage(pkg);
  const temporary=selectedRecovery(pkg);
  if(temporary&&!await confirm('Install this temporary allow-all recovery bridge?',`${pkg.name}\nInstalled profile: ${temporary.id}\nInstalled identity retained: ${temporary.installedIdentity}\nSHA-256 ${pkg.sha256}`,recoveryWarning,`RECOVERY ${temporary.id}`))return;
  if(pkg.architecture==='nrf52')await acknowledgeBoard(pkg);
  if(plan.erasePkg)await acknowledgeBoard(plan.erasePkg);
  const token = pkg.expert ? `WRITE 0x${plan.addresses[0].toString(16)}` : pkg.destructive||plan.erasePkg ? 'WIPE WITHOUT BACKUP' : 'FLASH';
  const detail = `${pkg.name}\nSHA-256 ${pkg.sha256}\n${plan.mac ? 'Verified chip MAC ' + plan.mac : plan.uf2Info || 'Board identity unknown to this browser. Confirm the selected nRF52 board yourself.'}${selectedBootloader(pkg)?'\nOur OTAFIX '+selectedBootloader(pkg).version+' · '+selectedBootloader(pkg).profile+'\n'+bootloaderReinstallWarning:''}${plan.erasePkg?'\nERASE FIRST: '+plan.erasePkg.name+'\nSHA-256 '+plan.erasePkg.sha256+'\n'+plan.erasePkg.warnings.join(' '):''}`;
  if(state.migrationApproval&&(plan.requiresRevisionOverride||plan.chunkedRecovery))fail('The new plan needs an unapproved compatibility override or interrupted-write recovery. Automatic continuation stopped. Inspect and acknowledge it manually.');
  let allowRevisionMismatch=false;
  if(plan.requiresRevisionOverride){if(!await confirm('ESP silicon-revision mismatch',detail+'\n'+(plan.compatibilityWarnings||[]).join('\n'),'The image is not compatible with the verified chip revision, or the constrained revision could not be verified. Force only if you accept that it may not boot. This does not override security, chip-family or flash bounds checks.',plan.revisionOverrideToken||'FORCE CHIP REVISION'))return;allowRevisionMismatch=true;}
  if(plan.chunkedRecovery&&!await confirm('Retry this exact ESP32 write in bounded chunks?',detail,'This retries only the verified same chip/image/addresses, in independent 16 KiB operations with readback. No automatic reconnect, reset or repeated whole-chip erase. At most three user-reselected recovery rounds are allowed.','RETRY IN CHUNKS'))return;
  const bridge=plan.needed&&!plan.verified;
  let approval=state.migrationApproval;
  if(!approval&&bridge&&!state.migration&&!plan.requiresRevisionOverride&&!plan.chunkedRecovery){
    const candidate=new MigrationApproval(pkg,plan,{identity:state.device});
    const scope=`${detail}\nUSB bridge SHA-256 ${plan.bridge_sha256}\nExpanded table SHA-256 ${plan.target_table_sha256}\nOne approval: write and verify bridge → run expansion → verify restored settings/layout on the same MAC → write and verify this exact final firmware → restart and check startup.`;
    if(!await confirm('Expand partitions and finish this firmware update?',scope,[firmwareDowngradeWarning(pkg),...pkg.warnings,...(plan.compatibilityWarnings||[])].filter(Boolean).join(' ')+' The bridge preserves supported identity/settings, not all logs or optional files. Power loss during partition-table replacement can require physical recovery. This approval includes the required restarts, even if automatic finish is off. Keep this tab and power connected. Existing granted USB ports resume automatically; the browser may still require you to choose a new interface. No further Prepare, Flash or Reset presses are needed. Failed checks stop the run without automatic write/reset retries.'+(candidate.identity?.publicKey?'':' No pre-flash public identity is available; final application identity cannot be independently proven.'),'EXPAND AND FLASH'))return;
    if(plan.generation!==state.generation||plan.port!==state.port)fail('Device disconnected or selection changed during confirmation.');
    state.migrationApproval=approval=candidate;state.approvalPort=state.port;state.approvalResetPort=state.port;controls();
  }else if(!approval){
    if(bridge&&!await confirm('Run USB partition expansion first?',`${plan.board} · ${plan.firmware_version} · ${plan.mac}`,'The verified middle firmware preserves supported identity/settings, not all logs or optional files. Power loss during partition-table replacement can require physical recovery. Keep this tab open and re-select the same chip when asked.','EXPAND PARTITIONS'))return;
    if(!await confirm('Write this firmware?',detail,[firmwareDowngradeWarning(pkg),...pkg.warnings,...(plan.compatibilityWarnings||[])].filter(Boolean).join(' ')+' Logical backups are not complete flash images. Keep power connected. Wrong bootloader firmware may require SWD recovery.',token))return;
  }
  if (plan.generation !== state.generation || plan.port !== state.port) fail('Device disconnected or selection changed during confirmation.');
  if(approval){if(approval!==state.migrationApproval)fail('Automatic migration approval was stopped.');if(bridge)approval.beginBridge(pkg,plan);else approval.beginFinal(pkg,plan);}
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
    if(approval&&state.migrationApproval===approval){if(bridge)approval.bridgeVerified(pkg,plan);else approval.finalVerified(pkg,plan);}
    state.espRecovery=null;persistEspRecovery();
    if(plan.needed && !plan.verified) {state.migration.phase='written';localStorage.setItem('meshfirmware.pendingMigration',JSON.stringify(state.migration));}
    notice(plan.needed && !plan.verified?'USB bridge write verified. Reset verified ESP32 to run the migration, wait for automatic ROM return, select the same device, then inspect again before the final firmware write.':'Target flash MD5 verified. Use Reset verified ESP32, then check application startup.');
    if(plan.verified) { state.migration=null; localStorage.removeItem('meshfirmware.pendingMigration'); }
    if(!plan.needed||plan.verified){queueVerification(pkg);if(approval?.identity){state.verification.publicKey=approval.identity.publicKey||null;state.verification.model=approval.identity.model||null;persistFlow('verification','meshfirmware.verifyApplication');}}
    if(approval&&state.migrationApproval!==approval){notice('Verified write completed. Automatic continuation was stopped; no next reset or write was sent. Use the manual verification/recovery controls to continue.');return;}
    if((approval||$('auto-finish').checked)&&!pkg.expert)await finishVerifiedEsp();
  }
  else { const link = new SerialLink(state.port); try { await link.open(); await flashNrf(link,pkg,progress);completeNrfTransfer(pkg); } finally { await link.close(); state.plan = null; } }
}
$('flash').onclick = () => operation(flashPreparedFirmware);
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
async function finishVerifiedEsp(){
  if (!state.plan?.written) fail('No verified write to finish.');
  const bridge=state.plan.needed && !state.plan.verified;
  if(bridge) {state.migration.phase='running';localStorage.setItem('meshfirmware.pendingMigration',JSON.stringify(state.migration));}
  const approval=state.migrationApproval,session=state.esp,previousPort=session.port||state.port,transport=state.plan.transportMode||session.connectMode||$('transport-mode').value;
  const physical=chooseConnection({usbInfo:session.port?.getInfo?.()||{}});
  await session.finish(transport!=='default_reset'&&physical.mode!=='default_reset'); await closeEsp();
  if(bridge && state.migration?.uart) {
    // External UART bridges remain selected while the ESP32 reboots. Waiting
    // only reads the MAC-bound settled message; it never resets the bridge.
    state.port=previousPort;await waitUartMigration();
    if(approval&&state.migrationApproval===approval)await continueApprovedMigration();
  }
  else if(bridge&&approval&&state.migrationApproval===approval&&(physical.mode==='default_reset'||transport==='usb_reset')){
    // C3/S3 bridges return to ROM themselves even through an external serial
    // adapter. That adapter (or hardware USB-JTAG) may stay enumerated: wait
    // on this exact granted port without another DTR/RTS/watchdog reset.
    state.port=previousPort;await continueApprovedMigration();
  }
  else if(bridge) {state.port=null;state.generation++;$('transport-mode').value='no_reset';$('port-status').textContent='Wait for ROM return';notice(approval?'Expansion bridge started. Waiting for the same granted ROM port; if the browser requires a new permission, choose the same radio with step 1. The final write continues automatically after chip, layout and restoration checks.':'Migration bridge started. Keep power connected, wait for its automatic ROM return, then choose the same USB device and inspect again without resetting it.');}
  else {
    state.port=null;state.generation++;$('already-bootloader').checked=false;notice('Reset requested after verified writes. Choose the application port; startup and storage layout will be verified automatically.');
    if(approval&&state.migrationApproval===approval&&(transport==='default_reset'||physical.mode==='default_reset')){state.port=previousPort;await continueApprovedMigration();}
  }
}
$('finish').onclick=()=>operation(finishVerifiedEsp);
const applicationReadyPause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function prepareApprovedFinal(approval,{timeoutMs=180000,retryMs=1000}={}){
  const deadline=Date.now()+timeoutMs;
  while(state.migrationApproval===approval){
    try{await prepareSelectedFirmware({waitForRom:true});return;}
    catch(error){
      if(state.migrationApproval!==approval)return;
      if(!error.romNotReady||Date.now()>=deadline)throw error;
      notice('Waiting for the approved bridge to return to ROM. Only no-reset connection checks are retried; no erase, flash or reset is repeated.');
      await applicationReadyPause(retryMs);
    }
  }
}
async function verifyApprovedStartup(approval,{timeoutMs=120000,retryMs=1000}={}){
  const deadline=Date.now()+timeoutMs;
  while(state.migrationApproval===approval){
    if(!state.port){notice('Waiting for the same radio’s application USB port. Use step 1 only if its new interface needs browser permission. Startup checks will continue automatically.');return;}
    try{
      await verifyApplication({automaticApproval:approval});
      if(state.migrationApproval!==approval)return;
      approval.complete();state.migrationApproval=null;state.approvalPort=null;state.approvalResetPort=null;state.approvalResumeRequested=null;
      progress(1,'Expansion and final firmware verified; application startup checked.');return;
    }catch(error){
      if(state.migrationApproval!==approval)return;
      if(!error.applicationNotReady||Date.now()>=deadline)throw error;
      notice('Final firmware write verified. Waiting for the application to answer; only read-only startup checks are retried.');
      await applicationReadyPause(retryMs);
    }
  }
}
async function continueApprovedMigration(){
  const approval=state.migrationApproval;if(!approval)fail('No active automatic migration approval.');
  if(state.pkg?.sha256!==approval.sha256)fail('The approved final firmware changed.');
  if(approval.phase==='waiting-rom'){
    if(!state.port||!state.migration||state.migration.sha256!==approval.sha256||state.migration.mac!==approval.mac)fail('The approved chip migration is not ready to continue.');
    if(state.migration.uart&&!state.migration.settled)fail('The UART bridge has not reported settled; no ROM reset is permitted.');
    // A changed port object is safe to inspect without reset, never safe to
    // reset merely because its descriptor resembles the original UART radio.
    $('transport-mode').value=state.migration.uart&&state.port===state.approvalResetPort?'default_reset':'no_reset';$('already-bootloader').checked=true;
    notice('Verifying the expanded table and restored settings on the approved chip before writing the original final firmware…');
    await prepareApprovedFinal(approval);
    if(state.migrationApproval!==approval)return;
    // beginFinal inside flashPreparedFirmware consumes this exact proof once.
    // A source-layout retry or any unapproved change must never write here.
    if(!state.plan?.verified)fail('Expansion completion is not verified. No automatic bridge retry or final write is permitted.');
    await flashPreparedFirmware();return;
  }
  if(approval.phase==='waiting-application'){
    if(!state.verification||state.verification.sha256!==approval.sha256)fail('The approved application startup record changed.');
    $('already-bootloader').checked=false;await verifyApprovedStartup(approval);return;
  }
  fail('Automatic continuation is not waiting for a USB interface.');
}
async function resumeApprovedPort(port){
  if(!state.migrationApproval||port!==state.approvalPort||!['waiting-rom','waiting-application'].includes(state.migrationApproval.phase))return;
  state.port=port;state.generation++;$('port-status').textContent='Approved radio reconnected';
  await continueApprovedMigration();
}
$('stop-migration-auto').onclick=()=>{
  revokeMigrationAutomation('User stopped automatic continuation. The current operation may finish, but no next automatic write or reset is authorized.');
  notice('Automatic continuation stopped. Any active operation finishes at its safe boundary; pending migration and verified-write records remain available for manual recovery.');controls();
};
$('backup').onclick = () => operation(async () => {
  await captureBackup();
});
$('backup-file').onchange = () => operation(async () => {
  revealPanel('backups');
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
window.addEventListener('beforeunload',event => { if (state.busy||state.migrationApproval) { event.preventDefault(); event.returnValue = ''; } });
window.addEventListener('hashchange',openLinkedPanel);openLinkedPanel();
window.addEventListener('click',event=>{
  // A same-fragment link does not emit hashchange; reopen a tool even if the
  // user collapsed it after the previous visit.
  const link=event.target?.closest?.('nav a[href^="#"]'),id=link?.getAttribute('href')?.slice(1);
  if(['backups','console','capabilities','advanced-options'].includes(id))revealPanel(id);
});
if(state.migration) notice('A partition migration is pending in this browser. Keep power connected, select its original firmware and the same device. Application commands are blocked until final verification.');
if(state.recovery)notice('An nRF52 erase/recovery is pending. Select its original final ZIP and explicitly choose the same radio’s DFU port.');
if(state.espRecovery)notice('An interrupted ESP32 write is pending. Select its original exact image and the same radio’s waiting ROM port without resetting it.');
if ('serial' in navigator) {
  $('browser-status').textContent = 'Web Serial available';
  navigator.serial.addEventListener('connect',event=>{
    const port=event.port||event.target;
    // Only the exact already user-granted object can resume itself. A changed
    // interface needs requestPort via step 1; never enumerate/guess a radio.
    if(state.migrationApproval&&port===state.approvalPort&&['waiting-rom','waiting-application'].includes(state.migrationApproval.phase)){
      if(state.busy)state.approvalResumeRequested={port,phase:state.migrationApproval.phase};
      else void operation(()=>resumeApprovedPort(port));
    }
  });
  navigator.serial.addEventListener('disconnect',event => { if (event.target === state.port || event.port === state.port) { state.port=null;state.generation++; state.plan = null;state.boardDetected=false;state.recoveryManual=false;state.recoveryDetectionRequested=false;$('recovery-profile').value='';$('installed-identity').value='';$('recovery-detection').textContent='';$('board-detection').textContent='Selected port disconnected; detect again after selecting the same radio.';if(!state.handoff&&!state.recovery&&!state.migration){state.device=null;state.backupApproved=null;} $('port-status').textContent = 'Disconnected'; log('Selected USB port disconnected. No different port will be substituted.'); controls(); } });
} else { $('browser-status').textContent = 'Web Serial unavailable'; notice('Use a browser with Web Serial support (typically desktop Chrome or Edge). Catalog browsing and local file inspection still work.',true); }
getCatalog().then(catalog => {
  state.items=catalog.items;state.recoveryCatalog=catalog.recoveryCatalog||null;updateRecoveryChoices();
  $('catalog-status').textContent=`${state.items.length.toLocaleString()} artifacts · snapshot ${new Date(catalog.generatedAt).toLocaleString()} · ${catalog.warnings.length} provider warnings${catalog.cached?' · cached':''}`;
  let saved={};try{const value=JSON.parse(localStorage.getItem('meshfirmware.selections')||'{}');if(value&&typeof value==='object'&&!Array.isArray(value))saved=value;}catch{}
  saved.provider=catalogProvider(saved.provider)||'Keymind Cascade';
  filterCatalog();for(const id of ['provider','hardware','role','version'])if([...$(id).options].some(o=>o.value===saved[id])){$(id).value=saved[id];if(id==='provider')state.manualSelections.provider=saved[id];filterCatalog(id);}
  if(state.boardDetected&&state.device)selectDetectedBoard();
  else if(state.recoveryDetectionRequested&&!state.recoveryManual&&!state.migration&&!state.recovery&&!state.espRecovery&&(state.port||$('installed-identity').value.trim()))matchInstalledRecovery($('installed-identity').value.trim());
}).catch(error=>{$('artifact').replaceChildren(new Option('Catalog unavailable · choose local firmware',''));$('catalog-status').textContent=error.message;controls();});
controls();
