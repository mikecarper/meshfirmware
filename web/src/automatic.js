// Selection suggestions only. This module never fetches firmware, opens USB,
// resets a device, or authorizes a write. Byte/chip/partition checks still run.
import {catalogProvider,catalogItemKey,compareVersions} from './catalog.js';

const applicationRoles=new Set(['companionFull','companionBle','companionUsb','repeater','roomServer','sensor','kissRadio','gui','guiSD']);
const companionRoles=new Set(['companionFull','companionBle','companionUsb']);
const commonRoles=new Set(['repeater','roomServer','sensor']);
const text=value=>typeof value==='string'?value.trim():'';
const distinct=values=>[...new Set(values)];
const numericVersion=value=>/\bv?(\d+(?:\.\d+){1,3})/i.exec(text(value))?.[1].split('.').map(Number)||null;
function olderThanRunning(candidate,running){
  const a=numericVersion(candidate),b=numericVersion(running);if(!a||!b)return false;
  for(let i=0;i<Math.max(a.length,b.length);i++){const delta=(a[i]||0)-(b[i]||0);if(delta)return delta<0;}
  return false;
}
// Advisory only: version age must not bypass hardware, partition, security,
// backup or write-confirmation checks, and unknown versions are not guessed.
export function firmwareVersionWarning(runningVersion,selectedVersion){
  if(!olderThanRunning(selectedVersion,runningVersion))return '';
  return `Downgrade warning: selected firmware ${text(selectedVersion)} is older than the running ${text(runningVersion)}. Older firmware may not understand current settings or partition layouts. Keep a backup and review compatibility before flashing. Downgrading is allowed after the normal checks and confirmation.`;
}
function inferredRole(device){
  // Meshtastic CLIENT/ROUTER roles and version numbers are not MeshCore roles.
  if(['meshtastic','bootloader'].includes(device?.firmwareFamily)||['meshtastic','bootloader'].includes(device?.role))return '';
  if(applicationRoles.has(device?.catalogRole))return device.catalogRole;
  const version=text(device?.version);
  const patterns=[['roomServer',/\broom[\s_-]*server\b/i],['repeater',/\brepeater\b/i],['sensor',/\bsensor\b/i],['companionFull',/\b(?:full[\s_-]*companion|companion[\s_-]*(?:radio[\s_-]*)?full)\b/i],['companionBle',/\bcompanion[\s_-]*(?:radio[\s_-]*)?ble\b/i],['companionUsb',/\bcompanion[\s_-]*(?:radio[\s_-]*)?usb\b/i]];
  const roles=patterns.filter(([,pattern])=>pattern.test(version)).map(([role])=>role);
  return roles.length===1?roles[0]:'';
}
function nrfBundledComponents(item){
  if(item.architecture!=='nrf52')return false;
  // Contents must be explicit. Every ordinary nRF52 application can carry
  // bootloaderInfo/utility links and compatibility advice for a separate update.
  // Those recommendations are not evidence that this application embeds one.
  if(['includesBootloader','containsBootloader','embeddedBootloader','includesSoftdevice','containsSoftdevice','embeddedSoftdevice'].some(key=>item[key]===true))return true;
  if(Array.isArray(item.components)&&item.components.some(component=>typeof component==='string'&&/^(?:bootloader|softdevice)$/i.test(component.trim())))return true;
  const names=[item.name];
  try{names.push(decodeURIComponent(new URL(item.url).pathname.split('/').pop()));}catch{/* The catalog validates URLs separately. */}
  if(names.some(name=>/(?:^|[_.\s-])(?:bootloader|softdevice)(?:[_.\s-]|$)/i.test(name)))return true;
  const description=[item.title,item.subtitle,item.artifactTitle].filter(value=>typeof value==='string').join('\n');
  const component='(?:bootloader|softdevice)',version='(?:(?:OTAFIX|Adafruit)\\s+)?(?:v?\\d+(?:\\.\\d+){1,3}\\s+)?';
  return new RegExp(`(?:\\b(?:includes?|bundles?|carries|embeds?)\\s+(?:the\\s+)?(?:exact[- ]board\\s+)?|\\+\\s*)${version}${component}\\b(?!\\s+(?:support|compatibility|requirements?))`,'i').test(description);
}
export function matchesInstallMode(item,installMode='update'){
  if(!['update','install'].includes(installMode))return false;
  if(!item||item.project!=='MeshCore'||!applicationRoles.has(item.role)||typeof item.name!=='string'||typeof item.version!=='string'||typeof item.url!=='string')return false;
  if(nrfBundledComponents(item))return false;
  if(/(?:^|[_.\s-])(?:bootloader|softdevice|erase|formatter|format)(?:[_.\s-]|$)|^R_/i.test(item.name))return false;
  const merged=/(?:^|[_.\s-])merged(?:[_.\s-]|$)/i.test(item.name);
  if(item.architecture==='esp32')return installMode==='install'
    ?item.action==='flash-wipe'&&/(?:^|[_.\s-])merged\.bin$/i.test(item.name)
    :item.action==='flash-update'&&/\.bin$/i.test(item.name)&&!merged;
  // nRF52 reinstalls use the same application ZIP, with a separately validated
  // erase package and explicit erase/reconnect consent in the flashing flow.
  return item.architecture==='nrf52'&&item.action==='flash'&&/\.zip$/i.test(item.name)&&!merged;
}
// Catalog visibility is broader only for historical application wrappers.
// nRF52 embedded-bootloader variants stay out of the normal firmware list;
// bootloader updates have their own exact-board, separately confirmed workflow.
export function matchesCatalogInstallMode(item,installMode='update'){
  if(matchesInstallMode(item,installMode))return true;
  if(!['update','install'].includes(installMode)||!item||item.project!=='MeshCore'||!applicationRoles.has(item.role))return false;
  if(![item.name,item.version,item.url].every(value=>typeof value==='string'&&value.trim()))return false;
  if(installMode!=='update'||/(?:^|[_.\s-])(?:merged|bootloader|softdevice|erase|formatter|format)(?:[_.\s-]|$)|^R_/i.test(item.name))return false;
  if(item.architecture==='noflash')return item.action==='download'&&/\.(?:bin|zip|uf2)$/i.test(item.name);
  return item.architecture==='esp32'&&['flash','download'].includes(item.action)&&/\.(?:zip|uf2)$/i.test(item.name);
}
function exactTargets(item){
  const targets=new Set();
  for(const match of text(item.releaseNotes).matchAll(/(?:^|\n)\s*EXACT TARGET\s*-\s*([A-Za-z0-9_-]+)(?:[.\s]|$)/g))targets.add(match[1]);
  if(targets.size)return targets.size===1?targets:new Set();
  // Build names can supply an exact full environment target, never a prefix.
  const name=/^(.+?)(?:-full(?:-[A-Za-z0-9_]+)*|-v\d)/.exec(item.name)?.[1];
  if(name&&/^[A-Za-z0-9_]+$/.test(name))targets.add(name);
  return targets;
}
function setupHardware(item){
  const targets=new Set();
  for(const match of text(item.releaseNotes).matchAll(/\bSETUP\s*-\s*(https:\/\/[^\s<>"']+)/g)){
    try{const url=new URL(match[1]);if(url.origin==='https://mikecarper.github.io'&&['/MeshCore/firmware_picker/','/MeshCore/firmware_picker'].includes(url.pathname)&&url.searchParams.getAll('hardware').length===1)targets.add(url.searchParams.get('hardware'));}catch{}
  }
  return targets.size===1?targets:new Set();
}
function reviewedModelHardware(device,selections){
  // HeltecV4Board::getManufacturerName() reports exact OLED/TFT/headless
  // status. Reviewed Keymind manifests map base OLED/headless profiles,
  // including canonical Full Companion (heltec_v4_2_v4_3_...),
  // to hardware=heltec_v4.
  // This is exact model evidence only, never a friendly-name/filename guess.
  if(selections.hardware!=='Heltec v4'||selections.provider!=='Keymind Cascade'||!['repeater','roomServer','sensor','companionFull'].includes(selections.role))return '';
  return /^(?:Heltec V4(?:\.[23])? OLED|Heltec V4\.[23] none detected)$/i.test(text(device?.model))?'heltec_v4':'';
}

export function chooseFirmware({items=[],device={},hardware='',provider='',role='',version='',installMode='update'}={}){
  const meshtastic=device?.firmwareFamily==='meshtastic'||device?.role==='meshtastic';
  const bootloader=device?.firmwareFamily==='bootloader'||device?.role==='bootloader';
  const migrating=meshtastic||bootloader;
  const selections={provider:catalogProvider(text(provider))||'Keymind Cascade',hardware:text(hardware),role:text(role)||inferredRole(device),version:text(version)};
  const result=(reason,candidates=[],artifactIndex=null)=>{
    const warning=migrating||artifactIndex===null?'':firmwareVersionWarning(device?.version,items[artifactIndex]?.version);
    return {selections,artifactIndex,candidates,reason,warning,downgrade:!!warning};
  };
  if(!['update','install'].includes(installMode))return result('Choose Update or Erase / new install explicitly. An unsupported install mode cannot select firmware.');
  if(!selections.hardware)return result(installMode==='install'?'Detect or choose exact hardware before selecting an erase/new install.':'Detect or choose exact hardware before selecting an application update.');
  let candidates=items.map((item,index)=>({item,index})).filter(({item})=>matchesInstallMode(item,installMode)&&item.hardware===selections.hardware&&catalogProvider(item.provider)===selections.provider);
  if(migrating&&!text(provider)&&!candidates.length){
    const stock=items.map((item,index)=>({item,index})).filter(({item})=>matchesInstallMode(item,installMode)&&item.hardware===selections.hardware&&catalogProvider(item.provider)==='MeshCore');
    if(stock.length){selections.provider='MeshCore';candidates=stock;}
  }
  if(!candidates.length)return result(installMode==='install'?'No erase/new install matches this exact hardware/provider. Choose a matching merged ESP32 install or nRF52 application ZIP; no update, component or other board was substituted.':'No write-only application update matches this exact hardware/provider. Choose another provider or an explicit firmware file; no wipe or bootloader was substituted.');
  if(!selections.role){
    if(migrating)selections.role=['companionFull','companionBle','companionUsb'].find(role=>candidates.some(({item})=>item.role===role))||'';
  }
  if(!selections.role){
    if(migrating)return result(`${meshtastic?'Meshtastic hardware':'Bootloader identity'} detected, but no compatible Companion build is available from this provider. Choose a MeshCore role explicitly; no previous application role was assumed.`,candidates.map(({index})=>index));
    const allowed=device?.role==='companion'?companionRoles:device?.role==='common-cli'?commonRoles:null;
    const roles=distinct(candidates.filter(({item})=>!allowed||allowed.has(item.role)).map(({item})=>item.role));
    if(roles.length===1)selections.role=roles[0];
    else return result('The running role/companion transport is not uniquely known. Choose the role to preserve; no role or BLE/USB transport was guessed.',candidates.map(({index})=>index));
  }
  candidates=candidates.filter(({item})=>item.role===selections.role);
  if(!candidates.length)return result(installMode==='install'?'No erase/new install matches the selected role. An unsupported explicit role is never replaced automatically.':'No write-only application update matches the selected role. An unsupported explicit role is never replaced automatically.');
  const exactTarget=text(device?.firmwareTarget||device?.exactTarget),hardwareId=text(device?.hardwareId)||(!exactTarget?reviewedModelHardware(device,selections):'');
  if(exactTarget||hardwareId){
    candidates=candidates.filter(({item})=>{
      const setup=setupHardware(item),declared=item.bootloaderInfo?.hardwareId;
      const hardwareMatches=!hardwareId||((!setup.size||setup.has(hardwareId))&&(!declared||declared===hardwareId)&&(setup.has(hardwareId)||declared===hardwareId));
      return (!exactTarget||exactTargets(item).has(exactTarget))&&hardwareMatches;
    });
    if(!candidates.length)return result(installMode==='install'?'No erase/new install matches the reported exact build target/hardware ID. Similar screen, storage or radio variants were not substituted.':'No write-only application matches the reported exact build target/hardware ID. Similar screen, storage or radio variants were not substituted.');
  }
  if(selections.version)candidates=candidates.filter(({item})=>item.version===selections.version);
  else{
    if(candidates.length)selections.version=distinct(candidates.map(({item})=>item.version)).sort(compareVersions)[0];
    candidates=candidates.filter(({item})=>item.version===selections.version);
  }
  if(!candidates.length)return result('No matching version is available for this exact selection. Choose another version or an explicit firmware file.');
  const equivalents=new Map();
  for(const candidate of candidates){const key=catalogItemKey(candidate.item);if(!equivalents.has(key))equivalents.set(key,candidate);}
  candidates=[...equivalents.values()];
  if(candidates.length!==1)return result('Multiple exact-board builds remain (for example a different display, storage or Full profile). Choose the exact artifact or supply its exact running build target; no first-match guess was made.',candidates.map(({index})=>index));
  const migrationNote=meshtastic?'Meshtastic detected. The selected MeshCore role is a new installation choice, not a conversion of Meshtastic settings or identity. ':bootloader?'Bootloader-file identity matched. The selected Companion is a new application choice; the file does not prove physical hardware, the previous role or a configuration backup. ':'';
  return result(migrationNote+(installMode==='install'?'Newest matching erase/new install selected. Erasing removes application settings and identity; nRF52 requires a separately validated erase ZIP. Firmware bytes, chip identity and partition compatibility still require inspection; nothing has been loaded or written.':'Newest matching write-only application selected. Firmware bytes, chip identity and partition compatibility still require inspection; nothing has been loaded or written.'),[candidates[0].index],candidates[0].index);
}
