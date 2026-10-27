// Selection suggestions only. This module never fetches firmware, opens USB,
// resets a device, or authorizes a write. Byte/chip/partition checks still run.
import {compareVersions} from './catalog.js';

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
function defaultProvider(device){
  const version=text(device?.version);
  if(/\bkeymind[\s_-]+cascade[\s_-]+logging\b/i.test(version))return 'Keymind Cascade Logging';
  return /\bkeymind[\s_-]+cascade\b/i.test(version)?'Keymind Cascade':'MeshCore';
}
function inferredRole(device){
  if(applicationRoles.has(device?.catalogRole))return device.catalogRole;
  const version=text(device?.version);
  const patterns=[['roomServer',/\broom[\s_-]*server\b/i],['repeater',/\brepeater\b/i],['sensor',/\bsensor\b/i],['companionFull',/\b(?:full[\s_-]*companion|companion[\s_-]*(?:radio[\s_-]*)?full)\b/i],['companionBle',/\bcompanion[\s_-]*(?:radio[\s_-]*)?ble\b/i],['companionUsb',/\bcompanion[\s_-]*(?:radio[\s_-]*)?usb\b/i]];
  const roles=patterns.filter(([,pattern])=>pattern.test(version)).map(([role])=>role);
  return roles.length===1?roles[0]:'';
}
function isApplicationUpdate(item){
  if(!item||item.project!=='MeshCore'||!applicationRoles.has(item.role)||typeof item.name!=='string'||typeof item.version!=='string'||typeof item.url!=='string')return false;
  if(/(?:^|[_.\s-])(?:merged|bootloader|softdevice|erase|formatter|format)(?:[_.\s-]|$)|^R_/i.test(item.name))return false;
  if(item.architecture==='esp32')return item.action==='flash-update'&&/\.bin$/i.test(item.name);
  return item.architecture==='nrf52'&&item.action==='flash'&&/\.zip$/i.test(item.name);
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
  // HeltecV4Board::getManufacturerName() distinguishes OLED from TFT, and the
  // reviewed Keymind setup manifests map the OLED repeater/room/sensor and
  // canonical Full Companion (heltec_v4_2_v4_3_...) to hardware=heltec_v4.
  // This is exact model evidence only, never a friendly-name/filename guess.
  if(selections.hardware!=='Heltec v4'||!['Keymind Cascade','Keymind Cascade Logging'].includes(selections.provider)||!['repeater','roomServer','sensor','companionFull'].includes(selections.role))return '';
  return /^Heltec V4(?:\.[23])? OLED$/i.test(text(device?.model))?'heltec_v4':'';
}

export function chooseFirmware({items=[],device={},hardware='',provider='',role='',version=''}={}){
  const selections={provider:text(provider)||defaultProvider(device),hardware:text(hardware),role:text(role)||inferredRole(device),version:text(version)};
  const result=(reason,candidates=[],artifactIndex=null)=>({selections,artifactIndex,candidates,reason});
  if(!selections.hardware)return result('Detect or choose exact hardware before selecting an application update.');
  let candidates=items.map((item,index)=>({item,index})).filter(({item})=>isApplicationUpdate(item)&&item.hardware===selections.hardware&&item.provider===selections.provider);
  if(!candidates.length)return result('No write-only application update matches this exact hardware/provider. Choose another provider or an explicit firmware file; no wipe or bootloader was substituted.');
  if(!selections.role){
    const allowed=device?.role==='companion'?companionRoles:device?.role==='common-cli'?commonRoles:null;
    const roles=distinct(candidates.filter(({item})=>!allowed||allowed.has(item.role)).map(({item})=>item.role));
    if(roles.length===1)selections.role=roles[0];
    else return result('The running role/companion transport is not uniquely known. Choose the role to preserve; no role or BLE/USB transport was guessed.',candidates.map(({index})=>index));
  }
  candidates=candidates.filter(({item})=>item.role===selections.role);
  if(!candidates.length)return result('No write-only application update matches the selected role. An unsupported explicit role is never replaced automatically.');
  const exactTarget=text(device?.firmwareTarget||device?.exactTarget),hardwareId=text(device?.hardwareId)||(!exactTarget?reviewedModelHardware(device,selections):'');
  if(exactTarget||hardwareId){
    candidates=candidates.filter(({item})=>{
      const setup=setupHardware(item),declared=item.bootloaderInfo?.hardwareId;
      const hardwareMatches=!hardwareId||((!setup.size||setup.has(hardwareId))&&(!declared||declared===hardwareId)&&(setup.has(hardwareId)||declared===hardwareId));
      return (!exactTarget||exactTargets(item).has(exactTarget))&&hardwareMatches;
    });
    if(!candidates.length)return result('No write-only application matches the reported exact build target/hardware ID. Similar screen, storage or radio variants were not substituted.');
  }
  if(selections.version)candidates=candidates.filter(({item})=>item.version===selections.version);
  else{
    candidates=candidates.filter(({item})=>!olderThanRunning(item.version,device?.version));
    if(candidates.length)selections.version=distinct(candidates.map(({item})=>item.version)).sort(compareVersions)[0];
    candidates=candidates.filter(({item})=>item.version===selections.version);
  }
  if(!candidates.length)return result('No matching version is available without an automatic downgrade. An explicit version may be selected manually.');
  const equivalents=new Map();
  for(const candidate of candidates){const item=candidate.item,key=JSON.stringify([item.url,item.name,item.architecture,item.action,item.role,item.sha256||null]);if(!equivalents.has(key))equivalents.set(key,candidate);}
  candidates=[...equivalents.values()];
  if(candidates.length!==1)return result('Multiple exact-board builds remain (for example a different display, storage or Full profile). Choose the exact artifact or supply its exact running build target; no first-match guess was made.',candidates.map(({index})=>index));
  return result('Newest matching write-only application selected. Firmware bytes, chip identity and partition compatibility still require inspection; nothing has been loaded or written.',[candidates[0].index],candidates[0].index);
}
