// Historical USB evidence is advisory only. These helpers never use the
// replacement image, selected provider, or manually selected board as proof.
const architectures=new Set(['esp32','nrf52']);
const modes=new Set(['hardware-cdc-jtag','tinyusb','uart','unknown']);
const companionRoles=new Set(['companionBle','companionUsb','companionFull']);
const commonRoles=new Set(['repeater','roomServer','sensor']);
const roles=new Set([...companionRoles,...commonRoles]);
// Retain catalog KISS builds in the reviewed data without treating a generic
// Companion/CommonCLI response as evidence that it is running a KISS role.
const mapRoles=new Set([...roles,'kissRadio']);
const tokenSource='v?\\d+\\.\\d+\\.\\d+(?:\\.\\d+)?(?:-[A-Za-z0-9][A-Za-z0-9._-]*)?(?:\\+[A-Za-z0-9][A-Za-z0-9._-]*)?';
const tokenPattern=new RegExp('^(?:'+tokenSource+')$');
const month='(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)';
const day='(?:0?[1-9]|[12]\\d|3[01])';
const dateSource='(?:'+day+'[- ]'+month+'[- ]\\d{4}|'+month+' {1,2}'+day+' \\d{4}|\\d{4}-\\d{2}-\\d{2})';
const commonVersionPattern=new RegExp('^('+tokenSource+')(?: \\(Build: '+dateSource+'\\))?$');
const companionVersionPattern=new RegExp('^Companion ('+tokenSource+') \\(protocol ([1-9]\\d{0,2}), build '+dateSource+'\\)$');
const source='firmware-map';

function invalid(path,message){throw new TypeError(`USB connection map ${path}: ${message}.`);}
function record(value,keys,path){
  if(!value||typeof value!=='object'||Array.isArray(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))invalid(path,'expected a plain object');
  const actual=Object.keys(value);
  if(actual.length!==keys.length||actual.some(key=>!keys.includes(key)))invalid(path,'unexpected or missing fields');
}
function boundedText(value,max,path){
  if(typeof value!=='string'||!value||value.length>max||value!==value.trim()||/[\u0000-\u001f\u007f]/.test(value))invalid(path,'expected bounded nonempty text');
}
function list(value,max,path,{empty=false}={}){
  if(!Array.isArray(value)||(!empty&&!value.length)||value.length>max)invalid(path,'invalid list length');
}
function uniqueStrings(values,path){if(new Set(values).size!==values.length)invalid(path,'duplicate values');}
function runtimeToken(value){return typeof value==='string'&&value.length<=192&&tokenPattern.exec(value)?.[0]===value;}

export function validateUsbConnectionMap(value){
  record(value,['schemaVersion','builds'],'root');
  if(value.schemaVersion!==1)invalid('schemaVersion','unsupported version');
  list(value.builds,256,'builds',{empty:true});
  let totalProfiles=0;
  value.builds.forEach((build,index)=>{
    const path=`builds[${index}]`;
    record(build,['version','source','profiles'],path);
    if(!runtimeToken(build.version))invalid(path+'.version','expected an exact runtime version token');
    record(build.source,['repository','revision'],path+'.source');
    if(typeof build.source.repository!=='string'||!/^https:\/\/github\.com\/[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9_.-]{1,100}$/.test(build.source.repository)||['.','..'].includes(build.source.repository.split('/').at(-1)))invalid(path+'.source.repository','expected an exact HTTPS GitHub repository');
    if(typeof build.source.revision!=='string'||!/^[a-f0-9]{40}$/.test(build.source.revision))invalid(path+'.source.revision','expected a full lowercase source revision');
    list(build.profiles,1024,path+'.profiles');
    totalProfiles+=build.profiles.length;
    if(totalProfiles>16384)invalid('profiles','too many profiles');
    build.profiles.forEach((profile,profileIndex)=>{
      const at=path+`.profiles[${profileIndex}]`;
      record(profile,['hardware','architecture','role','usbMode','usbIds','targets','evidence'],at);
      boundedText(profile.hardware,256,at+'.hardware');
      if(!architectures.has(profile.architecture))invalid(at+'.architecture','unsupported architecture');
      if(!mapRoles.has(profile.role))invalid(at+'.role','unsupported catalog role');
      if(!modes.has(profile.usbMode))invalid(at+'.usbMode','unsupported USB mode');
      list(profile.usbIds,64,at+'.usbIds',{empty:true});
      if(profile.usbIds.some(id=>typeof id!=='string'||!/^[a-f0-9]{4}:[a-f0-9]{4}$/.test(id)))invalid(at+'.usbIds','expected exact lowercase USB IDs');
      uniqueStrings(profile.usbIds,at+'.usbIds');
      list(profile.targets,256,at+'.targets');
      if(profile.targets.some(target=>typeof target!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$/.test(target)))invalid(at+'.targets','expected exact build-profile identifiers');
      uniqueStrings(profile.targets,at+'.targets');
      list(profile.evidence,64,at+'.evidence');
      if(profile.evidence.some(path=>typeof path!=='string'||!path||path.length>512||!/^[A-Za-z0-9_.@+/-]+$/.test(path)||path.split('/').some(part=>!part||part==='.'||part==='..')))invalid(at+'.evidence','expected relative source paths');
      uniqueStrings(profile.evidence,at+'.evidence');
    });
  });
  return value;
}

function runningVersion(device){
  const value=device?.version;
  if(typeof value!=='string'||!value||value.length>384)return null;
  if(device.role==='companion'||companionRoles.has(device.role)){
    // DEVICE_INFO has only twenty version bytes. A plain token from that
    // field cannot prove it was not truncated; require the full CLI reply.
    const match=companionVersionPattern.exec(value);
    return match?.[0]===value&&Number(match[2])<=255?match[1]:null;
  }
  const match=commonVersionPattern.exec(value);
  return match?.[0]===value?match[1]:null;
}
function applicableRoles(device){
  const exact=device.catalogRole|| (roles.has(device.role)?device.role:null);
  const family=device.role==='companion'||companionRoles.has(device.role)?companionRoles:device.role==='common-cli'||commonRoles.has(device.role)?commonRoles:null;
  if(!family)return null;
  if(exact)return roles.has(exact)&&family.has(exact)?new Set([exact]):null;
  return family;
}
function selectedUsbId(info){
  return [info?.usbVendorId,info?.usbProductId].every(value=>Number.isInteger(value)&&value>=0&&value<=65535)?[info.usbVendorId,info.usbProductId].map(value=>value.toString(16).padStart(4,'0')).join(':'):null;
}

export function lookupUsbConnectionMap({map,hardware,device,usbInfo}={}){
  const answer=(usbMode,reason,version=null)=>({usbMode,reason,source,...(version?{version}:{})});
  try{validateUsbConnectionMap(map);}catch(error){return answer(null,`Reviewed USB history is unavailable: ${error.message}`);}
  if(typeof hardware!=='string'||!hardware||hardware.length>256||hardware!==hardware.trim()||typeof device?.model!=='string'||!device.model.trim()||device.model.length>256||/[\u0000-\u001f\u007f]/.test(device.model)||!architectures.has(device.architecture))return answer(null,'An exact running model, hardware match and architecture are required.');
  const version=runningVersion(device);
  if(!version)return answer(null,'The complete running firmware version is unavailable or has an unsupported format; truncated companion versions are not used.');
  const roleSet=applicableRoles(device);
  if(!roleSet)return answer(null,'The running interface or catalog role is unknown or conflicting.',version);
  const usbId=selectedUsbId(usbInfo);
  if(!usbId)return answer(null,'The selected USB identity is unavailable.',version);
  const builds=map.builds.filter(build=>build.version===version);
  if(!builds.length)return answer(null,'This exact running firmware version has no reviewed USB mapping.',version);
  const profiles=builds.flatMap(build=>build.profiles).filter(profile=>profile.hardware===hardware&&profile.architecture===device.architecture&&roleSet.has(profile.role));
  if(!profiles.length)return answer(null,'No reviewed profile matches this running hardware, architecture and role.',version);
  // Missing USB identities represent uncertainty in an otherwise applicable
  // build. Never remove such a profile to manufacture a unique answer.
  if(profiles.some(profile=>!profile.usbIds.length))return answer(null,'An applicable running-build profile has unknown USB identities; choose the connection manually.',version);
  const matching=profiles.filter(profile=>profile.usbIds.includes(usbId));
  if(!matching.length)return answer(null,'The selected USB identity is not reviewed for this running build.',version);
  if(matching.some(profile=>profile.usbMode==='unknown'))return answer(null,'An applicable running-build profile has an unknown USB mode; choose the connection manually.',version);
  const choices=new Set(matching.map(profile=>profile.usbMode));
  if(choices.size!==1)return answer(null,'Reviewed profiles for this running build disagree about USB mode; choose the connection manually.',version);
  return answer([...choices][0],'Exact running firmware, hardware, role and USB identity match a unanimous reviewed build mapping.',version);
}
