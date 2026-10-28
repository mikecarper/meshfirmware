// A bounded read-only firmware report. It describes configuration support;
// it contains no setting values and never authorizes a restore by itself.
export const CAPABILITY_KEYS=Object.freeze([
  'system.watchdog','radio.cad','radio.fem.rxgain','radio.fem.txgain',
  'radio.rxps.rfrx_disabled','bluetooth','bluetooth.name','display.rotation',
  'usb.logging.always','usb.logging','usb.debug','radio.preamble',
]);
const command='get config.cap',maskLimit=2**CAPABILITY_KEYS.length-1;
const states=new Set(['supported','fixed','not_applicable','unknown']);
const unsupportedReason='Firmware did not provide a recognized setting capability report.';
const errorReason='Setting capabilities could not be read.';
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const exactKeys=(value,keys)=>object(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
const invalid=()=>{throw new Error('Invalid setting capability metadata.');};
const freeze=value=>{for(const child of Object.values(value))if(object(child))freeze(child);return Object.freeze(value);};

export function validateSettingCapabilities(value){
  try{
    if(!exactKeys(value,['version','settings'])||value.version!==1||!exactKeys(value.settings,CAPABILITY_KEYS))invalid();
    const settings={};
    for(const key of CAPABILITY_KEYS){
      const row=value.settings[key];
      if(!exactKeys(row,['state','readable','writable'])||!states.has(row.state)||typeof row.readable!=='boolean'||typeof row.writable!=='boolean')invalid();
      if(row.state==='supported'&&!row.readable||row.state==='unknown'&&row.readable||row.state==='fixed'&&row.writable||row.state==='not_applicable'&&(row.readable||row.writable))invalid();
      settings[key]={state:row.state,readable:row.readable,writable:row.writable};
    }
    return freeze({version:1,settings});
  }catch{invalid();}
}

export function validateSettingCapabilityRecord(record){
  try{
    if(!object(record)||!['complete','unsupported','error'].includes(record.state))invalid();
    if(record.state==='complete'){
      if(!exactKeys(record,['state','data']))invalid();
      return freeze({state:'complete',data:validateSettingCapabilities(record.data)});
    }
    if(!exactKeys(record,['state'])&&!exactKeys(record,['state','reason']))invalid();
    if(record.reason!==undefined&&(typeof record.reason!=='string'||record.reason.length>256||/[\x00-\x1f\x7f\u2028\u2029]/.test(record.reason)))invalid();
    // Archived diagnostic strings are not trusted display text.
    return Object.freeze({state:record.state,reason:record.state==='error'?errorReason:unsupportedReason});
  }catch{invalid();}
}

export function parseSettingCapabilities(reply){
  if(typeof reply!=='string'||reply.length>512||/[^\x20-\x7e\r\n]/.test(reply)||/\r(?!\n)/.test(reply))return null;
  const lines=reply.split(/\r?\n/).map(line=>line.trim()).filter(Boolean);
  if(lines[0]===command)lines.shift();
  if(lines.length!==1)return null;
  const line=lines[0].replace(/^-> ?/,'').replace(/^> ?/,'');
  const match=/^config\.cap v1 get=([a-f0-9]{8}) set=([a-f0-9]{8}) fixed=([a-f0-9]{8}) na=([a-f0-9]{8})$/i.exec(line);
  // Field names/version are canonical; only hex digits may vary in case.
  if(!match||!line.startsWith('config.cap v1 get=')||!line.includes(' set=')||!line.includes(' fixed=')||!line.includes(' na='))return null;
  const [get,set,fixed,na]=match.slice(1).map(value=>Number.parseInt(value,16));
  if([get,set,fixed,na].some(value=>value>maskLimit)||(na&(get|set|fixed))!==0||(fixed&set)!==0)return null;
  const settings={};
  for(const [index,key]of CAPABILITY_KEYS.entries()){
    const bit=2**index,readable=(get&bit)!==0,writable=(set&bit)!==0;
    settings[key]={state:(na&bit)!==0?'not_applicable':(fixed&bit)!==0?'fixed':readable?'supported':'unknown',readable,writable};
  }
  return validateSettingCapabilities({version:1,settings});
}

export async function captureSettingCapabilities(link,{assertCurrent=()=>{}}={}){
  assertCurrent();let reply;
  try{reply=await link.command(command,700);}
  catch{assertCurrent();return Object.freeze({state:'error',reason:errorReason});}
  assertCurrent();const data=parseSettingCapabilities(reply);
  return data?freeze({state:'complete',data}):Object.freeze({state:'unsupported',reason:unsupportedReason});
}

export function settingCapability(record,key){
  if(typeof key!=='string'||!CAPABILITY_KEYS.includes(key))return null;
  try{const checked=validateSettingCapabilityRecord(record);return checked.state==='complete'?checked.data.settings[key]:null;}catch{return null;}
}

export function shouldSkipSetting(record,query){
  if(typeof query!=='string'||!query.startsWith('get '))return false;
  const setting=settingCapability(record,query.slice(4));
  return setting?.state==='not_applicable'||setting?.state==='fixed'&&!setting.readable;
}
