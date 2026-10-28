// Reviewed CommonCLI getter/setter pairs. Archive text is data, never a script.
// Formats are from MeshCore CommonCLI.cpp, RadioProfileCLI.cpp and the local
// ACL exporter. Unsupported or unstructured snapshots remain manual-only.
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { fail } from './firmware.js';
import { regionRestorePreview, prepareRegionRestore, restoreRegions } from './regions.js';

export const COMMON_CLI_OPTIONAL_COMMANDS=Object.freeze([
  'board','get system.watchdog','get storage.layout','get cad','get radio.cad',
  'get radio.rxgain','get radio.fem.rxgain','get radio.fem.txgain',
  'get radio.rxps.config','get radio.rxps.rfrx_disabled',
  'get bluetooth','get bluetooth.name','get display.rotation','get powersaving',
  'get usb.logging','get usb.logging.always','get usb.debug',
  'get password','get guest.password','get wifi.ssid','get wifi.pwd',
]);
export const COMMON_CLI_COMMANDS=Object.freeze([
  'ver','get role','get prv.key','get name','get radio','get lat','get lon',
  'get tx','get repeat','get rxdelay','get txdelay','get af','get multi.acks',
  'get advert.interval','get flood.advert.interval','get flood.max',
  'get flood.max.advert','get flood.max.unscoped','get flood.channel.data',
  'get allow.read.only','get telemetry.access','get radio2','get radio2.cross',
  ...COMMON_CLI_OPTIONAL_COMMANDS,'get acl','region',
]);
const allowedCommands=new Set([...COMMON_CLI_COMMANDS,'get public.key']);
const blankSecretQueries=new Set(['get guest.password','get wifi.pwd']);
const credentialQueries=new Set(['get password','get guest.password','get wifi.pwd','get wifi.ssid']);
const control=/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u2028\u2029]/;
const encode=value=>new TextEncoder().encode(value);

export function commonCliReplyState(raw,command=''){
  if(typeof raw!=='string'||raw.length>8192||control.test(raw.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'')))return {state:'error',text:'',reason:'Invalid or oversized serial reply.'};
  const clean=raw.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,''),lines=clean.split(/[\r\n]+/).map(line=>line.trim().replace(/^(?:->\s*)+/,''));
  let text=lines.filter(line=>line!==command.trim()&&!(command===''&&allowedCommands.has(line))).map(line=>line.replace(/^>\s?/,'' )).filter(Boolean).join('\n').trim();
  if(credentialQueries.has(command)){
    const values=clean.split(/[\r\n]+/).filter(line=>line.trim()&&line.trim()!==command).map(line=>{const match=/^\s*(?:->\s*)?> ?(.*)$/.exec(line);return match?match[1]:line;}).filter(line=>line!=='>');
    if(values.length===1)text=values[0];else if(values.length>1)return {state:'error',text:'',reason:'Ambiguous credential reply.'};
  }
  if(!text&&!(blankSecretQueries.has(command)&&lines.some(line=>/^>\s*$/.test(line))))return {state:'error',text:'',reason:'No usable serial reply was returned.'};
  if(/^(?:(?:(?:error|err)\b[:, -]*\s*)?unknown\s+(?:command|setting|get|config)|(?:error|err)\b[^\n]*(?:unsupported|not supported)|unsupported\b|not supported\b)/im.test(text))return {state:'unsupported',text,reason:'Setting is not supported by this firmware.'};
  if(/^(?:error|err|invalid|usage)\b/im.test(text))return {state:'error',text,reason:'Firmware reported a query error.'};
  return {state:'complete',text};
}
const one=value=>{if(typeof value!=='string'||/[\t\r\n]/.test(value)||control.test(value))throw Error();return value.trim();};
const decimal=(value,min,max,integer=false)=>{const s=one(value);if(!/^-?(?:\d+(?:\.\d*)?|\.\d+)$/.test(s))throw Error();const n=Number(s);if(!Number.isFinite(n)||n<min||n>max||(integer&&!Number.isInteger(n)))throw Error();return n;};
const choice=(value,values)=>{const s=one(value).toLowerCase();if(!values.includes(s))throw Error();return s;};
const flag=value=>choice(value,['on','off']);
const finiteText=(value,max,{empty=false}={})=>{const s=one(value);if((!empty&&!s)||encode(s).length>max)throw Error();return s;};
const credential=(value,max,{empty=false}={})=>{if(value!==value.trim())throw Error('manual-only');return finiteText(value,max,{empty});};
const radioTuple=value=>{const fields=one(value).split(',');if(fields.length!==4)throw Error();return [decimal(fields[0],100,3000),decimal(fields[1],1,1000),decimal(fields[2],5,12,true),decimal(fields[3],5,8,true)];};
const norm=value=>JSON.stringify(value);
function parseCad(value){
  const match=/^(?:radio\.cad\s+)?(on|off),\s*scan=(auto|\d+)(?:\(\d+\))?\s*ms,\s*retry=(auto|\d+)\s*ms,\s*max=(auto|\d+)\s*ms(?:,\s*busy=\d+)?$/i.exec(one(value));
  if(!match)throw Error();return match.slice(1).map((s,index)=>index===0||s.toLowerCase()==='auto'?s.toLowerCase():decimal(s,0,60000,true));
}
function parseRadio2(value){
  const s=one(value);if(/auto-owned|automatic allowed|pending|;\s*@/i.test(s))throw Error('manual-only');
  if(/^off(?: \(manual\))?$/i.test(s))return {mode:'off'};
  const match=/^([^;,]+),([^;,]+),(\d+),(\d+),(rx|rxtx),(\d+)( \(auto\))?(?:;[^\r\n]*)?$/i.exec(s);
  if(!match)throw Error();return {tuple:radioTuple(match.slice(1,5).join(',')),mode:match[5].toLowerCase(),preamble:match[7]?0:decimal(match[6],4,65535,true)};
}
function parseRxps(value){
  const match=/^(on|off),level=(\d+),preamble=(\d+),rx=(\d+),sleep=(\d+)$/i.exec(one(value));
  if(!match)throw Error();const state=match[1].toLowerCase(),level=decimal(match[2],0,10,true),preamble=decimal(match[3],0,32,true),rx=decimal(match[4],1,0xffffff,true),sleep=decimal(match[5],1,0xffffff,true);
  if(![0,16,32].includes(preamble))throw Error();if(state==='off')return {state};return level?{state,level,preamble}:{state,rx,sleep};
}
function parseBluetoothName(value){
  const match=/^(.*?)\s+\((default from node name|custom)\)$/i.exec(one(value));if(!match)throw Error();return {name:finiteText(match[1],32),default:match[2].toLowerCase()!=='custom'};
}
function parseAcl(value){
  const lines=value.split('\n');if(!/^ACL:(?:\s*empty)?$/i.test(lines[0]))throw Error();
  const rows=[];const keys=new Set();for(const line of lines.slice(1)){const m=/^([a-f0-9]{2})\s+([a-f0-9]{64})$/i.exec(line);if(!m||m[1]==='00'||keys.has(m[2].toLowerCase()))throw Error();keys.add(m[2].toLowerCase());rows.push({key:m[2].toLowerCase(),permissions:parseInt(m[1],16)});}
  if(rows.length>350||(/empty/i.test(lines[0])&&rows.length))throw Error();return rows;
}
const scalar=(id,label,parse,{hardware=false,setter=null}={})=>({id,label,get:`get ${id}`,parse,hardware,commands:value=>[setter?setter(value):`set ${id} ${Array.isArray(value)?value.join(','):value}`]});
const specs=[
  scalar('name','Node name',s=>finiteText(s,31)),
  scalar('lat','Latitude',s=>decimal(s,-90,90)),scalar('lon','Longitude',s=>decimal(s,-180,180)),
  scalar('tx','TX power',s=>decimal(s,-20,40,true),{hardware:true}),
  scalar('radio','Primary radio',radioTuple),scalar('repeat','Repeating',flag),
  scalar('rxdelay','RX delay',s=>decimal(s,0,20)),scalar('txdelay','TX delay',s=>decimal(s,0,2)),
  scalar('af','Airtime factor',s=>decimal(s,0,10000)),scalar('multi.acks','Multiple acknowledgements',s=>decimal(s,0,1,true)),
  scalar('advert.interval','Local advertisement interval',s=>decimal(s,0,240,true)),
  scalar('flood.advert.interval','Flood advertisement interval',s=>{const n=decimal(s,0,168,true);if(n>0&&n<3)throw Error();return n;}),
  ...['flood.max','flood.max.advert','flood.max.unscoped'].map(id=>scalar(id,id,s=>decimal(s,0,64,true))),
  {...scalar('flood.channel.data','Flood channel data',s=>{const m=/^(on|off)(?:\s+(h=all|h>[1-7]))?$/i.exec(one(s));if(!m)throw Error();return {enabled:m[1].toLowerCase(),hops:m[2]?(m[2].toLowerCase()==='h=all'?'all':m[2].slice(2)):null};}),commands:v=>[...(v.hops?[`set flood.channel.data.hops ${v.hops}`]:[]),`set flood.channel.data ${v.enabled}`]},
  scalar('allow.read.only','Read-only access',flag),scalar('telemetry.access','Telemetry access',s=>choice(s,['all','acl'])),
  {...scalar('radio2','Secondary radio',parseRadio2),commands:v=>[`set radio2 ${v.mode==='off'?'off':[...v.tuple,v.mode,v.preamble||'auto'].join(',')}`]},
  scalar('radio2.cross','Radio crossing',s=>choice(s,['auto','on','off'])),
  scalar('cad','Channel activity detection',s=>{const m=/^(on|off)(?:\. # channel busy: \d+)?$/i.exec(one(s));if(!m)throw Error();return m[1].toLowerCase();},{hardware:true}),
  {...scalar('radio.cad','CAD timings',parseCad,{hardware:true}),commands:v=>[`set radio.cad timings ${v.slice(1).join(' ')}`,`set radio.cad ${v[0]}`]},
  ...['radio.rxgain','radio.fem.rxgain','radio.fem.txgain','radio.rxps.rfrx_disabled'].map(id=>scalar(id,id,flag,{hardware:true})),
  {...scalar('radio.rxps.config','RX power-saving configuration',parseRxps,{hardware:true}),commands:v=>[`set radio.rxps ${v.state==='off'?'off':v.level?`level ${v.level}${v.preamble?` preamble ${v.preamble}`:''}`:`${v.rx} ${v.sleep}`}`]},
  scalar('display.rotation','Display rotation',s=>{const value=one(s).replace(/^display\.rotation\s+/i,'');return value==='default'?0:decimal(choice(value,['0','90','180','270']),0,270,true);},{hardware:true}),
  scalar('powersaving','Power saving',flag,{hardware:true,setter:value=>`powersaving ${value}`}),
  {...scalar('bluetooth.name','Bluetooth name',parseBluetoothName),commands:v=>[`set bluetooth.name ${v.default?'default':v.name}`],equal:(a,b)=>a.default&&b.default||norm(a)===norm(b)},
  scalar('bluetooth','Bluetooth state',s=>{const m=/^(?:bluetooth\s+)?(on|off)(?:\s*\([^\r\n]*\))?$/i.exec(one(s));if(!m)throw Error();return m[1].toLowerCase();}),
  scalar('password','Administrator password',s=>credential(s,15),{setter:value=>`password ${value}`}),
  scalar('guest.password','Guest password',s=>credential(s,15,{empty:true})),
  scalar('wifi.ssid','Wi-Fi SSID',s=>{const value=credential(s,31);if(value==='(not configured)'||/\*{4,}|redacted/i.test(value))throw Error('manual-only');return value;}),
  scalar('wifi.pwd','Wi-Fi password',s=>{const value=credential(s,64,{empty:true});if((value.length===64&&!/^[a-f0-9]{64}$/i.test(value))||/\*{4,}|redacted|local connection only/i.test(value))throw Error('manual-only');return value;}),
  // Logging is restored last so a noisy USB stream cannot disrupt earlier reads.
  ...['usb.logging.always','usb.debug','usb.logging'].map(id=>scalar(id,id,value=>flag(one(value).replace(new RegExp('^'+id.replaceAll('.','\\.')+'\\s+','i'),'')))),
];
const specByQuery=new Map(specs.map(spec=>[spec.get,spec]));
function sourceRole(p){const raw=p.replies?.['get role'],status=commonCliReplyState(raw,'get role'),role=status.state==='complete'?status.text:p.nativeSource?.role;return role?role.toLowerCase().replace(/[- ]/g,''):'commoncli';}
function privateIdentity(p){
  const status=commonCliReplyState(p.replies?.['get prv.key'],'get prv.key');if(status.state!=='complete')return null;
  if(!/^[a-f0-9]{128}$/i.test(status.text))fail('Saved private identity is invalid.');const key=hexToBytes(status.text);let scalar=0n;for(let i=31;i>=0;i--)scalar=scalar*256n+BigInt(key[i]);scalar%=ed25519.CURVE.n;
  if(!scalar||bytesToHex(ed25519.ExtendedPoint.BASE.multiply(scalar).toRawBytes())!==p.publicKey.toLowerCase())fail('Saved private identity does not match the backup public identity.');return status.text.toLowerCase();
}
export function commonCliRestorePreview(payload,{newHardware=false}={}){
  if(payload?.role!=='common-cli'||!/^[a-f0-9]{64}$/i.test(payload.publicKey||'')||!payload.replies||typeof payload.replies!=='object'||Array.isArray(payload.replies))fail('A verified CommonCLI settings backup is required.');
  const operations=[],skipped=[],warnings=[],role=sourceRole(payload);if(!['repeater','roomserver','sensor','commoncli'].includes(role))fail('The backup role is not a supported CommonCLI role.');
  const addSkip=(id,label,reason)=>skipped.push({id,label,reason});
  for(const [command,raw] of Object.entries(payload.replies)){
    if(typeof raw!=='string'||raw.length>8192)fail('Saved CommonCLI replies are invalid or oversized.');
    if(command==='get public.key'||command==='get prv.key')continue;
    const spec=specByQuery.get(command),status=commonCliReplyState(raw,command);
    if(!spec){if(!['ver','board','get role'].includes(command))addSkip(command,command==='region'?'Regions':command==='get acl'?'Access permissions':'Diagnostic snapshot',status.state==='complete'?'Not automatically restored from unstructured text.':status.reason);continue;}
    if(status.state!=='complete'){addSkip(spec.id,spec.label,status.reason);continue;}
    if(newHardware&&spec.hardware){addSkip(spec.id,spec.label,'Hardware-specific setting is retained on the new board.');continue;}
    let value;try{value=spec.parse(status.text);}catch(error){if(error.message==='manual-only'){addSkip(spec.id,spec.label,'Automatic or masked state needs manual review.');continue;}fail(`Saved ${spec.label} is invalid; nothing was restored.`);}
    operations.push({id:spec.id,label:spec.label,get:spec.get,desired:value,commands:spec.commands(value)});
    if(spec.id==='radio')warnings.push('The primary radio tuple does not record preamble length; restoring it selects the firmware’s automatic preamble.');
    if(spec.id==='wifi.ssid'||spec.id==='wifi.pwd')warnings.push('Wi-Fi credentials are saved and read back; applying the new network may require a later manual reboot.');
  }
  if(payload.regions?.state==='complete'){
    const regionPlan=regionRestorePreview(payload.regions.data),index=skipped.findIndex(row=>row.id==='region');if(index>=0)skipped.splice(index,1);
    operations.push({id:'regions',label:'Region hierarchy and policies (merge)',get:null,desired:payload.regions.data,commands:[]});warnings.push(...regionPlan.warnings);
  }else if(payload.regions){
    const index=skipped.findIndex(row=>row.id==='region');if(index>=0)skipped.splice(index,1);
    addSkip('region','Regions','The backup does not contain a complete, supported region snapshot. Capture regions again on supported firmware.');
  }
  const aclStatus=commonCliReplyState(payload.replies['get acl'],'get acl');
  if(aclStatus.state==='complete')try{const rows=parseAcl(aclStatus.text);if(rows.length){const index=skipped.findIndex(row=>row.id==='get acl');if(index>=0)skipped.splice(index,1);operations.push({id:'acl',label:'Access permissions (merge)',get:'get acl',desired:rows,commands:rows.map(row=>`setperm ${row.key} ${row.permissions}`)});warnings.push('Access permissions are merged; existing target entries are not deleted. Permission writes may be persisted lazily by firmware.');}}catch{/* Unstructured, paged or truncated ACL remains explicitly manual-only. */}
  const key=privateIdentity(payload);if(key)warnings.push('Private identity replacement is optional and requires its separate checkbox. CommonCLI applies a saved replacement only after a manual reboot.');
  // The archive's object insertion order never determines write order. Keep
  // access permissions before logging and apply noisy logging preferences last.
  const order=new Map(specs.map((spec,index)=>[spec.id,index]));order.set('regions',-1);order.set('acl',specs.length-3.5);
  operations.sort((a,b)=>order.get(a.id)-order.get(b.id));
  return {operations,skipped,warnings:[...new Set(warnings)],privateIdentity:!!key,sourceRole:role};
}

export async function restoreCommonCli(link,payload,{newHardware=false,replaceIdentity=false,assertCurrent=()=>{}}={},progress=()=>{}){
  const plan=commonCliRestorePreview(payload,{newHardware}),key=privateIdentity(payload),result={restored:[],skipped:[...plan.skipped],warnings:[...plan.warnings],identityPendingReboot:false,restartRequired:false};
  const sourceKey=payload.publicKey.toLowerCase(),sourceBoard=commonCliReplyState(payload.replies.board,'board');
  if(!plan.operations.length&&!(replaceIdentity&&key))fail('This backup has no supported settings to restore.');
  const request=async(command,label)=>{assertCurrent();let reply;try{reply=await link.command(command,1200);}catch{fail(`Serial request failed while checking ${label}.`);}assertCurrent();return reply;};
  const getKey=async()=>{const s=commonCliReplyState(await request('get public.key','node identity'),'get public.key');if(s.state!=='complete'||!/^[a-f0-9]{64}$/i.test(s.text))fail('The selected port is not answering as a CommonCLI application.');return s.text.toLowerCase();};
  const targetKey=await getKey(),roleState=commonCliReplyState(await request('get role','node role'),'get role'),role=roleState.text.toLowerCase().replace(/[- ]/g,'');
  if(roleState.state!=='complete'||!['repeater','roomserver','sensor'].includes(role))fail('The selected application is not a supported CommonCLI role.');
  if(plan.sourceRole!=='commoncli'&&plan.sourceRole!==role)fail('Backup and target roles differ. No settings were written.');
  if(targetKey!==sourceKey&&!replaceIdentity)fail('Target identity differs. Explicit identity replacement approval is required.');
  if(targetKey!==sourceKey&&!key)fail('This backup cannot replace the target identity because its private key is unavailable.');
  const boardStatus=commonCliReplyState(await request('board','board model'),'board'),hint=sourceBoard.state==='complete'?sourceBoard.text:null;
  if(!newHardware&&hint&&boardStatus.state==='complete'&&hint.trim().toLowerCase()!==boardStatus.text.trim().toLowerCase())fail('Target board differs. Select Moving to different hardware before restoring.');
  if(!hint||boardStatus.state!=='complete')result.warnings.push('Exact board identity could not be compared; only validated supported settings are restored.');
  const checkIdentity=async()=>{if(await getKey()!==targetKey)fail('Target identity changed during restore. No further settings were written.');};
  const ready=[];
  // Probe every target getter before the first setter. Unknown/unsupported
  // settings are skipped, but transport failures and malformed replies stop.
  for(const operation of plan.operations){
    if(operation.id==='regions'){
      try{const prepared=await prepareRegionRestore(link,operation.desired,{assertCurrent});ready.push({...operation,prepared});}
      catch(error){if(!error.regionsUnsupported)throw error;result.skipped.push({id:'regions',label:operation.label,reason:typeof error.message==='string'&&error.message.length<=512?error.message:'Target firmware could not provide a complete supported region snapshot; regions were not changed.'});}
      continue;
    }
    const spec=specByQuery.get(operation.get),status=commonCliReplyState(await request(operation.get,operation.label),operation.get);
    if(status.state==='unsupported'){result.skipped.push({id:operation.id,label:operation.label,reason:'Target firmware does not support this setting.'});continue;}
    if(status.state!=='complete')fail(`Target ${operation.label} could not be read. No settings were written.`);
    let actual;try{actual=operation.id==='acl'?parseAcl(status.text):spec.parse(status.text);}catch(error){if(error.message==='manual-only'){result.skipped.push({id:operation.id,label:operation.label,reason:'Target automatic or masked state needs manual review.'});continue;}fail(`Target ${operation.label} reply is not recognized. No settings were written.`);}
    ready.push({...operation,actual,spec});
  }
  await checkIdentity();
  if(!ready.length&&!(replaceIdentity&&key&&targetKey!==sourceKey)){result.warnings.push('No target settings were changed; the saved settings are unsupported on this target.');progress(1,'No supported target settings were changed');return result;}
  let regionsApplied=false;
  for(const [index,operation] of ready.entries()){
    progress(index/Math.max(1,ready.length),'Restoring '+operation.label);
    if(operation.id==='regions'){
      const regionResult=await restoreRegions(link,operation.desired,{prepared:operation.prepared,assertCurrent,beforeWrite:checkIdentity},(value,message)=>progress((index+value)/Math.max(1,ready.length),message));
      result.restored.push(...regionResult.restored);result.skipped.push(...regionResult.skipped);result.warnings.push(...regionResult.warnings);regionsApplied=true;continue;
    }
    // Selecting a default region can reconcile radio2 automatically. Never
    // skip a later setting using the value read before that policy change.
    if(regionsApplied){
      const current=commonCliReplyState(await request(operation.get,operation.label),operation.get);
      try{if(current.state!=='complete')throw Error();operation.actual=operation.id==='acl'?parseAcl(current.text):operation.spec.parse(current.text);}
      catch(error){if(current.state==='unsupported'||error.message==='manual-only'){result.skipped.push({id:operation.id,label:operation.label,reason:'Setting became unsupported or automatically managed after region restoration.'});continue;}fail(`Target ${operation.label} could not be checked after restoring regions. Restore stopped.`);}
    }
    if(operation.id!=='acl'&&(operation.spec.equal?operation.spec.equal(operation.actual,operation.desired):norm(operation.actual)===norm(operation.desired))){result.restored.push({id:operation.id,label:operation.label,unchanged:true});continue;}
    for(const command of operation.commands){
      await checkIdentity();const status=commonCliReplyState(await request(command,operation.label),command);
      const accepted=operation.id==='password'?status.state==='complete'&&status.text===`password now: ${operation.desired}`:status.state==='complete'&&/^OK\b/i.test(status.text);
      if(!accepted)fail(`${operation.label} was rejected. Restore stopped; earlier settings may already have changed.`);
      if(/reboot|restart/i.test(status.text)&&['wifi.ssid','wifi.pwd'].includes(operation.id))result.restartRequired=true;
      if(/reboot|restart/i.test(status.text)&&!['wifi.ssid','wifi.pwd'].includes(operation.id))fail(`${operation.label} needs a manual restart. Restore stopped without restarting the radio.`);
    }
    const status=commonCliReplyState(await request(operation.get,operation.label),operation.get);let actual;
    try{if(status.state!=='complete')throw Error();actual=operation.id==='acl'?parseAcl(status.text):operation.spec.parse(status.text);}catch{fail(`${operation.label} readback failed. Restore stopped; earlier settings may already have changed.`);}
    const matches=operation.id==='acl'?operation.desired.every(row=>actual.some(candidate=>candidate.key===row.key&&candidate.permissions===row.permissions)):operation.spec.equal?operation.spec.equal(actual,operation.desired):norm(actual)===norm(operation.desired);
    if(!matches)fail(`${operation.label} readback did not match. Restore stopped; earlier settings may already have changed.`);
    result.restored.push({id:operation.id,label:operation.label});
  }
  await checkIdentity();
  if(replaceIdentity&&key&&targetKey!==sourceKey){
    progress(.98,'Saving private identity for manual reboot');
    const command=`set prv.key ${key}`,status=commonCliReplyState(await request(command,'private identity'),command);
    const match=/^OK, reboot to apply! New pubkey: ([a-f0-9]{64})$/i.exec(status.text);
    if(status.state!=='complete'||!match||match[1].toLowerCase()!==sourceKey)fail('Private identity save was not confirmed. No reboot was sent; verify the target manually.');
    await checkIdentity();result.identityPendingReboot=true;result.restartRequired=true;result.warnings.push('Private identity was saved but is not active or startup-verified. Manually reboot and verify the expected public identity before using this radio.');
  }
  progress(1,'Supported CommonCLI settings restored and read back');return result;
}
