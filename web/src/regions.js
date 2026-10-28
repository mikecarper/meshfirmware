// Public CommonCLI region settings. This intentionally does not restore private
// transport keys or execute the interactive `region load` protocol.
import { fail } from './firmware.js';

const schema='org.meshfirmware.regions/v1',maxEntries=32,exportCapacity=159;
const encode=value=>new TextEncoder().encode(value),plans=new WeakMap();
const ansi=/\x1b\[[0-?]*[ -/]*[@-~]/g;
const own=(value,key)=>Object.hasOwn(value,key);
const unsupported=message=>{throw Object.assign(new Error(message),{regionsUnsupported:true});};
const name=value=>{
  if(typeof value!=='string'||!value||value==='*'||value.startsWith('#')||!/^[-_\p{L}\p{M}\p{N}]+$/u.test(value)||encode(value).length>30)fail('Region name is invalid or cannot be safely represented.');
  return value;
};
const canonicalName=value=>value==='*'?'*':name(typeof value==='string'&&value.startsWith('#')?value.slice(1):value);
const freeze=value=>{if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;};
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);

export function validateRegions(value){
  if(!value||value.schema!==schema||!Array.isArray(value.entries)||value.entries.length>maxEntries||typeof value.wildcardFloodAllowed!=='boolean'||!own(value,'home')||!own(value,'default'))fail('A complete, versioned region snapshot is required.');
  const entries=[],byName=new Map();
  for(const entry of value.entries){
    if(!entry||typeof entry.floodAllowed!=='boolean')fail('Region flood policy is missing or invalid.');
    const key=name(entry.name),parent=entry.parent==='*'?'*':name(entry.parent);
    if(byName.has(key)||key===parent)fail('Region names must be unique and cannot be their own parent.');
    const row={name:key,parent,floodAllowed:entry.floodAllowed};entries.push(row);byName.set(key,row);
  }
  for(const entry of entries){
    const visited=new Set([entry.name]);let parent=entry.parent;
    while(parent!=='*'){if(visited.has(parent))fail('The region hierarchy contains a cycle.');visited.add(parent);const row=byName.get(parent);if(!row)fail('A region parent is missing.');parent=row.parent;}
  }
  const home=value.home==='*'?'*':name(value.home),defaultName=value.default===null?null:name(value.default);
  if(home!=='*'&&!byName.has(home)||defaultName!==null&&!byName.has(defaultName))fail('Region home or default refers to a missing region.');
  entries.sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0);
  return {schema,entries,wildcardFloodAllowed:value.wildcardFloodAllowed,home,default:defaultName};
}

function unwrap(raw,command,{tree=false}={}){
  if(typeof raw!=='string'||raw.length>8192||/[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]/.test(raw))fail('Region serial reply is invalid or oversized.');
  let body=raw.replace(ansi,'');
  // Remove only an exact leading command echo. Indentation belongs to the map.
  for(;;){const end=body.indexOf('\n');if(end<0)break;const first=body.slice(0,end).replace(/\r$/,'');if(first.trim()!==command&&first.trim()!=='')break;body=body.slice(end+1);}
  const wrapper=/^[ \t]*-> ?/.exec(body);
  if(wrapper){
    body=body.slice(wrapper[0].length);
    // The repeater console appends CRLF even to a truncated exporter body.
    // It cannot count as the exporter's own terminating LF.
    if(tree&&!body.endsWith('\r\n'))unsupported('The original region reply framing is unavailable; a complete map cannot be proven.');
    if(body.endsWith('\r\n'))body=body.slice(0,-2);
  }
  if(tree)return body;
  const text=body.replace(/\r\n/g,'\n').split('\n').map(line=>line.trim().replace(/^(?:->\s*)?\s*>\s?/,'' )).filter(Boolean).join('\n');
  if(/^(?:unsupported|unknown command|unknown setting|(?:err|error)[^\n]*(?:unknown command|unknown setting|not supported|unsupported|\?\?))/i.test(text))unsupported('Region commands are not supported by this firmware.');
  if(!text||/^(?:err|error)\b/i.test(text))fail('Region command did not return a usable response.');
  return text;
}

function treeSnapshot(raw){
  const body=unwrap(raw,'region',{tree:true});
  if(/^(?:unknown|unsupported|err|error)\b/i.test(body.trim()))unsupported('Region map export is not supported by this firmware.');
  if(encode(body).length>=exportCapacity||!body.endsWith('\n')||body.includes('\r')||body.includes('\t'))unsupported('Region map export may be truncated; this firmware exposes only a 160-byte region buffer.');
  const lines=body.slice(0,-1).split('\n'),entries=[],parents=[],homeNames=[];let wildcardFloodAllowed;
  for(const [index,line]of lines.entries()){
    const match=/^( *)(\*|[^\s]+?)(\^)?(?: (F))?$/.exec(line);
    if(!match)unsupported('Region tree formatting is not recognized.');
    const depth=match[1].length,rawName=match[2];
    if(rawName.startsWith('$'))unsupported('Private region transport keys are not exported; these regions require manual recovery.');
    let key;try{key=canonicalName(rawName);}catch{unsupported('A region name cannot be safely represented by the serial restore protocol.');}
    if(index===0){if(depth!==0||key!=='*')unsupported('Region map does not include its wildcard root.');wildcardFloodAllowed=!!match[4];}
    else{
      if(key==='*'||depth<1||depth>maxEntries||!parents[depth-1])unsupported('Region hierarchy indentation is incomplete or invalid.');
      entries.push({name:key,parent:parents[depth-1],floodAllowed:!!match[4]});
    }
    parents.length=depth+1;parents[depth]=key;if(match[3])homeNames.push(key);
  }
  if(homeNames.length!==1)unsupported('The region map does not contain exactly one home marker.');
  return {schema,entries,wildcardFloodAllowed,home:homeNames[0]};
}
const parseHome=(text,writing=false)=>{const match=new RegExp('^home is '+(writing?'now ':'')+'(\\S+)$').exec(text);if(!match)fail('Region home response is not recognized.');return canonicalName(match[1]);};
const parseDefault=(text,writing=false)=>{const match=new RegExp('^default scope is '+(writing?'now ':'')+'(\\S+)$').exec(text);if(!match)fail('Region default response is not recognized.');return match[1]==='<null>'?null:name(match[1].startsWith('#')?match[1].slice(1):match[1]);};
function parseEntry(text){
  const match=/^(\S+?)(?: \((\S+)\))?(?: (F))?$/.exec(text.trim());if(!match)fail('Region entry response is not recognized.');
  return {name:canonicalName(match[1]),parent:match[2]?canonicalName(match[2]):'*',floodAllowed:!!match[3]};
}
function requests(link,assertCurrent){return async command=>{assertCurrent();let reply;try{reply=await link.command(command,900);}catch{fail('A region serial request failed. No automatic retry or restart was sent.');}assertCurrent();return reply;};}
async function readSnapshot(request,progress){
  progress?.(0,'Reading public region hierarchy');const parsed=treeSnapshot(await request('region'));
  const home=parseHome(unwrap(await request('region home'),'region home')),defaultName=parseDefault(unwrap(await request('region default'),'region default'));
  if(home!==parsed.home)fail('Region home changed during capture.');
  const snapshot=validateRegions({...parsed,default:defaultName});
  for(const [index,entry]of [{name:'*',parent:'*',floodAllowed:snapshot.wildcardFloodAllowed},...snapshot.entries].entries()){
    const command='region get '+entry.name,actual=parseEntry(unwrap(await request(command),command));
    if(!equal(actual,entry))fail('Region entry changed or its full name could not be verified.');progress?.((index+1)/(snapshot.entries.length+2),'Checking region hierarchy and flood policy');
  }
  const repeated=validateRegions({...treeSnapshot(await request('region')),default:parseDefault(unwrap(await request('region default'),'region default'))});
  if(!equal(snapshot,repeated)||parseHome(unwrap(await request('region home'),'region home'))!==snapshot.home)fail('Region settings changed during capture.');
  return snapshot;
}

export async function captureRegions(link,{assertCurrent=()=>{}}={},progress=()=>{}){
  try{return {state:'complete',data:await readSnapshot(requests(link,assertCurrent),progress)};}
  catch(error){return {state:error.regionsUnsupported?'unsupported':'error',reason:error.regionsUnsupported?error.message:'Region capture did not complete or remain stable; no region settings were written.'};}
}
function mergeSnapshots(target,source){
  const entries=new Map(target.entries.map(entry=>[entry.name,entry]));for(const entry of source.entries)entries.set(entry.name,entry);
  if(entries.size>maxEntries)fail('The merged region map exceeds the reviewed 32-entry capacity.');
  return validateRegions({...source,entries:[...entries.values()]});
}
function depth(entry,byName){let count=1,parent=entry.parent;while(parent!=='*'){count++;parent=byName.get(parent).parent;}return count;}
function exportSize(snapshot){const byName=new Map(snapshot.entries.map(row=>[row.name,row]));return encode('*'+(snapshot.home==='*'?'^':'')+(snapshot.wildcardFloodAllowed?' F':'')+'\n'+snapshot.entries.map(row=>' '.repeat(depth(row,byName))+row.name+(snapshot.home===row.name?'^':'')+(row.floodAllowed?' F':'')+'\n').join('')).length;}
export function regionRestorePreview(snapshot){
  const source=validateRegions(snapshot);
  return {operations:[{id:'regions',label:`Region map (${source.entries.length} public regions)`}],warnings:['Region settings are merged; unrelated target regions are retained. Region writes are not atomic. Private transport keys are not restored.']};
}
export async function prepareRegionRestore(link,snapshot,{assertCurrent=()=>{}}={}){
  const source=validateRegions(snapshot),captured=await captureRegions(link,{assertCurrent});
  if(captured.state==='unsupported')unsupported(captured.reason);
  if(captured.state!=='complete')fail('The target region map could not be verified before restore. No region settings were written.');
  const target=captured.data,merged=mergeSnapshots(target,source);
  if(exportSize(merged)>=exportCapacity)unsupported('The merged region map would exceed this firmware’s readable export buffer. No region settings were written.');
  const token=Object.freeze({kind:'verified-region-restore',regionCount:source.entries.length});plans.set(token,{link,source:freeze(source),target:freeze(target),merged:freeze(merged)});return token;
}
export async function restoreRegions(link,snapshot,{prepared=null,assertCurrent=()=>{},beforeWrite=async()=>{}}={},progress=()=>{}){
  const source=validateRegions(snapshot),token=prepared||await prepareRegionRestore(link,source,{assertCurrent}),plan=plans.get(token);
  if(!plan||plan.link!==link||!equal(plan.source,source))fail('Region restore approval does not match this snapshot and serial link.');
  const request=requests(link,assertCurrent),current=await readSnapshot(request);
  if(!equal(current,plan.target))fail('The target region map changed after preflight. No region settings were written.');
  let written=0;const working=structuredClone(current),byName=new Map(working.entries.map(row=>[row.name,row])),sourceByName=new Map(source.entries.map(row=>[row.name,row]));
  const send=async(command,verify)=>{await beforeWrite();assertCurrent();const raw=await request(command);written++;let text;try{text=unwrap(raw,command);}catch{fail('Region write was rejected or could not be confirmed. Restore stopped; earlier region settings may already have changed.');}if(verify(text)!==true)fail('Region write was not acknowledged or read back. Restore stopped; earlier region settings may already have changed.');};
  const verifyEntry=async expected=>{const command='region get '+expected.name;if(!equal(parseEntry(unwrap(await request(command),command)),expected))fail('Region entry readback did not match. Restore stopped; earlier region settings may already have changed.');};
  const entries=[...source.entries].sort((a,b)=>depth(a,sourceByName)-depth(b,sourceByName));
  for(const [index,row]of entries.entries()){
    const existing=byName.get(row.name);if(!existing||existing.parent!==row.parent){
      await send(`region put ${row.name} ${row.parent}`,text=>/^OK(?: - \(flood allowed\))?$/.test(text));
      const command='region get '+row.name,changed=parseEntry(unwrap(await request(command),command));
      if(changed.name!==row.name||changed.parent!==row.parent)fail('Region parent readback did not match. Earlier region settings may already have changed.');
      // Older region-put implementations default to denied flood. Read that
      // actual policy rather than guessing from a generic OK acknowledgement.
      byName.set(row.name,changed);
    }progress(index/(entries.length+4),'Restoring public region hierarchy');
  }
  if(working.default!==source.default){await send(`region default ${source.default??'<null>'}`,text=>parseDefault(text,true)===source.default);working.default=source.default;if(source.default!==null)byName.get(source.default).floodAllowed=true;}
  for(const row of [{name:'*',parent:'*',floodAllowed:source.wildcardFloodAllowed},...source.entries]){
    const actual=row.name==='*'?{name:'*',parent:'*',floodAllowed:working.wildcardFloodAllowed}:byName.get(row.name);
    if(actual.floodAllowed!==row.floodAllowed){await send(`region ${row.floodAllowed?'allowf':'denyf'} ${row.name}`,text=>text==='OK');await verifyEntry(row);actual.floodAllowed=row.floodAllowed;if(row.name==='*')working.wildcardFloodAllowed=row.floodAllowed;}
  }
  if(working.home!==source.home){await send(`region home ${source.home}`,text=>parseHome(text,true)===source.home);working.home=source.home;}
  const settingsChanged=written>0;progress(.9,'Saving region settings');await send('region save',text=>text==='OK');
  const actual=await readSnapshot(request);if(!equal(actual,plan.merged))fail('Final region map readback did not match. Earlier region settings may already have changed.');
  plans.delete(token);progress(1,'Public region settings saved and verified');return {restored:[{id:'regions',label:'Public region hierarchy, flood policy, home and default',unchanged:!settingsChanged}],skipped:[],warnings:regionRestorePreview(source).warnings,saved:true};
}
