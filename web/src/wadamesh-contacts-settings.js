import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

// Reviewed companion-protocol operations. Callers bind assertCurrent to the
// verified application identity/session and obtain approval before any save.
const encode = value => new TextEncoder().encode(value);
const bytesEqual = (a,b) => a.length===b.length && a.every((value,index)=>value===b[index]);
const fail = message => { throw new Error(message); };
// TAK's hashtag join uses lowercased ASCII and removes spaces before hashing.
// Only simple names are accepted here; #r2- aliases have separate routing rules.
export function hashtagChannel(input) {
  if(typeof input!=='string'||input.length>128||!/^#*[A-Za-z0-9._ -]+$/.test(input))fail('Use letters, numbers, spaces, dots, underscores or hyphens for a hashtag channel.');
  const name='#'+input.replace(/^#+/,'').replace(/ /g,'').replace(/[A-Z]/g,char=>char.toLowerCase());
  if(name==='#'||encode(name).length>31)fail('Hashtag channel name must be 1–30 characters after normalization.');
  if(name.startsWith('#r2-'))fail('Radio2 channel aliases must be configured on the device.');
  return {name,secretHex:bytesToHex(sha256(encode(name)).subarray(0,16))};
}
function adapter(core, assertCurrent, publicKey) {
  if (!core || typeof core.request!=='function' || typeof core.self!=='function' || typeof core.info!=='function' || typeof assertCurrent!=='function' || typeof publicKey!=='string' || !/^[a-f0-9]{64}$/i.test(publicKey)) fail('A verified radio session and identity are required.');
  const key=Uint8Array.from(publicKey.match(/../g),pair=>parseInt(pair,16));
  const check=async()=>{await assertCurrent();const self=validateSelf(await core.self());await assertCurrent();if(!bytesEqual(self.subarray(4,36),key))fail('The radio identity changed. No further settings were sent.');};
  return async task => { await check(); const value=await task(); await check(); return value; };
}
function validateSelf(value) {
  if (!(value instanceof Uint8Array) || value.length<58 || value[0]!==5 || value[1]!==1) fail('Invalid application identity or settings response.');
  return value.slice();
}
function channelRecord(value,index) {
  if (!(value instanceof Uint8Array) || value.length!==50 || value[0]!==18 || value[1]!==index) fail('Invalid channel response.');
  return value.slice();
}
function channelName(record) {
  const bytes=record.subarray(2,34),end=bytes.indexOf(0);
  let value;
  try { value=new TextDecoder('utf-8',{fatal:true}).decode(end<0?bytes:bytes.subarray(0,end)); }
  catch { fail('Invalid channel name response.'); }
  if(/[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029]/u.test(value))fail('Invalid channel name response.');
  return value;
}
function channelView(record) { return {index:record[1],name:channelName(record),hasSecret:record.subarray(34).some(Boolean),record:record.slice()}; }
function autoRecord(value) {
  if (!(value instanceof Uint8Array) || ![2,3].includes(value.length) || value[0]!==25 || (value.length===3 && value[2]>64)) fail('Invalid auto-add response.');
  return value.slice();
}
function autoView(record,self) {
  return {manual:!!(self[47]&1),overwrite:!!(record[1]&1),chat:!!(record[1]&2),repeater:!!(record[1]&4),room:!!(record[1]&8),sensor:!!(record[1]&16),maxHops:record.length===3?record[2]:null,record:record.slice(),self:self.slice()};
}
export async function readChannels(core,{assertCurrent,publicKey}={}) {
  const guarded=adapter(core,assertCurrent,publicKey),info=await guarded(()=>core.info());
  if (!(info instanceof Uint8Array) || info.length<80 || info[0]!==13 || !info[3]) fail('Channel capacity is unavailable.');
  const rows=[];
  for(let index=0;index<info[3];index++) rows.push(channelView(channelRecord(await guarded(()=>core.request([31,index],18)),index)));
  return rows;
}
export async function saveChannel(core,{expected,name,secretHex=''}={}, {assertCurrent,publicKey}={}) {
  const guarded=adapter(core,assertCurrent,publicKey);
  if (!expected || !Number.isInteger(expected.index) || expected.index<0 || expected.index>254) fail('Select a valid channel.');
  const old=channelRecord(expected.record,expected.index);
  if (typeof name!=='string' || !name.trim() || /[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029]/u.test(name) || encode(name).length>31) fail('Channel name must be 1–31 UTF-8 bytes without control characters.');
  if (typeof secretHex!=='string' || (secretHex!==''&&!/^[0-9a-fA-F]{32}$/.test(secretHex))) fail('Channel key must be 32 hexadecimal characters, or blank to keep it.');
  if (!channelName(old) && !secretHex) fail('A new channel needs a channel key.');
  const next=old.slice(); next.fill(0,2,34); next.set(encode(name),2);
  if(secretHex)for(let i=0;i<16;i++)next[34+i]=parseInt(secretHex.slice(i*2,i*2+2),16);
  const current=channelRecord(await guarded(()=>core.request([31,expected.index],18)),expected.index);
  if (!bytesEqual(current,old)) fail('The channel changed since it was read. Reload before saving.');
  if (bytesEqual(old,next)) return channelView(current);
  try {
    await guarded(()=>core.request([32,...next.subarray(1)],0));
    const verified=channelRecord(await guarded(()=>core.request([31,expected.index],18)),expected.index);
    if (!bytesEqual(verified,next)) fail('Channel readback failed.');
    return channelView(verified);
  } catch(error) { throw new Error('Channel save could not be verified; the setting may have changed. '+(error.message||'')); }
}
export async function deleteChannel(core,{expected}={}, {assertCurrent,publicKey}={}) {
  const guarded=adapter(core,assertCurrent,publicKey);
  if (!expected || !Number.isInteger(expected.index) || expected.index<0 || expected.index>254) fail('Select a valid channel.');
  const old=channelRecord(expected.record,expected.index);
  channelName(old);
  const current=channelRecord(await guarded(()=>core.request([31,expected.index],18)),expected.index);
  if(!bytesEqual(current,old))fail('The channel changed since it was read. Reload before removing it.');
  const next=new Uint8Array(50);next[0]=18;next[1]=expected.index;
  if(bytesEqual(current,next))return channelView(current);
  try {
    await guarded(()=>core.request([32,...next.subarray(1)],0));
    const verified=channelRecord(await guarded(()=>core.request([31,expected.index],18)),expected.index);
    if(!bytesEqual(verified,next))fail('Channel removal readback failed.');
    return channelView(verified);
  } catch(error) { throw new Error('Channel removal could not be verified; the channel may have changed. '+(error.message||'')); }
}
export async function readAutoAdd(core,{assertCurrent,publicKey}={}) {
  const guarded=adapter(core,assertCurrent,publicKey),self=validateSelf(await guarded(()=>core.self())),record=autoRecord(await guarded(()=>core.request([59],25)));
  return autoView(record,self);
}
export async function saveAutoAdd(core,{expected,manual,overwrite,chat,repeater,room,sensor,maxHops}={}, {assertCurrent,publicKey}={}) {
  const guarded=adapter(core,assertCurrent,publicKey);
  if (!expected || [manual,overwrite,chat,repeater,room,sensor].some(value=>typeof value!=='boolean')) fail('Choose all auto-add settings.');
  const old=autoRecord(expected.record),oldSelf=validateSelf(expected.self);
  if (old.length===2 ? maxHops!==null : !Number.isInteger(maxHops)||maxHops<0||maxHops>64) fail('Invalid or unsupported auto-add maximum hops.');
  const next=old.slice(); next[1]=(old[1]&~31)|(overwrite?1:0)|(chat?2:0)|(repeater?4:0)|(room?8:0)|(sensor?16:0);if(next.length===3)next[2]=maxHops;
  const currentSelf=validateSelf(await guarded(()=>core.self())),current=autoRecord(await guarded(()=>core.request([59],25)));
  if(!bytesEqual(current,old)||!bytesEqual(currentSelf.subarray(4,36),oldSelf.subarray(4,36))||!bytesEqual(currentSelf.subarray(44,48),oldSelf.subarray(44,48)))fail('Auto-add settings or radio identity changed. Reload before saving.');
  let changed=false;
  try {
    if(!bytesEqual(current,next)) {
      changed=true;await guarded(()=>core.request([58,...next.subarray(1)],0));
      if(!bytesEqual(autoRecord(await guarded(()=>core.request([59],25))),next))fail('Auto-add policy readback failed.');
    }
    const desiredManual=(currentSelf[47]&~1)|(manual?1:0);
    if(desiredManual!==currentSelf[47]) {
      const fresh=validateSelf(await guarded(()=>core.self()));
      if(!bytesEqual(fresh.subarray(4,36),oldSelf.subarray(4,36))||!bytesEqual(fresh.subarray(44,48),currentSelf.subarray(44,48)))fail('Radio identity or other settings changed before saving.');
      changed=true;await guarded(()=>core.request([38,desiredManual,fresh[46],fresh[45],fresh[44]],0));
      const verified=validateSelf(await guarded(()=>core.self()));
      if(!bytesEqual(verified.subarray(4,36),oldSelf.subarray(4,36))||!bytesEqual(verified.subarray(44,47),fresh.subarray(44,47))||verified[47]!==desiredManual)fail('Auto-add mode readback failed.');
    }
    const result=await readAutoAdd(core,{assertCurrent,publicKey});
    if(!bytesEqual(result.record,next)||result.manual!==manual)fail('Auto-add settings changed before the final readback.');
    return result;
  } catch(error) { if(changed) throw new Error('Some auto-add settings may have been saved; reload before trying again. '+(error.message||'Verification failed.')); throw error; }
}
