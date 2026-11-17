import {isRunningWadameshTak} from './automatic.js';

// This is a convenience preference, not hardware attestation. An identity
// change (including a new identity after erase) requires a fresh user choice.
export const PAGER_VARIANTS_KEY='meshfirmware.pagerVariants.v1';
const LIMIT=32;
const variants=new Map([
  ['LilyGo T-Lora Pager (SX1262)','tlora-pager-sx1262'],
  ['LilyGo T-Lora Pager (LR1121)','tlora-pager-lr1121'],
]);
function publicIdentity(device){
  if(!isRunningWadameshTak(device)||!/^LilyGo T-LoRa Pager$/i.test(typeof device?.model==='string'?device.model.trim():''))return null;
  const key=typeof device.publicKey==='string'?device.publicKey.toLowerCase():'';
  return /^[a-f0-9]{64}$/.test(key)&&!/^0+$/.test(key)?key:null;
}
function catalogContains(items,hardware){
  const build=variants.get(hardware);
  return !!build&&Array.isArray(items)&&items.some(item=>item?.project==='MeshCore'&&item.provider==='Wadamesh TAK'&&item.architecture==='esp32'&&item.role==='gui'&&item.hardware===hardware&&item.wadameshBuild===build);
}
function entries(storage){
  try{
    const raw=storage?.getItem(PAGER_VARIANTS_KEY);if(!raw||raw.length>8192)return [];
    const value=JSON.parse(raw);
    if(value?.version!==1||!Array.isArray(value.entries)||value.entries.length>LIMIT)return [];
    const keys=new Set();
    for(const entry of value.entries){
      if(!entry||Object.keys(entry).length!==2||typeof entry.key!=='string'||!/^[a-f0-9]{64}$/.test(entry.key)||/^0+$/.test(entry.key)||!variants.has(entry.hardware)||keys.has(entry.key))return [];
      keys.add(entry.key);
    }
    return value.entries;
  }catch{return [];}
}

// Call only after the user deliberately chooses this exact hardware variant.
export function rememberPagerVariant({storage,device,hardware,items}={}){
  const key=publicIdentity(device);
  if(!key||!catalogContains(items,hardware))return false;
  const updated=entries(storage).filter(entry=>entry.key!==key);
  updated.push({key,hardware});
  try{storage.setItem(PAGER_VARIANTS_KEY,JSON.stringify({version:1,entries:updated.slice(-LIMIT)}));return true;}catch{return false;}
}

// Never use a remembered value to bypass physical-board, display or image checks.
export function recallPagerVariant({storage,device,items}={}){
  const key=publicIdentity(device);if(!key)return null;
  const entry=entries(storage).find(entry=>entry.key===key);
  return entry&&catalogContains(items,entry.hardware)?entry.hardware:null;
}

// A deliberate clear or different hardware choice revokes this identity's
// preference, while leaving other radios' independently chosen variants intact.
export function forgetPagerVariant({storage,device}={}){
  const key=publicIdentity(device);if(!key)return false;
  const saved=entries(storage),updated=saved.filter(entry=>entry.key!==key);
  if(updated.length===saved.length)return false;
  try{storage.setItem(PAGER_VARIANTS_KEY,JSON.stringify({version:1,entries:updated}));return true;}catch{return false;}
}
