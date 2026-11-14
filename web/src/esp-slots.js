import {fail} from './firmware.js';

const choices=new Set(['a','b','both']);
const address=value=>'0x'+value.toString(16);
const immutable=value=>Object.freeze(value);
const validAddress=value=>Number.isSafeInteger(value)&&value>=0x10000&&value%0x10000===0;
const sourceAddresses=plan=>Array.isArray(plan?.allSlotAddresses)?plan.allSlotAddresses:Array.isArray(plan?.addresses)?plan.addresses:[];
const sameSet=(left,right)=>left.length===right.length&&left.every(value=>right.includes(value));

// A and B mean partition identities ota_0/ota_1, never "first written" and
// "second written". The normal plan deliberately writes the boot slot last.
export function espSlotChoices(pkg,plan){
  const selected=choices.has(plan?.slotSelection)?plan.slotSelection:'both',all=sourceAddresses(plan),parts=Array.isArray(plan?.parts)?plan.parts:[];
  const apps=parts.filter(part=>part?.type===0),a=apps.find(part=>part.subtype===0x10),b=apps.find(part=>part.subtype===0x11);
  const bootAddress=Number.isSafeInteger(plan?.slotBootAddress)?plan.slotBootAddress:Number.isSafeInteger(plan?.active_offset)?plan.active_offset:!pkg?.merged&&!pkg?.expert&&all.length?all.at(-1):null;
  let reason='',canSelect=true;
  if(pkg?.architecture!=='esp32'||!plan){canSelect=false;reason='Slot selection is available only for an inspected ESP32 application.';}
  else if(pkg.merged||plan.merged){canSelect=false;reason='A merged install erases the whole chip and writes its bootloader and partition table. Keep all required application slots.';}
  else if(pkg.expert||plan.expert){canSelect=false;reason='Component and bootloader images use their explicit inspected address, not OTA slot selection.';}
  else if(plan.needed||plan.verified||plan.recovered||plan.bridge||plan.format==='meshcore-usb-partition-expansion-v2'){canSelect=false;reason='Partition expansion and its final update require the complete approved slot plan.';}
  else if(plan.chunkedRecovery){canSelect=false;reason='Interrupted-write recovery must retain the exact slots from its original write.';}
  else if(plan.segments){canSelect=false;reason='This segmented write must retain every inspected segment.';}
  else if(apps.length!==2||!a||!b||!validAddress(a.offset)||!validAddress(b.offset)||a.offset===b.offset||!sameSet(all,[a.offset,b.offset])||new Set(all).size!==2||!Number.isSafeInteger(pkg?.payload?.length)||[a,b].some(part=>!Number.isSafeInteger(part.size)||part.size<pkg.payload.length)){
    canSelect=false;reason='This device does not expose exactly the two fitting OTA application slots A and B. Keep the inspected layout.';
  }
  if(canSelect&&!all.includes(bootAddress)){canSelect=false;reason='The current OTA boot slot is not verified. Keep the complete inspected application plan.';}
  const targets={both:[...all],a:a&&validAddress(a.offset)?[a.offset]:[],b:b&&validAddress(b.offset)?[b.offset]:[]};
  const writesBootSlot=selection=>pkg?.merged||pkg?.expert?selection==='both':bootAddress===null?selection==='both':targets[selection].includes(bootAddress);
  const bothLabel=canSelect?'Both slots (default)':selected==='both'?'Required targets (fixed)':'Both slots (unavailable)';
  const options=['both','a','b'].map(value=>immutable({value,label:value==='both'?bothLabel:`Slot ${value.toUpperCase()}${targets[value].length?` · ${address(targets[value][0])}`:''}`,addresses:immutable(targets[value]),available:canSelect||value===selected,writesBootSlot:writesBootSlot(value)}));
  const selectedAddresses=selected==='both'?[...all]:[...targets[selected]];
  return immutable({visible:pkg?.architecture==='esp32',selected,canSelect,reason:reason||'A is ota_0; B is ota_1. Boot selection is not changed.',bootAddress,writesBootSlot:writesBootSlot(selected),selectedAddresses:immutable(selectedAddresses),options:immutable(options)});
}

// This only narrows a previously inspected ordinary app plan. The session
// rechecks compatibility and seals the result before it can be flashed.
export function selectEspWriteSlots(pkg,plan,selection='both'){
  if(!choices.has(selection))fail('Choose ESP32 slot A, slot B, or both.');
  if(pkg?.architecture!=='esp32'||!plan)fail('Inspect the ESP32 application before selecting slots.');
  const inspected=espSlotChoices(pkg,plan),option=inspected.options.find(item=>item.value===selection);
  if(!option?.available)fail(inspected.reason);
  if(!inspected.canSelect&&selection!==inspected.selected)fail(inspected.reason);
  const all=[...sourceAddresses(plan)],addresses=selection==='both'?all:all.filter(value=>option.addresses.includes(value));
  if(!addresses.length||addresses.some(value=>!all.includes(value)))fail('The selected OTA slot is not part of the inspected flash plan.');
  return {...plan,addresses,allSlotAddresses:all,slotSelection:selection,slotBootAddress:inspected.bootAddress,writesBootSlot:option.writesBootSlot};
}
