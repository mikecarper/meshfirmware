import {catalogProvider} from './catalog.js';

const boards = new Map([
  ['RAK WisBlock / WisMesh (RAK 4631)', '4631'],
  ['RAK WisMesh 1W Booster (3401 + 13302)', '3401'],
]);
const storage = new Set(['lora_ota_no_external_sensors', 'w25q16_lora_ota',
  'rak15001_slot_c_lora_ota', 'rak13302_w25q16_lora_ota']);
const bridges = new Set(['bridge_rs232_serial1_lora_ota_no_external_sensors',
  'bridge_rs232_serial2_lora_ota_no_external_sensors']);

function rakProfile(item) {
  if(item?.project!=='MeshCore'||catalogProvider(item.provider)!=='Keymind Cascade'
    ||item.architecture!=='nrf52'||item.role!=='repeater'||item.action!=='flash')return null;
  const match=/^(RAK_(3401|4631)_repeater_([A-Za-z0-9_]+))-(full|reduced)-ota-(v[0-9][A-Za-z0-9.+-]*-[0-9a-f]{8})\.zip$/.exec(item.name||'');
  if(!match||boards.get(item.hardware)!==match[2]||item.version!==match[5])return null;
  const targets=[...(item.releaseNotes||'').matchAll(/(?:^|\n)\s*EXACT TARGET\s*-\s*([A-Za-z0-9_-]+)(?:[.\s]|$)/g)];
  if(targets.length!==1||targets[0][1]!==match[1])return null;
  const releaseKey=JSON.stringify([catalogProvider(item.provider),item.hardware,item.role,item.action,item.version]);
  return {target:match[1],family:match[2],variant:match[3],sensors:match[4],
    releaseKey,key:`${releaseKey}:${match[4]}`};
}

// Presentation only: retain every original catalog entry and its stable index.
// Storage/serial replacements match the board, source, and sensor policy.
// Ethernet prefers Full for the same board/release. Exact storage/serial targets
// and shared links remain visible, including legacy UART1 wiring.
export function firmwareChoices(items,{showOlder=false,installedTarget='',keepNames=[]}={}) {
  const profiles=new Map(items.map(item=>[item,rakProfile(item)])),unified=new Map(),fullEthernet=new Map();
  for(const [item,profile] of profiles){
    if(profile?.variant==='unified_lora_ota'){
      const group=unified.get(profile.key)||[];group.push(item);unified.set(profile.key,group);
    }
    if(profile?.variant==='ethernet'&&profile.sensors==='full')
      fullEthernet.set(profile.releaseKey,(fullEthernet.get(profile.releaseKey)||0)+1);
  }
  const older=new Set();
  for(const [item,profile] of profiles){
    if(profile&&(storage.has(profile.variant)||(profile.family==='4631'&&bridges.has(profile.variant)))
      &&unified.get(profile.key)?.length===1)older.add(item);
    if(profile?.variant==='ethernet'&&profile.sensors==='reduced'
      &&fullEthernet.get(profile.releaseKey)===1)older.add(item);
  }
  const names=new Set(keepNames.filter(Boolean));
  return {olderCount:older.size,items:items.filter(item=>{
    const profile=profiles.get(item);
    return showOlder||!older.has(item)||names.has(item.name)
      ||(profile?.target===installedTarget&&profile.variant!=='ethernet');
  })};
}

export function firmwareChoiceLabel(item,{showHardware=false,showVersion=false}={}) {
  const profile=rakProfile(item),recommendation=/-reduced-ota-v\d/i.test(item.name||'')?'(PICK THIS) ':'';
  if(profile&&['unified_lora_ota','ethernet'].includes(profile.variant)){
    const kind=profile.variant==='unified_lora_ota'?'Unified':'Ethernet';
    const sensors=profile.sensors==='full'?'Full sensors':'Reduced optional sensors';
    return `${recommendation}${showHardware?item.hardware+' / ':''}Repeater / ${kind} - ${sensors} + LoRa OTA${showVersion?' - '+item.version:''}`;
  }
  return `${recommendation}${[item.title,item.subtitle].filter(Boolean).join(' / ')} - ${item.name} - ${item.action}`;
}
