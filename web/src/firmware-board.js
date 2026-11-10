// Board compatibility is evidence, not permission to flash. A matching model
// is still a firmware-reported claim, never independent physical-board proof.
import {hash,partitionTable} from './firmware.js';
import {endfIdentity,isKnownDfu,payloadBoardIdentity} from './board-safety.js';
import {canonicalHardware} from './hardware-aliases.js';
import {detectBoard} from './board-detection.js';
import {detectMeshtasticBoard} from './meshtastic-boards.js';
import {genericNrfEraseIntent} from './generic-nrf-erase.js';

const normalize=value=>typeof value==='string'&&value.length<=256?canonicalHardware(value).trim().toLowerCase().replace(/[\s_-]+/g,' '):'';
const unique=values=>[...new Set(values)].sort();
const encode=value=>new TextEncoder().encode(value);
const tags=new Map([
  ['t1000e',['Seeed Studio SenseCAP T1000-E']],
  ['RAK4631',['RAK WisBlock / WisMesh (RAK 4631)']],
  ['RAK_4631',['RAK WisBlock / WisMesh (RAK 4631)']],
  ['RAK3401',['RAK WisMesh 1W Booster (3401 + 13302)']],
  ['RAK_3401',['RAK WisMesh 1W Booster (3401 + 13302)']],
  ['RAK3112',['RAK WisBlock 3112']],
  ['RAK_3112',['RAK WisBlock 3112']],
  ['WISMESHTAG',['RAK WisMesh Tag']],
  ['Xiao_nrf52',['Seeed Studio Xiao nRF52 WIO']],
  ['wio_wm1110',['Seeed Studio Wio WM1110']],
  ['WioTrackerL1',['Seeed Studio Wio Tracker L1 Pro']],
  ['WioTrackerL1Eink',['Seeed Studio Wio Tracker L1 E-Ink']],
  ['WioTrackerL1_1W',['Seeed WioTracker L1 1W']],
  ['meshtracker_x1',['Seeed SenseCAP MeshTracker X1']],
  ['sensecap_solar',['Seeed Studio SenseCAP Solar']],
  ['SenseCapIndicator-LoRa',['Seeed Studio SenseCAP Indicator LoRa']],
  ['Station_G2',['UnitEng Station G2']],
  ['Station_G3_ESP32',['UnitEng/BQ Voyage Station G3']],
  ['Heltec_t096',['Heltec Mesh Node T096']],
  ['Heltec_tower_v2',['Heltec MeshTower V2']],
  ['LilyGo_T-Echo',['LilyGo T-Echo']],
  ['LilyGo_T-Echo-Lite',['LilyGo T-Echo Lite']],
  ['LilyGo_T-Echo_Card',['LilyGo T-Echo Card']],
  ['Tbeam_SX1262',['LilyGo T-Beam (SX1262)']],
  ['Tbeam_SX1276',['LilyGo T-Beam 1.2 (SX1276)']],
  ['LilyGo_T3S3_sx1262',['LilyGo T3 S3 (SX126x)']],
  ['LilyGo_T3S3_sx1276',['LilyGo T3 S3 (SX127x)']],
  // These are shared build-family tags. Filtering catalog/role/provider must
  // not turn missing variant evidence into a positive board match.
  ['Heltec_v3',['Heltec v3','Heltec WSL3']],
  ['Tbeam',['LilyGo T-Beam (SX1262)','LilyGo T-Beam 1.2 (SX1276)']],
  ['LilyGo_T3S3',['LilyGo T3 S3 (SX126x)','LilyGo T3 S3 (SX127x)']],
  ['SenseCapIndicator',['Seeed Studio SenseCAP Indicator LoRa','Seeed Studio SenseCAP Indicator ESP-NOW']],
].map(([tag,hardware])=>[normalize(tag),hardware.map(canonicalHardware)]));
const genericFamilies=new Set(['Tbeam','LilyGo_T3S3','SenseCapIndicator'].map(normalize));
const storageTags=new Map([
  ['RAK4631_RAK15001_C',['RAK WisBlock / WisMesh (RAK 4631)']],
  ['RAK4631_W25Q16',['RAK WisBlock / WisMesh (RAK 4631)']],
  ['RAK3401_RAK13302_W25Q16',['RAK WisMesh 1W Booster (3401 + 13302)']],
  ['SenseCapIndicator-LoRa-N16R2',['Seeed Studio SenseCAP Indicator LoRa']],
].map(([tag,hardware])=>[normalize(tag),hardware]));
const embeddedModels=new Map([
  ['Seeed Tracker T1000-E',['Seeed Studio SenseCAP T1000-E']],
  ['Seeed Xiao-nrf52',['Seeed Studio Xiao nRF52 WIO']],
  ['Seeed Wio WM1110',['Seeed Studio Wio WM1110']],
  ['RAK 4631',['RAK WisBlock / WisMesh (RAK 4631)']],
  ['WisCore RAK4631 Board',['RAK WisBlock / WisMesh (RAK 4631)']],
  ['RAK 3401',['RAK WisMesh 1W Booster (3401 + 13302)']],
  ['WisCore RAK3401 Board',['RAK WisMesh 1W Booster (3401 + 13302)']],
  ['Heltec V4 OLED',['Heltec v4']],['Heltec V4.2 OLED',['Heltec v4']],['Heltec V4.3 OLED',['Heltec v4']],
  ['Heltec V4.2 none detected',['Heltec v4']],['Heltec V4.3 none detected',['Heltec v4']],
  ['Station G2',['UnitEng Station G2']],['Station G3 ESP32',['UnitEng/BQ Voyage Station G3']],
  ['GAT562 30S Mesh Kit',['GAT-IoT GAT562 30s']],['GAT562 EVB Pro',['GAT-IoT GAT562 EVB Pro']],
  ['GAT562 Mesh Tracker Pro',['GAT-IoT GAT562 Tracker']],['GAT562 Mesh Watch 13',['GAT-IoT GAT562 Mesh Watch13']],
]);
function exactItems(items){return Array.isArray(items)?items.filter(item=>item?.project==='MeshCore'&&typeof item.hardware==='string'&&item.hardware.length<=256):[];}
function exactNames(value,items){
  const key=normalize(value),reviewed=storageTags.get(key)||tags.get(key);
  if(reviewed)return [...reviewed];
  return unique(items.filter(item=>normalize(item.hardware)===key).map(item=>canonicalHardware(item.hardware)));
}
function catalogIdentity(identity,items){
  const tag=normalize(identity.hardware),candidates=[];
  if(genericFamilies.has(tag))return [];
  for(const item of items){
    const notes=typeof item.releaseNotes==='string'?item.releaseNotes.slice(0,100000):'';
    const environments=unique([...notes.matchAll(/\bEXACT TARGET\s*-\s*([A-Za-z0-9_-]{1,160})(?=[.\s]|$)/g)].map(match=>match[1]));
    if(environments.length!==1)continue;
    const environment=environments[0],digest=hash(encode(environment));
    const target=Number.parseInt(digest.match(/../g).slice(0,4).reverse().join(''),16);
    if(target!==identity.target)continue;
    const role=environment.search(/[_-](?:partition_expander|repeater|repeatr|room_server|room_svr|sensor|terminal_chat|kiss_modem|companion_radio|companion|comp_radio)(?=[_-]|$)/i);
    let family=(role>=0?environment.slice(0,role):environment).replace(/^[_-]+|[_-]+$/g,'');
    family=({Heltec_WSL3:'Heltec_v3',Heltec_t114_without_display:'Heltec_t114',RAK_4631:'RAK4631'})[family]||family;
    if(family.length>32)family=family.slice(0,23).replace(/[_-]+$/g,'')+'-'+hash(encode(family)).slice(0,8);
    const aliases=exactNames(identity.hardware,items);
    if(normalize(family)===tag||aliases.some(name=>normalize(name)===normalize(item.hardware)))candidates.push(canonicalHardware(item.hardware));
  }
  return unique(candidates);
}
function imageIdentities(pkg){
  if(!pkg.merged)return {identities:[endfIdentity(pkg.payload)].filter(Boolean),missing:false};
  const start=pkg.partitionTableOffset??0x8000-(pkg.flashOffset??0),origin=pkg.flashOffset??0;
  let parts;try{parts=partitionTable(pkg.payload.subarray(start,start+4096));}catch{return {identities:[],missing:true};}
  const identities=[];let missing=false;
  for(const part of parts.filter(part=>part.type===0)){
    const at=part.offset-origin;if(at<0||at>=pkg.payload.length)continue;
    let end=Math.min(at+part.size,pkg.payload.length);
    while(end>at&&pkg.payload[end-1]===255)end--;
    if(end===at)continue;
    const identity=endfIdentity(pkg.payload.subarray(at,end));
    if(identity)identities.push(identity);else missing=true;
  }
  return {identities,missing};
}
function embeddedIdentity(payload){
  const found=new Set();let part='',long=false;
  const accept=()=>{if(!long)for(const name of embeddedModels.get(part)||[])found.add(canonicalHardware(name));part='';long=false;};
  for(const byte of payload){if(byte>=32&&byte<=126){if(part.length<256)part+=String.fromCharCode(byte);else long=true;}else accept();}
  accept();return unique([...found]);
}
function connectedIdentity(device,items){
  if(!device||device.firmwareFamily==='bootloader')return {candidates:[],certain:false};
  if(device.firmwareFamily==='meshtastic'||Number.isInteger(device.meshtasticHardware)){
    const result=detectMeshtasticBoard({items,hwModel:device.meshtasticHardware,pioEnv:device.meshtasticPioEnv||''});
    return {candidates:result.candidates||[],certain:!!result.hardware};
  }
  const model=typeof device.model==='string'?device.model:'';
  if(!model)return {candidates:[],certain:false};
  const known=embeddedModels.get(model);if(known)return {candidates:known,certain:known.length===1};
  const result=detectBoard({items,deviceModel:model});
  if(result.hardware)return {candidates:[result.hardware],certain:true};
  const aliases=storageTags.get(normalize(model))||tags.get(normalize(model));
  return aliases?{candidates:aliases,certain:aliases.length===1}:{candidates:result.candidates||[],certain:false};
}
const result=(status,reason,extra={})=>Object.freeze({status,requiresOverride:status!=='match',reason,...extra});

export function assessFirmwareBoard({pkg,hardware='',device=null,items=[],plan=null}={}){
  if(!pkg||!(pkg.payload instanceof Uint8Array))return result('unknown','Load a validated firmware file before checking its board identity.');
  const payloadHash=hash(pkg.payload),catalog=exactItems(items),selected=canonicalHardware(hardware||'');
  if(payloadHash!==pkg.payloadHash)return result('mismatch','Firmware payload changed after inspection. Reload and validate the file before writing.');
  const architectures=new Set();if(['esp32','nrf52','uf2'].includes(device?.architecture))architectures.add(device.architecture);
  if(Number.isInteger(device?.chipId))architectures.add('esp32');
  if(isKnownDfu(device?.usbInfo||device||{}))architectures.add('nrf52');
  if(architectures.size>1)return result('mismatch','Connected-device evidence reports conflicting processor architectures. Reconnect and identify the same radio again.');
  if(architectures.size===1&&!architectures.has(pkg.architecture))return result('mismatch',`The file is ${pkg.architecture}, but the connected device reports ${[...architectures][0]}. This is not a compatible processor family.`);
  if(pkg.architecture==='esp32'&&Number.isInteger(device?.chipId)&&device.chipId!==pkg.chipId)return result('mismatch',`The firmware chip ID ${pkg.chipId} differs from the verified connected chip ID ${device.chipId}. A board override cannot bypass the silicon checks.`);
  // A mounted drive describes its installed loader, not the physical board.
  // It can expose a processor-family contradiction, but never prove a match.
  const rawDrive=typeof plan?.uf2Info==='string'?plan.uf2Info.slice(0,4096):null;
  const driveInfo=rawDrive===null?plan?.uf2Info:{boardId:/^Board-ID:\s*([^\r\n]*)/mi.exec(rawDrive)?.[1],model:/^Model:\s*([^\r\n]*)/mi.exec(rawDrive)?.[1]};
  const driveId=String(driveInfo?.boardId||'')+' '+String(driveInfo?.model||'');
  const driveFamily=/(?:^|[-_ ])nrf52(?:840|833)?(?=$|[-_ ])/i.test(driveId)?'nrf52':/(?:^|[-_ ])rp2040(?=$|[-_ ])/i.test(driveId)?'rp2040':null;
  const fileFamily=pkg.architecture==='uf2'&&pkg.family===0xe48bff56?'rp2040':pkg.architecture;
  if(driveFamily&&((fileFamily==='rp2040'&&driveFamily!=='rp2040')||(fileFamily==='nrf52'&&driveFamily!=='nrf52')||fileFamily==='esp32'))return result('mismatch',`The firmware processor family ${fileFamily} conflicts with the selected drive’s installed ${driveFamily} bootloader. Drive labels are not physical-board proof.`);
  const selectedArchitectures=new Set(catalog.filter(item=>canonicalHardware(item.hardware)===selected&&['esp32','nrf52','uf2'].includes(item.architecture)).map(item=>item.architecture));
  if(selectedArchitectures.size===1&&!selectedArchitectures.has(pkg.architecture))return result('mismatch',`The file is ${pkg.architecture}, but the selected ${selected} catalog target uses ${[...selectedArchitectures][0]}.`);
  const connected=connectedIdentity(device,catalog),deviceHardware=connected.certain?connected.candidates[0]:null;
  const neutral=pkg.architecture==='nrf52'&&pkg.kind==='application'&&pkg.mode===4&&pkg.erase===true&&pkg.destructive===true&&pkg.appSize===pkg.payload.length&&pkg.sdSize===0&&pkg.blSize===0&&!!genericNrfEraseIntent(payloadHash);
  if(neutral)return result('unknown','Verified official generic nRF52 erase utility; it does not claim a board identity. Erase confirmation and final-firmware board checks still apply.',{requiresOverride:false,boardNeutralErase:true,deviceHardware});
  if(selected&&deviceHardware&&normalize(selected)!==normalize(deviceHardware))return result('mismatch',`The connected radio reports ${deviceHardware}, but ${selected} is selected. Changing a firmware selection does not change the connected USB device.`,{deviceHardware});
  const extracted=imageIdentities(pkg),identities=extracted.identities,identitySets=[];
  for(const identity of identities){const exact=catalogIdentity(identity,catalog),aliases=exactNames(identity.hardware,catalog);identitySets.push({identity,candidates:exact.length?exact:aliases,qualified:storageTags.has(normalize(identity.hardware))});}
  const evidence={payloadHardware:unique(identities.map(identity=>identity.hardware)).join(', ')||null,deviceHardware};
  if(identitySets.length>1){
    const first=identitySets[0];
    if(identitySets.slice(1).some(entry=>{
      const overlap=entry.candidates.some(name=>first.candidates.includes(name));
      return entry.candidates.length&&first.candidates.length&&!overlap || normalize(entry.identity.hardware)!==normalize(first.identity.hardware)&&(!entry.candidates.length||!first.candidates.length||!overlap);
    }))return result('mismatch','The merged firmware contains application images reporting different hardware identities. Every embedded application must be reviewed for the intended radio.',{...evidence,proof:'conflicting-endf'});
  }
  let candidates=unique(identitySets.flatMap(entry=>entry.candidates)),proof=identities.length?'endf':'unknown';
  if(!identities.length){
    candidates=embeddedIdentity(pkg.payload);if(candidates.length)proof='embedded-model-string';
    // Preserve the established RAK exact-string evidence without considering
    // other boards' embedded build-target names as physical-board strings.
    if(!candidates.length&&pkg.architecture==='nrf52'){
      const rak=payloadBoardIdentity(pkg.payload);
      if(rak.family==='rak3401')candidates=tags.get(normalize('RAK3401'));
      if(rak.family==='rak4631')candidates=tags.get(normalize('RAK4631'));
      if(candidates.length)proof='embedded-model-string';
    }
  }
  // A raw BIN/UF2 digest can be recomputed directly from its complete bytes.
  // A DFU ZIP envelope is not retained in pkg.payload: never pretend that its
  // un-recomputable ZIP SHA alone proves the extracted application's board.
  if(pkg.architecture!=='nrf52'){
    const byDigest=unique(catalog.filter(item=>typeof item.sha256==='string'&&item.sha256.toLowerCase()===payloadHash).map(item=>canonicalHardware(item.hardware)));
    if(byDigest.length){
      if(candidates.length&&!byDigest.some(name=>candidates.includes(name)))return result('mismatch','The byte-matched published firmware target conflicts with its embedded board identity.',{...evidence,proof:'conflicting-catalog-hash'});
      candidates=byDigest;proof='catalog-sha256';
    }
  }
  const payloadHardware=evidence.payloadHardware||(candidates.length===1?candidates[0]:null),extra={...evidence,payloadHardware,payloadCandidates:candidates,proof};
  if(candidates.length&&selected&&!candidates.some(name=>normalize(name)===normalize(selected)))return result('mismatch',`The firmware identifies ${candidates.join(' / ')}, not the selected ${selected}.`,extra);
  if(candidates.length&&connected.certain&&!candidates.some(name=>normalize(name)===normalize(deviceHardware)))return result('mismatch',`The firmware identifies ${candidates.join(' / ')}, but the connected radio reports ${deviceHardware}.`,extra);
  if(identitySets.some(entry=>entry.qualified)&&!identitySets.every(entry=>normalize(device?.model)===normalize(entry.identity.hardware)))return result('unknown','The firmware names a specific storage or hardware revision that the connected model has not confirmed. Review that exact variant before proceeding.',extra);
  if(extracted.missing)return result('unknown','Not every populated application in the merged image has a verified board identity. Chip and partition checks still apply; confirm the board yourself.',extra);
  if(candidates.length===1&&connected.certain&&normalize(candidates[0])===normalize(deviceHardware))return result('match',`Firmware byte identity matches the reported ${deviceHardware} model. This is not independent physical-board proof; chip, bootloader, layout and write checks still apply.`,extra);
  return result('unknown',!candidates.length?'The firmware does not expose a verified, unambiguous board identity. Its filename and the nRF52 init packet do not prove the physical board.':candidates.length>1?'The firmware identity is shared by multiple hardware variants. Confirm the exact board; a catalog filter cannot prove the variant.':`Firmware identifies ${candidates[0]}, but the connected board has not been identified unambiguously. Confirm it is the intended radio.`,extra);
}
