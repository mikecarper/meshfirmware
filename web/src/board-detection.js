// Selection convenience only, never proof for a write/board-safety override.
// Compare complete model strings. Do not strip vendors, suffixes, or revisions:
// V4 and V4 R8 (or an internal/SD bootloader) are not interchangeable.
const normalize=value=>typeof value==='string'&&value.length<=256?value.trim().toLowerCase().replace(/[\s_-]+/g,' '):'';
const unique=values=>[...new Set(values)].sort();

// Exact getManufacturerName() strings reviewed in MeshCore variants. Values
// are catalog hardware display names, NOT a fuzzy name-search vocabulary.
const modelAliases=[
  ['Station G3 ESP32',['UnitEng/BQ Voyage Station G3']],
  ['Station G2',['UnitEng Station G2']],
  ['Seeed Tracker T1000-E',['Seeed Studio SenseCAP T1000-E']],
  ['RAK 4631',['RAK WisBlock / WisMesh (RAK 4631)']],
  ['WisCore RAK4631 Board',['RAK WisBlock / WisMesh (RAK 4631)']],
  ['RAK 3401',['RAK WisMesh 1W Booster (3401 + 13302)']],
  ['RAK 3112',['RAK WisBlock 3112']],
  ['Seeed Xiao-nrf52',['Seeed Studio Xiao nRF52 WIO']],
  ['Xiao S3',['Seeed Studio Xiao S3']],
  ['Xiao S3 WIO',['Seeed Studio Xiao S3 WIO']],
  ['Xiao C3',['Seeed Studio Xiao C3']],
  ['Xiao C6',['Seeed Studio Xiao C6']],
  ['Xiao RP2040',['Seeed Studio Xiao RP2040']],
  ['Seeed Wio WM1110',['Seeed Studio Wio WM1110']],
  ['Seeed Wio Tracker L2 Pro',['Seeed Wio Tracker L2']],
  // Both manufacturer strings are identical in the current L1/1W variants.
  ['Seeed Wio Tracker L1',['Seeed Studio Wio Tracker L1 Pro','Seeed WioTracker L1 1W']],
  ['Seeed SenseCap Solar',['Seeed Studio SenseCAP Solar','Seeed Studio SenseCAP Solar Node P1']],
  ['ProMicro DIY',['ProMicro nrf52 (faketec)']],
  ['Minewsemi',['Minewsemi ME25LS01']],
  ['GAT562 30S Mesh Kit',['GAT-IoT GAT562 30s']],
  ['GAT562 EVB Pro',['GAT-IoT GAT562 EVB Pro']],
  ['GAT562 Mesh Tracker Pro',['GAT-IoT GAT562 Tracker']],
  ['GAT562 Mesh Watch 13',['GAT-IoT GAT562 Mesh Watch13']],
  ['Heltec Mesh Solar',['Heltec MeshSolar / MeshTower']],
  ['LILYGO T-LoRa V2.1-1.6',['LilyGo LoRa32 V2.1_1.6']],
  ['LilyGo T-Impulse-Plus',['LilyGo T-Impulse Plus nRF52840']],
  ['LilyGO T-ETH Elite',['LilyGo T-ETH Elite (SX1262)']],
  ['Unit C6L',['M5Stack Unit C6L']],
  ['Ikoka Handheld E22 30dBm (Xiao_nrf52)',['Ikoka Handheld nRF E22 30 dBm']],
  ['Waveshare RP2040-LoRa',['Waveshare RP2040-LoRa-HF/LF']],
];
const aliases=new Map(modelAliases.map(([model,hardware])=>[normalize(model),hardware.map(normalize)]));

// These exact PIDs are useful hints only. Firmware/bootloaders can have been
// installed on the wrong board and several boards deliberately share IDs.
const usbHints=new Map([
  ['2886:8044',['Seeed Studio Xiao nRF52 WIO','Ikoka Handheld nRF E22 30 dBm','Ikoka Nano','Ikoka Stick','SolarXiao']],
  ['2886:0059',['Seeed Studio Xiao S3','Seeed Studio Xiao S3 WIO']],
]);
function usbIdentity(info){
  return [info?.usbVendorId,info?.usbProductId].every(n=>Number.isInteger(n)&&n>=0&&n<=65535)?[info.usbVendorId,info.usbProductId].map(n=>n.toString(16).padStart(4,'0')).join(':'):'';
}

export function detectBoard({items=[],deviceModel='',usbInfo={}}={}) {
  const available=items.filter(item=>item?.project==='MeshCore'&&typeof item.hardware==='string'),model=normalize(deviceModel);
  if(model){
    const names=new Set([model,...(aliases.get(model)||[])]);
    const candidates=unique(available.filter(item=>names.has(normalize(item.hardware))||(item.bootloaderInfo?.hardwareId&&model===normalize(item.bootloaderInfo.hardwareId))).map(item=>item.hardware));
    if(candidates.length===1)return {hardware:candidates[0],candidates,source:'application-model',reason:'Exact running-firmware model matched the catalog. This selects hardware only; it is not independent physical-board proof.'};
    return {hardware:null,candidates,source:'application-model',reason:candidates.length?'The reported model matches multiple catalog boards; choose the exact hardware manually.':'No complete exact catalog match for the reported model; choose hardware manually. Truncated or similar names are not guessed.'};
  }
  const id=usbIdentity(usbInfo),hints=new Set((usbHints.get(id)||[]).map(normalize)),profileHints=recoveryUsb.get(id)||[],candidates=unique(available.filter(item=>hints.has(normalize(item.hardware))||(item.bootloaderInfo?.tag===recoveryTag&&profileHints.includes(item.bootloaderInfo.profile))).map(item=>item.hardware));
  return {hardware:null,candidates,source:candidates.length?'usb-hint':'unknown',reason:candidates.length?`USB ${id} provides candidate hints only, not physical-board proof. Read the running node or choose hardware manually.`:'USB IDs do not identify this physical board. Read the running node or choose hardware manually.'};
}

// Reviewed against the exact release's src/boards/**/board.h, including inherited
// headers. Scope to that release and its FULL recovery inventory: filtering the
// catalog must never make a shared PID appear unique. UF2 and CDC-only PIDs are
// included; this reads USB metadata only and never opens a mounted drive.
const recoveryTag='v0.11.0-OTAFIX2.4.12';
const rakRecovery=['wiscore_rak3401','wiscore_rak3401_auto','wiscore_rak3401_rak13302_w25q16','wiscore_rak4631_auto','wiscore_rak4631_board','wiscore_rak4631_board_rak15001_slot_c','wiscore_rak4631_w25q16','wismesh_tag'];
const recoveryUsb=new Map([
  ['2886:0044',['sensecap_solar_p1','xiao_nrf52840_ble']],
  ['2886:0045',['xiao_nrf52840_ble_sense']],
  ['2886:0057',['t1000_e']],
  ['2886:1667',['wio_tracker_l1']],
  ['239a:0029',['gat562','minewsemi_mx25le01','lilygo_techo',...rakRecovery]],
  ['239a:002a',['gat562','minewsemi_mx25le01',...rakRecovery]],
  ['239a:0071',['heltec_mesh_pocket','heltec_mesh_tower_v2_sdcard','heltec_t096','heltec_t1','heltec_t114']],
  ['239a:00b3',['keepteen_lt1','promicro_nrf52840']],
  ['239a:00da',['lilygo_techo_lite','pca10056','thinknode_m1','thinknode_m3','thinknode_m6']],
]);
const recoveryUniverse=unique([...recoveryUsb.values()].flat());
const recoveryVolumes=new Map([
  ['GAT562BOOT',['gat562']],['MESHPOCKET',['heltec_mesh_pocket']],['HT-n5262G',['heltec_t096']],
  ['HELTEC-T1',['heltec_t1']],['HT-n5262',['heltec_mesh_tower_v2_sdcard','heltec_t114']],['KEEPTEENLT1',['keepteen_lt1']],
  ['TECHOBOOT',['lilygo_techo']],['TECHOLITE',['lilygo_techo_lite']],['MX25LE01',['minewsemi_mx25le01']],
  ['PCA10056',['pca10056']],['PROMICRO',['promicro_nrf52840']],['SENSECAP',['sensecap_solar_p1']],
  ['T1000-E',['t1000_e']],['ThinkNodeM1',['thinknode_m1']],['ThinkNodeM3',['thinknode_m3']],['ThinkNodeM6',['thinknode_m6']],
  ['TRACKER L1',['wio_tracker_l1']],['RAK3401',['wiscore_rak3401']],['3401A',['wiscore_rak3401_auto']],
  ['3401W25Q16',['wiscore_rak3401_rak13302_w25q16']],['4631A',['wiscore_rak4631_auto']],
  ['RAK4631',['wiscore_rak4631_board','wismesh_tag']],['RAK15001C',['wiscore_rak4631_board_rak15001_slot_c']],
  ['4631W25Q16',['wiscore_rak4631_w25q16']],['XIAO-BOOT',['xiao_nrf52840_ble']],['XIAO-SENSE',['xiao_nrf52840_ble_sense']],
].map(([label,ids])=>[normalize(label),ids]));
const knownSharedIdentity=new Map([
  [normalize('XIAO_DFU'),['xiao_nrf52840_ble','xiao_nrf52840_ble_sense']],
  ...[...recoveryVolumes].filter(([,ids])=>ids.length>1),
]);

export function detectRecoveryProfile({profiles=[],installedIdentity='',usbInfo={},tag=''}={}) {
  const valid=profiles.filter(p=>typeof p?.id==='string'),identity=normalize(installedIdentity),ids=valid.map(p=>p.id),reviewed=tag===recoveryTag&&ids.length===recoveryUniverse.length&&new Set(ids).size===ids.length&&ids.every(id=>recoveryUniverse.includes(id));
  // An explicit ID remains usable in new releases; version-specific labels/PIDs
  // require a complete reviewed inventory. New release profiles are not guessed.
  const aliases=reviewed?recoveryVolumes.get(identity)||[]:[];
  const textCandidates=identity?unique(valid.filter(p=>identity===normalize(p.id)||identity===normalize(`R_${p.id}`)||identity===normalize(p.installedIdentity)||aliases.includes(p.id)).map(p=>p.id)):[];
  const usbCandidates=reviewed?recoveryUsb.get(usbIdentity(usbInfo))||[]:[];
  if(!reviewed&&knownSharedIdentity.has(identity))return {profile:null,candidates:knownSharedIdentity.get(identity).filter(id=>ids.includes(id)),source:'identity',reason:'This known installed identity is shared. An incomplete or unreviewed inventory cannot make it unique; enter the full exact installed profile ID or select it manually.'};
  if(identity&&!textCandidates.length)return {profile:null,candidates:[],source:'identity',reason:'No exact installed-bootloader identity/profile matched. The USB hint cannot override an unknown or truncated supplied identity.'};
  let candidates=textCandidates.length?textCandidates:usbCandidates,source=textCandidates.length?'identity':usbCandidates.length?'usb':'unknown';
  if(textCandidates.length&&usbCandidates.length){candidates=textCandidates.filter(id=>usbCandidates.includes(id));if(!candidates.length)return {profile:null,candidates:[],source,reason:'Installed-identity text conflicts with the selected USB bootloader ID. Choose the correct installed profile manually; no automatic selection was made.'};}
  candidates=unique(candidates);
  return {profile:candidates.length===1?candidates[0]:null,candidates,source,reason:candidates.length===1?'Exact installed-bootloader evidence matched a single recovery profile. Confirm it is the currently installed bootloader, not the intended physical target.':candidates.length?'This USB/installed identity is shared by multiple recovery profiles; choose the exact installed profile manually.':!reviewed?'USB recovery matching is unavailable for this release or incomplete profile inventory. Enter the exact installed identity/profile or select it manually.':'No unique exact installed-bootloader evidence was available. Recovery is never inferred from the physical board.'};
}
