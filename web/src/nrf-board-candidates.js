// Selection hints only. A USB identity describes the INSTALLED bootloader,
// which can be shared or installed on the wrong physical board. Nothing in
// this module selects hardware, opens a port or authorizes a write.
import {canonicalHardware} from './hardware-aliases.js';

// Reviewed USB_DESC_{VID,UF2_PID,CDC_ONLY_PID} values in OTAFIX src/boards/**/
// board.h, including inherited headers and the factory identities reviewed in
// bootloader-info.js. The full union is retained before catalog intersection:
// provider/role filtering must not turn a shared USB ID into board proof.
// Source: https://github.com/mikecarper/Adafruit_nRF52_Bootloader_OTAFIX/tree/v0.11.0-OTAFIX2.4.12/src/boards
// Additional factory/current source headers: gat562_mesh_watch13, meshtiny,
// muzi_base, nano_g2_ultra, lilygo_techo_card, lilygo_t_impulse_plus,
// heltec_mesh_solar and meshtracker_x1. These are hints, not bootloader offers.
const rakHardware = ['RAK WisMesh 1W Booster (3401 + 13302)', 'RAK WisBlock / WisMesh (RAK 4631)', 'RAK WisMesh Tag', 'Muzi Works R1 Neo'];
const rakProfiles = ['wiscore_rak3401', 'wiscore_rak3401_auto', 'wiscore_rak3401_rak13302_w25q16', 'wiscore_rak4631_auto', 'wiscore_rak4631_board', 'wiscore_rak4631_board_rak15001_slot_c', 'wiscore_rak4631_w25q16', 'wismesh_tag'];
const sharedAdafruitHardware = [...rakHardware, 'GAT-IoT GAT562 30s', 'GAT-IoT GAT562 EVB Pro', 'GAT-IoT GAT562 Tracker', 'GAT-IoT GAT562 Mesh Watch13', 'Minewsemi ME25LS01', 'Meshtiny'];
const sharedAdafruitProfiles = [...rakProfiles, 'gat562', 'gat562_mesh_watch13', 'minewsemi_mx25le01', 'meshtiny'];
const xiaoHardware = ['Seeed Studio Xiao nRF52 WIO', 'Ikoka Handheld nRF E22 30 dBm', 'Ikoka Nano', 'Ikoka Stick', 'SolarXiao'];
const usbCandidates = new Map([
  ['239a:0029', {hardware: [...sharedAdafruitHardware, 'LilyGo T-Echo'], profiles: [...sharedAdafruitProfiles, 'lilygo_techo']}],
  ['239a:002a', {hardware: sharedAdafruitHardware, profiles: sharedAdafruitProfiles}],
  ['239a:0071', {hardware: ['Heltec T114', 'Heltec Mesh Node T096', 'Heltec Mesh Node T1', 'Heltec MeshPocket', 'Heltec MeshTower V2', 'Heltec MeshSolar / MeshTower'], profiles: ['heltec_t114', 'heltec_t096', 'heltec_t1', 'heltec_mesh_pocket', 'heltec_mesh_tower_v2', 'heltec_mesh_tower_v2_sdcard', 'heltec_mesh_solar']}],
  ['239a:0081', {hardware: ['Muzi Works Base Duo', 'Muzi Works Base Uno'], profiles: ['muzi_base']}],
  ['239a:00b3', {hardware: ['Keepteen LT1', 'ProMicro nrf52 (faketec)'], profiles: ['keepteen_lt1', 'promicro_nrf52840']}],
  ['239a:00da', {hardware: ['Elecrow ThinkNode M1', 'Elecrow ThinkNode M3', 'Elecrow ThinkNode M6', 'LilyGo T-Echo Lite', 'LilyGo T-Echo Card', 'LilyGo T-Impulse Plus nRF52840'], profiles: ['thinknode_m1', 'thinknode_m3', 'thinknode_m6', 'pca10056', 'lilygo_techo_lite', 'lilygo_techo_card', 'lilygo_t_impulse_plus']}],
  ['2886:0044', {hardware: [...xiaoHardware, 'Seeed Studio SenseCAP Solar'], profiles: ['xiao_nrf52840_ble', 'sensecap_solar_p1']}],
  ['2886:0045', {hardware: ['Seeed Studio Xiao nRF52 WIO'], profiles: ['xiao_nrf52840_ble_sense']}],
  ['2886:0057', {hardware: ['Seeed Studio SenseCAP T1000-E', 'Seeed SenseCAP MeshTracker X1'], profiles: ['t1000_e', 'meshtracker_x1']}],
  ['2886:1667', {hardware: ['Seeed Studio Wio Tracker L1 Pro', 'Seeed Studio Wio Tracker L1 E-Ink', 'Seeed WioTracker L1 1W'], profiles: ['wio_tracker_l1']}],
  ['4251:8695', {hardware: ['UnitEng Nano G2 Ultra'], profiles: ['nano_g2_ultra']}],
]);
const reviewedProfileTag = 'v0.11.0-OTAFIX2.4.12';
const unique = values => [...new Set(values)].sort();
const usbIdentity = info => [info?.usbVendorId, info?.usbProductId].every(value => Number.isInteger(value) && value >= 0 && value <= 65535)
  ? [info.usbVendorId, info.usbProductId].map(value => value.toString(16).padStart(4, '0')).join(':') : '';

export function nrfBoardCandidates({items = [], usbInfo = {}, hardware = ''} = {}) {
  const available = Array.isArray(items) ? items.filter(item => item?.project === 'MeshCore' && item.architecture === 'nrf52' && typeof item.hardware === 'string' && item.hardware.length > 0) : [];
  const exact = typeof hardware === 'string' && hardware ? canonicalHardware(hardware) : '';
  if (exact && available.some(item => canonicalHardware(item.hardware) === exact)) return {
    candidates: [exact], source: 'identified-hardware',
    reason: 'The previously identified hardware is available as an exact nRF52 catalog target. This narrows the list only; it is not independent physical-board proof or permission to flash.',
  };
  const id = usbIdentity(usbInfo), reviewed = usbCandidates.get(id);
  if (!reviewed) return {candidates: [], source: 'unknown', reason: 'No reviewed nRF52 bootloader USB candidate list is available. Keep all nRF52 hardware available for manual selection.'};
  const names = new Set(reviewed.hardware.map(canonicalHardware));
  const candidates = unique(available.filter(item => names.has(canonicalHardware(item.hardware)) || (item.bootloaderInfo?.tag === reviewedProfileTag && reviewed.profiles.includes(item.bootloaderInfo.profile))).map(item => canonicalHardware(item.hardware)));
  return {
    candidates, source: 'usb-hint',
    reason: candidates.length ? `USB ${id} is shared by the listed installed-bootloader candidates. Choose the physical board; this is not board proof. Show all nRF52 hardware if a different bootloader was installed.` : `No catalog boards match the reviewed USB ${id} hints. Keep all nRF52 hardware available; USB identity is not physical-board proof.`,
  };
}
