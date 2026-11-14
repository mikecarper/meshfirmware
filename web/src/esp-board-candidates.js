// Selection hints only: a processor family is not a physical-board identity.
// This helper never opens a port, selects a board or authorizes a write. Its
// caller must bind chipInfo to the selected port's actual ROM inspection, never
// to a proposed image, remembered selection or user-entered hardware name.
import {canonicalHardware} from './hardware-aliases.js';

// Reviewed board -> MCU recipes, not a guess from the catalog display name.
// MeshCore source pinned at f2162bcaca652d6172aa2a0f045858ab9dd35ce8:
// https://github.com/mikecarper/MeshCore/tree/f2162bcaca652d6172aa2a0f045858ab9dd35ce8
// Each row names variants/<variant>/platformio.ini and boards/<board>.json.
// A leading @ means the board JSON is in the matching, locally inspected
// PlatformIO espressif32 6.11.0 package, not in MeshCore's boards directory:
// https://github.com/platformio/platform-espressif32/tree/v6.11.0/boards
// Only build.mcu / explicit board_build.mcu is used. Upload flash_size,
// maximum_size, BOARD_HAS_PSRAM and memory_type do NOT prove physical memory.
const reviewedRecipes = [
  ['ESP32', 'GEPRC Linkflow 900', 'geprc_linkflow_900', '@esp32dev'],
  ['ESP32', 'Generic E22', 'generic-e22', '@esp32doit-devkit-v1'],
  ['ESP32', 'Heltec v2', 'heltec_v2', '@heltec_wifi_lora_32_V2'],
  ['ESP32', 'LilyGo LoRa32 V2.1_1.6', 'lilygo_tlora_v2_1', '@ttgo-lora32-v1'],
  ['ESP32', 'LilyGo T-Beam (SX1262)', 'lilygo_tbeam_SX1262', '@ttgo-t-beam'],
  ['ESP32', 'LilyGo T-Beam 1.2 (SX1276)', 'lilygo_tbeam_SX1276', '@ttgo-t-beam'],
  ['ESP32', 'Meshadventurer', 'meshadventurer', '@esp32doit-devkit-v1'],
  ['ESP32-C3', 'Generic ESP-NOW', 'generic_espnow', '@esp32-c3-devkitm-1'],
  ['ESP32-C3', 'Heltec CT62', 'heltec_ct62', '@esp32-c3-devkitm-1'],
  ['ESP32-C3', 'Seeed Studio Xiao C3', 'xiao_c3', '@seeed_xiao_esp32c3'],
  ['ESP32-C3', 'Tenstar C3', 'tenstar_c3', '@esp32-c3-devkitm-1'],
  ['ESP32-C6', 'LilyGo T-LoRa C6', 'lilygo_tlora_c6', '@esp32-c6-devkitm-1'],
  ['ESP32-C6', 'M5Stack Unit C6L', 'm5stack_unit_c6l', '@esp32-c6-devkitm-1'],
  ['ESP32-C6', 'Meshimi', 'xiao_c6', '@esp32-c6-devkitm-1'],
  ['ESP32-C6', 'Seeed Studio Xiao C6', 'xiao_c6', '@esp32-c6-devkitm-1'],
  ['ESP32-C6', 'WHY2025 Badge', 'xiao_c6', '@esp32-c6-devkitm-1'],
  ['ESP32-S3', 'Ebyte EoRa-S3', 'ebyte_eora_s3', 'ebyte_eora-s3'],
  ['ESP32-S3', 'Elecrow ThinkNode M2', 'thinknode_m2', 'ESP32-S3-WROOM-1-N4'],
  ['ESP32-S3', 'Elecrow ThinkNode M5', 'thinknode_m5', 'ESP32-S3-WROOM-1-N4'],
  ['ESP32-S3', 'Elecrow ThinkNode M7', 'thinknode_m7', 'thinknode_m7'],
  ['ESP32-S3', 'Elecrow ThinkNode M9', 'thinknode_m9', 'thinknode_m9'],
  ['ESP32-S3', 'Heltec RC32', 'heltec_rc32', 'heltec-rc32'],
  ['ESP32-S3', 'Heltec Vision Master E213', 'heltec_e213', 'heltec_e213'],
  ['ESP32-S3', 'Heltec Vision Master E290', 'heltec_e290', 'heltec_e290'],
  ['ESP32-S3', 'Heltec Vision Master T190', 'heltec_t190', 'heltec_t190'],
  ['ESP32-S3', 'Heltec WSL3', 'heltec_v3', '@esp32-s3-devkitc-1'],
  ['ESP32-S3', 'Heltec Wireless Paper', 'heltec_wireless_paper', '@esp32-s3-devkitc-1'],
  ['ESP32-S3', 'Heltec Wireless Tracker', 'heltec_tracker', '@esp32-s3-devkitc-1'],
  ['ESP32-S3', 'Heltec Wireless Tracker v1.1', 'heltec_tracker_v2', 'heltec_tracker_v1_1'],
  ['ESP32-S3', 'Heltec Wireless Tracker v2', 'heltec_tracker_v2', 'heltec_tracker_v2'],
  ['ESP32-S3', 'Heltec v3', 'heltec_v3', '@esp32-s3-devkitc-1'],
  ['ESP32-S3', 'Heltec v4', 'heltec_v4', 'heltec_v4'],
  ['ESP32-S3', 'Heltec v4 + Expansion Kit (Touch)', 'heltec_v4', 'heltec_v4'],
  ['ESP32-S3', 'Heltec v4 R8', 'heltec_v4_r8', 'heltec_v4_r8'],
  ['ESP32-S3', 'LilyGo T-Beam 1W', 'lilygo_tbeam_1w', 't_beam_1w'],
  ['ESP32-S3', 'LilyGo T-Beam Supreme (SX1262)', 'lilygo_tbeam_supreme_SX1262', 't_beams3_supreme'],
  ['ESP32-S3', 'LilyGo T-Deck', 'lilygo_tdeck', 't-deck'],
  ['ESP32-S3', 'LilyGo T-ETH Elite (SX1262)', 'lilygo_teth_elite', '@esp32s3box'],
  ['ESP32-S3', 'LilyGo T3 S3 (SX126x)', 'lilygo_t3s3', 't3_s3_v1_x'],
  ['ESP32-S3', 'LilyGo T3 S3 (SX127x)', 'lilygo_t3s3_sx1276', 't3_s3_v1_x'],
  ['ESP32-S3', 'MKE S3', 'mke_s3', '@esp32-s3-devkitc-1'],
  ['ESP32-S3', 'Meshnology W12', 'meshnology_w12', 'meshnology_w12'],
  ['ESP32-S3', 'Nibble Screen Connect', 'nibble_screen_connect', 'esp32-s3-zero'],
  ['ESP32-S3', 'Nibble Zero Connect', 'nibble_zero_connect', 'esp32-s3-zero'],
  ['ESP32-S3', 'RAK WisBlock 3112', 'rak3112', '@esp32-s3-devkitc-1'],
  ['ESP32-S3', 'Seeed Studio SenseCAP Indicator ESP-NOW', 'sensecap_indicator-espnow', '@esp32-s3-devkitc-1'],
  ['ESP32-S3', 'Seeed Studio SenseCAP Indicator LoRa', 'sensecap_indicator-espnow', '@esp32-s3-devkitc-1'],
  ['ESP32-S3', 'Seeed Studio Xiao S3', 'xiao_s3', '@seeed_xiao_esp32s3'],
  ['ESP32-S3', 'Seeed Studio Xiao S3 WIO', 'xiao_s3_wio', '@seeed_xiao_esp32s3'],
  ['ESP32-S3', 'Seeed Wio Tracker L2', 'wio-tracker-l2', 'seeed_wio_tracker_l2'],
  ['ESP32-S3', 'UnitEng Station G2', 'station_g2', 'station-g2'],
  ['ESP32-S3', 'UnitEng/BQ Voyage Station G3', 'station_g3_esp32', 'station-g3-esp32'],
  ['ESP32-S3', 'Waveshare ESP32-S3 LR1121', 'waveshare_esp32s3_lr1121', 'esp32-s3-zero'],
];
const reviewedChips = new Map(reviewedRecipes.map(([chip, hardware]) => [hardware, chip]));
// Additional explicit chip fields reviewed in the released primary manifest:
// https://raw.githubusercontent.com/jade-on-mesh/wadamesh-tak/tak-beta_103.1/boards.json
// boards pager (both exact radio options) and crowpanel (both screen sizes).
for (const hardware of ['Elecrow CrowPanel Advance 3.5', 'Elecrow CrowPanel Advance 5.0', 'LilyGo T-Lora Pager (SX1262)', 'LilyGo T-Lora Pager (LR1121)']) reviewedChips.set(hardware, 'ESP32-S3');
// T-Deck Pro / T-Display Pro have no reviewed recipe here and remain unknown.
// Never use the old generic Pager inventory's unrelated t-echo recipe.

const chipIds = new Map([[0, 'ESP32'], [2, 'ESP32-S2'], [5, 'ESP32-C3'], [9, 'ESP32-S3'], [13, 'ESP32-C6']]);
const families = new Set(chipIds.values());
// These IDs establish only an Espressif native-USB family hint. 303a:1001
// is shared; it does not prove S3 or distinguish hardware CDC from TinyUSB.
// Reviewed identities are already used by the application's ESP connection
// flow; arbitrary Espressif PIDs and generic CP210x/CH340 bridges are excluded.
const nativeUsbIds = new Set(['303a:0002', '303a:1001']);
const unique = values => [...new Set(values)].sort();
const usbIdentity = info => [info?.usbVendorId, info?.usbProductId].every(value => Number.isInteger(value) && value >= 0 && value <= 65535)
  ? [info.usbVendorId, info.usbProductId].map(value => value.toString(16).padStart(4, '0')).join(':') : '';

function romChip(info) {
  if (!info || typeof info !== 'object' || Array.isArray(info)) return {architecture: '', chipFamily: '', conflict: false};
  const choices = [];
  if (Number.isInteger(info.chipId) && chipIds.has(info.chipId)) choices.push(chipIds.get(info.chipId));
  for (const field of ['chip', 'chipName', 'name']) {
    const value = info[field];
    if (typeof value !== 'string' || value.length > 128 || /[\x00-\x1f\x7f]/.test(value)) continue;
    const match = /^(ESP32(?:-(?:S2|S3|C3|C6))?)(?:$|[ (])/i.exec(value.trim());
    if (match) choices.push(match[1].toUpperCase());
  }
  const chips = unique(choices);
  return {architecture: chips.length ? 'esp32' : '', chipFamily: chips.length === 1 ? chips[0] : '', conflict: chips.length > 1};
}

function catalogChip(rows, hardware) {
  const reviewed = reviewedChips.get(hardware), choices = new Set(reviewed ? [reviewed] : []);
  for (const row of rows) {
    // Absent per-artifact metadata can use a reviewed board-wide recipe. An
    // unknown board needs complete unanimous chip fields; missing/conflicting
    // metadata must never manufacture an exclusion.
    if (row.chipFamily === undefined || row.chipFamily === null || row.chipFamily === '') {
      if (!reviewed) return '';
      continue;
    }
    if (typeof row.chipFamily !== 'string' || !families.has(row.chipFamily)) return '';
    choices.add(row.chipFamily);
  }
  return choices.size === 1 ? [...choices][0] : '';
}

export function espBoardCandidates({items = [], chipInfo = null, usbInfo = {}} = {}) {
  const chip = romChip(chipInfo), id = usbIdentity(usbInfo), usbHint = nativeUsbIds.has(id);
  const architecture = chip.architecture || (usbHint ? 'esp32' : '');
  if (!architecture) return {architecture: '', chipFamily: '', candidates: [], excluded: [], unknown: [], source: 'unknown', reason: 'No ROM processor identity or reviewed native ESP USB hint is available. Keep all hardware available; a generic USB-to-serial adapter does not identify the radio.'};
  const rows = new Map();
  for (const item of Array.isArray(items) ? items : []) {
    if (item?.project !== 'MeshCore' || item.architecture !== 'esp32' || typeof item.hardware !== 'string' || !item.hardware || item.hardware.length > 256) continue;
    const hardware = canonicalHardware(item.hardware);
    if (!rows.has(hardware)) rows.set(hardware, []);
    rows.get(hardware).push(item);
  }
  const candidates = [], excluded = [], unknown = [];
  for (const [hardware, entries] of rows) {
    const family = catalogChip(entries, hardware);
    if (!family) unknown.push(hardware);
    if (chip.chipFamily && family && family !== chip.chipFamily) excluded.push(hardware);
    else candidates.push(hardware);
  }
  const source = chip.architecture ? 'rom-chip' : 'usb-hint';
  const reason = chip.conflict
    ? 'ROM chip fields disagree. Showing ESP32-family boards without chip-specific exclusions; reconnect and inspect the same radio again.'
    : chip.chipFamily
      ? `Showing candidates compatible with the observed ${chip.chipFamily}, including boards with unknown or conflicting chip metadata. Flash/PSRAM capacities are informational only; this is not physical-board proof or permission to flash.`
      : `USB ${id} is a shared native ESP identity. Showing ESP32-family boards only; the exact chip, memory and physical board are not identified.`;
  return {architecture, chipFamily: chip.chipFamily, candidates: unique(candidates), excluded: unique(excluded), unknown: unique(unknown), source, reason};
}
