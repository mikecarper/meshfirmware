// Selection hints from a responding Meshtastic application's HardwareModel.
// Reviewed 2026-10-28 against the official enum (not USB IDs or node names):
// https://github.com/meshtastic/protobufs/blob/ffd5ad428da6db4a7ddfe62e06548718cc2603e0/meshtastic/mesh.proto#L209
// Catalog labels are explicit MeshCore targets, not a fuzzy-search vocabulary.
// A firmware-reported model is never independent physical-board proof.
const reviewed = new Map([
  [3, ['LILYGO T-LoRa V2.1-1.6', 'esp32', ['LilyGo LoRa32 V2.1_1.6']]],
  [7, ['LILYGO T-Echo', 'nrf52', ['LilyGo T-Echo']]],
  [10, ['Heltec V2.1', 'esp32', ['Heltec v2']]],
  [18, ['Nano G2 Ultra', 'nrf52', ['UnitEng Nano G2 Ultra']]],
  [31, ['Station G2', 'esp32', ['UnitEng Station G2']]],
  [43, ['Heltec V3', 'esp32', ['Heltec v3']]],
  [44, ['Heltec Wireless Stick Lite V3', 'esp32', ['Heltec WSL3']]],
  [49, ['Heltec Wireless Paper', 'esp32', ['Heltec Heltec Wireless Paper']]],
  [50, ['LILYGO T-Deck', 'esp32', ['LilyGo T-Deck']]],
  [53, ['Heltec HT-CT62', 'esp32', ['Heltec CT62']]],
  [61, ['EBYTE EoRa-S3', 'esp32', ['Ebyte EoRa-S3']]],
  [66, ['Heltec Vision Master T190', 'esp32', ['Heltec Vision Master T190']]],
  [67, ['Heltec Vision Master E213', 'esp32', ['Heltec Vision Master E213']]],
  [68, ['Heltec Vision Master E290', 'esp32', ['Heltec Vision Master E290']]],
  // HELTEC_MESH_NODE_T114 = 69. Revision V2/H2T still uses this enum; it
  // must never be confused with the ESP32 HELTEC_V2_0/V2_1 enums (5/10).
  [69, ['Heltec Mesh Node T114', 'nrf52', ['Heltec T114']]],
  [71, ['Seeed SenseCAP T1000-E', 'nrf52', ['Seeed Studio SenseCAP T1000-E']]],
  [75, ['Minewsemi ME25LS01', 'nrf52', ['Minewsemi ME25LS01']]],
  [88, ['Seeed XIAO nRF52840 + Wio SX1262 kit', 'nrf52', ['Seeed Studio Xiao nRF52 WIO']]],
  [89, ['Elecrow ThinkNode M1', 'nrf52', ['Elecrow ThinkNode M1']]],
  [90, ['Elecrow ThinkNode M2', 'esp32', ['Elecrow ThinkNode M2']]],
  [94, ['Heltec MeshPocket', 'nrf52', ['Heltec MeshPocket']]],
  [100, ['Seeed Wio Tracker L1 E-Ink', 'nrf52', ['Seeed Studio Wio Tracker L1 E-Ink', 'Seeed Studio Wio Tracker L1 EINK']]],
  [101, ['Muzi Works R1 Neo', 'nrf52', ['Muzi Works R1 Neo']]],
  [102, ['LILYGO T-Deck Pro', 'esp32', ['LilyGo T-Deck Pro']]],
  [103, ['LILYGO T-LoRa Pager', 'esp32', ['LilyGo T-Lora Pager']]],
  [105, ['RAK WisMesh Tag', 'nrf52', ['RAK WisMesh Tag']]],
  [107, ['Elecrow ThinkNode M5', 'esp32', ['Elecrow ThinkNode M5']]],
  [108, ['Heltec MeshSolar', 'nrf52', ['Heltec MeshSolar / MeshTower']]],
  [109, ['LILYGO T-Echo Lite', 'nrf52', ['LilyGo T-Echo Lite']]],
  [110, ['Heltec V4', 'esp32', ['Heltec v4']]],
  [111, ['M5Stack Unit C6L', 'esp32', ['M5Stack Unit C6L']]],
  [113, ['Heltec Wireless Tracker V2', 'esp32', ['Heltec Wireless Tracker v2']]],
  [115, ['Elecrow ThinkNode M3', 'nrf52', ['Elecrow ThinkNode M3']]],
  [119, ['Elecrow ThinkNode M4', 'nrf52', ['Elecrow ThinkNode M4']]],
  [120, ['Elecrow ThinkNode M6', 'nrf52', ['Elecrow ThinkNode M6']]],
  [122, ['LILYGO T-Beam 1W', 'esp32', ['LilyGo T-Beam 1W']]],
  [126, ['LILYGO T-Display S3 Pro LR1121', 'esp32', ['LilyGo T-Display Pro']]],
  [127, ['Heltec Mesh Node T096', 'nrf52', ['Heltec Mesh Node T096']]],
  [128, ['Seeed SenseCAP MeshTracker X1', 'nrf52', ['Seeed SenseCAP MeshTracker X1', 'Seeed Studio SenseCAP MeshTracker X1']]],
  [129, ['Elecrow ThinkNode M7', 'esp32', ['Elecrow ThinkNode M7']]],
  [130, ['Elecrow ThinkNode M8', 'nrf52', ['Elecrow ThinkNode M8']]],
  [131, ['Elecrow ThinkNode M9', 'esp32', ['Elecrow ThinkNode M9']]],
  [132, ['Heltec V4 R8', 'esp32', ['Heltec v4 R8']]],
  [133, ['Heltec Mesh Node T1', 'nrf52', ['Heltec Mesh Node T1']]],
  [134, ['Station G3', 'esp32', ['UnitEng/BQ Voyage Station G3']]],
  [135, ['LILYGO T-Impulse Plus', 'nrf52', ['LilyGo T-Impulse Plus nRF52840']]],
  [136, ['LILYGO T-Echo Card', 'nrf52', ['LilyGo T-Echo Card']]],
  [137, ['Seeed Wio Tracker L2', 'esp32', ['Seeed Wio Tracker L2']]],
  [139, ['Heltec MeshTower V2', 'nrf52', ['Heltec MeshTower V2']]],
  [141, ['Heltec RC32', 'esp32', ['Heltec RC32']]],
  [144, ['Seeed Wio Tracker L1 Pro 1W', 'nrf52', ['Seeed WioTracker L1 1W']]],
  [145, ['Meshnology W12', 'esp32', ['Meshnology W12']]],
]);

// These enums cannot identify one supported physical target. Keep them manual
// independently of the supplied catalog: filtering out alternatives must never
// turn a shared enum into an automatic match.
const manual = new Map([
  [0, ['Unknown Meshtastic hardware', '', [], 'The running firmware did not report a hardware model.']],
  [4, ['LILYGO T-Beam', 'esp32', ['LilyGo T-Beam (SX1262)', 'LilyGo T-Beam 1.2 (SX1276)'], 'This enum does not identify the T-Beam radio variant.']],
  // MeshCore HeltecV2Board.h uses battery ADC GPIO37; HELTEC_V2_0 uses 13.
  // https://github.com/meshcore-dev/MeshCore/blob/main/variants/heltec_v2/HeltecV2Board.h
  [5, ['Heltec V2.0', 'esp32', [], 'The older Heltec V2.0 battery-pin revision has no reviewed exact catalog mapping.']],
  [9, ['RAK4631', 'nrf52', ['RAK WisBlock / WisMesh (RAK 4631)'], 'The RAK4631 core enum does not establish the carrier, radio or storage profile.']],
  [12, ['LILYGO T-Beam S3 Core', 'esp32', [], 'The core enum alone does not establish a supported T-Beam Supreme radio variant.']],
  [16, ['LILYGO T-LoRa T3-S3', 'esp32', ['LilyGo T3 S3 (SX126x)', 'LilyGo T3 S3 (SX127x)'], 'This enum is shared by different T3-S3 radio/display variants.']],
  [36, ['Unknown nRF52 hardware', 'nrf52', [], 'A generic nRF52 enum does not identify a physical board.']],
  [42, ['M5Stack', 'esp32', [], 'The generic M5Stack enum covers multiple incompatible boards.']],
  [48, ['Heltec Wireless Tracker V1.1 / TrackSenger', 'esp32', ['Heltec Wireless Tracker', 'Heltec Wireless Tracker v1.1'], 'This enum is also used by TrackSenger builds and cannot uniquely identify the physical board.']],
  [63, ['nRF52 ProMicro DIY', 'nrf52', ['ProMicro nrf52 (faketec)'], 'The DIY enum does not identify the radio wiring or board profile.']],
  [70, ['Seeed SenseCAP Indicator', 'esp32', ['Seeed Studio SenseCAP Indicator ESP-NOW', 'Seeed Studio SenseCAP Indicator LoRa'], 'This enum does not establish the required Indicator radio configuration.']],
  [81, ['Seeed XIAO ESP32-S3', 'esp32', ['Seeed Studio Xiao S3', 'Seeed Studio Xiao S3 WIO'], 'The XIAO S3 enum does not identify the attached radio/carrier.']],
  [86, ['Mesh-Tab', 'esp32', [], 'Mesh-Tab is not Heltec T114 and has no reviewed exact catalog mapping.']],
  [91, ['LILYGO T-ETH Elite', 'esp32', ['LilyGo T-ETH Elite (SX1262)'], 'The enum does not establish the T-ETH Elite radio module.']],
  [93, ['Muzi Works Base', 'nrf52', ['Muzi Works Base Duo', 'Muzi Works Base Uno'], 'This enum is shared by Muzi Base Duo and Uno.']],
  [95, ['Seeed SenseCAP Solar Node', 'nrf52', ['Seeed Studio SenseCAP Solar', 'Seeed Studio SenseCAP Solar Node P1'], 'The enum does not establish the exact Solar Node catalog/storage profile.']],
  [99, ['Seeed Wio Tracker L1', 'nrf52', ['Seeed Studio Wio Tracker L1 Pro', 'Seeed WioTracker L1 1W'], 'The generic Tracker L1 enum does not establish the exact hardware/power profile.']],
  [106, ['RAK3312', 'esp32', [], 'RAK3312 is not the differently named RAK3112 catalog target.']],
  [117, ['RAK3401', 'nrf52', ['RAK WisMesh 1W Booster (3401 + 13302)'], 'The RAK3401 core enum does not establish the exact booster/carrier or storage profile.']],
  [255, ['Private Meshtastic hardware', '', [], 'A private hardware enum has no reviewed physical-board mapping.']],
]);

export function detectMeshtasticBoard({items = [], hwModel} = {}) {
  const answer = (hardware, candidates, reason, model) => ({hardware, candidates, source: 'meshtastic-hardware', reason, ...(model ? {model} : {})});
  if (!Number.isInteger(hwModel) || hwModel < 0 || hwModel > 0x7fffffff) {
    return answer(null, [], 'No valid integer Meshtastic hardware enum was reported; choose the exact hardware manually.');
  }
  const mapping = manual.get(hwModel) || reviewed.get(hwModel);
  if (!mapping) return answer(null, [], `Meshtastic hardware enum ${hwModel} has no reviewed exact catalog mapping; choose the exact hardware manually. USB IDs and similar names are not used as substitutes.`);
  const [model, architecture, names, manualReason] = mapping;
  const available = Array.isArray(items) ? items : [];
  const candidates = [...new Set(available.filter(item => item?.project === 'MeshCore' && item.architecture === architecture && names.includes(item.hardware)).map(item => item.hardware))].sort();
  if (manualReason) return answer(null, candidates, `${manualReason} Choose the exact hardware manually.`, model);
  if (candidates.length !== 1) return answer(null, candidates, candidates.length ? 'The reviewed enum matches multiple exact catalog hardware labels; choose the exact hardware manually.' : 'The reviewed Meshtastic hardware has no exact compatible catalog entry; choose hardware manually. Similar names, other revisions and USB IDs are not substituted.', model);
  return answer(candidates[0], candidates, 'The running Meshtastic hardware enum matched one reviewed exact MeshCore target. This selects hardware only, not a role, firmware file or independent physical-board proof.', model);
}
