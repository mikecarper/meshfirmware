// Read-only INFO_UF2.TXT parsing and installed-bootloader selection hints.
// Nothing here opens a device, runs file contents or authorizes a firmware write.
import {canonicalHardware} from './hardware-aliases.js';
const maxInfoLength = 4096;
const versionPart = '(?:0|[1-9][0-9]{0,3})';
const semver = new RegExp(`^v?${versionPart}\\.${versionPart}\\.${versionPart}(?:-[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*)?(?:\\+[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*)?$`);
const compactVersion = /^(?:BL|TEST|R)_0x[0-9A-Fa-f]{8}$/;
const validVersion = value => typeof value === 'string' && value.length <= 128 && (semver.test(value) || compactVersion.test(value));
const validModel = value => typeof value === 'string' && value.length <= 128 && value === value.trim() && /^[A-Za-z0-9][A-Za-z0-9 ._()+/-]*$/.test(value);
const validBoardId = value => typeof value === 'string' && value.length <= 128 && value === value.trim() && /^[A-Za-z0-9][A-Za-z0-9 ._+-]*$/.test(value);
const validSoftDevice = value => typeof value === 'string' && value.length <= 64 && (value === 'not found' || /^S1[0-9]{2} (?:0x[0-9A-Fa-f]{1,4}|[0-9]{1,5}|(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2}))$/.test(value));
const fail = message => { throw new TypeError(`Invalid INFO_UF2.TXT: ${message}`); };

function validDate(value) {
  const match = /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}([1-9]|[12][0-9]|3[01]) ([12][0-9]{3})$/.exec(value);
  if (!match) return false;
  const month = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'].indexOf(match[1]);
  const date = new Date(Date.UTC(Number(match[3]), month, Number(match[2])));
  return date.getUTCMonth() === month && date.getUTCDate() === Number(match[2]);
}

function validateInfo(info) {
  if (!info || typeof info !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(info)) || Object.keys(info).some(key => !['version','model','boardId','softDevice'].includes(key))) fail('unexpected identity fields.');
  if (!validVersion(info.version)) fail('missing or malformed bootloader version.');
  if (!validModel(info.model)) fail('missing or malformed Model.');
  if (!validBoardId(info.boardId)) fail('missing or malformed Board-ID.');
  if (Object.hasOwn(info, 'softDevice') && !validSoftDevice(info.softDevice)) fail('malformed SoftDevice.');
  return info;
}

export function parseBootloaderInfo(text) {
  if (typeof text !== 'string' || !text.length || text.length > maxInfoLength) fail('expected a nonempty text file no larger than 4096 characters.');
  if (/[^\x20-\x7e\r\n]/.test(text) || /[<>&]/.test(text) || /\r(?!\n)/.test(text)) fail('control characters, non-ASCII text or HTML are not accepted.');
  if (!text.endsWith('\n')) fail('missing final newline; the file may be truncated.');
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  lines.pop();
  if (lines.length < 3 || lines.length > 5 || lines.some(line => !line || line.length > 512)) fail('missing, extra or overlong lines.');
  // Factory Adafruit builds append dependency revisions to the version line.
  // Accept only these known descriptor fields, never arbitrary trailing prose.
  const header = /^UF2 Bootloader ([^ ]+)((?: lib\/(?:nrfx|tinyusb|uf2) \([A-Za-z0-9][A-Za-z0-9._+/-]{0,95}\)){0,3})$/.exec(lines[0]);
  if (!header || !validVersion(header[1])) fail('missing or malformed UF2 Bootloader version line.');
  const dependencies = [...header[2].matchAll(/lib\/(nrfx|tinyusb|uf2) /g)].map(match => match[1]);
  if (new Set(dependencies).size !== dependencies.length) fail('duplicate dependency descriptors.');
  const info = {version: header[1]}, seen = new Set();
  for (const line of lines.slice(1)) {
    const field = /^(Model|Board-ID|Date|SoftDevice): (.+)$/.exec(line);
    if (!field) fail('unknown or malformed information line.');
    const [, name, value] = field;
    if (seen.has(name)) fail(`duplicate ${name} field.`);
    seen.add(name);
    if (name === 'Date') { if (!validDate(value)) fail('malformed build date.'); }
    else info[{Model:'model', 'Board-ID':'boardId', SoftDevice:'softDevice'}[name]] = value;
  }
  return Object.freeze(validateInfo(info));
}

// Full exact Model + Board-ID pairs reviewed against src/boards/**/board.h,
// including inherited headers and source-confirmed factory identities. No
// substring/case folding. The original OTAFIX 2.4.12 profile reference is:
// https://github.com/mikecarper/Adafruit_nRF52_Bootloader_OTAFIX/tree/v0.11.0-OTAFIX2.4.12/src/boards
// These describe the INSTALLED loader, never independent physical-board proof.
const records = [
  ['HT-n5262', 'HT-n5262', ['Heltec T114'], ['239a:0071'], 'legacy-heltec'],
  ['Heltec MeshTower V2', 'HT-n5262', ['Heltec MeshTower V2'], ['239a:0071']],
  ['HT-n5262G', 'HT-n5262G', ['Heltec Mesh Node T096'], ['239a:0071']],
  ['Heltec Mesh Node T1', 'Heltec-Mesh-Node-T1', ['Heltec Mesh Node T1'], ['239a:0071']],
  ['Heltec Mesh Pocket', 'Heltec-Mesh-Pocket', ['Heltec MeshPocket'], ['239a:0071']],
  ['Seeed T1000-E for Meshtastic', 'nRF52840-T1000-E-v1', ['Seeed Studio SenseCAP T1000-E'], ['2886:0057']],
  ['Keepteen LT1', 'Keepteen-LT1', ['Keepteen LT1'], ['239a:00b3']],
  ['LilyGo T-Echo', 'nRF52840-TEcho-v1', ['LilyGo T-Echo'], ['239a:0029']],
  ['LilyGo T-Echo Lite', 'T-Echo-Lite-nRF52840', ['LilyGo T-Echo Lite'], ['239a:00da']],
  // Factory identities confirmed in their source board headers. These are
  // read-only selection hints, not qualification of a replacement bootloader.
  ['B and Q Nano G2 Ultra', 'nRF52840-BQ-rev1', ['UnitEng Nano G2 Ultra'], ['4251:8695']],
  ['T-Echo Card', 'LilyGo-T-Echo-Card', ['LilyGo T-Echo Card'], ['239a:00da']],
  ['T-Impulse Plus', 'LilyGo-T-Impulse-Plus', ['LilyGo T-Impulse Plus nRF52840'], ['239a:00da']],
  ['Meshtiny Board', 'Meshtiny-MT001-Board', ['Meshtiny'], ['239a:0029','239a:002a']],
  ['GAT562 Mesh Watch13', 'GAT562-Watch13', ['GAT-IoT GAT562 Mesh Watch13'], ['239a:0029','239a:002a']],
  ['ELECROW ThinkNodeM1', 'nRF52840-ThinkNodeM1-v1', ['Elecrow ThinkNode M1'], ['239a:00da']],
  ['ELECROW ThinkNode-M3', 'nRF52840-ThinkNode-M3-v1', ['Elecrow ThinkNode M3'], ['239a:00da']],
  ['ELECROW ThinkNodeM6', 'nRF52840-ThinkNodeM6-v1', ['Elecrow ThinkNode M6'], ['239a:00da']],
  ['MinewSemi MX25LE01', 'MinewSemi-MX25LE01', ['Minewsemi ME25LS01'], ['239a:0029','239a:002a']],
  ['WisMesh Tag', 'WisMesh-Tag', ['RAK WisMesh Tag'], ['239a:0029','239a:002a']],
  // Universal RAK3401 builds share this hardware family across the supported
  // carrier/storage profiles. Exact installed Model + Board-ID is still needed;
  // a shared RAK USB ID alone is never board identity or permission to flash.
  ['WisBlock RAK3401', 'WisBlock-RAK3401', ['RAK WisMesh 1W Booster (3401 + 13302)'], ['239a:0029','239a:002a']],
  ['RAK3401', '3401A', ['RAK WisMesh 1W Booster (3401 + 13302)'], ['239a:0029','239a:002a']],
  ['WisBlock RAK3401 + RAK13302 + W25Q16', 'WisBlock-RAK3401-RAK13302-W25Q16', ['RAK WisMesh 1W Booster (3401 + 13302)'], ['239a:0029','239a:002a']],
  // RAK4631's universal application family handles the supported stores. The
  // exact installed profile still matters for a separately offered bootloader.
  ['WisBlock RAK4631 Board', 'WisBlock-RAK4631-Board', ['RAK WisBlock / WisMesh (RAK 4631)'], ['239a:0029','239a:002a']],
  ['RAK4631', '4631A', ['RAK WisBlock / WisMesh (RAK 4631)'], ['239a:0029','239a:002a']],
  ['WisBlock RAK4631 + W25Q16', 'WisBlock-RAK4631-W25Q16', ['RAK WisBlock / WisMesh (RAK 4631)'], ['239a:0029','239a:002a']],
  ['WisBlock RAK4631 + RAK15001 C', 'WisBlock-RAK4631-RAK15001-Slot-C', ['RAK WisBlock / WisMesh (RAK 4631)'], ['239a:0029','239a:002a']],
  ['Seeed Solar Node P1', 'nRF52840-SeeedSenseCAPSolarP1-v1', ['Seeed Studio SenseCAP Solar'], ['2886:0044']],
  // Shared carrier/storage identities remain manual, even with a filtered list.
  ['MTools Tec GAT562', 'GAT562-Family', ['GAT-IoT GAT562 30s','GAT-IoT GAT562 EVB Pro','GAT-IoT GAT562 Tracker'], ['239a:0029','239a:002a'], 'shared'],
  ['Seeed XIAO nRF52840', 'nRF52840-SeeedXiao-v1', ['Seeed Studio Xiao nRF52 WIO','Ikoka Handheld nRF E22 30 dBm','Ikoka Nano','Ikoka Stick','SolarXiao'], ['2886:0044'], 'shared'],
  ['Seeed XIAO nRF52840', 'nRF52840-SeeedXiaoSense-v1', ['Seeed Studio Xiao nRF52 WIO'], ['2886:0045'], 'shared'],
  ['Seeed TRACKER L1', 'TRACKER L1', ['Seeed Studio Wio Tracker L1 Pro','Seeed WioTracker L1 1W'], ['2886:1667'], 'shared'],
  ['Muzi Base', 'muzi-Base-Board', ['Muzi Works Base Duo','Muzi Works Base Uno'], ['239a:0081'], 'shared'],
  ['ProMicro NRF52840', 'nRF52840-promicro', ['ProMicro nrf52 (faketec)'], ['239a:00b3'], 'shared'],
];
const reviewed = new Map(records.map(([model, boardId, hardware, usbIds, restriction]) => [JSON.stringify([model, boardId]), {hardware, usbIds, restriction}]));
const legacyHeltecHardware = ['Heltec T114','Heltec MeshTower V2','Heltec MeshPocket','Heltec MeshSolar / MeshTower'];
const reviewedHeltecVersion = /^(?:v)?0\.11\.0-OTAFIX2\.4\.12$/;

function usbIdentity(info) {
  const values = [info?.usbVendorId, info?.usbProductId];
  if (values.every(value => value === undefined)) return '';
  if (!values.every(value => Number.isInteger(value) && value >= 0 && value <= 65535)) return null;
  return values.map(value => value.toString(16).padStart(4, '0')).join(':');
}

export function detectBootloaderBoard({items = [], info, usbInfo = {}} = {}) {
  const answer = (hardware, candidates, reason, known = false) => ({hardware, candidates, source: 'bootloader-info', reason, ...(known ? {model: info.model, architecture: 'nrf52'} : {})});
  try { validateInfo(info); } catch { return answer(null, [], 'No validated complete INFO_UF2.TXT identity is available; choose hardware manually.'); }
  const entry = reviewed.get(JSON.stringify([info.model, info.boardId]));
  if (!entry) return answer(null, [], 'No reviewed exact Model + Board-ID pair matched. Similar names, a Board-ID alone and USB hints are not substituted; choose hardware manually.');
  const id = usbIdentity(usbInfo);
  if (id === null || id && !entry.usbIds.includes(id)) return answer(null, [], 'The selected USB interface conflicts with this bootloader information or has invalid USB metadata. Select the same radio’s matching DFU interface; choose hardware manually if uncertain.');
  const sharedLegacy = entry.restriction === 'legacy-heltec' && !reviewedHeltecVersion.test(info.version);
  const names = (sharedLegacy ? legacyHeltecHardware : entry.hardware).map(canonicalHardware);
  const available = Array.isArray(items) ? items : [];
  const candidates = [...new Set(available.filter(item => item?.project === 'MeshCore' && item.architecture === 'nrf52' && names.includes(canonicalHardware(item.hardware))).map(item => canonicalHardware(item.hardware)))].sort();
  if (/^(?:R|TEST)_/.test(info.version)) return answer(null, candidates, 'A recovery/test loader can be installed on a different board. Its information is not a physical-board identity; choose the actual hardware manually.', true);
  if (sharedLegacy) return answer(null, candidates, 'The legacy HT-n5262 Model + Board-ID is shared by Heltec products. Only the exact reviewed OTAFIX release distinguishes these installed profiles; check the physical label and choose hardware manually.', true);
  if (entry.restriction === 'shared') return answer(null, candidates, 'This installed bootloader identity does not establish the exact physical carrier, radio or storage profile. Check the physical board and choose hardware manually, even when only one catalog candidate is present.', true);
  if (candidates.length !== 1) return answer(null, candidates, candidates.length ? 'Multiple exact catalog hardware labels match this installed loader; choose hardware manually.' : 'No exact compatible nRF52 catalog entry matches this installed loader. Choose hardware manually; other revisions and architectures are not substituted.', true);
  return answer(candidates[0], candidates, 'Exact reviewed Model + Board-ID matched an installed-bootloader hint. Confirm the physical board and that the file belongs to the selected radio. This is not physical-board proof, a MeshCore identity, a board-safety override or permission to write.', true);
}
