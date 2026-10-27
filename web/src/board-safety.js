import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

const digest = bytes => bytesToHex(sha256(bytes));
const families = new Set(['unknown','rak3401','rak4631','ambiguous']);
const models = /^(?:WisCore[ _-]+RAK[ _-]*(?:3401|4631)(?:[ _-]+Board)?|RAK\s+(?:3401|4631)|RAK(?:3401|4631)_OTA|RAK\s+WisMesh\s+Tag|WISMESHTAG_OTA)\s*$/i;
const dfuIds = new Set(['2886:0044','2886:0045','2886:0057','2886:1667','239a:0029','239a:002a','239a:0071','239a:00b3','239a:00da']);

export function isKnownDfu(info = {}) {
  if (![info.usbVendorId,info.usbProductId].every(n => Number.isInteger(n) && n >= 0 && n <= 65535)) return false;
  return dfuIds.has([info.usbVendorId,info.usbProductId].map(n => n.toString(16).padStart(4,'0')).join(':'));
}

export function rakFamily(value = '') {
  const text = String(value), rak3401 = /rak[\s_-]*3401/i.test(text), rak4631 = /rak[\s_-]*4631|wismesh[\s_-]*tag/i.test(text);
  return rak3401 && rak4631 ? 'ambiguous' : rak3401 ? 'rak3401' : rak4631 ? 'rak4631' : 'unknown';
}

// Identical EndF length/hash/ASCII checks to the shared Python validator.
// A filename alone is never a verified payload identity or firmware version.
export function endfIdentity(payload) {
  if (!(payload instanceof Uint8Array) || payload.length < 56) return null;
  const trailer = payload.subarray(payload.length - 56), view = new DataView(trailer.buffer,trailer.byteOffset,trailer.byteLength);
  if (String.fromCharCode(...trailer.subarray(0,4)) !== 'EndF' || view.getUint32(4,true) !== payload.length - 56 || bytesToHex(trailer.subarray(8,16)) !== digest(payload.subarray(0,-56)).slice(0,16)) return null;
  const version = view.getUint32(16,true), target = view.getUint32(20,true), raw = trailer.subarray(24), firstZero = raw.indexOf(0);
  if (firstZero >= 0 && raw.subarray(firstZero).some(b => b !== 0)) return null;
  const nameBytes = firstZero < 0 ? raw : raw.subarray(0,firstZero);
  const hardware = String.fromCharCode(...nameBytes);
  if (!version || !target || !/^[A-Za-z0-9_-]{1,32}$/.test(hardware)) return null;
  const versionParts = [24,16,8,0].map(shift => (version >>> shift) & 255);
  return Object.freeze({version,target,hardware,versionParts:Object.freeze(versionParts),versionText:'v'+versionParts.join('.'),proof:'endf'});
}

export function payloadBoardIdentity(payload) {
  if (!(payload instanceof Uint8Array)) throw new Error('Board safety requires validated firmware bytes.');
  const endf = endfIdentity(payload), found = new Set();
  if (endf && rakFamily(endf.hardware) !== 'unknown') found.add(rakFamily(endf.hardware));
  // Match standalone board/model strings only, just like the native guard.
  // Full Companion carries other board *build-target* strings, which must not
  // be mistaken for the current board (e.g. RAK_4631_companion_radio_usb).
  let part = '';
  const accept = () => { if (models.test(part)) found.add(rakFamily(part)); part = ''; };
  for (const byte of payload) { if (byte >= 32 && byte <= 126) { if (part.length <= 2048) part += String.fromCharCode(byte); } else accept(); }
  accept(); found.delete('unknown');
  const family = found.size > 1 || found.has('ambiguous') ? 'ambiguous' : [...found][0] || 'unknown';
  return Object.freeze({family,proof:endf && rakFamily(endf.hardware) !== 'unknown' ? 'endf' : family !== 'unknown' ? 'embedded-model-string' : 'unknown',hardware:endf?.hardware || null});
}

// The returned token authorizes only the current connected -> payload decision.
// Callers must bind it to their immutable package, selection and USB generation
// and ask again after an erase/reconnect; never cache it as a global override.
export function assessBoard(pkg, {selectedHardware = '',deviceModel = '',usbText = '',deviceFamily = 'unknown'} = {}) {
  if (pkg?.architecture !== 'nrf52' || !(pkg.payload instanceof Uint8Array) || digest(pkg.payload) !== pkg.payloadHash) throw new Error('nRF52 payload changed before board assessment.');
  if (!families.has(deviceFamily)) throw new Error('Invalid connected-board family.');
  const identity = payloadBoardIdentity(pkg.payload), selectionFamily = rakFamily(`${selectedHardware} ${pkg.name || ''}`), boardFamily = rakFamily(deviceModel), usbFamily = rakFamily(usbText);
  const evidence = [boardFamily,usbFamily,deviceFamily].filter(family => family !== 'unknown');
  const connected = new Set(evidence), device = connected.size > 1 || connected.has('ambiguous') ? 'ambiguous' : evidence[0] || 'unknown';
  let firmwareFamily = identity.family, reason = '', requiresOverride = true;
  if (identity.family !== 'unknown' && selectionFamily !== 'unknown' && identity.family !== selectionFamily) { firmwareFamily = 'ambiguous'; reason = 'The embedded firmware target conflicts with the selected board or filename.'; }
  else if (identity.family !== 'unknown' && identity.family === device && device !== 'ambiguous') requiresOverride = false;
  else if (identity.family === 'unknown' && selectionFamily === 'unknown' && device === 'unknown') requiresOverride = false;
  else if (identity.family === 'unknown' && selectionFamily !== 'unknown') { firmwareFamily = selectionFamily; reason = 'The selection or filename suggests a protected RAK target, but the payload does not prove it.'; }
  else if (identity.family === 'unknown') reason = 'The connected device is a protected RAK target, but the firmware payload target is unknown.';
  else if (device === 'unknown') reason = 'The firmware targets a protected RAK board, but the connected board identity is unknown.';
  else reason = 'The firmware target does not match the connected board evidence.';
  return Object.freeze({requiresOverride,token:requiresOverride ? `${device}-to-${firmwareFamily}` : null,firmwareFamily,deviceFamily:device,payloadFamily:identity.family,selectionFamily,identity,matched:!requiresOverride && identity.family !== 'unknown',reason});
}
