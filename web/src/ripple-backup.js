import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { zipSync } from 'fflate';
import { hash, fail } from './firmware.js';
import { expandedPublicKey, findRippleIdentity } from './ripple-identity.js';

const MAX_FILES = 256, MAX_FILE = 1 << 20, MAX_TOTAL = 4 << 20;
const hexKey = /^[a-f0-9]{128}$/;
const publicKey = /^[a-f0-9]{64}$/;
const macPattern = /^(?:[a-f0-9]{2}:){5}[a-f0-9]{2}$/;
const equalIdentity = identity => hexKey.test(identity?.privateKey || '') && publicKey.test(identity?.publicKey || '') && bytesToHex(expandedPublicKey(hexToBytes(identity.privateKey))) === identity.publicKey;

function savedPath(value) {
  if (typeof value !== 'string' || value.length > 240 || /[\\:\x00-\x1f\x7f]/.test(value)) fail('Invalid Ripple SD file path.');
  const parts = value.split('/');
  if (parts[0] !== 'ripple' || parts.length < 2 || parts.some(part => !part || /^\.{1,2}$/.test(part) || /[. ]$/.test(part) || /[<>"|?*]/.test(part) || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part))) fail('Choose files inside the Ripple folder on the SD card.');
  return value;
}

function encode64(bytes) {
  let value = '';
  for (let at = 0; at < bytes.length; at += 8192) value += String.fromCharCode(...bytes.subarray(at, at + 8192));
  return btoa(value);
}
function decode64(value) {
  if (typeof value !== 'string' || value.length > Math.ceil(MAX_FILE / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) fail('Invalid Ripple file data.');
  const bytes = Uint8Array.from(atob(value), char => char.charCodeAt(0));
  if (encode64(bytes) !== value) fail('Noncanonical Ripple file encoding.');
  return bytes;
}

export function validateRipplePayload(payload) {
  if (payload?.role !== 'ripple' || payload.safeForWipe !== false || !equalIdentity(payload)) fail('Ripple private/public identity verification failed.');
  const source = payload.source;
  if (!source || !['usb-jtag', 'sd-files'].includes(source.method)) fail('Invalid Ripple backup source.');
  if (source.method === 'usb-jtag') {
    if (source.chip !== 'ESP32-S3' || source.usbVendorId !== 0x303a || source.usbProductId !== 0x1001 || !macPattern.test(source.mac || '') || source.usbSerial?.toLowerCase() !== source.mac || !/^v[0-9]+\.[0-9]+(?:\.[0-9]+)?$/.test(source.version || '') || !/^[A-Za-z0-9_-]{1,100}$/.test(source.environment || '') || !['SX1262', 'LR1121', null].includes(source.radio) || !['sd-card', 'internal-flash'].includes(source.storage)) fail('Invalid Ripple USB source metadata.');
  }
  if (!Array.isArray(payload.files) || payload.files.length > MAX_FILES) fail('Invalid Ripple saved-file inventory.');
  let total = 0;
  const names = new Set();
  for (const file of payload.files) {
    const path = savedPath(file?.path), normalized = path.normalize('NFC').toLowerCase();
    if (names.has(normalized)) fail('Duplicate Ripple SD file path.');
    names.add(normalized);
    if (!Number.isInteger(file.size) || file.size < 0 || file.size > MAX_FILE || !publicKey.test(file.sha256 || '')) fail('Invalid Ripple saved-file metadata.');
    total += file.size;
    if (total > MAX_TOTAL) fail('Ripple saved files exceed 4 MiB.');
    const bytes = decode64(file.data);
    if (bytes.length !== file.size || hash(bytes) !== file.sha256) fail('Ripple saved-file integrity check failed.');
    bytes.fill(0);
  }
  if (payload.filesExcluded !== undefined && (!Number.isInteger(payload.filesExcluded) || payload.filesExcluded < 0 || payload.filesExcluded > 100000)) fail('Invalid Ripple excluded-file count.');
  return payload;
}

export function ripplePayload(capture) {
  return validateRipplePayload({ role: 'ripple', publicKey: capture.publicKey, privateKey: capture.privateKey, source: { ...capture.source, method: 'usb-jtag' }, files: [], safeForWipe: false });
}

// Store original Ripple files, without guessing the version-specific layouts
// of preferences, contacts or channels. An imported file never becomes a CLI
// command or a flash write. Maps and recorded tracks are separate SD content.
export async function addRippleSdFiles(files, existing = null, progress = () => {}) {
  if (existing) validateRipplePayload(existing);
  const selected = Array.from(files || []);
  if (!selected.length || selected.length > 100000) fail('Choose the Ripple folder from its SD card.');
  const records = [], identities = new Map();
  let total = 0, excluded = 0;
  for (const file of selected) {
    const parts = (file.webkitRelativePath || file.name || '').split('/');
    const root = parts.findIndex(part => part.toLowerCase() === 'ripple');
    if (root < 0 || root > 1 || /^(?:trk|tracks|maps|tiles)$/i.test(parts[root + 1] || '')) { excluded++; continue; }
    const path = savedPath(['ripple', ...parts.slice(root + 1)].join('/'));
    if (records.length >= MAX_FILES || !Number.isInteger(file.size) || file.size > MAX_FILE || (total += file.size) > MAX_TOTAL) fail('Ripple settings backup is limited to 256 files, 1 MiB per file and 4 MiB total. Choose the Ripple folder without maps or tracks.');
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (bytes.length !== file.size) fail('Ripple SD file changed while reading.');
    try {
      if (bytes.length >= 96 && bytes.length <= 16384) {
        try {
          const identity = await findRippleIdentity(bytes, { alignment: 1 });
          identities.set(identity.privateKey, identity);
        } catch (error) {
          if (!/^No verified Ripple identity was found\./.test(error.message)) throw error;
        }
      }
      records.push({ path, size: bytes.length, sha256: hash(bytes), data: encode64(bytes) });
    } finally { bytes.fill(0); }
    progress(records.length / Math.min(MAX_FILES, selected.length), 'Reading Ripple SD files');
  }
  if (!records.length) fail('No Ripple settings files were selected. Choose the Ripple folder on the SD card.');
  if (existing && identities.size && !identities.has(existing.privateKey)) fail('The SD identities do not match the selected Ripple USB identity. Choose the matching SD card before adding its files.');
  let identity = existing;
  if (!identity) {
    if (identities.size !== 1) fail(identities.size ? 'Several different SD identities were found. Back up the running Ripple device over USB to identify the active key first.' : 'No verified private key was found in these SD files. Include the identity file or back up the running Ripple device over USB first.');
    identity = identities.values().next().value;
  }
  // A USB identity determines the active key even when the card also holds
  // identities for other profiles. Every included original file is preserved.
  return validateRipplePayload({ role: 'ripple', publicKey: identity.publicKey, privateKey: identity.privateKey, source: existing?.source || { method: 'sd-files', storage: 'sd-card' }, files: records.sort((a, b) => a.path.localeCompare(b.path)), filesExcluded: excluded, safeForWipe: false });
}

export function rippleSavedFilesZip(payload) {
  validateRipplePayload(payload);
  if (!payload.files.length) fail('This backup contains no SD files.');
  const files = Object.create(null);
  try {
    for (const file of payload.files) files[file.path] = decode64(file.data);
    return zipSync(files, { level: 6 });
  } finally { for (const bytes of Object.values(files)) bytes.fill(0); }
}

// Wadamesh's on-device settings importer reads these exact fields. Omit
// channels, contacts and preferences: absent sections leave those untouched.
export function wadameshIdentityImport(payload) {
  validateRipplePayload(payload);
  return { public_key: payload.publicKey, private_key: payload.privateKey };
}

export function rippleCoverage(payload) {
  validateRipplePayload(payload);
  const included = ['Public identity', 'Verified private identity'];
  if (payload.source.method === 'usb-jtag') included.push('Firmware version, radio build and factory MAC');
  if (payload.files.length) included.push(`${payload.files.length} original Ripple SD files`);
  const notIncluded = [
    { label: 'Firmware and bootloader images', reason: 'Firmware is not copied or changed.' },
    { label: 'General memory and runtime logs', reason: 'The memory snapshot is discarded after key verification.' },
    { label: 'Maps, recorded tracks and files outside the selected Ripple folder', reason: 'These are separate SD-card content.' },
  ];
  if (!payload.files.length) notIncluded.push({ label: 'Saved contacts, channels and preferences', reason: 'Add the Ripple SD folder to include the original saved files.' });
  return { included, notIncluded, failed: [], summaryText: 'Verified identity' + (payload.files.length ? ` and ${payload.files.length} original SD files are saved in the JSON.` : ' is saved in the JSON.'), notIncludedText: 'Not backed up: ' + notIncluded.map(item => item.label).join('; ') };
}

export async function restoreRippleIdentity(api, payload, { replaceIdentity = false, assertCurrent = () => {} } = {}) {
  validateRipplePayload(payload);
  assertCurrent();
  const before = await api.self();
  assertCurrent();
  if (before[0] !== 5 || before[1] !== 1 || before.length < 36) fail('Select a running MeshCore companion to restore this Ripple identity.');
  if (bytesToHex(before.subarray(4, 36)) === payload.publicKey) return { identityChanged: false, warnings: ['The selected companion already has this identity.'] };
  if (!replaceIdentity) fail('Enable Explicitly replace the target identity before moving a Ripple key.');
  const key = hexToBytes(payload.privateKey);
  try {
    assertCurrent();
    await api.request(Uint8Array.from([24, ...key]), 0);
    assertCurrent();
    const after = await api.self();
    assertCurrent();
    if (after[0] !== 5 || bytesToHex(after.subarray(4, 36)) !== payload.publicKey) fail('The target identity did not verify after import. Inspect the target before retrying.');
    return { identityChanged: true, warnings: [] };
  } finally { key.fill(0); }
}
