import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { fail } from './firmware.js';
import { expandedPublicKey, findRippleIdentity } from './ripple-identity.js';
import { validateSavedFiles, readSavedFolder, decodeSavedFile, savedFilesZip } from './saved-files.js';

const ROOTS = ['meshcomod', 'prefs'];
export function validateWadameshFiles(value) {
  if (!value || value.version !== 1 || !Number.isInteger(value.filesExcluded) || value.filesExcluded < 0 || value.filesExcluded > 100000) fail('Invalid Wadamesh saved-settings record.');
  validateSavedFiles(value.files, ROOTS);
  return value;
}

export async function addWadameshFiles(payload, files, progress = () => {}) {
  if (payload?.role !== 'companion' || !/^[a-f0-9]{64}$/.test(payload.publicKey || '')) fail('Create or import the Wadamesh USB backup before adding its saved settings.');
  const bundle = await readSavedFolder(files, {
    roots: ROOTS, skipOversized: true,
    excludedFolders: ['trk', 'tracks', 'maps', 'tiles', 'msgs', 'messages', 'history', 'logs', 'discover'],
    excludeFile: path => /\.(?:log|csv)$|\/(?:battery|ui_msgs|ui_chat_history)[^/]*$/i.test(path),
  }, progress);
  if(payload.wadamesh){
    validateWadameshFiles(payload.wadamesh);
    // Add one storage root at a time without dropping a previously saved
    // root. Reselecting a folder replaces that folder's complete snapshot.
    const selectedRoots=new Set(bundle.files.map(file=>file.path.split('/')[0]));
    bundle.files=[...payload.wadamesh.files.filter(file=>!selectedRoots.has(file.path.split('/')[0])),...bundle.files].sort((a,b)=>a.path.localeCompare(b.path));
    bundle.filesExcluded+=payload.wadamesh.filesExcluded;
  }
  let privateKey = payload.privateKey;
  // Primary identity only: an old .bak can legitimately contain a previous
  // key. A present primary must agree with the live USB identity.
  for (const file of bundle.files.filter(file => /\/identity\/_main\.id$/.test(file.path))) {
    const bytes = decodeSavedFile(file.data);
    try {
      const identity = await findRippleIdentity(bytes, { alignment: 1 });
      if (identity.publicKey !== payload.publicKey || privateKey && privateKey.slice(2) !== identity.privateKey) fail('The Wadamesh data folder does not match this USB identity.');
      privateKey ||= '0e' + identity.privateKey;
    } finally { bytes.fill(0); }
  }
  return { ...payload, ...(privateKey ? { privateKey } : {}), wadamesh: validateWadameshFiles({ version: 1, ...bundle }) };
}
export function wadameshFilesZip(payload) {
  return savedFilesZip(validateWadameshFiles(payload.wadamesh).files, ROOTS);
}

// Format the verified Companion snapshot for Wadamesh's own settings importer.
// The browser archive remains the fuller backup: the on-device importer does
// not understand route paths, BLE PIN, telemetry or sensor/custom settings.
export function wadameshSettingsImport(payload) {
  if (payload?.role !== 'companion' || !/^0e[a-f0-9]{128}$/.test(payload.privateKey || '')) fail('A verified private identity is required for Wadamesh settings export.');
  const key = hexToBytes(payload.privateKey.slice(2));
  try { if (bytesToHex(expandedPublicKey(key)) !== payload.publicKey) fail('Wadamesh export private/public identity mismatch.'); }
  finally { key.fill(0); }
  const self = hexToBytes(payload.self), info = hexToBytes(payload.info);
  if (self.length < 58 || self[0] !== 5 || info.length < 80 || info[0] !== 13 || !Array.isArray(payload.channels) || !Array.isArray(payload.contacts)) fail('Invalid Wadamesh core snapshot.');
  const text = bytes => { const end=bytes.indexOf(0);return new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0,end<0?bytes.length:end)); };
  const view = new DataView(self.buffer, self.byteOffset, self.byteLength);
  const channels = payload.channels.map(raw => {
    const channel = hexToBytes(raw);
    if (channel.length !== 50 || channel[0] !== 18) fail('Invalid Wadamesh channel snapshot.');
    return { name: text(channel.subarray(2, 34)), secret: bytesToHex(channel.subarray(34, 50)) };
  });
  const contacts = payload.contacts.map(raw => {
    const contact = hexToBytes(raw);
    if (contact.length !== 148 || contact[0] !== 3) fail('Invalid Wadamesh contact snapshot.');
    const data = new DataView(contact.buffer, contact.byteOffset, contact.byteLength);
    return { type: contact[33], name: text(contact.subarray(100, 132)), custom_name: null, public_key: bytesToHex(contact.subarray(1, 33)), flags: contact[34], latitude: String(data.getInt32(136, true) / 1e6), longitude: String(data.getInt32(140, true) / 1e6), last_advert: data.getUint32(132, true), last_modified: data.getUint32(144, true), out_path: null };
  });
  return {
    name: text(self.subarray(58)), public_key: payload.publicKey, private_key: payload.privateKey.slice(2),
    radio_settings: { frequency: view.getUint32(48, true) / 1000, bandwidth: view.getUint32(52, true) / 1000, spreading_factor: self[56], coding_rate: self[57], tx_power: self[2] < 128 ? self[2] : self[2] - 256 },
    position_settings: { latitude: view.getInt32(36, true) / 1e6, longitude: view.getInt32(40, true) / 1e6 },
    channels, contacts,
  };
}
