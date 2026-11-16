import { zipSync } from 'fflate';
import { fail, hash } from './firmware.js';

export const MAX_SAVED_FILES = 256, MAX_SAVED_FILE = 1 << 20, MAX_SAVED_TOTAL = 4 << 20;
export function savedPath(value, roots) {
  if (typeof value !== 'string' || value.length > 240 || /[\\:\x00-\x1f\x7f]/.test(value)) fail('Invalid saved-file path.');
  const parts = value.split('/');
  if (!roots.includes(parts[0]) || parts.length < 2 || parts.some(part => !part || /^\.{1,2}$/.test(part) || /[. ]$/.test(part) || /[<>"|?*]/.test(part) || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part))) fail('Choose files inside the supported settings folder.');
  return value;
}
export function encodeSavedFile(bytes) {
  let value = '';
  for (let at = 0; at < bytes.length; at += 8192) value += String.fromCharCode(...bytes.subarray(at, at + 8192));
  return btoa(value);
}
export function decodeSavedFile(value) {
  if (typeof value !== 'string' || value.length > Math.ceil(MAX_SAVED_FILE / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) fail('Invalid saved-file data.');
  const bytes = Uint8Array.from(atob(value), char => char.charCodeAt(0));
  if (encodeSavedFile(bytes) !== value) fail('Noncanonical saved-file encoding.');
  return bytes;
}
export function validateSavedFiles(files, roots) {
  if (!Array.isArray(files) || files.length > MAX_SAVED_FILES) fail('Invalid saved-file inventory.');
  let total = 0;
  const names = new Set();
  for (const file of files) {
    const normalized = savedPath(file?.path, roots).normalize('NFC').toLowerCase();
    if (names.has(normalized)) fail('Duplicate saved-file path.');
    names.add(normalized);
    if (!Number.isInteger(file.size) || file.size < 0 || file.size > MAX_SAVED_FILE || !/^[a-f0-9]{64}$/.test(file.sha256 || '')) fail('Invalid saved-file metadata.');
    if ((total += file.size) > MAX_SAVED_TOTAL) fail('Saved files exceed 4 MiB.');
    const bytes = decodeSavedFile(file.data);
    try { if (bytes.length !== file.size || hash(bytes) !== file.sha256) fail('Saved-file integrity check failed.'); }
    finally { bytes.fill(0); }
  }
  return files;
}
export async function readSavedFolder(files, { roots, excludedFolders = [], skipOversized = false, excludeFile = () => false }, progress = () => {}) {
  const selected = Array.from(files || []);
  if (!selected.length || selected.length > 100000) fail('Choose the settings folder from the device.');
  if (skipOversized) selected.sort((a, b) => a.size - b.size);
  const records = []; let total = 0, excluded = 0;
  for (const file of selected) {
    const parts = (file.webkitRelativePath || file.name || '').split('/');
    const root = parts.findIndex(part => roots.includes(part.toLowerCase()));
    if (root < 0 || root > 1 || excludedFolders.includes((parts[root + 1] || '').toLowerCase())) { excluded++; continue; }
    const path = savedPath([parts[root].toLowerCase(), ...parts.slice(root + 1)].join('/'), roots);
    if (excludeFile(path)) { excluded++; continue; }
    if (!Number.isInteger(file.size) || file.size < 0) fail('Invalid saved-file size.');
    if (records.length >= MAX_SAVED_FILES || file.size > MAX_SAVED_FILE || total + file.size > MAX_SAVED_TOTAL) {
      if (skipOversized) { excluded++; continue; }
      fail('Settings backup is limited to 256 files, 1 MiB per file and 4 MiB total. Choose the settings folder without maps or tracks.');
    }
    const bytes = new Uint8Array(await file.arrayBuffer());
    try {
      if (bytes.length !== file.size) fail('Settings file changed while reading.');
      records.push({ path, size: bytes.length, sha256: hash(bytes), data: encodeSavedFile(bytes) });
      total += bytes.length;
    } finally { bytes.fill(0); }
    progress(records.length / Math.min(MAX_SAVED_FILES, selected.length), 'Reading saved settings files');
  }
  if (!records.length) fail('No settings files were selected. Choose the supported settings folder.');
  validateSavedFiles(records, roots);
  return { files: records.sort((a, b) => a.path.localeCompare(b.path)), filesExcluded: excluded };
}
export function savedFilesZip(files, roots) {
  validateSavedFiles(files, roots);
  if (!files.length) fail('This backup contains no saved files.');
  const decoded = Object.create(null);
  try {
    for (const file of files) decoded[file.path] = decodeSavedFile(file.data);
    return zipSync(decoded, { level: 6 });
  } finally { for (const bytes of Object.values(decoded)) bytes.fill(0); }
}
