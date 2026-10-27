import { unzipSync } from 'fflate';
import { sha256 } from '@noble/hashes/sha2.js';
import { md5 } from '@noble/hashes/legacy.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { endfIdentity, payloadBoardIdentity } from './board-safety.js';

export const hash = data => bytesToHex(sha256(data));
export const md5hex = data => bytesToHex(md5(data));
export const text = data => new TextDecoder().decode(data);
export const fail = message => { throw new Error(message); };
export const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
export const nrfMetadataHash = pkg => hash(new TextEncoder().encode(JSON.stringify([pkg.name,pkg.architecture,pkg.kind,pkg.mode,pkg.sdSize,pkg.blSize,pkg.appSize,pkg.payloadHash,pkg.initHash,pkg.destructive,pkg.erase,pkg.eraseEvidence,pkg.boardIdentity,pkg.firmwareIdentity])));
// Hash the actual destructive application, not its ZIP envelope: a renamed or
// repacked erase package must not become an apparently ordinary app update.
const knownNrfErasePayloads = new Map([
  ['f17500b598ce53d4d4183f6bd20e06e9bf2bd3468d9a22ff3af7f148bb0dfc0c','official SoftDevice v6 erase payload'],
  ['01f8d553e5ce865312fcfe3ddf1eb06f10ed7ca6bd4f34dd81e58b6f8400be8e','official SoftDevice v7 erase payload'],
  // Published by flasher.meshcore.io/firmware/*_QSPIFlash_Format-v1.2.zip.
  // Bind destructive intent to the BIN, not the ZIP filename or compression.
  ['bfd6d72de724c4b84395a963c0428c89de245038a44f02241907838e6caf9e09','official QSPI formatter payload (WioTrackerL1 v1.2)'],
  ['dc6f52a8c7c6734be1cc1d3ce9ee01db657acac1383bbd48f4be017408cb20b9','official QSPI formatter payload (LilyGo_T-Echo v1.2)'],
  ['400008ca61ead5d5ccd6a22278aef7555e0377e9982a676f17a030642384bd82','official QSPI formatter payload (Xiao_nrf52 v1.2)'],
  ['5f704a28b9abe49998cad9a63565c855ae27d3af4bc8dd1870a468618025ceb2','official QSPI formatter payload (ThinkNode_M1 v1.2)'],
  ['c3580dcd94d4f9983a9bf1d5e40ff678b38c6e9074f5e287360f27e992f29174','official QSPI formatter payload (Nano_G2_Ultra v1.2)']
]);
const eraseName = value => /(?:^|[\\/_. -])(?:flash[_. -]*)?(?:erase|wipe|(?:qspi[_. -]*flash[_. -]*)?format(?:ter)?)(?:[\\/_. -]|$)/i.test(value || '');
export const nrfEraseIntent = (name,payloadHash,entryNames = []) => knownNrfErasePayloads.get(payloadHash) || ([name,...entryNames].some(eraseName) ? 'erase/wipe package name (conservative destructive classification)' : null);
export function crc16(data) {
  let crc = 0xffff;
  for (const b of data) { crc ^= b << 8; for (let i = 0; i < 8; i++) crc = ((crc & 0x8000) ? (crc << 1) ^ 0x1021 : crc << 1) & 0xffff; }
  return crc;
}
export function crc32(data, initial = 0) {
  let crc = (initial ^ 0xffffffff) >>> 0;
  for (const b of data) { crc ^= b; for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0); }
  return (crc ^ 0xffffffff) >>> 0;
}
export function words(...values) {
  const result = new Uint8Array(values.length * 4), view = new DataView(result.buffer);
  values.forEach((value, i) => view.setUint32(i * 4, value, true)); return result;
}

// Inspect the central directory BEFORE decompression. CRC and declared sizes
// are checked again afterwards; paths, ZIP64, encryption, and bombs fail closed.
export function checkedZip(bytes, { maxEntries = 256, maxExpanded = 64 << 20, directoryOnly = false, select = null } = {}) {
  if (!(bytes instanceof Uint8Array) || bytes.length > (64 << 20) || bytes.length < 22) fail('Invalid or oversized ZIP.');
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let eocd = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
    if (v.getUint32(i, true) === 0x06054b50 && i + 22 + v.getUint16(i + 20, true) === bytes.length) { eocd = i; break; }
  }
  if (eocd < 0 || v.getUint16(eocd + 4, true) || v.getUint16(eocd + 6, true)) fail('Missing or multi-disk ZIP directory.');
  const count = v.getUint16(eocd + 10, true), start = v.getUint32(eocd + 16, true), size = v.getUint32(eocd + 12, true);
  if (!count || count > maxEntries || v.getUint16(eocd + 8, true) !== count || start + size !== eocd) fail('ZIP directory bounds or entry count invalid.');
  const records = new Map(), ranges = []; let offset = start, total = 0;
  for (let i = 0; i < count; i++) {
    if (offset + 46 > eocd || v.getUint32(offset, true) !== 0x02014b50) fail('Invalid ZIP directory record.');
    const flags = v.getUint16(offset + 8, true), method = v.getUint16(offset + 10, true);
    const packed = v.getUint32(offset + 20, true), length = v.getUint32(offset + 24, true);
    const n = v.getUint16(offset + 28, true), extra = v.getUint16(offset + 30, true), comment = v.getUint16(offset + 32, true);
    if (offset + 46 + n + extra + comment > eocd) fail('Invalid ZIP directory record bounds.');
    const nameBytes = bytes.subarray(offset + 46, offset + 46 + n);
    let name; try { name = new TextDecoder('utf-8', {fatal:true}).decode(nameBytes); } catch { fail('Invalid ZIP entry name encoding.'); }
    const local = v.getUint32(offset + 42, true);
    const crc = v.getUint32(offset + 16, true), unixMode = v.getUint32(offset + 38, true) >>> 16;
    if ((flags & ~0x080e) || (method === 0 && ((flags & 6) || packed!==length)) || ![0, 8].includes(method) || !name || /(^\/|\\|(^|\/)\.\.?($|\/)|\x00|:)/.test(name) || name.split('/').some(part => ['__proto__','constructor','prototype'].includes(part)) || records.has(name) || (!(flags & 0x0800) && nameBytes.some(b => b > 127)) || v.getUint16(offset + 34,true) || (unixMode & 0xf000) === 0xa000 || [packed,length,local].includes(0xffffffff)) fail('Encrypted, duplicate, unsafe, or unsupported ZIP entry.');
    // ZIP64 would change the sizes used for the bounded preflight. Never let
    // the decompressor reinterpret a different set of sizes afterwards.
    for (let field = offset + 46 + n; field < offset + 46 + n + extra;) {
      if (field + 4 > offset + 46 + n + extra) fail('Invalid ZIP extra field.');
      const id = v.getUint16(field,true), fieldLength = v.getUint16(field+2,true);
      field += 4; if (id === 1 || field + fieldLength > offset + 46 + n + extra) fail('ZIP64 or malformed ZIP extra field.'); field += fieldLength;
    }
    if (local + 30 > start || v.getUint32(local, true) !== 0x04034b50) fail('Invalid ZIP local record.');
    const dataOffset = local + 30 + v.getUint16(local + 26, true) + v.getUint16(local + 28, true);
    if (dataOffset + packed > start || v.getUint16(local+6,true)!==flags || v.getUint16(local+8,true)!==method || v.getUint16(local+26,true)!==n || !nameBytes.every((b,i)=>bytes[local+30+i]===b)) fail('ZIP local/central records disagree.');
    for (const [at,expected] of [[14,crc],[18,packed],[22,length]]) if (v.getUint32(local+at,true)!==expected && (!(flags&8) || v.getUint32(local+at,true)!==0)) fail('ZIP local/central sizes or CRC disagree.');
    let end = dataOffset + packed;
    if (flags & 8) {
      if (end + 12 > start) fail('Truncated ZIP data descriptor.');
      if (v.getUint32(end,true) === 0x08074b50) end += 4;
      if (end + 12 > start || v.getUint32(end,true)!==crc || v.getUint32(end+4,true)!==packed || v.getUint32(end+8,true)!==length) fail('ZIP data descriptor disagrees with its directory.');
      end += 12;
    }
    ranges.push([local,end]);
    total += length; if (total > maxExpanded) fail('ZIP expands beyond the safety limit.');
    records.set(name, { length, crc });
    offset += 46 + n + extra + comment;
  }
  if (offset !== eocd) fail('Unexpected ZIP directory data.');
  ranges.sort((a,b)=>a[0]-b[0]); if (ranges.some((range,i)=>i && range[0]<ranges[i-1][1])) fail('ZIP local records overlap.');
  if (directoryOnly) return [...records].map(([name,record]) => ({name,...record}));
  const selected = new Map([...records].filter(([name]) => !select || select(name)));
  if ([...selected.values()].reduce((n,r) => n + r.length,0) > (64 << 20)) fail('Selected files expand beyond 64 MiB.');
  const files = unzipSync(bytes,{filter:entry => selected.has(entry.name)});
  if (Object.keys(files).length !== selected.size) fail('ZIP inventory mismatch.');
  for (const [name, record] of selected) if (files[name]?.length !== record.length || crc32(files[name]) !== record.crc) fail(`ZIP integrity failed: ${name}`);
  return files;
}

export function nrfPackage(name, bytes) {
  if (bytes.length > 4 << 20) fail('Legacy DFU ZIP exceeds 4 MiB.');
  const files = checkedZip(bytes, { maxEntries: 3, maxExpanded: 2 << 20 });
  if (!files['manifest.json'] || files['manifest.json'].length > 65536) fail('DFU manifest missing or too large.');
  const manifest = JSON.parse(text(files['manifest.json'])).manifest;
  const kinds = { application: 4, bootloader: 2, softdevice_bootloader: 3, softdevice: 1 };
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest) || (manifest.dfu_version != null && manifest.dfu_version !== 0.5)) fail('Only legacy Adafruit serial DFU ZIPs are supported.');
  const keys = Object.keys(manifest).filter(k => k !== 'dfu_version');
  if (keys.length !== 1 || !Object.hasOwn(kinds,keys[0])) fail('DFU must contain exactly one application, bootloader, or combined component.');
  const kind = keys[0], entry = manifest[kind];
  if (!entry || typeof entry !== 'object' || Array.isArray(entry) || typeof entry.bin_file!=='string' || typeof entry.dat_file!=='string' || entry.bin_file === entry.dat_file || [entry.bin_file,entry.dat_file].includes('manifest.json') || !Object.hasOwn(files,entry.bin_file) || !Object.hasOwn(files,entry.dat_file) || Object.keys(files).length !== 3) fail('Invalid DFU inventory.');
  const payload = files[entry.bin_file], init = files[entry.dat_file];
  if (!payload?.length || payload.length > 900 * 1024 || payload.length % 4 || !init || init.length < 12) fail('Invalid DFU payload or DAT length/alignment.');
  const d = new DataView(init.buffer, init.byteOffset, init.byteLength), required = d.getUint16(8, true), crcOffset = 10 + required * 2;
  if (required > 32 || init.length !== crcOffset + 2 || crc16(payload) !== d.getUint16(crcOffset, true)) fail('DFU DAT structure or firmware CRC is invalid.');
  if (![0x52, 0xffff].includes(d.getUint16(0, true))) fail('This DFU init packet is not for nRF52.');
  const sdSize = kind === 'softdevice' ? payload.length : kind === 'softdevice_bootloader' ? entry.sd_size : 0;
  const blSize = kind === 'bootloader' ? payload.length : kind === 'softdevice_bootloader' ? entry.bl_size : 0;
  const appSize = kind === 'application' ? payload.length : 0;
  if (![sdSize, blSize, appSize].every(n => Number.isInteger(n) && n >= 0 && n % 4 === 0) || sdSize + blSize + appSize !== payload.length || (kind==='softdevice_bootloader' && (!sdSize || !blSize)) || (kind!=='softdevice_bootloader' && ('sd_size' in entry || 'bl_size' in entry))) fail('DFU component sizes disagree with the payload.');
  if (entry.init_packet_data != null) {
    const metadata=entry.init_packet_data, expected={device_type:d.getUint16(0,true),device_revision:d.getUint16(2,true),application_version:d.getUint32(4,true),firmware_crc16:d.getUint16(crcOffset,true)}, requiredIds=Array.from({length:required},(_,i)=>d.getUint16(10+i*2,true));
    if (typeof metadata!=='object' || Array.isArray(metadata) || Object.keys(metadata).some(k=>!Object.hasOwn(expected,k) && k!=='softdevice_req') || Object.entries(expected).some(([k,value])=>Object.hasOwn(metadata,k) && metadata[k]!==value) || (Object.hasOwn(metadata,'softdevice_req') && (!Array.isArray(metadata.softdevice_req) || metadata.softdevice_req.length!==requiredIds.length || metadata.softdevice_req.some((value,i)=>value!==requiredIds[i])))) fail('DFU manifest and DAT metadata disagree.');
  }
  const payloadHash = hash(payload), eraseEvidence = nrfEraseIntent(name,payloadHash,[entry.bin_file,entry.dat_file]), erase = !!eraseEvidence;
  const pkg={ name, architecture: 'nrf52', kind, mode: kinds[kind], payload, init, sdSize, blSize, appSize, sha256: hash(bytes), payloadHash, initHash: hash(init), erase, eraseEvidence, boardIdentity:payloadBoardIdentity(payload),firmwareIdentity:endfIdentity(payload),destructive: kind !== 'application' || erase, warnings: [...(erase?['This is an erase/wipe application. Its application-type DFU manifest does NOT make it a non-destructive update. It erases stored identity/settings and must be followed by the intended firmware.']:[]),...(kind!=='application'?['This replaces the bootloader and/or SoftDevice. A wrong target can invalidate the application or require physical SWD recovery; a logical backup cannot recover the bootloader.']:[]),'Browser APIs cannot prove physical identity across a DFU reconnect. Explicitly select the same device.', 'DFU completion does not verify application startup.'] };
  pkg.metadataHash=nrfMetadataHash(pkg); return pkg;
}

export function partitionTable(data, flashBytes = 128 << 20) {
  if (data.length !== 4096) fail('Partition table must contain exactly 4096 bytes.');
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength), parts = [], labels=new Set();
  for (let i = 0; i + 32 <= data.length; i += 32) {
    const magic = view.getUint16(i, true);
    if (magic === 0xffff) { if (!data.subarray(i).every(b=>b===255)) fail('Partition table has malformed trailing data.'); break; }
    if (magic === 0xebeb) {
      if (!data.subarray(i+2,i+16).every(b=>b===255) || bytesToHex(data.subarray(i+16,i+32))!==md5hex(data.subarray(0,i))) fail('Partition table MD5 verification failed.');
      if (!data.subarray(i+32).every(b=>b===255)) fail('Partition table has entries after its checksum.'); break;
    }
    if (magic !== 0x50aa) fail('Invalid ESP32 partition table magic.');
    const labelBytes=data.subarray(i+12,i+28), end=labelBytes.indexOf(0), labelData=labelBytes.subarray(0,end<0?16:end);
    const part = { type: data[i + 2], subtype: data[i + 3], offset: view.getUint32(i + 4, true), size: view.getUint32(i + 8, true), label: text(labelData), flags:view.getUint32(i+28,true) };
    if (!part.label || labelData.some(b=>b>127) || labels.has(part.label) || (part.flags & ~3) || !part.size || part.offset < 0x9000 || part.offset + part.size > flashBytes || part.offset % 4096 || part.size % 4096 || (part.type===0 && part.offset%65536) || parts.some(p => part.offset < p.offset + p.size && part.offset + part.size > p.offset)) fail('Partition bounds, labels, flags, alignment, or overlap invalid.');
    labels.add(part.label);
    parts.push(part);
  }
  if (!parts.some(p => p.type === 0)) fail('Partition table has no application.');
  return parts;
}
export function activeOta(parts, data) {
  if (data.length !== 8192) fail('OTA metadata must be 8192 bytes.');
  const apps = parts.filter(p => p.type === 0 && p.subtype >= 0x10 && p.subtype <= 0x1f).sort((a,b) => a.subtype - b.subtype);
  if (!apps.length || apps.some((p, i) => p.subtype !== 0x10 + i)) fail('OTA slots are ambiguous; no safe application write order can be established.');
  const v = new DataView(data.buffer, data.byteOffset, data.byteLength), seqs = [];
  for (const off of [0, 4096]) {
    const seq = v.getUint32(off, true), state = v.getUint32(off + 24, true), crc = v.getUint32(off + 28, true);
    if (seq && seq !== 0xffffffff && ![3,4].includes(state) && crc === crc32(data.subarray(off,off+4), 0xffffffff)) seqs.push(seq);
  }
  if (!seqs.length) {
    if (![...data.subarray(0,32),...data.subarray(4096,4128)].every(b => b === 255)) fail('OTA metadata has no verified active sequence.');
    return parts.find(p => p.type === 0 && p.subtype === 0)?.offset ?? apps[0].offset;
  }
  let newest = seqs[0]; for (const seq of seqs.slice(1)) { const delta = (seq - newest) >>> 0; if (delta === 0x80000000) fail('Ambiguous OTA sequence order.'); if (delta && delta < 0x80000000) newest = seq; }
  return apps[(newest - 1) % apps.length].offset;
}
export function inspectFirmware(name, bytes) {
  if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > 64 << 20) fail('Firmware is empty or exceeds 64 MiB.');
  if (/\.zip$/i.test(name)) return nrfPackage(name, bytes);
  if (/\.uf2$/i.test(name)) {
    const family=validateUf2(bytes);
    if([0x1b57745f,0x621e937a,0xada52840,0x820d9a5f,0x72721d4e,0x6f752678].includes(family)) fail('nRF52 flashing uses serial DFU only. Select the board’s legacy DFU ZIP, not a UF2 mounted-drive file.');
    return { name, architecture: 'uf2', kind: 'UF2 drive copy', family, sha256: hash(bytes), payloadHash:hash(bytes), payload: bytes, destructive:true, warnings: ['Choose the mounted UF2 bootloader drive yourself. Family IDs do not prove board compatibility. Target startup remains unverified after copying.'] };
  }
  if (!/\.bin$/i.test(name)) fail('Choose a BIN, legacy nRF52 DFU ZIP, or UF2, or select a supported image inside a release archive.');
  const merged = bytes.length > 0x9000 && bytes[0x8000] === 0xaa && bytes[0x8001] === 0x50;
  const offset = bytes[0] === 0xe9 ? 0 : merged && bytes[0x1000] === 0xe9 ? 0x1000 : -1;
  if (offset < 0 || bytes.length < offset + 24) fail('Not a validated ESP32 image.');
  const bootLength=validateEspImage(bytes.subarray(offset));
  if(merged && offset+bootLength>0x8000) fail('Merged bootloader overlaps its partition table.');
  if (merged) partitionTable(bytes.subarray(0x8000, 0x9000));
  else if (/-merged|factory|full.?install/i.test(name)) fail('Filename claims a merged install, but no valid partition table exists.');
  const expert = !merged && (bytes.length < 36 || new DataView(bytes.buffer, bytes.byteOffset).getUint32(32, true) !== 0xabcd5432);
  const chipId = bytes[offset + 12] | bytes[offset + 13] << 8;
  if (merged && offset !== ([0,2].includes(chipId) ? 0x1000 : 0)) fail('Merged bootloader is not at the expected offset for its declared ESP32 chip.');
  return { name, architecture: 'esp32', kind: merged ? 'Merged install' : expert ? 'Expert ESP image / bootloader' : 'Application update', merged, expert, chipId, payload: bytes, payloadHash: hash(bytes), sha256: hash(bytes), destructive: merged || expert, warnings: merged ? ['Whole-chip erase. Node identity and settings will be lost.'] : expert ? ['Validated image without an ESP-IDF application descriptor. You must supply its exact flash offset. A wrong bootloader or offset can require physical recovery. No settings preservation is promised.'] : ['The physical partition table, OTA state, NVS migration state, image chip, and chip MAC are checked before writes. Required partition expansion must be verified before the final application update.'] };
}

export function validateUf2(bytes) {
  if (!bytes.length || bytes.length % 512) fail('UF2 must contain whole 512-byte blocks.');
  const v = new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength), ids = new Set(), ranges=[]; let family;
  for (let offset=0;offset<bytes.length;offset+=512) {
    if (v.getUint32(offset,true)!==0x0a324655 || v.getUint32(offset+4,true)!==0x9e5d5157 || v.getUint32(offset+508,true)!==0x0ab16f30) fail('UF2 block magic is invalid.');
    const flags=v.getUint32(offset+8,true),address=v.getUint32(offset+12,true),length=v.getUint32(offset+16,true),index=v.getUint32(offset+20,true),count=v.getUint32(offset+24,true),id=v.getUint32(offset+28,true);
    if (flags!==0x2000 || !length || length>476 || length%4 || address%4 || address+length>0x100000000 || !id || count!==bytes.length/512 || index>=count || ids.has(index) || (family!==undefined && id!==family)) fail('UF2 flags, address, payload, family, or block inventory is inconsistent.');
    ids.add(index); ranges.push([address,address+length]); family=id;
  }
  ranges.sort((a,b)=>a[0]-b[0]); if(ranges.some((range,i)=>i && range[0]<ranges[i-1][1])) fail('UF2 target address ranges overlap.');
  return family;
}

export function validateEspImage(data) {
  if (data.length < 24 || data[0] !== 0xe9 || !data[1] || data[1] > 16 || ![0,1].includes(data[23])) fail('Invalid ESP image header.');
  let offset = 24, checksum = 0xef;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  for (let i = 0; i < data[1]; i++) {
    if (offset + 8 > data.length) fail('Truncated ESP segment header.');
    const size = view.getUint32(offset + 4, true); offset += 8;
    if (size > 16 << 20 || offset + size > data.length) fail('Truncated or oversized ESP segment.');
    for (const b of data.subarray(offset, offset + size)) checksum ^= b;
    offset += size;
  }
  const checksumOffset = Math.ceil((offset + 1) / 16) * 16 - 1;
  if (checksumOffset >= data.length || data[checksumOffset] !== checksum) fail('ESP image checksum mismatch.');
  if (data[23] === 1 && (checksumOffset + 33 > data.length || bytesToHex(data.subarray(checksumOffset + 1,checksumOffset + 33)) !== hash(data.subarray(0,checksumOffset + 1)))) fail('ESP image appended SHA-256 mismatch.');
  return checksumOffset + 1 + (data[23] === 1 ? 32 : 0);
}
