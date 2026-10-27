// Revision selection follows Espressif esptool cmds._get_image_incompatibility.
// Compatibility is independent of chip ID, secure boot and flash bounds: a
// revision acknowledgement must never bypass those separate checks.
import { fail, hash } from './firmware.js';

export function imageRevisionRequirements(image) {
  if (!(image instanceof Uint8Array) || image.length < 24 || image[0] !== 0xe9) fail('Invalid ESP image revision header.');
  const view = new DataView(image.buffer, image.byteOffset, image.byteLength);
  const chipId = view.getUint16(12, true), minRev = image[14], minRevFull = view.getUint16(15, true), maxRevFull = view.getUint16(17, true);
  const full = maxRevFull !== 0 && !(maxRevFull === 65535 && minRevFull === 0 && minRev !== 0);
  const constrained = full ? minRevFull !== 0 || maxRevFull !== 65535 : minRev !== 0;
  return { chipId, minRev, minRevFull, maxRevFull, full, constrained };
}

export async function readChipRevision(loader) {
  const chip = loader.chip, id = chip.IMAGE_CHIP_ID;
  const checked = Object.create(loader);
  checked.readReg = async (...args) => {
    const value = await loader.readReg(...args);
    // esptool-js 0.7.0 decodes ROM words with bitwise operators, so bit 31
    // produces a signed value. Accept either 32-bit representation only.
    if (!Number.isInteger(value) || value < -0x80000000 || value > 0xffffffff) fail('ESP revision eFuse read failed.');
    return value >>> 0;
  };
  checked.debug = (...args) => loader.debug?.(...args);
  let major, minor;
  if (id === 0) {
    // esptool-js names its classic-ESP32 major-only method getChipRevision.
    const majorReader = chip.getMajorChipVersion || chip.getChipRevision;
    if (typeof majorReader !== 'function') fail('ESP32 revision reader is unavailable.');
    major = await majorReader.call(chip, checked);
    minor = typeof chip.getMinorChipVersion === 'function' ? await chip.getMinorChipVersion(checked) : ((await checked.readReg(0x3ff5a014)) >>> 24) & 3;
  } else if ([2, 5, 9].includes(id)) {
    if (typeof chip.getMajorChipVersion !== 'function' || typeof chip.getMinorChipVersion !== 'function') fail('ESP revision reader is unavailable.');
    major = await chip.getMajorChipVersion(checked); minor = await chip.getMinorChipVersion(checked);
  } else if (id === 13) {
    // The JS C6 target inherits C3 revision methods, but C6 puts BOTH fields
    // in BLOCK1 word 3 (native esptool targets/esp32c6.py), not C3 word 5.
    const word = await checked.readReg(0x600b0850);
    major = (word >>> 22) & 3; minor = (word >>> 18) & 15;
  } else fail('No reviewed ESP silicon revision reader for this chip.');
  if (![major, minor].every(value => Number.isInteger(value) && value >= 0 && value < 100)) fail('ESP silicon revision could not be verified.');
  return { major, minor, full: major * 100 + minor };
}

export function revisionIncompatibility(requirements, revision, label = 'Image') {
  if (!requirements.constrained) return null;
  if (!revision) return `${label}: silicon revision could not be read; the image has revision constraints.`;
  if (requirements.full) {
    if (revision.full >= requirements.minRevFull && revision.full <= requirements.maxRevFull) return null;
    const format = value => `${Math.floor(value / 100)}.${value % 100}`;
    return `${label}: requires silicon revision ${format(requirements.minRevFull)} to ${requirements.maxRevFull === 65535 ? 'any newer revision' : format(requirements.maxRevFull)}; connected revision is ${revision.major}.${revision.minor}.`;
  }
  // ESP-IDF's legacy C3 field is MINOR; every other supported chip uses MAJOR.
  const actual = requirements.chipId === 5 ? revision.minor : revision.major;
  return actual >= requirements.minRev ? null : `${label}: requires legacy ${requirements.chipId === 5 ? 'minor' : 'major'} silicon revision ${requirements.minRev} or newer; connected value is ${actual}.`;
}

export function compatibilityImages(pkg, plan) {
  const bootOffset = [0, 2].includes(pkg.chipId) ? 0x1000 : 0;
  const images = [];
  const add = (image, offset, label) => images.push({ image, offset, label, bootloader: offset === bootOffset, requirements: imageRevisionRequirements(image) });
  if (pkg.merged) {
    add(pkg.payload.subarray(bootOffset), bootOffset, 'Merged bootloader');
    for (const part of plan.parts || []) if (part.type === 0 && part.offset < pkg.payload.length && pkg.payload[part.offset] === 0xe9) add(pkg.payload.subarray(part.offset, Math.min(part.offset + part.size, pkg.payload.length)), part.offset, `Application 0x${part.offset.toString(16)}`);
  } else add(pkg.payload, plan.addresses[0], pkg.expert ? 'ESP component' : 'Application');
  if (plan.needed && !plan.verified) add(Uint8Array.from(plan.bridge), plan.addresses[0], 'USB migration bridge');
  return images;
}

export async function assessEspCompatibility(loader, pkg, plan) {
  const images = compatibilityImages(pkg, plan);
  if (images.some(image => image.requirements.chipId !== pkg.chipId)) fail('Image revision header belongs to a different ESP chip.');
  let revision = null;
  if (images.some(image => image.requirements.constrained)) {
    try { revision = await readChipRevision(loader); } catch { /* Explicit, fail-closed unknown-revision issue below. */ }
  }
  const issues = images.map(image => ({ reason: revisionIncompatibility(image.requirements, revision, image.label), bootloader: image.bootloader, offset: image.offset })).filter(issue => issue.reason);
  const revisionCheck = { revision, images: images.map(({ requirements, offset, bootloader }) => ({ requirements, offset, bootloader })), issues };
  return {
    revisionCheck,
    revisionProof: hash(new TextEncoder().encode(JSON.stringify(revisionCheck))),
    compatibilityWarnings: issues.map(issue => `${issue.bootloader ? 'BOOTLOADER' : 'APPLICATION'}: ${issue.reason}`),
    requiresRevisionOverride: issues.length > 0,
    revisionOverrideToken: 'FORCE CHIP REVISION'
  };
}
