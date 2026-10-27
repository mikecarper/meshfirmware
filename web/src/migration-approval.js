import {fail, hash, partitionTable, validateEspImage} from './firmware.js';

const FORMAT = 'meshcore-usb-partition-expansion-v2';
// The native planner qualifies both embedded USB bridges and the standalone
// set. Its chip/capacity support is broader than that set's six published files.
const reviewedChips = new Set([0, 5, 9]), reviewedFlashSizes = new Set([4 << 20, 8 << 20, 16 << 20]);
const deny = message => fail(`Automatic migration approval: ${message}`);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const freeze = value => {
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) freeze(item);
    Object.freeze(value);
  }
  return value;
};
const label = (value, name) => {
  if (typeof value !== 'string' || !value.trim() || value.length > 512 || /[\x00-\x1f\x7f]/.test(value)) deny(`${name} is missing or invalid.`);
  return value;
};
const digest = (value, name) => {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/i.test(value)) deny(`${name} is missing or invalid.`);
  return value.toLowerCase();
};
const mac = value => {
  if (typeof value !== 'string' || !/^(?:[a-f0-9]{12}|(?:[a-f0-9]{2}:){5}[a-f0-9]{2})$/i.test(value)) deny('chip MAC is missing or invalid.');
  const compact = value.replace(/:/g, '').toLowerCase();
  if (/^(?:0{12}|f{12})$/.test(compact)) deny('chip MAC is not a physical device identity.');
  return compact.match(/../g).join(':');
};
const bytes = (value, name, maximum = 16 << 20) => {
  if (!(value instanceof Uint8Array) && !(Array.isArray(value) && value.every(b => Number.isInteger(b) && b >= 0 && b <= 255))) deny(`${name} bytes are missing or invalid.`);
  if (!value.length || value.length > maximum) deny(`${name} length is invalid.`);
  return Uint8Array.from(value);
};
const noOverrides = (pkg, plan) => {
  if (!pkg || !plan || pkg.architecture !== 'esp32' || pkg.merged || pkg.expert || pkg.destructive || plan.merged || plan.expert || plan.segments != null || plan.requiresRevisionOverride || plan.chunkedRecovery || (plan.installMode != null && plan.installMode !== 'update')) deny('only ordinary application updates without recovery or compatibility overrides can continue automatically.');
};
function packageBinding(pkg, plan) {
  noOverrides(pkg, plan);
  const payload = bytes(pkg.payload, 'firmware'), sha256 = digest(pkg.sha256, 'firmware SHA-256'), payloadHash = digest(pkg.payloadHash, 'firmware payload SHA-256');
  if (hash(payload) !== sha256 || payloadHash !== sha256) deny('firmware bytes or hashes changed.');
  validateEspImage(payload);
  if (payload.length < 36 || new DataView(payload.buffer).getUint32(32, true) !== 0xabcd5432 || (payload[12] | payload[13] << 8) !== pkg.chipId) deny('firmware is not the approved ordinary chip application.');
  if (digest(plan.sha256, 'plan firmware SHA-256') !== sha256 || digest(plan.payloadHash, 'plan payload SHA-256') !== payloadHash || digest(plan.firmware_sha256, 'planner firmware SHA-256') !== sha256) deny('plan is for different firmware.');
  return {name: label(pkg.name, 'firmware filename'), sha256, payloadHash, chipId: pkg.chipId, payloadBytes: payload.length, installMode: 'update'};
}
function partsBinding(parts, flashBytes) {
  if (!Array.isArray(parts) || !parts.length || parts.length > 128) deny('partition geometry is missing or invalid.');
  const result = parts.map(part => {
    if (!part || !['type', 'subtype', 'offset', 'size', 'flags'].every(key => Number.isSafeInteger(part[key]) && part[key] >= 0) || part.type > 255 || part.subtype > 255 || part.offset < 0x9000 || !part.size || part.offset % 4096 || part.size % 4096 || part.offset + part.size > flashBytes || part.flags & ~3 || part.type === 0 && part.offset % 65536) deny('partition geometry is invalid.');
    return {type: part.type, subtype: part.subtype, offset: part.offset, size: part.size, label: label(part.label, 'partition label'), flags: part.flags};
  }).sort((a, b) => a.offset - b.offset);
  if (new Set(result.map(part => part.label)).size !== result.length || result.some((part, i) => i && part.offset < result[i - 1].offset + result[i - 1].size)) deny('partition geometry overlaps or has duplicate labels.');
  return result;
}
function offsets(value, name, flashBytes, length) {
  if (!Array.isArray(value) || value.length !== 2 || new Set(value).size !== 2 || value.some(offset => !Number.isSafeInteger(offset) || offset < 0x10000 || offset % 65536 || offset + length > flashBytes)) deny(`${name} must contain two reviewed application offsets.`);
  return [...value];
}
function identityBinding(identity) {
  if (identity == null) return null;
  if (typeof identity !== 'object' || Array.isArray(identity)) deny('application identity is invalid.');
  const result = {};
  for (const key of ['publicKey', 'model', 'role', 'version']) {
    if (identity[key] != null) result[key] = key === 'publicKey' ? digest(identity[key], 'application public identity') : label(identity[key], `application ${key}`);
  }
  return freeze(result);
}
function initialBinding(pkg, plan) {
  const firmware = packageBinding(pkg, plan);
  if (plan.format !== FORMAT || plan.ok !== true || plan.needed !== true || plan.verified || plan.usb_safe !== true || plan.resume || plan.started || plan.completed) deny('a fresh, reviewed USB expansion plan is required.');
  if (!reviewedChips.has(plan.chip) || !reviewedFlashSizes.has(plan.flash_bytes) || plan.chip !== firmware.chipId) deny('chip or physical flash capacity is not a reviewed migration profile.');
  const deviceMac = mac(plan.mac);
  if (mac(plan.device_mac) !== deviceMac) deny('planner and connected chip identities disagree.');
  const bridge = bytes(plan.bridge, 'bridge'), bridgeHash = digest(plan.bridge_sha256, 'bridge SHA-256');
  if (!Number.isSafeInteger(plan.bridge_bytes) || bridge.length !== plan.bridge_bytes || hash(bridge) !== bridgeHash) deny('bridge bytes or hash changed.');
  const bridgeOffsets = offsets(plan.bridge_offsets, 'bridge offsets', plan.flash_bytes, bridge.length);
  if (!bridgeOffsets.includes(0x10000) || !same(bridgeOffsets, offsets(plan.app_offsets, 'source app offsets', plan.flash_bytes, bridge.length)) || !same(bridgeOffsets, offsets(plan.addresses, 'source write addresses', plan.flash_bytes, bridge.length)) || bridgeOffsets.at(-1) !== plan.active_offset) deny('source bridge geometry or active-last write order changed.');
  const sourceParts = partsBinding(plan.parts, plan.flash_bytes), sourceApps = sourceParts.filter(part => part.type === 0);
  if (sourceApps.length !== 2 || bridgeOffsets.some(offset => !sourceApps.some(part => part.offset === offset && bridge.length <= part.size))) deny('bridge writes are not contained in the two original application slots.');
  const table = bytes(plan.targetTable, 'target partition table', 4096), targetHash = digest(plan.target_table_sha256, 'target partition table SHA-256');
  if (hash(table) !== targetHash) deny('target partition table bytes changed.');
  // Reuse the shared parser; the native planner owns canonical-layout math.
  const targetParts = partsBinding(partitionTable(table, plan.flash_bytes), plan.flash_bytes), targetApps = targetParts.filter(part => part.type === 0).sort((a, b) => a.subtype - b.subtype);
  if (targetApps.length !== 2 || targetApps[0].subtype !== 0x10 || targetApps[1].subtype !== 0x11 || targetApps[0].offset !== 0x10000 || targetApps.some(part => firmware.payloadBytes > part.size)) deny('target table does not contain two fitting reviewed OTA slots.');
  return {
    firmware, mac: deviceMac, flashBytes: plan.flash_bytes, board: label(plan.board, 'board'), target: label(plan.target, 'target'),
    bridgeHash, bridgeBytes: bridge.length, bridgeOffsets, sourceHash: digest(plan.source_table_sha256, 'source partition table SHA-256'), sourceParts,
    targetHash, targetTable: Array.from(table), targetParts, targetOffsets: targetApps.map(part => part.offset)
  };
}

// One memory-only approval binds both writes to one chip, package and reviewed
// migration. It cannot be serialized/reloaded to restore write authorization.
// EspSession still owns live chip checks, readback and reset permissions.
export class MigrationApproval {
  #phase = 'bridge-ready';
  #binding;
  #identity;
  #finalProof = null;

  constructor(pkg, plan, {identity = null} = {}) {
    this.#binding = freeze(initialBinding(pkg, plan));
    this.#identity = identityBinding(identity);
  }
  get phase() { return this.#phase; }
  get mac() { return this.#binding.mac; }
  get sha256() { return this.#binding.firmware.sha256; }
  get identity() { return this.#identity; }

  #transition(expected, next, validate) {
    try {
      if (this.#phase !== expected) deny(`expected ${expected}, not ${this.#phase}; approval cannot be replayed.`);
      validate?.();
      this.#phase = next;
      return this;
    } catch (error) {
      this.revoke();
      throw error;
    }
  }
  #initial(pkg, plan) {
    if (!same(initialBinding(pkg, plan), this.#binding)) deny('the originally approved bridge plan changed.');
  }
  #final(pkg, plan) {
    const binding = this.#binding, firmware = packageBinding(pkg, plan);
    if (!same(firmware, binding.firmware) || mac(plan.mac) !== binding.mac || plan.flash_bytes !== binding.flashBytes || plan.target !== binding.target || plan.verified !== true || plan.identity_restored !== true || plan.configuration_restored !== true) deny('expanded layout, restored identity, firmware or chip proof does not match the approval.');
    if (plan.device_mac != null && mac(plan.device_mac) !== binding.mac || plan.board != null && plan.board !== binding.board || plan.chip != null && plan.chip !== binding.firmware.chipId) deny('the final plan belongs to a different board or chip.');
    if (digest(plan.completed_bridge_sha256, 'completed bridge SHA-256') !== binding.bridgeHash || digest(plan.completed_source_table_sha256, 'completed source partition table SHA-256') !== binding.sourceHash || digest(plan.completed_target_table_sha256, 'completed target partition table SHA-256') !== binding.targetHash) deny('completion provenance does not match the approved bridge.');
    const expectedSegments = binding.bridgeOffsets.map(address => ({address, sourceOffset: 0, length: binding.bridgeBytes, payloadHash: binding.bridgeHash}));
    if (!Array.isArray(plan.completed_bridge_segments) || plan.completed_bridge_segments.length !== 2 || plan.completed_bridge_segments.some((segment, i) => !segment || segment.address !== expectedSegments[i].address || segment.sourceOffset !== 0 || segment.length !== binding.bridgeBytes || digest(segment.payloadHash, 'completed bridge segment SHA-256') !== binding.bridgeHash)) deny('completed bridge write geometry changed.');
    const parts = partsBinding(plan.parts, binding.flashBytes), addresses = offsets(plan.addresses, 'final write addresses', binding.flashBytes, firmware.payloadBytes);
    if (!same(parts, binding.targetParts) || !same(addresses, offsets(plan.app_offsets, 'final app offsets', binding.flashBytes, firmware.payloadBytes)) || !same([...addresses].sort((a, b) => a - b), [...binding.targetOffsets].sort((a, b) => a - b)) || addresses.at(-1) !== plan.active_offset) deny('final writes do not match the approved target table and active-last order.');
    return {firmware, mac: binding.mac, target: plan.target, flashBytes: plan.flash_bytes, parts, addresses, active: plan.active_offset, segments: expectedSegments, bridgeHash: binding.bridgeHash, sourceHash: binding.sourceHash, targetHash: binding.targetHash};
  }
  beginBridge(pkg, plan) { return this.#transition('bridge-ready', 'bridge-writing', () => this.#initial(pkg, plan)); }
  bridgeVerified(pkg, plan) { return this.#transition('bridge-writing', 'waiting-rom', () => this.#initial(pkg, plan)); }
  beginFinal(pkg, plan) { return this.#transition('waiting-rom', 'final-writing', () => { this.#finalProof = freeze(this.#final(pkg, plan)); }); }
  finalVerified(pkg, plan) { return this.#transition('final-writing', 'waiting-application', () => { if (!same(this.#final(pkg, plan), this.#finalProof)) deny('the verified final write plan changed.'); }); }
  complete() { return this.#transition('waiting-application', 'complete'); }
  revoke() { this.#phase = 'revoked'; }
}
