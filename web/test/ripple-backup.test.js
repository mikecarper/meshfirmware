import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { unzipSync } from 'fflate';
import { sealBackup, verifyBackup, parseBackup, backupSummary } from '../src/meshcore.js';
import { backupCoverage } from '../src/backup-coverage.js';
import { expandedPublicKey, findRippleIdentity } from '../src/ripple-identity.js';
import { captureRippleUsb, chooseRippleUsbDevice } from '../src/ripple-usb.js';
import { ripplePayload, validateRipplePayload, addRippleSdFiles, rippleSavedFilesZip, restoreRippleIdentity, wadameshIdentityImport } from '../src/ripple-backup.js';

function identity(value = 7) {
  const key = sha512(new Uint8Array(32).fill(value));
  key[0] &= 248; key[31] &= 63; key[31] |= 64;
  return { privateKey: bytesToHex(key), publicKey: bytesToHex(expandedPublicKey(key)) };
}
const enc = value => new TextEncoder().encode(value);
const keyFile = id => Uint8Array.from([...hexToBytes(id.publicKey), ...hexToBytes(id.privateKey)]);
const file = (path, bytes) => ({ name: path.split('/').at(-1), webkitRelativePath: path, size: bytes.length, arrayBuffer: async () => bytes.slice().buffer });
const usbDevice = () => ({ vendorId: 0x303a, productId: 0x1001, serialNumber: '00:11:22:33:44:55' });
const source = () => ({ mac: '00:11:22:33:44:55', usbSerial: '00:11:22:33:44:55', usbVendorId: 0x303a, usbProductId: 0x1001, chip: 'ESP32-S3', version: 'v8.3', environment: 'TPager_GeoQwerty_sx1262_SD', radio: 'SX1262', storage: 'sd-card' });
const payload = (id = identity()) => ripplePayload({ ...id, source: source() });

test('finds the expanded key with a derived matching public key in both storage layouts', async () => {
  const id = identity();
  for (const [offset, bytes] of [[16, keyFile(id)], [0, Uint8Array.from([...hexToBytes(id.privateKey), ...hexToBytes(id.publicKey)])]]) {
    const memory = new Uint8Array(offset + bytes.length); memory.set(bytes, offset);
    assert.deepEqual(await findRippleIdentity(memory), id);
  }
});
test('rejects plausible scalars without matching public keys, deduplicates copies and refuses different identities', async () => {
  const a = identity(), b = identity(9);
  await assert.rejects(findRippleIdentity(hexToBytes(a.privateKey)), /No verified/);
  assert.deepEqual(await findRippleIdentity(Uint8Array.from([...keyFile(a), ...keyFile(a)])), a);
  await assert.rejects(findRippleIdentity(Uint8Array.from([...keyFile(a), ...keyFile(b)])), /Several different/);
  await assert.rejects(findRippleIdentity(new Uint8Array(0x78004)), /Invalid Ripple memory/);
});
test('SD identity scanning supports a file header without assuming a RAM address or alignment', async () => {
  const id = identity(), bytes = Uint8Array.from([1, ...keyFile(id)]);
  assert.deepEqual(await findRippleIdentity(bytes, { alignment: 1 }), id);
});
test('Ripple archives round trip with honest coverage and reject recomputed-checksum key mismatches', async () => {
  const p = payload(), archive = sealBackup(p);
  assert.deepEqual(verifyBackup(await parseBackup(JSON.stringify(archive))), p);
  assert.equal(backupSummary(archive).privateIdentity, true);
  assert.equal(backupSummary(archive).safeForWipe, false);
  assert.match(backupCoverage(archive).notIncludedText, /Saved contacts, channels and preferences/);
  const bad = structuredClone(p); bad.publicKey = identity(9).publicKey;
  assert.throws(() => verifyBackup(sealBackup(bad)), /identity verification/);
  assert.throws(() => verifyBackup({ ...archive, sha256: '0'.repeat(64) }), /SHA-256/);
  for (const change of [q => q.source.mac = 'aa:bb:cc:dd:ee:ff', q => q.safeForWipe = true, q => q.source.environment = '<script>']) {
    const q = structuredClone(p); change(q); assert.throws(() => verifyBackup(sealBackup(q)));
  }
});
test('SD folder backup preserves original bytes, verifies identity and exports safe original paths', async () => {
  const id = identity(), prefs = enc('original version-specific preferences');
  const p = await addRippleSdFiles([file('SDCARD/ripple/identity/_main.id', keyFile(id)), file('SDCARD/ripple/prefs.bin', prefs), file('SDCARD/ripple/trk/walk.trk', enc('track')), file('SDCARD/maps/tile.png', enc('map'))]);
  assert.equal(p.publicKey, id.publicKey); assert.equal(p.source.method, 'sd-files');
  assert.equal(p.files.length, 2); assert.equal(p.filesExcluded, 2);
  const unpacked = unzipSync(rippleSavedFilesZip(p));
  assert.deepEqual(unpacked['ripple/prefs.bin'], prefs);
  assert.deepEqual(unpacked['ripple/identity/_main.id'], keyFile(id));
  assert.equal(backupCoverage(sealBackup(p)).included.some(label => label.includes('original Ripple SD files')), true);
});
test('adding SD files never silently substitutes a USB key or an unrelated card', async () => {
  const p = payload(), other = identity(9);
  await assert.rejects(addRippleSdFiles([file('ripple/other.id', keyFile(other))], p), /do not match/);
  const saved = await addRippleSdFiles([file('ripple/main.id', keyFile(p)), file('ripple/other.id', keyFile(other))], p);
  assert.equal(saved.privateKey, p.privateKey); assert.equal(saved.source.mac, p.source.mac);
  await assert.rejects(addRippleSdFiles([file('ripple/main.id', keyFile(p)), file('ripple/other.id', keyFile(other))]), /Several different SD identities/);
  await assert.rejects(addRippleSdFiles([file('ripple/prefs.bin', enc('no key'))]), /No verified private key/);
});
test('SD import rejects traversal, FAT path collisions, oversized files and archive file corruption', async () => {
  const p = payload();
  for (const path of ['ripple/../key', 'ripple/a\\key', 'ripple/C:/key', 'ripple/con.txt', 'ripple/a./key']) await assert.rejects(addRippleSdFiles([file(path, enc('x'))], p));
  await assert.rejects(addRippleSdFiles([file('ripple/Prefs', enc('a')), file('ripple/prefs', enc('b'))], p), /Duplicate/);
  await assert.rejects(addRippleSdFiles([{ ...file('ripple/large.bin', new Uint8Array()), size: (1 << 20) + 1 }], p), /limited to/);
  const good = await addRippleSdFiles([file('ripple/prefs.bin', enc('prefs'))], p);
  for (const mutate of [q => q.files[0].data = 'bm90LXByZWZz', q => q.files[0].path = '../outside', q => q.files[0].size++, q => q.files[0].data += '\n']) {
    const q = structuredClone(good); mutate(q); assert.throws(() => validateRipplePayload(q));
  }
});

function fakeProbe({ macMismatch = false, wrongFirmware = false, failRead = false, failResume = false, failReset = false, failAttach = false } = {}) {
  const id = identity(), calls = [], memory = new Uint8Array(0x78000);
  memory.set(keyFile(id), 0x1000);
  const mmu = new Uint32Array(256).fill(0x4000); mmu[0] = 6; mmu[9] = 1;
  const page = new Uint8Array(65536); page.set(enc(wrongFirmware ? 'other firmware' : 'Ripple   v8.3  \0.pio/libdeps/TPager_GeoQwerty_sx1262_SD/SensorLib/'));
  const cores = [0, 1].map(index => ({
    halt: async () => { calls.push('halt' + index); },
    run: async () => { calls.push('run' + index); if (failResume && index === 0) throw Error('resume failed'); },
    reset: async () => { calls.push('reset' + index); if (failReset) throw Error('reset failed'); },
    readMemory32: async address => {
      calls.push('read32:' + address.toString(16));
      if (address === 0x60007044) return new Uint32Array([0x22334455, macMismatch ? 0x1234 : 0x0011]);
      if (address === 0x600c5000) return mmu;
      if (address === 0x3c090000) return new Uint32Array(page.slice(0, 16384).buffer);
      if (failRead) throw Error('device disconnected');
      const bytes = memory.slice(address - 0x3fc88000, address - 0x3fc88000 + 16384);
      return new Uint32Array(bytes.buffer);
    },
    readMemory8: async (address, count) => {
      calls.push('read8:' + address.toString(16));
      if (address === 0x3c090000) return page;
      if (failRead) throw Error('device disconnected');
      return memory.slice(address - 0x3fc88000, address - 0x3fc88000 + count);
    },
  }));
  const client = {
    listProbes: async () => [{ vendor_id: 0x303a, product_id: 0x1001, serial_number: '00:11:22:33:44:55', inaccessible: false }],
    attach: async options => { calls.push('attach'); assert.equal(options.allowEraseAll, false); assert.equal(options.connectUnderReset, false); assert.equal(options.chip, 'esp32s3'); if (failAttach) throw Error('attach failed'); return { core: index => cores[index] }; },
    close: () => { calls.push('close'); },
  };
  return { calls, client, id };
}
test('USB backup chooses only built-in USB and never enumerates or opens devices before a click', async () => {
  let options;
  assert.equal(await chooseRippleUsbDevice({ requestDevice: async value => { options = value; return 'chosen'; } }), 'chosen');
  assert.deepEqual(options, { filters: [{ vendorId: 0x303a, productId: 0x1001 }] });
  assert.throws(() => chooseRippleUsbDevice({}), /Chrome or Edge/);
});
test('USB capture verifies factory MAC and Ripple, reads bounded memory and restarts normally to restore watchdogs', async () => {
  const { calls, client, id } = fakeProbe();
  const result = await captureRippleUsb(usbDevice(), { connect: async () => client });
  assert.equal(result.privateKey, id.privateKey); assert.equal(result.source.radio, 'SX1262');
  assert.equal(result.source.storage, 'sd-card'); assert.equal(result.source.version, 'v8.3');
  assert.deepEqual(calls.slice(-4), ['run1', 'run0', 'reset0', 'close']);
  assert.equal(calls.filter(call => call.startsWith('read32:3fc')).length, 30);
});
test('USB failures restore normal startup or resume both cores as fallback and never claim success after failed restart', async () => {
  for (const settings of [{ macMismatch: true }, { wrongFirmware: true }, { failRead: true }, { failReset: true }, { failReset: true, failResume: true }, { failAttach: true }]) {
    const { calls, client } = fakeProbe(settings);
    await assert.rejects(captureRippleUsb(usbDevice(), { connect: async () => client }));
    assert.equal(calls.at(-1), 'close');
    if (!settings.failAttach) {
      if (settings.failReset) assert.deepEqual(calls.slice(-3), ['run0', 'run1', 'close']);
      else assert.deepEqual(calls.slice(-4), ['run1', 'run0', 'reset0', 'close']);
    }
    if (settings.macMismatch || settings.wrongFirmware) assert.equal(calls.some(call => call.startsWith('read32:3fc')), false);
  }
});
test('a missing or ambiguous chosen USB serial never attaches another board', async () => {
  let attached = false, closed = false;
  const client = { listProbes: async () => [], attach: async () => { attached = true; }, close: () => { closed = true; } };
  await assert.rejects(captureRippleUsb(usbDevice(), { connect: async () => client }), /unavailable/);
  assert.equal(attached, false); assert.equal(closed, true);
});

const selfInfo = id => { const frame = new Uint8Array(62); frame.set([5, 1]); frame.set(hexToBytes(id.publicKey), 4); return frame; };
test('Ripple identity restore uses the MeshCore/Wadamesh import command and verifies the resulting public key', async () => {
  const p = payload(), calls = []; let active = identity(9);
  const api = { self: async () => selfInfo(active), request: async (command, response) => { calls.push(command); assert.equal(response, 0); active = p; } };
  await assert.rejects(restoreRippleIdentity(api, p), /Explicitly replace/); assert.equal(calls.length, 0);
  assert.equal((await restoreRippleIdentity(api, p, { replaceIdentity: true })).identityChanged, true);
  assert.equal(calls.length, 1); assert.equal(calls[0][0], 24); assert.equal(bytesToHex(calls[0].subarray(1)), p.privateKey);
  assert.equal((await restoreRippleIdentity(api, p)).identityChanged, false); assert.equal(calls.length, 1);
});
test('restore refuses unsupported roles, stale selections, corrupt identities and failed post-import verification', async () => {
  const p = payload(); let writes = 0;
  const api = { self: async () => selfInfo(identity(9)), request: async () => { writes++; } };
  await assert.rejects(restoreRippleIdentity(api, p, { replaceIdentity: true, assertCurrent: () => { throw Error('selection changed'); } }), /selection changed/);
  assert.equal(writes, 0);
  await assert.rejects(restoreRippleIdentity({ ...api, self: async () => new Uint8Array([5, 2]) }, p, { replaceIdentity: true }), /companion/); assert.equal(writes, 0);
  await assert.rejects(restoreRippleIdentity(api, { ...p, publicKey: identity(9).publicKey }, { replaceIdentity: true }), /identity verification/); assert.equal(writes, 0);
  await assert.rejects(restoreRippleIdentity(api, p, { replaceIdentity: true }), /did not verify/); assert.equal(writes, 1);
});

test('Wadamesh native identity file supplies its exact import fields without empty settings inventories', () => {
  const p = payload(), native = wadameshIdentityImport(p);
  assert.deepEqual(native, { public_key: p.publicKey, private_key: p.privateKey });
  for (const omitted of ['name', 'channels', 'contacts', 'radio_settings', 'position_settings']) assert.equal(Object.hasOwn(native, omitted), false);
  assert.throws(() => wadameshIdentityImport({ ...p, privateKey: identity(9).privateKey }), /identity verification/);
});
