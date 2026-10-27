import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { loadPyodide } from 'pyodide';
import { hash } from '../src/firmware.js';
import { createPlannerService } from '../src/planner-runtime.js';
import { BrowserPlanner } from '../src/planner.js';
import { parseBackup, verifyBackup } from '../src/meshcore.js';

const sources = {};
for (const name of ['meshcore_partition_expansion.py', 'meshcore_backup.py']) sources[name] = new Uint8Array(await readFile(new URL('../../tools/' + name, import.meta.url)));
const manifest = JSON.stringify(Object.fromEntries(Object.entries(sources).map(([name, bytes]) => [name, hash(bytes)])));
let py;
const service = createPlannerService({
  persistent: false,
  loadRuntime: async () => py = await loadPyodide({ indexURL: fileURLToPath(new URL('../node_modules/pyodide/', import.meta.url)), stdout: () => {}, stderr: () => {} }),
  readValidator: async name => name === 'integrity.json' ? manifest : sources[name]
});

test('real WebAssembly runtime loads unchanged shared validators', async () => {
  await assert.rejects(service.call('validateBackup', { text: '{}' }), /archive schema or kind/);
  assert.ok(py.FS.filesystems.IDBFS, 'runtime includes durable browser filesystem backend');
  assert.equal(py.runPython('m.FORMAT'), 'meshcore-usb-partition-expansion-v2');
});

test('unchanged partition validator hermetic suite passes in WebAssembly', async () => {
  py.FS.mkdirTree('/repo/tools'); py.FS.mkdirTree('/repo/tests');
  py.FS.writeFile('/repo/tools/meshcore_partition_expansion.py', sources['meshcore_partition_expansion.py']);
  py.FS.writeFile('/repo/tests/test_meshcore_partition_expansion.py', await readFile(new URL('../../tests/test_meshcore_partition_expansion.py', import.meta.url)));
  const result = JSON.parse(await py.runPythonAsync(`
import unittest, io, importlib.util
spec = importlib.util.spec_from_file_location('wasm_partition_tests', '/repo/tests/test_meshcore_partition_expansion.py')
suite_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite_module)
suite = unittest.defaultTestLoader.loadTestsFromModule(suite_module)
def browser_cases(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from browser_cases(item)
        elif item._testMethodName != 'test_cli_failures_are_json_without_snapshot_secrets':
            yield item
stream = io.StringIO()
result = unittest.TextTestRunner(stream=stream).run(unittest.TestSuite(browser_cases(suite)))
json.dumps({'run': result.testsRun, 'errors': len(result.errors), 'failures': len(result.failures), 'output': stream.getvalue()})
`));
  assert.equal(result.errors, 0, result.output); assert.equal(result.failures, 0, result.output); assert.ok(result.run >= 60);
});

test('browser service plans fitting app, keeps snapshots volatile, rejects unsafe identities', async () => {
  const fixtures = JSON.parse(py.runPython(`json.dumps({'image': list(suite_module.esp_image(1024)), 'table': list(suite_module.table(suite_module.legacy_entries())), 'nvs': list(b'\\xff' * 0x5000), 'ota': list(b'\\xff' * 8192)})`));
  const data = Object.fromEntries(Object.entries(fixtures).map(([key, value]) => [key, new Uint8Array(value)]));
  const result = await service.call('plan', { ...data, name: '../../unsafe.bin', mac: 'aa:bb:cc:dd:ee:ff', flashBytes: 16 << 20, chip: 'ESP32-S3' });
  assert.equal(result.needed, false); assert.deepEqual(result.app_offsets, [0x150000, 0x10000]);
  for (const name of ['nvs.bin', 'ota.bin', 'table.bin']) assert.equal(py.FS.analyzePath('/work/' + name).exists, false);
  await assert.rejects(service.call('plan', { ...data, mac: '../../escape', flashBytes: 16 << 20, chip: 'ESP32-S3' }), /physical device MAC/);
});

test('browser service validates download inputs before accepting artifacts', async () => {
  await assert.rejects(service.call('download', { url: 'http://example.test/x', bytes: new Uint8Array(1) }), /public HTTPS/);
  await assert.rejects(service.call('download', { url: 'https://u:p@example.test/x', bytes: new Uint8Array(1) }), /public HTTPS/);
  await assert.rejects(service.call('download', { url: 'https://example.test/x', bytes: [] }), /32 MiB/);
});

test('browser service exact migration plan, begin and final proof work in WebAssembly', async () => {
  const fixtures = JSON.parse(py.runPython(`
_image = suite_module.esp_image(0x140100)
json.dumps({'image': list(_image), 'table': list(suite_module.table(suite_module.legacy_entries())), 'expanded': list(m.canonical_table(16 << 20)), 'nvs': list(suite_module.finished_nvs()), 'ota': list(b'\\xff' * 8192), 'package': list(suite_module.migration_archive(_image))})
`));
  const { expanded, ...data } = Object.fromEntries(Object.entries(fixtures).map(([key, value]) => [key, new Uint8Array(value)]));
  const binding = { name: 'heltec_v4_repeater-v1.17.1.9-halo-keymind-cascade-dev-88c85108.bin', mac: 'aa:bb:cc:dd:ee:ff', flashBytes: 16 << 20, chip: 'ESP32-S3' };
  const plan = await service.call('plan', { ...binding, ...data });
  assert.equal(plan.needed, true); assert.equal(plan.usb_safe, true); assert.equal(hash(new Uint8Array(plan.bridge)), plan.bridge_sha256);
  const begun = await service.call('begin'); assert.equal(begun.started, true);
  await assert.rejects(service.call('verify', { ...binding, ...data, table: expanded, mac: '00:11:22:33:44:55', sha256: hash(data.image) }), /Different device MAC/);
  const verified = await service.call('verify', { ...binding, ...data, table: expanded, sha256: hash(data.image) });
  assert.equal(verified.verified, true); assert.deepEqual(verified.app_offsets, [0x650000, 0x10000]);
  assert.equal(verified.completed_bridge_sha256,plan.bridge_sha256);
  assert.equal(verified.completed_source_table_sha256,hash(data.table));
  assert.equal(verified.completed_target_table_sha256,hash(expanded));
  assert.deepEqual(verified.completed_bridge_segments,plan.bridge_offsets.map(address=>({address,sourceOffset:0,length:plan.bridge_bytes,payloadHash:plan.bridge_sha256})));
  for (const directory of py.FS.readdir('/work/cache/AABBCCDDEEFF').filter(x => /^[a-f0-9]{64}$/.test(x))) {
    assert.deepEqual(py.FS.readdir('/work/cache/AABBCCDDEEFF/' + directory).sort(), ['.', '..', 'plan.json', 'target-partitions.bin', 'usb-bridge.bin'].sort());
  }
});

test('exact automatic resolver requests HTTPS artifacts and retries safely', async () => {
  const fixtures = JSON.parse(py.runPython(`
_image = suite_module.esp_image(0x140100)
json.dumps({'image': list(_image), 'table': list(suite_module.table(suite_module.legacy_entries())), 'nvs': list(b'\\xff' * 0x5000), 'ota': list(b'\\xff' * 8192), 'package': list(suite_module.migration_archive(_image))})
`));
  const { package: archive, ...data } = Object.fromEntries(Object.entries(fixtures).map(([key, value]) => [key, new Uint8Array(value)]));
  Object.assign(data, { name: 'heltec_v4_repeater-v1.17.1.9-halo-keymind-cascade-dev-88c85108.bin', mac: 'aa:bb:cc:dd:ee:00', flashBytes: 16 << 20, chip: 'ESP32-S3' });
  const tag = 'utility-v1.17.1.9-halo-keymind-cascade-dev-88c85108';
  const name = 'heltec-v4-v1.17.1.9-halo-keymind-cascade-dev-88c85108-migration.zip';
  const url = `https://github.com/mikecarper/MeshCore/releases/download/${tag}/${name}`;
  await assert.rejects(service.call('plan', data), error => error.download?.url === `https://api.github.com/repos/mikecarper/MeshCore/releases/tags/${tag}`);
  await service.call('download', { url: `https://api.github.com/repos/mikecarper/MeshCore/releases/tags/${tag}`, bytes: new TextEncoder().encode(JSON.stringify({ tag_name: tag, assets: [{ name, size: archive.length, browser_download_url: url }] })) });
  await assert.rejects(service.call('plan', data), error => error.download?.url === url);
  await service.call('download', { url, bytes: archive });
  assert.equal((await service.call('plan', data)).artifact, url);
});

test('Python backup import preserves canonical floating point integrity and proves private identity', async () => {
  py.FS.writeFile('/repo/tests/test_meshcore_backup.py', await readFile(new URL('../../tests/test_meshcore_backup.py', import.meta.url)));
  py.FS.writeFile('/repo/tools/meshcore_backup.py', sources['meshcore_backup.py']);
  const fixture = JSON.parse(await py.runPythonAsync(`
spec = importlib.util.spec_from_file_location('backup_fixtures', '/repo/tests/test_meshcore_backup.py')
backup_fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup_fixtures)
_fixture_backup = backup_fixtures.backup
_derive = _fixture_backup._derive_meshcore_public_key
try:
    _fixture_backup._derive_meshcore_public_key = lambda key: backup_fixtures.PUBLIC_KEY
    payload = await _fixture_backup.collect_companion(backup_fixtures.FakeClient(), backup_fixtures.MeshCoreBackupTests().make_request('/work/fixture'))
    fixture_text = json.dumps(_fixture_backup.make_archive(payload))
finally:
    _fixture_backup._derive_meshcore_public_key = _derive
json.dumps({'text': fixture_text, 'privateHex': backup_fixtures.PRIVATE_KEY, 'expectedPub': backup_fixtures.PUBLIC_KEY})
`));
  const validated = await service.call('validateBackup', fixture);
  assert.equal(validated.payload.source.node.public_key, fixture.expectedPub); assert.equal(validated.summary.safe_for_wipe, false);
  const converted = await parseBackup(fixture.text, { validatePython: data => service.call('validateBackup', data) });
  assert.equal(verifyBackup(converted).publicKey, fixture.expectedPub);
  assert.equal(py.runPython("'_archive_text' in globals() or '_private_hex' in globals()"), false);
  await assert.rejects(service.call('validateBackup', { ...fixture, expectedPub: '00'.repeat(32) }), /private\/public identity mismatch/);
  await assert.rejects(service.call('validateBackup', { ...fixture, text: fixture.text.replace('"max_channels": 2', '"max_channels": 3') }), /digest mismatch/);
});

test('unavailable durable storage blocks planning but not backup validation', async () => {
  const original = py.FS.filesystems.IDBFS;
  const withoutStorage = createPlannerService({ loadRuntime: async () => py, readValidator: async name => name === 'integrity.json' ? manifest : sources[name] });
  try {
    py.FS.filesystems.IDBFS = null;
    await assert.rejects(withoutStorage.call('plan', {}), /Persistent browser filesystem unavailable/);
    await assert.rejects(withoutStorage.call('validateBackup', { text: '{}' }), /archive schema or kind/);
  } finally { py.FS.filesystems.IDBFS = original; }
});

test('unfinished bridge recovery after reload binds original image, MAC, source table and offsets', async () => {
  const recoveryService = createPlannerService({ persistent: false, loadRuntime: async () => py, readValidator: async name => name === 'integrity.json' ? manifest : sources[name] });
  const fixtures = JSON.parse(py.runPython(`
_image = suite_module.esp_image(0x140100)
json.dumps({'image': list(_image), 'table': list(suite_module.table(suite_module.legacy_entries())), 'nvs': list(b'\\xff' * 0x5000), 'ota': list(b'\\xff' * 8192), 'package': list(suite_module.migration_archive(_image))})
`));
  const data = Object.fromEntries(Object.entries(fixtures).map(([key, value]) => [key, new Uint8Array(value)]));
  const mac = 'aa:bb:cc:dd:ee:01', sha256 = hash(data.image);
  const plan = await recoveryService.call('plan', { ...data, name: 'full.bin', mac, flashBytes: 16 << 20, chip: 'ESP32-S3' });
  await recoveryService.call('begin');
  const reloaded = createPlannerService({ persistent: false, loadRuntime: async () => py, readValidator: async name => name === 'integrity.json' ? manifest : sources[name] });
  await assert.rejects(reloaded.call('resumeBridge', { mac: 'aa:bb:cc:dd:ee:02', sha256, image: data.image }), /device MAC/);
  await assert.rejects(reloaded.call('resumeBridge', { mac, sha256: '00'.repeat(32), image: data.image }), /exact final firmware/);
  const other = data.image.slice(); other[100] ^= 1;
  await assert.rejects(reloaded.call('resumeBridge', { mac, sha256: hash(other), image: other }), /different firmware/);
  const resumed = await reloaded.call('resumeBridge', { mac, sha256, image: data.image });
  assert.equal(resumed.source_table_sha256, hash(data.table));
  assert.deepEqual(resumed.app_offsets, plan.bridge_offsets); assert.deepEqual(resumed.bridge_offsets, plan.bridge_offsets);
  assert.equal(hash(new Uint8Array(resumed.bridge)), plan.bridge_sha256);
  assert.equal(py.FS.analyzePath(plan.firmware_file).exists, false, 'final image remains volatile');
  const original = JSON.parse(new TextDecoder().decode(py.FS.readFile(plan.plan_file)));
  py.FS.writeFile(plan.plan_file, new TextEncoder().encode(JSON.stringify({ ...original, completed: true })));
  await assert.rejects(reloaded.call('resumeBridge', { mac, sha256, image: data.image }), /unfinished.*unavailable/);
});

test('worker failure and timeout reject pending calls instead of hanging', async () => {
  const worker = { postMessage() {}, terminate() { this.terminated = true; } };
  const planner = new BrowserPlanner({ worker, timeout: 1000 });
  const pending = planner.call('plan', {});
  worker.onerror({});
  await assert.rejects(pending, /failed to load or stopped/); assert.equal(worker.terminated, true);
  await assert.rejects(planner.call('plan', {}), /closed/);
  const timed = new BrowserPlanner({ worker: { postMessage() {}, terminate() {} }, timeout: 5 });
  await assert.rejects(timed.call('plan', {}), /timed out/);
});
