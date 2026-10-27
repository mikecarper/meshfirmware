// Exercise the real Pyodide/Emscripten IDBFS backend, backed by the IndexedDB
// API implementation for Node. This is not a browser/hardware acceptance test.
import 'fake-indexeddb/auto';
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { loadPyodide } from 'pyodide';
import { createPlannerService } from '../src/planner-runtime.js';
import { hash } from '../src/firmware.js';

const sources = {};
for (const name of ['meshcore_partition_expansion.py', 'meshcore_backup.py']) sources[name] = new Uint8Array(await readFile(new URL('../../tools/' + name, import.meta.url)));
const manifest = JSON.stringify(Object.fromEntries(Object.entries(sources).map(([name, bytes]) => [name, hash(bytes)])));
function instance() {
  let runtime;
  const service = createPlannerService({
    loadRuntime: async () => runtime = await loadPyodide({ indexURL: fileURLToPath(new URL('../node_modules/pyodide/', import.meta.url)), stdout: () => {}, stderr: () => {} }),
    readValidator: async name => name === 'integrity.json' ? manifest : sources[name]
  });
  return { service, get runtime() { return runtime; } };
}
const openDatabase = () => new Promise((resolve, reject) => {
  const request = indexedDB.open('/work/cache');
  request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
});
const keys = db => new Promise((resolve, reject) => {
  const request = db.transaction('FILE_DATA', 'readonly').objectStore('FILE_DATA').getAllKeys();
  request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
});

test('started migration and public artifacts survive actual IDBFS sync into a fresh WASM runtime', async () => {
  const first = instance();
  await assert.rejects(first.service.call('validateBackup', { text: '{}' }), /archive schema or kind/);
  const py = first.runtime;
  py.FS.mkdirTree('/repo/tools'); py.FS.mkdirTree('/repo/tests');
  py.FS.writeFile('/repo/tools/meshcore_partition_expansion.py', sources['meshcore_partition_expansion.py']);
  py.FS.writeFile('/repo/tests/test_meshcore_partition_expansion.py', await readFile(new URL('../../tests/test_meshcore_partition_expansion.py', import.meta.url)));
  const fixture = JSON.parse(await py.runPythonAsync(`
import importlib.util
spec = importlib.util.spec_from_file_location('persistence_fixtures', '/repo/tests/test_meshcore_partition_expansion.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
image = fixtures.esp_image(0x140100)
json.dumps({'image': list(image), 'table': list(fixtures.table(fixtures.legacy_entries())), 'nvs': list(b'\\xff' * 0x5000), 'ota': list(b'\\xff' * 8192), 'package': list(fixtures.migration_archive(image))})
`));
  const data = Object.fromEntries(Object.entries(fixture).map(([name, value]) => [name, new Uint8Array(value)]));
  const mac = '01:23:45:67:89:ab';
  const planned = await first.service.call('plan', { ...data, name: 'full.bin', mac, chip: 'ESP32-S3', flashBytes: 16 << 20 });
  assert.equal((await first.service.call('begin')).started, true);
  // Read IndexedDB directly, rather than assuming an in-memory file is durable.
  const db = await openDatabase();
  const persistedKeys = await keys(db); db.close();
  assert.deepEqual(persistedKeys.filter(path => /\.(?:bin|json)$/.test(path)).sort(), [planned.plan_file, planned.bridge_file, planned.target_table_file].sort());
  assert.ok(!persistedKeys.some(path => /(?:^|\/)(?:nvs|ota|image|archive)\./.test(path)), 'raw snapshots and identity archives are never persisted');

  const second = instance();
  await assert.rejects(second.service.call('validateBackup', { text: '{}' }), /archive schema or kind/);
  assert.notEqual(second.runtime, first.runtime);
  assert.deepEqual(second.runtime.FS.readdir('/work/cache'), ['.', '..'], 'fresh WASM filesystem has no inherited cache');
  const recovered = await second.service.call('resumeBridge', { mac, sha256: hash(data.image), image: data.image });
  assert.equal(recovered.started, true); assert.equal(recovered.completed, false);
  assert.equal(recovered.device_mac, '0123456789AB');
  assert.equal(recovered.source_table_sha256, hash(data.table));
  assert.equal(hash(new Uint8Array(recovered.bridge)), planned.bridge_sha256);
  assert.deepEqual(recovered.bridge_offsets, planned.bridge_offsets);
  assert.equal(second.runtime.FS.analyzePath(planned.firmware_file).exists, false, 'final firmware remains memory-only after readback recovery');
});
