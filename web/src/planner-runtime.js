import { hash } from './firmware.js';
import { publicFromPrivate } from './meshcore.js';
import { hexToBytes } from '@noble/hashes/utils.js';

const MODULES = ['meshcore_partition_expansion.py', 'meshcore_backup.py'];
const MAX_IMAGE = 64 << 20;
const MAX_ARTIFACT = 32 << 20;
const MAC = /^(?:[\da-f]{2}:){5}[\da-f]{2}$/i;
const sync = (py, populate) => new Promise((resolve, reject) => py.FS.syncfs(populate, error => error ? reject(new Error('Browser migration storage could not be synchronized. No flash is authorized.')) : resolve()));

export function createPlannerService({ loadRuntime, readValidator, persistent = true } = {}) {
  let runtime, initialization, currentPlan, pendingDownload, persistentReady = false;
  const fetched = new Map();

  async function initialize() {
    if (runtime) return runtime;
    if (initialization) return initialization;
    initialization = (async () => {
      let py;
      if (loadRuntime) py = await loadRuntime();
      else {
        const indexURL = new URL('../python/', import.meta.url).href;
        const { loadPyodide } = await import(/* @vite-ignore */ indexURL + 'pyodide.mjs');
        py = await loadPyodide({ indexURL });
      }
      const manifestResponse = readValidator ? await readValidator('integrity.json') : await fetch(new URL('../validators/integrity.json', import.meta.url),{cache:'no-store'}).then(response => { if (!response.ok) throw new Error('Cannot load validator integrity manifest.'); return response.text(); });
      const manifest = JSON.parse(manifestResponse);
      if (Object.keys(manifest).sort().join(',') !== [...MODULES].sort().join(',')) throw new Error('Shared validator module list is invalid.');
      py.FS.mkdirTree('/validators'); py.FS.mkdirTree('/work/cache');
      for (const name of MODULES) {
        const bytes = readValidator ? await readValidator(name) : new Uint8Array(await fetch(new URL('../validators/' + name, import.meta.url),{cache:'no-store'}).then(response => { if (!response.ok) throw new Error('Cannot load shared validator.'); return response.arrayBuffer(); }));
        if (!/^[a-f0-9]{64}$/.test(manifest[name]) || hash(bytes) !== manifest[name]) throw new Error('Shared validator hash mismatch.');
        py.FS.writeFile('/validators/' + name, bytes);
      }
      await py.runPythonAsync(`import sys, json\nfrom pathlib import Path\nsys.path.insert(0, '/validators')\nimport meshcore_partition_expansion as m\nimport meshcore_backup as backup_validator\n`);
      const download = (url, limit) => {
        if (!fetched.has(url)) { pendingDownload = { url, limit }; throw new Error('Browser download required'); }
        const bytes = fetched.get(url);
        if (bytes.length > limit) throw new Error('Downloaded artifact exceeds validator limit.');
        return bytes;
      };
      py.globals.set('browser_download', download);
      await py.runPythonAsync(`def _browser_download(url, limit):\n    return bytes(browser_download(url, limit).to_py())\nm.download = _browser_download\n`);
      runtime = py;
      return py;
    })();
    try { return await initialization; } catch (error) { initialization = null; throw error; }
  }

  async function ensurePersistence(py) {
    if (persistentReady) return;
    if (persistent) {
      if (!py.FS.filesystems.IDBFS) throw new Error('Persistent browser filesystem unavailable; migration planning is disabled.');
      py.FS.mount(py.FS.filesystems.IDBFS, {}, '/work/cache');
      try { await sync(py, true); } catch (error) { try { py.FS.unmount('/work/cache'); } catch {} throw error; }
    }
    persistentReady = true;
  }

  function put(py, name, bytes, maximum = MAX_IMAGE) {
    if (!(bytes instanceof Uint8Array) || bytes.length > maximum) throw new Error('Invalid or oversized validator input: ' + name);
    py.FS.writeFile('/work/' + name, bytes);
  }
  function erase(py) {
    if (!py) return;
    for (const name of py.FS.readdir('/work').filter(name => !['.', '..', 'cache'].includes(name))) {
      try { py.FS.unlink('/work/' + name); } catch {}
    }
    // Snapshots and archive (including private identity) remain memory-only.
    py.runPython(`for _name in ('a', 'args_json', '_archive_text', '_backup_archive', '_backup_result', '_private_hex', '_expected_pub'):\n    globals().pop(_name, None)\n`);
  }

  return {
    async call(op, data = {}) {
      pendingDownload = null;
      try {
        if (op === 'download') {
          if (!(data.bytes instanceof Uint8Array) || data.bytes.length > MAX_ARTIFACT) throw new Error('Artifact exceeds 32 MiB.');
          const url = new URL(data.url);
          if (url.protocol !== 'https:' || url.username || url.password) throw new Error('Artifact URL must be public HTTPS.');
          if (!fetched.has(url.href) && fetched.size >= 5) throw new Error('Too many cached migration artifacts. Reload to clear them.');
          fetched.set(url.href, data.bytes); return true;
        }
        const py = await initialize();
        if (op === 'validateBackup' || op === 'sealBackup') {
          const archiveText=op==='sealBackup'?JSON.stringify(data.payload):data.text;
          if (typeof archiveText !== 'string' || new TextEncoder().encode(archiveText).length > (16 << 20)) throw new Error('Backup JSON exceeds 16 MiB.');
          let privateHex = '', expectedPub = '';
          if (data.privateHex != null) {
            if (typeof data.privateHex !== 'string' || !/^[a-f0-9]{128}$/i.test(data.privateHex) || typeof data.expectedPub !== 'string' || !/^[a-f0-9]{64}$/i.test(data.expectedPub)) throw new Error('Invalid backup identity.');
            privateHex = data.privateHex.toLowerCase(); expectedPub = publicFromPrivate(hexToBytes(privateHex));
            if (expectedPub !== data.expectedPub.toLowerCase()) throw new Error('Backup private/public identity mismatch.');
          }
          py.globals.set('_archive_text', archiveText); py.globals.set('_private_hex', privateHex); py.globals.set('_expected_pub', expectedPub);py.globals.set('_seal_archive',op==='sealBackup');
          const result = JSON.parse(await py.runPythonAsync(`
_backup_archive = backup_validator.make_archive(json.loads(_archive_text)) if _seal_archive else json.loads(_archive_text)
_original_derive = backup_validator._derive_meshcore_public_key
def _verified_browser_derive(value):
    if not _private_hex or value.lower() != _private_hex:
        raise ValueError('Unexpected private identity during browser validation')
    return _expected_pub
try:
    backup_validator._derive_meshcore_public_key = _verified_browser_derive
    _backup_result = backup_validator.validate_archive_data(_backup_archive)
finally:
    backup_validator._derive_meshcore_public_key = _original_derive
json.dumps({'summary': _backup_result, 'payload': _backup_archive['payload'], **({'archive': _backup_archive} if _seal_archive else {})})
`));
          erase(py); return result;
        }
        if (!['plan', 'begin', 'verify', 'resumeBridge'].includes(op)) throw new Error('Unknown validator operation.');
        await ensurePersistence(py);
        let result;
        if (op === 'resumeBridge') {
          if (typeof data.mac !== 'string' || !MAC.test(data.mac)) throw new Error('Invalid verified physical device MAC.');
          if (typeof data.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(data.sha256) || !(data.image instanceof Uint8Array) || data.image.length > MAX_IMAGE || hash(data.image) !== data.sha256) throw new Error('Original exact final firmware is required to recover the pending bridge.');
          const normalizedMac = data.mac.replace(/:/g, '').toUpperCase();
          const directory = '/work/cache/' + normalizedMac;
          if (!py.FS.analyzePath(directory).exists) throw new Error('No pending browser bridge plan exists for this device MAC.');
          const paths = py.FS.readdir(directory).filter(name => /^[a-f0-9]{64}$/.test(name)).map(name => directory + '/' + name + '/plan.json');
          const plans = paths.map(path => ({ path, plan: JSON.parse(new TextDecoder().decode(py.FS.readFile(path))) })).filter(({ plan }) => plan.started === true && plan.completed !== true);
          if (plans.length !== 1) throw new Error('Original unfinished browser bridge plan is unavailable or ambiguous.');
          const { path, plan } = plans[0];
          const planDirectory = directory + '/' + data.sha256;
          if (plan.firmware_sha256 !== data.sha256 || plan.device_mac !== normalizedMac) throw new Error('Pending bridge belongs to a different firmware or physical device MAC.');
          if (path !== planDirectory + '/plan.json' || plan.plan_file !== path || plan.bridge_file !== planDirectory + '/usb-bridge.bin' || plan.target_table_file !== planDirectory + '/target-partitions.bin' || !/^\/work\/[A-Za-z0-9_.-]{1,240}$/.test(plan.firmware_file)) throw new Error('Cached bridge artifact paths changed.');
          if (!/^[a-f0-9]{64}$/.test(plan.source_table_sha256) || !Array.isArray(plan.bridge_offsets) || plan.bridge_offsets.length !== 2 || new Set(plan.bridge_offsets).size !== 2 || !plan.bridge_offsets.includes(0x10000) || plan.bridge_offsets.some(offset => !Number.isInteger(offset) || offset < 0x10000 || offset % 0x1000 || offset + plan.bridge_bytes > plan.flash_bytes)) throw new Error('Cached original bridge geometry is invalid.');
          // Re-run the unchanged helper's complete artifact and USB qualification
          // checks. This only rewrites an already-started public cache marker;
          // it never touches the radio or authorizes a write to it.
          py.FS.writeFile(plan.firmware_file, data.image);
          py.globals.set('plan_path', path);
          py.runPython('m.begin_plan(Path(plan_path))');
          const bridge = py.FS.readFile(plan.bridge_file);
          if (hash(bridge) !== plan.bridge_sha256) throw new Error('Cached bridge SHA-256 changed.');
          currentPlan = plan;
          if (persistent) await sync(py, false);
          erase(py);
          return { ...plan, bridge: Array.from(bridge), app_offsets: [...plan.bridge_offsets] };
        }
        if (op === 'plan') { currentPlan = null; erase(py); }
        if (op === 'plan' || op === 'verify') {
          if (typeof data.mac !== 'string' || !MAC.test(data.mac)) throw new Error('Invalid verified physical device MAC.');
          put(py, 'image.bin', data.image); put(py, 'table.bin', data.table, 4096);
          if(op==='verify' || data.nvs!=null) put(py,'nvs.bin',data.nvs,1<<20);else {try{py.FS.unlink('/work/nvs.bin');}catch{}}
          if(op==='verify' || data.ota!=null) put(py,'ota.bin',data.ota,8192);else {try{py.FS.unlink('/work/ota.bin');}catch{}}
        }
        if (op === 'plan') {
          if (!Number.isInteger(data.flashBytes) || data.flashBytes < (256 << 10) || data.flashBytes > (128 << 20) || !/^ESP32(?:-[A-Z0-9]+)?$/.test(data.chip)) throw new Error('Invalid physical flash identification.');
          if (data.package) put(py, 'package.zip', data.package, MAX_ARTIFACT);
          if (data.usbSet) put(py, 'usb-set.zip', data.usbSet, MAX_ARTIFACT);
          // The shared validator obtains the exact release tag/source from the
          // filename. Preserve its content, but never allow a filesystem path.
          const filename = typeof data.name === 'string' ? data.name.replace(/[^A-Za-z0-9_.-]/g, '_').slice(-240) : 'image.bin';
          if (!filename || filename === '.' || filename === '..') throw new Error('Invalid firmware filename.');
          put(py, filename, data.image);
          if (filename !== 'image.bin') py.FS.unlink('/work/image.bin');
          const args = { image: '/work/' + filename, mac: data.mac, flash: data.flashBytes, chip: data.chip, package: data.package ? '/work/package.zip' : null, usbSet: data.usbSet ? '/work/usb-set.zip' : null,nvs:data.nvs!=null?'/work/nvs.bin':null,ota:data.ota!=null?'/work/ota.bin':null };
          py.globals.set('args_json', JSON.stringify(args));
          await py.runPythonAsync(`a = json.loads(args_json)\nPath('/work/flash.txt').write_text('Chip is ' + a['chip'] + '\\nDetected flash size: ' + str(a['flash'] // (1024*1024)) + 'MB\\n')\np = m.make_plan(Path(a['image']), Path('/work/table.bin'), Path('/work/flash.txt'), Path('/work/cache') / a['mac'].replace(':','').upper(), Path(a['package']) if a['package'] else None, Path(a['ota']) if a['ota'] else None, a['mac'], Path(a['nvs']) if a['nvs'] else None, Path(a['usbSet']) if a['usbSet'] else None)\n`);
          result = JSON.parse(py.runPython('json.dumps(p)')); currentPlan = result;
          if (result.needed) result = { ...result, bridge: Array.from(py.FS.readFile(result.bridge_file)), targetTable: Array.from(py.FS.readFile(result.target_table_file)) };
        } else if (op === 'begin') {
          if (!currentPlan?.needed || !currentPlan.plan_file) throw new Error('No verified migration plan.');
          if (!py.FS.analyzePath(currentPlan.firmware_file).exists) {
            if (!(data.image instanceof Uint8Array) || hash(data.image) !== currentPlan.firmware_sha256) throw new Error('Original final firmware is required before beginning migration.');
            py.FS.writeFile(currentPlan.firmware_file, data.image);
          }
          py.globals.set('plan_path', currentPlan.plan_file); result = JSON.parse(py.runPython('json.dumps(m.begin_plan(Path(plan_path)))'));
        } else {
          if (!currentPlan?.plan_file) {
            const directory = '/work/cache/' + data.mac.replace(/:/g, '').toUpperCase();
            const candidates = py.FS.readdir(directory).filter(n => /^[a-f0-9]{64}$/.test(n)).map(n => directory + '/' + n + '/plan.json');
            const plans = candidates.map(path => JSON.parse(new TextDecoder().decode(py.FS.readFile(path)))).filter(p => p.started && p.firmware_sha256 === data.sha256);
            if (plans.length !== 1) throw new Error('Original browser plan is unavailable or ambiguous. Do not write another image.');
            currentPlan = plans[0];
          }
          if (data.mac.replace(/:/g, '').toUpperCase() !== currentPlan.device_mac) throw new Error('Different device MAC after migration.');
          if (hash(data.image) !== currentPlan.firmware_sha256) throw new Error('Different final firmware after migration.');
          py.FS.writeFile(currentPlan.firmware_file, data.image);
          py.globals.set('plan_path', currentPlan.plan_file); result = JSON.parse(py.runPython(`json.dumps(m.verify_plan(Path(plan_path), Path('/work/table.bin'), Path('/work/nvs.bin'), Path('/work/ota.bin')))`));
          // Public provenance lets an interrupted bridge descriptor be
          // superseded only by completion of that exact cached bridge/geometry.
          result={...result,completed_bridge_sha256:currentPlan.bridge_sha256,completed_source_table_sha256:currentPlan.source_table_sha256,completed_target_table_sha256:currentPlan.target_table_sha256,completed_bridge_segments:currentPlan.bridge_offsets.map(address=>({address,sourceOffset:0,length:currentPlan.bridge_bytes,payloadHash:currentPlan.bridge_sha256}))};
        }
        // The started marker must be durable before authorizing any bridge write.
        if (persistent) await sync(py, false);
        // Keep final image in volatile memory for the next begin call only.
        for (const name of ['nvs.bin', 'ota.bin', 'table.bin', 'package.zip', 'usb-set.zip', 'flash.txt']) { try { py.FS.unlink('/work/' + name); } catch {} }
        return result;
      } catch (error) {
        erase(runtime);
        if (pendingDownload) error.download = pendingDownload;
        throw error;
      }
    }
  };
}
