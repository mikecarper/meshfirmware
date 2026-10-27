import { fail } from './firmware.js';

// Same public settled-status contract as tools/meshcore_partition_expansion.py.
// Never print the unrelated serial stream; it may contain private data.
export function migrationStatus(line, mac) {
  const prefix = 'MESHCORE_USB_MIGRATION_STATE ';
  if (!line.startsWith(prefix)) return null;
  let value; try { value = JSON.parse(line.slice(prefix.length)); } catch { return null; }
  if (!value || value.format !== 'meshcore-usb-partition-migration-v1') return null;
  const expected = mac.replace(/[:-]/g,'').toUpperCase();
  if (!/^[0-9A-F]{12}$/.test(expected)) fail('Invalid migration chip identity.');
  if (typeof value.device_mac !== 'string' || value.device_mac.toUpperCase() !== expected) fail('Migration bridge reported a different chip MAC. No reset or final write allowed.');
  return value.settled === true && typeof value.restored === 'boolean' ? {settled:true,restored:value.restored,device_mac:expected} : null;
}

export async function waitForMigration(link, mac, timeout = 180000, now = Date.now) {
  if (!(timeout > 0 && timeout <= 600000)) fail('Invalid migration wait timeout.');
  const end = now() + timeout; let pending = '';
  while (now() < end) {
    for (const byte of await link.read(Math.min(500, Math.max(1,end-now())))) {
      if (byte === 10) {
        const result = migrationStatus(pending.replace(/\r$/,''),mac); pending = '';
        if (result) return result;
      } else if (pending.length < 4096) pending += String.fromCharCode(byte);
      else pending = '';
    }
  }
  fail('Migration has not reported settled state. Keep power connected. No ROM reset or final write is allowed; wait again.');
}
