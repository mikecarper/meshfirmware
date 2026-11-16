import { fail } from './firmware.js';
import { findRippleIdentity } from './ripple-identity.js';

const VID = 0x303a, PID = 0x1001;
const DRAM_START = 0x3fc88000, DRAM_SIZE = 0x78000;
const MAC_REGISTER = 0x60007044, MMU_TABLE = 0x600c5000;
const littleEndianBytes = words => {
  const bytes = new Uint8Array(words.length * 4), view = new DataView(bytes.buffer);
  words.forEach((word, index) => view.setUint32(index * 4, word, true));
  return bytes;
};

export function chooseRippleUsbDevice(usb = globalThis.navigator?.usb) {
  if (!usb?.requestDevice) fail('Ripple USB backup needs desktop Chrome or Edge with WebUSB. You can also back up files from its SD card.');
  // Ask only after a click. Shared USB IDs never identify a board; the exact
  // chosen serial is checked against the probe and the chip's factory MAC.
  return usb.requestDevice({ filters: [{ vendorId: VID, productId: PID }] });
}

export function rippleUsbSerial(device) {
  if (device?.vendorId !== VID || device?.productId !== PID || !/^(?:[a-f0-9]{2}:){5}[a-f0-9]{2}$/i.test(device.serialNumber || '')) fail('Choose Ripple on an ESP32-S3 with its built-in USB connection.');
  return device.serialNumber.toLowerCase();
}

const connectClient = async () => {
  const { Client, createLocalWorker } = await import('@probe-web/client');
  const worker = createLocalWorker({ log: 'off' });
  try { return await Client.connect({ kind: 'webusb', worker }); }
  catch (error) { worker.terminate(); throw error; }
};

// The debug library disables watchdogs on attach. A normal system restart
// is required afterward so firmware startup restores its runtime settings.
// No flash/erase operation is exposed. Restart before slow key/file work.
export async function captureRippleUsb(device, { connect = connectClient, progress = () => {} } = {}) {
  const serial = rippleUsbSerial(device);
  let client, session, memory, result, captureError, restartError;
  try {
    progress(0, 'Loading Ripple USB backup support');
    client = await connect();
    progress(.02, 'Connecting to the chosen Ripple device');
    const probes = (await client.listProbes()).filter(probe => probe.vendor_id === VID && probe.product_id === PID && probe.serial_number.toLowerCase() === serial);
    if (probes.length !== 1 || probes[0].inaccessible) fail('The chosen Ripple USB connection is unavailable. Close other tabs and device tools, then try again.');
    session = await client.attach({ probe: probes[0], chip: 'esp32s3', protocol: 'Jtag', connectUnderReset: false, allowEraseAll: false });
    progress(.04, 'Checking the Ripple chip identity');
    for (const index of [0, 1]) await session.core(index).halt(1000);
    const core = session.core(0);
    const mac = await core.readMemory32(MAC_REGISTER, 2);
    const actualMac = [mac[1] >>> 8, mac[1], mac[0] >>> 24, mac[0] >>> 16, mac[0] >>> 8, mac[0]].map(byte => (byte & 255).toString(16).padStart(2, '0')).join(':');
    if (actualMac !== serial) fail('The USB serial does not match the chip factory MAC. No backup was accepted.');
    progress(.06, 'Checking the running Ripple firmware');
    // Inspect only an already mapped flash page, without changing the MMU.
    // ESP32-S3 MMU bit 14 is invalid, bit 15 selects external RAM.
    const mmu = await core.readMemory32(MMU_TABLE, 256);
    // Instruction and data mappings share this table. A low virtual slot
    // can contain code from later in the image; the lowest physical page
    // contains the application's descriptor and initial read-only data.
    const mapped = Array.from(mmu, (entry, index) => ({ entry, index })).filter(({ entry }) => !(entry & 0xc000) && (entry & 0x3fff) > 0).sort((a, b) => (a.entry & 0x3fff) - (b.entry & 0x3fff));
    const firstFlash = mapped[0]?.index ?? -1;
    if (firstFlash < 0) fail('The running firmware has no readable application page. Start Ripple normally before backing up.');
    const page = littleEndianBytes(await core.readMemory32(0x3c000000 + firstFlash * 65536, 4096));
    const text = new TextDecoder('latin1').decode(page);
    const version = /Ripple[ \t]+v([0-9]+\.[0-9]+(?:\.[0-9]+)?)/.exec(text)?.[1];
    const environment = /\.pio\/libdeps\/([A-Za-z0-9_-]*(?:TPager|TDeck|TWatch|TDisplay)[A-Za-z0-9_-]*)\//.exec(text)?.[1];
    if (!version || !environment) fail('This USB device could not be verified as running supported Ripple firmware. No identity was exported.');
    progress(.15, 'Reading the loaded Ripple identity');
    memory = new Uint8Array(DRAM_SIZE);
    for (let offset = 0; offset < DRAM_SIZE; offset += 16384) {
      const length = Math.min(16384, DRAM_SIZE - offset);
      const block = littleEndianBytes(await core.readMemory32(DRAM_START + offset, length / 4));
      if (block.length !== length) fail('Ripple memory read was incomplete.');
      memory.set(block, offset);
      progress(.15 + .35 * (offset + length) / DRAM_SIZE, 'Reading the loaded Ripple identity');
    }
    result = { mac: serial, usbSerial: device.serialNumber, usbVendorId: VID, usbProductId: PID, chip: 'ESP32-S3', version: 'v' + version, environment, radio: /sx1262/i.test(environment) ? 'SX1262' : /lr1121/i.test(environment) ? 'LR1121' : null, storage: /(?:^|_)SD(?:_|$)/i.test(environment) ? 'sd-card' : 'internal-flash' };
  } catch (error) {
    captureError = error;
  } finally {
    if (session) {
      try {
        progress(.5, 'Restarting Ripple normally');
        // Release both debug stalls before the chip reset. A stalled second
        // core must not be carried into firmware startup on this SMP chip.
        await session.core(1).run();
        await session.core(0).run();
        await session.core(0).reset();
      } catch (error) {
        // A failed reset must not strand either core halted. Do not report a
        // completed backup with uncertain runtime recovery.
        for (const index of [0, 1]) try { await session.core(index).run(); } catch { /* The explicit restart instruction below covers this failure. */ }
        restartError = new Error('Ripple could not be restarted cleanly after reading. Restart the selected device before retrying backup, using it or flashing.');
        restartError.rippleRestartDetail = String(error?.message || error?.kind || error?.name || 'USB reset failed').replace(/[0-9a-f]{8,}/gi, '<redacted>').replace(/[^\x20-\x7e]/g, ' ').slice(0, 240);
      }
    }
    try { client?.close(); }
    catch { captureError ||= new Error('The Ripple USB connection could not be closed cleanly. Reconnect the device before continuing.'); }
  }
  try {
    if (restartError) throw restartError;
    if (captureError) throw captureError;
    const identity = await findRippleIdentity(memory, { progress: (fraction, message) => progress(.5 + fraction * .5, message) });
    progress(1, 'Ripple private key verified; device restarted normally');
    return { source: result, ...identity };
  } finally {
    // The general RAM snapshot is never exported, logged or retained.
    memory?.fill(0);
  }
}
