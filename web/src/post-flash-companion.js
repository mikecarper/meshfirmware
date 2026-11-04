// Older companions do not implement CMD_RUN_CLI_COMMAND (66). Expose only the
// primary-radio operations their versioned binary API can actually represent.
const unsupported = '> Error: unsupported setting';
const reject = message => { throw new Error(message); };
const signed = value => value > 127 ? value - 256 : value;
const hex = bytes => Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');

function radioTuple(frequency, bandwidth, sf, cr) {
  if (!Number.isInteger(frequency) || frequency < 150000 || frequency > 2500000 ||
      !Number.isInteger(bandwidth) || bandwidth < 7000 || bandwidth > 500000 ||
      !Number.isInteger(sf) || sf < 5 || sf > 12 ||
      !Number.isInteger(cr) || cr < 5 || cr > 8) reject('Invalid companion primary-radio parameters.');
  return { frequency, bandwidth, sf, cr };
}

// Decimal parsing avoids silently rounding a requested sub-kHz frequency into
// the older protocol's whole-kHz field (or a fractional Hz into whole Hz).
function scaledDecimal(value, description) {
  if (!/^\d+(?:\.\d+)?$/.test(value)) reject(`Invalid ${description}.`);
  const [whole, fraction = ''] = value.split('.');
  if (/[^0]/.test(fraction.slice(3))) reject(`${description} is too precise for this companion's binary API.`);
  const result = Number(whole) * 1000 + Number(fraction.slice(0, 3).padEnd(3, '0'));
  if (!Number.isSafeInteger(result)) reject(`Invalid ${description}.`);
  return result;
}

export function createPostFlashCompanionRequest(mc, device, { isCurrent = () => true } = {}) {
  if (!mc || !Number.isInteger(device?.protocol) || device.protocol < 1 || device.protocol > 255 ||
      typeof isCurrent !== 'function') reject('Verified companion protocol and session are required.');
  const guard = () => { if (isCurrent() === false) reject('The post-flash companion session changed.'); };
  if (device.protocol >= 14) {
    if (typeof mc.cli !== 'function') reject('Companion CLI is unavailable.');
    return async command => { guard(); const result = await mc.cli(command); guard(); return result; };
  }
  const publicKey = device.publicKey?.toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(publicKey || '') || typeof mc.self !== 'function' || typeof mc.request !== 'function')
    reject('The verified companion public key and binary API are required.');
  const protocol = device.protocol, expectedModel = device.model, expectedVersion = device.shortVersion || device.version;
  const readRepeat = async () => {
    if (protocol < 9) return null;
    if (typeof mc.info !== 'function') reject('DEVICE_INFO is required to preserve this companion\'s repeat setting.');
    guard(); const info = await mc.info(); guard();
    if (!(info instanceof Uint8Array) || info.length < 81 || info.length > 128 || info[0] !== 13 ||
        info[1] !== protocol || ![0, 1].includes(info[80])) reject('Invalid companion DEVICE_INFO repeat setting.');
    const decode = bytes => new TextDecoder('utf-8', { fatal: true }).decode(bytes).split('\0')[0];
    const model = decode(info.subarray(20, 60)), version = decode(info.subarray(60, 80));
    if (!model || !version || /[\x00-\x1f\x7f]/.test(model + version) ||
        expectedModel && model !== expectedModel || expectedVersion && version !== expectedVersion)
      reject('The companion model or firmware version changed before applying radio settings.');
    return info[80];
  };
  const readSelf = async () => {
    guard(); const self = await mc.self(); guard();
    if (!(self instanceof Uint8Array) || self.length < 58 || self.length > 90 || self[0] !== 5 || self[1] !== 1)
      reject('Invalid companion SELF_INFO response.');
    if (hex(self.subarray(4, 36)) !== publicKey) reject('The companion public key changed before applying radio settings.');
    const data = new DataView(self.buffer, self.byteOffset, self.byteLength);
    const radio = radioTuple(data.getUint32(48, true), data.getUint32(52, true), self[56], self[57]);
    const tx = signed(self[2]), maxTx = signed(self[3]);
    if (maxTx < -9 || maxTx > 40 || tx < -9 || tx > maxTx) reject('Invalid companion TX-power limits.');
    return { ...radio, tx, maxTx };
  };
  const write = async command => {
    guard(); const reply = await mc.request(command, 0); guard();
    if (!(reply instanceof Uint8Array) || reply.length !== 1 || reply[0] !== 0)
      reject('The companion did not acknowledge the radio setting.');
    return '> OK';
  };
  return async command => {
    guard();
    if (typeof command !== 'string' || /[\r\n\x00]/.test(command)) reject('Invalid post-flash companion command.');
    if (command === 'get radio') {
      const radio = await readSelf(); guard();
      return `> ${radio.frequency / 1000},${radio.bandwidth / 1000},${radio.sf},${radio.cr}`;
    }
    if (command === 'get tx') { const radio = await readSelf(); guard(); return `> ${radio.tx}`; }
    if (command.startsWith('set radio ')) {
      const values = command.slice(10).split(',').map(value => value.trim());
      if (values.length !== 4 || !/^\d+$/.test(values[2]) || !/^\d+$/.test(values[3]))
        reject('The legacy companion requires exactly frequency,bandwidth,SF,CR.');
      const radio = radioTuple(scaledDecimal(values[0], 'Frequency'), scaledDecimal(values[1], 'Bandwidth'), Number(values[2]), Number(values[3]));
      const repeat = await readRepeat(); guard();
      // SELF_INFO carries the identity; check it after DEVICE_INFO, immediately
      // before the write. The repeat extension is available starting at v9.
      await readSelf(); guard();
      const bytes = new Uint8Array(repeat === null ? 11 : 12), view = new DataView(bytes.buffer); bytes[0] = 11;
      view.setUint32(1, radio.frequency, true); view.setUint32(5, radio.bandwidth, true); bytes[9] = radio.sf; bytes[10] = radio.cr;
      if (repeat !== null) bytes[11] = repeat;
      const result = await write(bytes); guard(); return result;
    }
    if (command.startsWith('set tx ')) {
      const value = command.slice(7);
      if (!/^-?\d+$/.test(value) || !Number.isInteger(Number(value)) || Number(value) < -9 || Number(value) > 40)
        reject('TX power must be a whole number from -9 to 40 dBm.');
      const power = Number(value), radio = await readSelf(); guard();
      if (power > radio.maxTx) reject(`TX power exceeds this companion's ${radio.maxTx} dBm limit.`);
      const result = await write(Uint8Array.of(12, power & 255)); guard(); return result;
    }
    return unsupported;
  };
}
