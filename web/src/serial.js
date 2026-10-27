import { fail, sleep, words, crc16, hash, nrfMetadataHash } from './firmware.js';

export class SerialLink {
  constructor(port) { this.port = port; this.buffer = []; this.error = null; this.reader = null; this.readTask = null; }
  async open(baudRate = 115200) {
    this.buffer.length=0; this.error=null;
    await this.port.open({ baudRate, flowControl: 'none', bufferSize: 65536 });
    try { await this.port.setSignals({ dataTerminalReady: false, requestToSend: false }); }
    catch (e) { await this.port.close(); throw e; }
    this.reader = this.port.readable.getReader();
    this.readTask = (async () => { try { while (true) { const { value, done } = await this.reader.read(); if (done) { this.error=new Error('Serial device disconnected.'); break; } if (this.buffer.length + value.length > (1 << 20)) fail('Serial receive limit exceeded.'); for(const byte of value) this.buffer.push(byte); } } catch (e) { this.error = e; } finally { this.reader.releaseLock(); this.reader = null; } })();
  }
  async write(data) { const writer = this.port.writable.getWriter(); try { await writer.write(data); } finally { writer.releaseLock(); } }
  async read(ms = 500) { const until = Date.now() + ms; while (!this.buffer.length && !this.error && Date.now() < until) await sleep(10); if (this.error && !this.buffer.length) throw this.error; return Uint8Array.from(this.buffer.splice(0)); }
  async close() { if (this.reader) await this.reader.cancel().catch(() => {}); await this.readTask; await this.port.close().catch(() => {}); }
  async command(command, ms = 800) { this.buffer.length = 0; await this.write(new TextEncoder().encode(command + '\r\n')); await sleep(ms); return new TextDecoder().decode(await this.read(50)); }
}

export function slipEncode(data) { const out = [0xc0]; for (const b of data) out.push(...(b === 0xc0 ? [0xdb,0xdc] : b === 0xdb ? [0xdb,0xdd] : [b])); return Uint8Array.from([...out,0xc0]); }
export function slipDecode(data) { const out = []; for (let i = 0; i < data.length; i++) { let b = data[i]; if (b === 0xdb) { b = data[++i]; if (![0xdc,0xdd].includes(b)) fail('Invalid DFU SLIP escape.'); b = b === 0xdc ? 0xc0 : 0xdb; } out.push(b); } return Uint8Array.from(out); }
export function hciPacket(payload, sequence) {
  if(!Number.isInteger(sequence) || sequence<0 || sequence>7 || !payload.length || payload.length>4095) fail('Invalid DFU HCI payload length or sequence.');
  const header = [sequence | (((sequence + 1) & 7) << 3) | 0xc0, 0xe | ((payload.length & 15) << 4), payload.length >> 4, 0];
  header[3] = -(header[0] + header[1] + header[2]) & 255;
  const body = [...header,...payload], crc = crc16(body); return slipEncode([...body,crc & 255,crc >> 8]);
}
export function parseAck(frame) {
  if (frame.length < 4 || ((frame[0] + frame[1] + frame[2] + frame[3]) & 255) || (frame[1] & 15) || (frame[1] >> 4 | frame[2] << 4)) fail('Invalid DFU acknowledgement header.');
  const hasCrc = frame[0] & 0x40;
  if (frame.length !== 4 + (hasCrc ? 2 : 0) || (hasCrc && crc16(frame.subarray(0,4)) !== (frame[4] | frame[5] << 8))) fail('Invalid DFU acknowledgement CRC/length.');
  return (frame[0] >> 3) & 7;
}
export async function flashNrf(link, pkg, onProgress, {delay = sleep, now = Date.now} = {}) {
  if (hash(pkg.payload) !== pkg.payloadHash || hash(pkg.init) !== pkg.initHash || nrfMetadataHash(pkg)!==pkg.metadataHash) fail('DFU bytes or component metadata changed after validation.');
  let sequence = 0, receive = [];
  await link.port.setSignals({ dataTerminalReady: true, requestToSend: false });
  link.buffer.length = 0;
  async function send(payload) {
    sequence = (sequence + 1) & 7; const packet = hciPacket(payload, sequence);
    for (let attempt = 0; attempt < 3; attempt++) {
      await link.write(packet); const until = now() + 2000;
      while (now() < until) {
        receive.push(...await link.read(100)); if (receive.length > 4096) fail('DFU reply limit exceeded.');
        for (;;) {
          const start = receive.indexOf(0xc0); if (start < 0) { receive = []; break; }
          if (start > 0) receive.splice(0,start);
          const end = receive.indexOf(0xc0,1); if (end < 0) break;
          const escaped = receive.slice(1,end); receive.splice(0,end);
          if (escaped.length && parseAck(slipDecode(escaped)) === ((sequence + 1) & 7)) return;
        }
      }
    }
    fail(`DFU did not acknowledge packet ${sequence}. No reset will be attempted.`);
  }
  const pages = Math.ceil(pkg.payload.length / 4096) + 1, eraseWait = Math.min(30000,Math.max(500,Math.ceil(pages * 89.7)));
  onProgress(0,'Preparing DFU'); await send(words(3,pkg.mode,pkg.sdSize,pkg.blSize,pkg.appSize)); await delay(eraseWait);
  await send(Uint8Array.from([...words(1),...pkg.init,0,0]));
  await delay(205);
  for (let offset = 0; offset < pkg.payload.length; offset += 512) {
    const end = Math.min(offset + 512,pkg.payload.length); await send(Uint8Array.from([...words(4),...pkg.payload.subarray(offset,end)]));
    onProgress(end / pkg.payload.length * .95,'Writing DFU'); if ((offset / 512 + 1) % 8 === 0) await delay(205);
  }
  await delay(205); await send(words(5)); onProgress(.96,'Activating; keep power connected');
  await delay(eraseWait + Math.ceil(pages * 204.8)); onProgress(1,'DFU transfer completed. Application / installed bootloader remains unverified.');
}

// User gesture only. A re-enumerated port is never silently substituted.
export async function touch1200(port, kind) {
  try {
    await port.open({ baudRate: 1200 });
    if (kind === 'nrf52') {
      await port.setSignals({ dataTerminalReady: true, requestToSend: false }); await sleep(100);
      await port.setSignals({ dataTerminalReady: false, requestToSend: false });
    } else await sleep(100);
  } finally { await port.close().catch(() => {}); }
}
