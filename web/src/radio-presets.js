import bundled from './data/radio-presets-fallback.json' with { type: 'json' };

export const radioPresetsUrl = 'https://api.meshcore.nz/api/v1/config';
const maximumBytes = 256 * 1024;
const bandwidths = new Set([7800,10400,15600,20800,31250,41700,62500,125000,250000,500000]);
const networkNote = 'Additional network settings are not changed.';
const reject = message => { throw new Error(message); };
const record = value => !!value && typeof value === 'object' && !Array.isArray(value);

function decimal(value, scale, label) {
  if (typeof value !== 'string' && typeof value !== 'number') reject(`Invalid ${label}.`);
  const text = String(value);
  if (!/^\d+(?:\.\d+)?$/.test(text) || text.length > 20) reject(`Invalid ${label}.`);
  const [whole, fraction = ''] = text.split('.'), places = scale === 1000 ? 3 : 0;
  if (/[^0]/.test(fraction.slice(places))) reject(`Invalid ${label} precision.`);
  const scaled = Number(whole) * scale + Number(fraction.slice(0, places).padEnd(places, '0'));
  if (!Number.isSafeInteger(scaled)) reject(`Invalid ${label} precision.`);
  return scaled;
}

function entry(value) {
  if (!record(value) || typeof value.title !== 'string') reject('Invalid preset entry.');
  const title = value.title.trim().replace(/ +/g, ' ');
  // Display-only text, never upstream HTML, links, descriptions or commands.
  if (!/^[\p{L}\p{N}][\p{L}\p{N} .,:;()/+&'_-]{0,79}$/u.test(title)) reject('Invalid preset title.');
  const frequencyKHz = decimal(value.frequency, 1000, 'frequency');
  const bandwidthHz = decimal(value.bandwidth, 1000, 'bandwidth');
  const spreadingFactor = decimal(value.spreading_factor, 1, 'spreading factor');
  const codingRate = decimal(value.coding_rate, 1, 'coding rate');
  if (frequencyKHz < 150000 || frequencyKHz > 2500000 || !bandwidths.has(bandwidthHz) ||
      spreadingFactor < 5 || spreadingFactor > 12 || codingRate < 5 || codingRate > 8) reject('Preset radio values are out of range.');
  const titleId = title.normalize('NFKC').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, '-').replace(/^-|-$/g, '');
  return Object.freeze({ id: `${titleId}-${frequencyKHz}-${bandwidthHz}-${spreadingFactor}-${codingRate}`, title,
    frequencyHz: frequencyKHz * 1000, bandwidthHz, spreadingFactor, codingRate,
    ...(Object.hasOwn(value, 'network_settings') ? { notes: networkNote } : {}) });
}

function parsed(json) {
  const entries = json?.config?.suggested_radio_settings?.entries;
  if (!Array.isArray(entries) || entries.length > 100) reject('Preset feed needs at most 100 entries.');
  const presets = [], ids = new Map(); let invalid = 0, duplicates = 0;
  for (const value of entries) {
    let preset; try { preset = entry(value); } catch { invalid++; continue; }
    if (ids.has(preset.id)) {
      duplicates++;
      const index = ids.get(preset.id);
      if (preset.notes && !presets[index].notes) presets[index] = Object.freeze({ ...presets[index], notes: networkNote });
      continue;
    }
    ids.set(preset.id, presets.length); presets.push(preset);
  }
  return { presets: Object.freeze(presets), invalid, duplicates };
}

/** Return only validated RF tuples. No region is guessed or selected, and no
 * network/path-hash, TX power, preamble, or device configuration is imported. */
export function parseRadioPresets(json) { return parsed(json).presets; }

async function boundedJson(response, signal) {
  if (!response?.ok || response.redirected || response.type === 'opaque' || response.url && response.url !== radioPresetsUrl)
    reject('Preset feed is unavailable.');
  const length = response.headers?.get('content-length');
  if (length && (!/^\d+$/.test(length) || Number(length) > maximumBytes)) reject('Preset feed is too large.');
  if (!response.body?.getReader) reject('Preset feed has no readable body.');
  const reader = response.body.getReader(), chunks = []; let size = 0, completed = false;
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener('abort', cancel, { once: true });
  try {
    for (;;) {
      if (signal.aborted) reject('Preset request cancelled.');
      const { value, done } = await reader.read();
      if (signal.aborted) reject('Preset request cancelled.');
      if (done) { completed = true; break; }
      if (!(value instanceof Uint8Array)) reject('Invalid preset response stream.');
      size += value.length; if (size > maximumBytes) reject('Preset feed is too large.'); chunks.push(value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } finally {
    signal.removeEventListener('abort', cancel);
    if (!completed) cancel();
    reader.releaseLock();
  }
}

/** Fetch one fixed public feed with no credentials, device data or redirects.
 * The bundled community snapshot remains usable offline or when CORS fails. */
export async function loadRadioPresets({ fetchImpl = globalThis.fetch, signal, timeoutMs = 5000 } = {}) {
  const fallback = () => parseRadioPresets(bundled);
  if (typeof fetchImpl !== 'function' || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000 ||
      signal != null && (typeof signal.aborted !== 'boolean' || typeof signal.addEventListener !== 'function' || typeof signal.removeEventListener !== 'function'))
    return { presets: fallback(), source: 'bundled', warning: 'Live presets are unavailable. Showing bundled community presets; Custom is still available.' };
  const controller = new AbortController(); let timer, onAbort;
  try {
    const stopped = new Promise((_, rejectStop) => {
      const stop = message => { controller.abort(); rejectStop(new Error(message)); };
      onAbort = () => stop('Preset request cancelled.');
      if (signal?.aborted) onAbort();
      else signal?.addEventListener('abort', onAbort, { once: true });
      timer = setTimeout(() => stop('Preset request timed out.'), timeoutMs);
    });
    const downloaded = (async () => {
      if (controller.signal.aborted) reject('Preset request cancelled.');
      const response = await fetchImpl(radioPresetsUrl, { method: 'GET', credentials: 'omit', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer', headers: { Accept: 'application/json' }, signal: controller.signal });
      const result = parsed(await boundedJson(response, controller.signal));
      if (!result.presets.length) reject('No valid presets are available.');
      const warnings = [];
      if (result.invalid) warnings.push(`${result.invalid} invalid preset ${result.invalid === 1 ? 'entry was' : 'entries were'} ignored.`);
      if (result.duplicates) warnings.push(`${result.duplicates} duplicate preset ${result.duplicates === 1 ? 'entry was' : 'entries were'} ignored.`);
      return { presets: result.presets, source: 'live', warning: warnings.join(' ') || null };
    })();
    return await Promise.race([downloaded, stopped]);
  } catch {
    return { presets: fallback(), source: 'bundled', warning: 'Live presets are unavailable. Showing bundled community presets; Custom is still available.' };
  } finally {
    clearTimeout(timer); if (onAbort) signal?.removeEventListener('abort', onAbort);
  }
}
