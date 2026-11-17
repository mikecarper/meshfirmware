import { commonCliReplyState } from './common-cli.js';
import { createPostFlashSettingsPlan } from './post-flash-settings.js';

// Only these reviewed TAK CLI commands are generated. The caller owns the
// application/profile check, explicit approval, port and session lifetime.
const preparedPlans = new WeakMap();
const reject = message => { throw new Error(message); };
const decimal = value => {
  if (!/^(?:\d+(?:\.\d*)?|\.\d+)$/.test(value)) reject('Unrecognized radio response.');
  const number = Number(value);
  if (!Number.isFinite(number)) reject('Unrecognized radio response.');
  return number;
};
function radioTuple(text) {
  const fields = text.split(',');
  if (fields.length !== 4) reject('Wadamesh did not return a four-field radio tuple.');
  const [frequencyMHz, bandwidthKHz, spreadingFactor, codingRate] = fields.map(decimal);
  if (frequencyMHz < 150 || frequencyMHz > 2500 || bandwidthKHz < 7 || bandwidthKHz > 500 ||
      !Number.isInteger(spreadingFactor) || spreadingFactor < 5 || spreadingFactor > 12 ||
      !Number.isInteger(codingRate) || codingRate < 5 || codingRate > 8) reject('Wadamesh returned radio values outside the supported range.');
  return Object.freeze({ frequencyMHz, bandwidthKHz, spreadingFactor, codingRate,
    // The reviewed firmware trims trailing zeros from ftoa/ftoa3. The
    // current value's displayed digits are not the getter's precision.
    frequencyPlaces: Math.max(3,(fields[0].split('.')[1] || '').length), bandwidthPlaces: Math.max(3,(fields[1].split('.')[1] || '').length) });
}
function powerValue(text) {
  if (!/^-?\d+$/.test(text) || Number(text) < -9 || Number(text) > 40) reject('Wadamesh returned an invalid TX power.');
  return Number(text);
}
const formatted = (value, scale) => String(Number((value / scale).toFixed(6)));
const radioCommand = p => `set radio ${formatted(p.frequencyHz, 1e6)},${formatted(p.bandwidthHz, 1000)},${p.spreadingFactor},${p.codingRate}`;
const mediaCommand = m => m.preset === 'off' ? 'set radio2 off' : `set radio2 ${formatted(m.frequencyHz,1e6)},${formatted(m.bandwidthHz,1000)},${m.spreadingFactor},${m.codingRate},${m.mode},${m.preambleSymbols === 0 ? 'auto' : m.preambleSymbols}`;
const near = (actual, desired, places) => Math.abs(actual - Math.fround(desired)) <= Math.min(.0005, .5 * 10 ** -Math.min(9, places)) + 1e-7;
const representable = (value, places) => Math.abs(value - Number(value.toFixed(Math.min(9,places)))) <= .0005;
const matches = (actual, p) => near(actual.frequencyMHz, p.frequencyHz / 1e6, actual.frequencyPlaces) &&
  near(actual.bandwidthKHz, p.bandwidthHz / 1000, actual.bandwidthPlaces) && actual.spreadingFactor === p.spreadingFactor && actual.codingRate === p.codingRate;
const radioEqual = (a,b) => a.frequencyMHz === b.frequencyMHz && a.bandwidthKHz === b.bandwidthKHz && a.spreadingFactor === b.spreadingFactor && a.codingRate === b.codingRate;
const warning = value => /^(?:WARN (?:need >\d+:|recommended preamble:|radio2 overlaps radio1 \(6kHz guard\))[^\r\n]*|short override: (?:radio|radio2|radio,radio2)|switch=\d+us)$/.test(value);
function splitWarnings(text) {
  const [value, ...warnings] = text.split('; ');
  if (warnings.some(value => !warning(value))) reject('Radio2 has an active override or an unrecognized status; no settings were changed.');
  return { value, warnings };
}
function radio2Value(text) {
  if (/client repeat is on/i.test(text)) reject('Client Repeat currently controls radio2; no MediaMesh settings were changed.');
  const { value, warnings } = splitWarnings(text);
  if (value === 'off') return Object.freeze({ mode:'off', warnings:Object.freeze(warnings) });
  const match = /^([^,]+),([^,]+),(\d+),(\d+),(rx|rxtx),(\d+)( \(auto\))?$/.exec(value);
  if (!match) reject('Wadamesh did not return a recognized radio2 profile.');
  const tuple = radioTuple(match.slice(1,5).join(',')), effective = Number(match[6]);
  if (effective < 4 || effective > 65535) reject('Wadamesh returned an invalid radio2 preamble.');
  return Object.freeze({ ...tuple, mode:match[5], preambleSymbols:match[7]?0:effective, warnings:Object.freeze(warnings) });
}
function crossValue(text) { if (!['auto','on','off'].includes(text)) reject('Wadamesh returned an invalid radio2 crossing value.'); return text; }
const mediaMatches = (actual, m) => m.preset === 'off' ? actual.mode === 'off' :
  actual.mode === m.mode && actual.preambleSymbols === m.preambleSymbols && matches(actual,m);
const mediaEqual = (a,b) => a.mode === b.mode && (a.mode === 'off' || radioEqual(a,b) && a.preambleSymbols === b.preambleSymbols);
const UNSUPPORTED = Symbol('unsupported');

function adapter(request, isCurrent) {
  if (typeof request !== 'function' || typeof isCurrent !== 'function') reject('A verified Wadamesh application session is required.');
  const current = () => { if (isCurrent() !== true) reject('The application, selected port, or approved settings changed. No further commands were sent.'); };
  const ask = async (command, parse, {optional=false} = {}) => {
    current();
    let raw;
    try { raw = await request(command); } catch { current(); reject('The application did not answer the settings request.'); }
    current();
    const reply = commonCliReplyState(raw, command);
    if (reply.state === 'unsupported' && optional) return UNSUPPORTED;
    if (reply.state !== 'complete' || reply.text.includes('\n')) reject('The Wadamesh settings reply was unsupported or ambiguous.');
    return parse(reply.text);
  };
  return { current, ask };
}

async function mediaSnapshot(ask) {
  const radio = await ask('get radio2', radio2Value, {optional:true});
  const cross = await ask('get radio2.cross', crossValue, {optional:true});
  if (radio === UNSUPPORTED || cross === UNSUPPORTED) return null;
  // Off cancels saved schedules and an active temporary profile; never let a
  // generic radio change silently discard those user settings.
  const temporary = await ask('get tempradio2', value => value, {optional:true});
  const scheduled = await ask('get radioat2', value => value, {optional:true});
  const temporaryScheduled = await ask('get tempradioat2', value => value, {optional:true});
  if ([temporary,scheduled,temporaryScheduled].includes(UNSUPPORTED)) return null;
  if (temporary !== 'off' || scheduled !== 'slots:' || temporaryScheduled !== 'slots:') reject('A temporary or scheduled radio2 profile is active. Finish it before changing MediaMesh.');
  return Object.freeze({ radio, cross });
}

/** Prepare a reviewable, in-memory plan without changing device settings.
 * The selected firmware profile and physical session must be checked by caller. */
export async function prepareWadameshConfig(plan, { request, isCurrent, maxTxDbm } = {}) {
  if (!plan || plan.schema !== 'meshfirmware-post-flash-settings/v1') reject('Invalid Wadamesh settings plan.');
  const canonical = createPostFlashSettingsPlan({ primary: plan.primary, mediaMesh: plan.mediaMesh });
  const { current, ask } = adapter(request, isCurrent);
  const skipped = [], changes = [], warnings = [];
  const primary = canonical.primary;
  let radio = null, power = null, media = null;
  current();
  if (primary?.preambleSymbols !== null) {
    if (primary) skipped.push(Object.freeze({ section:'primary', reason:'This Wadamesh CLI does not support setting or verifying the selected primary preamble. Primary settings will not be changed.' }));
  } else if (primary) {
    if (primary.txPowerDbm !== null && (!Number.isInteger(maxTxDbm) || maxTxDbm < -9 || maxTxDbm > 40 || primary.txPowerDbm > maxTxDbm)) reject('Selected TX power exceeds the verified device limit or that limit is unavailable.');
    radio = await ask('get radio', radioTuple);
    if (!representable(primary.frequencyHz/1e6,radio.frequencyPlaces) || !representable(primary.bandwidthHz/1000,radio.bandwidthPlaces)) reject('The selected radio values are more precise than this firmware can report. No settings were changed.');
    if (primary.txPowerDbm !== null) power = await ask('get tx', powerValue);
    if (!matches(radio, primary)) changes.push(Object.freeze({ section:'primary', setting:'radio', before:radio, after:Object.freeze({frequencyHz:primary.frequencyHz,bandwidthHz:primary.bandwidthHz,spreadingFactor:primary.spreadingFactor,codingRate:primary.codingRate}), requiresReboot:true }));
    if (primary.txPowerDbm !== null && power !== primary.txPowerDbm) changes.push(Object.freeze({ section:'primary', setting:'tx', before:power, after:primary.txPowerDbm, requiresReboot:false }));
  }
  if (canonical.mediaMesh.preset !== 'unchanged' || canonical.mediaMesh.cross !== 'unchanged') {
    media = await mediaSnapshot(ask);
    if (!media) skipped.push(Object.freeze({section:'mediaMesh', reason:'This firmware cannot safely report all required MediaMesh state; MediaMesh settings will not be changed.'}));
    else {
      const m = canonical.mediaMesh;
      warnings.push('MediaMesh routing and region permissions are not changed; check the device settings if needed.');
      warnings.push(...media.radio.warnings);
      const radioChange=m.preset !== 'unchanged' && !mediaMatches(media.radio,m),crossChange=m.cross !== 'unchanged' && m.cross !== media.cross;
      const activeMedia=!['unchanged','off'].includes(m.preset),crossFirst=activeMedia&&m.cross==='off';
      // Turn crossing off and read it back before enabling or changing radio2.
      if (crossChange && crossFirst) changes.push(Object.freeze({section:'mediaMesh',setting:'cross',before:media.cross,after:m.cross,requiresReboot:false}));
      if (radioChange) changes.push(Object.freeze({section:'mediaMesh',setting:'radio2',before:media.radio,after:m,requiresReboot:false}));
      if (crossChange && !crossFirst) changes.push(Object.freeze({section:'mediaMesh',setting:'cross',before:media.cross,after:m.cross,requiresReboot:false}));
    }
  }
  if (changes.some(change => change.requiresReboot)) warnings.push('Radio settings require a manual reboot to take effect.');
  const result = Object.freeze({ schema:'meshfirmware-wadamesh-config/v1', summary:canonical.summary, changes:Object.freeze(changes), skipped:Object.freeze(skipped), warnings:Object.freeze(warnings) });
  preparedPlans.set(result, { canonical, radio, power, media, request, isCurrent, used:false });
  return result;
}

/** Apply a previously reviewed plan exactly once; no reset, reboot or retry. */
export async function applyWadameshConfig(prepared, { request, isCurrent } = {}) {
  const state = preparedPlans.get(prepared);
  if (!state || state.used || request !== state.request || isCurrent !== state.isCurrent) reject('The approved Wadamesh configuration plan or session is invalid.');
  state.used = true;
  const { current, ask } = adapter(request, isCurrent), p = state.canonical.primary;
  const result = { complete:false, applied:[], skipped:[...prepared.skipped], errors:[], writes:[], warnings:[...prepared.warnings], rebootRequired:false };
  let stage = 'preflight';
  try {
    current();
    if (state.radio) {
      const radio = await ask('get radio', radioTuple);
      if (!radioEqual(radio, state.radio)) reject('The radio settings changed after review. No settings were sent.');
      if (state.power !== null && await ask('get tx', powerValue) !== state.power) reject('The TX power changed after review. No settings were sent.');
    }
    if (state.media) {
      const media = await mediaSnapshot(ask);
      if (!media || !mediaEqual(media.radio,state.media.radio) || media.cross !== state.media.cross) reject('MediaMesh settings changed after review. No settings were sent.');
    }
    let mediaChecked = false;
    for (const change of prepared.changes) {
      if (change.section === 'mediaMesh' && !mediaChecked) {
        const media = await mediaSnapshot(ask);
        if (!media || !mediaEqual(media.radio,state.media.radio) || media.cross !== state.media.cross) reject('MediaMesh settings changed after review. No further settings were sent.');
        mediaChecked = true;
      }
      if (change.setting === 'tx' && await ask('get tx',powerValue) !== state.power) reject('TX power changed after review. No further settings were sent.');
      if (change.setting === 'radio2' && !['unchanged','off'].includes(state.canonical.mediaMesh.preset) && state.canonical.mediaMesh.cross==='off' && await ask('get radio2.cross',crossValue) !== 'off') reject('Radio crossing is not off. MediaMesh was not enabled; no further settings were sent.');
      stage = 'write'; current();
      const m = state.canonical.mediaMesh;
      const command = change.setting === 'radio' ? radioCommand(p) : change.setting === 'tx' ? `set tx ${p.txPowerDbm}` : change.setting === 'radio2' ? mediaCommand(m) : `set radio2.cross ${m.cross}`;
      const attempt = { section:change.section, setting:change.setting, sent:true, acknowledged:false };
      result.writes.push(attempt);
      // An uncertain or lost response can follow a successful write. Do not
      // claim that no reboot is needed merely because its ACK was lost.
      if (change.setting === 'radio') result.rebootRequired = true;
      await ask(command, text => {
        let parsed;
        if (change.setting === 'radio2' && m.preset !== 'off') {
          const match = /^(OK - radio2 (?:rx|rxtx); preamble=\d+)(.*)$/.exec(text);
          if (!match) reject('The firmware did not give the expected settings acknowledgement.');
          parsed = splitWarnings('ok' + match[2]);
        } else parsed = splitWarnings(text);
        if (change.setting === 'radio' ? parsed.value !== 'OK - reboot to apply' : change.setting === 'radio2' ? !(m.preset === 'off' ? parsed.value === 'OK - single radio' : parsed.value === 'ok') : parsed.value !== 'OK') reject('The firmware did not give the expected settings acknowledgement.');
        result.warnings ??= [];result.warnings.push(...parsed.warnings);
        return text;
      });
      attempt.acknowledged = true;
      stage = 'readback';
      const actual = change.setting === 'radio' ? await ask('get radio', radioTuple) : change.setting === 'tx' ? await ask('get tx', powerValue) : change.setting === 'radio2' ? await ask('get radio2',radio2Value) : await ask('get radio2.cross',crossValue);
      if (change.setting === 'radio' ? !matches(actual, p) : change.setting === 'tx' ? actual !== p.txPowerDbm : change.setting === 'radio2' ? !mediaMatches(actual,m) : actual !== m.cross) reject('Settings readback did not match; earlier changes may have been saved.');
      if (change.setting === 'radio2' && m.cross === 'unchanged' && await ask('get radio2.cross',crossValue) !== state.media.cross) reject('Radio2 crossing changed unexpectedly; earlier changes may have been saved.');
      if (change.setting === 'radio2' && !['unchanged','off'].includes(m.preset) && m.cross==='off' && await ask('get radio2.cross',crossValue) !== 'off') reject('Radio2 crossing is not off after the MediaMesh change; earlier changes may have been saved.');
      if (change.setting === 'radio2' && ['on','auto'].includes(m.cross) && !prepared.changes.some(row=>row.setting==='cross') && await ask('get radio2.cross',crossValue) !== m.cross) reject('Radio2 crossing changed unexpectedly; earlier changes may have been saved.');
      result.applied.push({ section:change.section, setting:change.setting, readbackMatched:true, pendingReboot:change.requiresReboot });
    }
    current();result.complete=result.skipped.length===0;
  } catch (error) {
    result.errors.push({ stage, reason:(error.message || 'Settings could not be applied; no further commands were sent.') + (result.writes.length ? ' One or more settings may already have changed; review the device before retrying.' : '') });
  }
  return result;
}
