function unsigned(value, min, max, label) {
  if (!/^\d+$/.test(value) || +value < min || +value > max) throw Error(`Enter ${label} from ${min} to ${max}.`);
  return String(+value);
}

export function boundaryCommand(text, radius) {
  const points = text.trim().split(/\n+/).map(line => line.trim().split(/[ ,\t]+/));
  if (points.length > 9 || points.some(pair => pair.length !== 2)) throw Error('Enter one latitude and longitude per line, up to nine points.');
  for (const pair of points) {
    pair.forEach((value, i) => {
      if (!/^-?\d{1,3}(?:\.\d{1,7})?$/.test(value) || Math.abs(+value) > (i ? 180 : 90))
        throw Error('Enter decimal coordinates with up to seven decimal places.');
    });
  }
  const args = points.flat();
  if (points.length === 1) args.push(unsigned(radius, 1, 4294967295, 'a radius in meters'));
  return 'fence ' + args.join(' ');
}

export function parseTuneNotes(notes) {
  const parts = notes.trim().split(',').map(part => part.trim().split(':'));
  if (parts.length > 8 || parts.some(note => note.length !== 2)) throw Error('Enter up to eight frequency:duration pairs.');
  return parts.map(([hz, ms]) => {
    const frequency = hz === '0' ? hz : unsigned(hz, 200, 5000, 'a frequency in Hz');
    return [+frequency, +unsigned(ms, 50, 1000, 'a duration in milliseconds')];
  });
}

export function tuneCommand(notes, interval) {
  const parsed = parseTuneNotes(notes);
  return 'tune ' + unsigned(interval, 1, 3600, 'a repeat interval in seconds') + ' ' + parsed.map(note => note.join(':')).join(',');
}

export function scheduleTunePreview(audio, notes, ended) {
  const oscillator = audio.createOscillator();
  const gain = audio.createGain();
  oscillator.connect(gain);
  gain.connect(audio.destination);
  const start = audio.currentTime + 0.02;
  let at = start;
  gain.gain.value = 0;
  for (const [hz, ms] of notes) {
    const end = at + ms / 1000;
    if (hz) {
      oscillator.frequency.setValueAtTime(hz, at);
      gain.gain.setValueAtTime(0, at);
      gain.gain.linearRampToValueAtTime(0.12, at + 0.005);
      gain.gain.setValueAtTime(0.12, end - 0.005);
      gain.gain.linearRampToValueAtTime(0, end);
    }
    at = end;
  }
  oscillator.onended = ended;
  oscillator.start(start);
  oscillator.stop(at);
}

export function installTunePreview($, createAudio = () => {
  const Audio = globalThis.AudioContext ?? globalThis.webkitAudioContext;
  if (!Audio) throw Error('Audio preview is unavailable in this browser.');
  return new Audio();
}) {
  const button = $('pet-tune-preview'), status = $('pet-preview-status');
  let playing = null;
  function show(active) {
    const label = active ? 'Stop tune preview' : 'Play tune preview';
    button.setAttribute('aria-label', label);
    button.title = label;
    $('pet-preview-icon').textContent = active ? '\u25a0' : '\u25b6';
    $('pet-preview-label').textContent = active ? 'Stop preview' : 'Preview notes';
  }
  function finish(audio) {
    if (playing !== audio) return;
    playing = null;
    show(false);
    void audio.close().catch(() => {});
  }
  button.onclick = async () => {
    if (playing) { finish(playing); return; }
    status.hidden = true;
    let audio;
    try {
      const notes = parseTuneNotes($('pet-notes').value);
      if (!notes.some(([hz]) => hz)) throw Error('Add at least one audible note to preview.');
      audio = playing = createAudio();
      show(true);
      await audio.resume();
      if (playing === audio) scheduleTunePreview(audio, notes, () => finish(audio));
    } catch (error) {
      if (audio && playing !== audio) return;
      if (audio) finish(audio);
      status.textContent = error.message || 'Audio preview failed.';
      status.hidden = false;
    }
  };
}

const clean = text => text.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '').replace(/\r/g, '\n').split('\n').map(s => s.trim()).filter(Boolean);
function collarStatus(reply) {
  const lines = clean(reply);
  return lines.some(s => /^role=tracker-(sensor|companion)$/.test(s)) && lines.includes('pet_api=1')
    ? lines.filter(s => /^(role|id|radio_params|owner_radio)=/.test(s)) : null;
}
export async function readCollar(link) {
  const status = collarStatus(await link.command('pet status'));
  if (!status) throw Error('This firmware does not expose full collar controls. Read tracker settings again.');
  return status;
}
export async function collarCommand(link, command) {
  if (!/^[a-zA-Z0-9 .,:-]+$/.test(command) || command.length > 245) throw Error('Invalid pet command.');
  const lines = clean(await link.command('pet ' + command));
  const error = lines.find(s => /Mesh unavailable|unknown command/i.test(s));
  if (error || !lines.includes('OK')) {
    const reasons = {'-2':'Set the required owner first.', '-16':'Pause tracking and wait for the current radio exchange to finish.', '-17':'That slot is already enrolled.', '-19':'Check the collar radio settings and owner public key.', '-22':'Check the values you entered.'};
    throw Error((error || 'No acknowledgement from the collar.') + ' ' + (reasons[error?.match(/\((-\d+)\)/)?.[1]] || ''));
  }
  return lines.filter(s => !s.includes('pet ' + command) && !s.endsWith('>') && !s.endsWith('~$') && s !== 'OK');
}

const trackerLines = text => clean(text).map(line => line.replace(/^->\s*/, ''));
const trackerKey = /^[a-f\d]{64}$/i;
const trackerPath = /^path=(unknown|direct|saved) hops=(\d{1,2}) hash\.bytes=([0-3])$/;
async function readTrackerStatus(link) {
  const pattern = /^mode=(pet|off) status=(yes|no|unknown) interval=(\d{2,5}) lost\.interval=(\d{2,5}) flood=(locked|6h) clock=(ok|fault) storage=(ok|fault)$/;
  const match = trackerLines(await link.command('get tracker status')).map(line => line.match(pattern)).find(Boolean);
  if (!match || [+match[3], +match[4]].some(n => n < 60 || n > 86400))
    throw Error('This firmware did not report pet tracker settings. Use a supported Sensor or combined tracker build.');
  const [, mode, lost, interval, lostInterval, flood, clock, storage] = match;
  return {mode, lost, interval, lostInterval, flood, clock, storage};
}
async function readTrackerDetails(link, status) {
  const owner = trackerLines(await link.command('get tracker.owner')).find(line => trackerKey.test(line));
  const path = trackerLines(await link.command('get tracker.path')).map(line => line.match(trackerPath)).find(Boolean);
  if (!owner || !path) throw Error('The tracker did not return its owner and route settings.');
  return {...status, owner: /^0+$/.test(owner) ? '' : owner, path: path[1],
    hops: Number(path[2]), hashBytes: Number(path[3])};
}
export function trackerRoute(input) {
  const route = input.toLowerCase().trim();
  if (route === 'direct' || route === 'clear') return route;
  const hops = route.split(',').map(hop => hop.trim());
  const size = hops[0].length;
  if (![2,4,6].includes(size) || hops.length > 63 || hops.length * size > 128 ||
      hops.some(hop => hop.length !== size || !/^[a-f0-9]+$/.test(hop)))
    throw Error('Enter direct, clear, or comma-separated 1-, 2-, or 3-byte hex prefixes of the same length.');
  const normalized = hops.join(',');
  // Leave room for the CR in the Sensor's 160-byte console line buffer.
  if (('set tracker.path ' + normalized).length > 157)
    throw Error('That route is too long for the tracker’s USB console. Enter fewer repeaters.');
  return normalized;
}

function matchesTrackerWrite(tracker, cmd) {
  const setting = cmd.split(' ')[1];
  const value = cmd.split(' ').at(-1);
  switch (setting) {
    case 'tracker.owner': return tracker.owner.toLowerCase() === value.toLowerCase();
    case 'tracker.interval': return tracker.interval === value;
    case 'tracker.lost.interval': return tracker.lostInterval === value;
    case 'tracker.mode': return tracker.mode === value;
    case 'tracker.path': {
      if (value === 'direct' || value === 'clear') return tracker.path === (value === 'clear' ? 'unknown' : 'direct');
      const hops = value.split(',');
      return tracker.path === 'saved' && tracker.hops === hops.length && tracker.hashBytes === hops[0].length / 2;
    }
    default: return false;
  }
}

export function petPanel({$, operation, linkOperation, target, available, confirmChange}) {
  installTunePreview($);
  const value = id => $('pet-' + id).value.trim();
  const output = $('pet-result');
  const collarCommands = {
    'fence-save': () => boundaryCommand(value('boundary'), value('radius')),
    'fence-off': () => 'fence off',
    'tune-save': () => tuneCommand(value('notes'), value('repeat')),
    'tune-play': () => 'tune play', 'tune-off': () => 'tune off',
    'timeout-save': () => 'hike timeout ' + unsigned(value('timeout'), 1, 3600, 'a timeout in seconds'),
    'hike-on': () => 'hike on', 'hike-off': () => 'hike off',
    enroll: () => 'phone ' + unsigned(value('slot'),1,2,'a phone slot') + ' enroll',
    forget: () => 'phone ' + unsigned(value('slot'),1,2,'a phone slot') + ' forget',
    'radio-save': () => {
      const words = value('radio').split(/\s+/);
      if (words.length !== 4 || !['62.5','125','250','500'].includes(words[1])) throw Error('Enter Hz, bandwidth (62.5, 125, 250 or 500), SF and CR.');
      const [hz,bw,sf,cr] = words;
      return ['radio',unsigned(hz,150000000,960000000,'a frequency'),bw,unsigned(sf,7,12,'a spreading factor'),unsigned(cr,5,8,'a coding rate')].join(' ');
    },
    'owner-save': () => {
      const key = value('owner');
      if (!/^[a-fA-F0-9]{64}$/.test(key)) throw Error('Enter the owner radio public key (64 hex characters).');
      return 'owner ' + key;
    },
    on: () => 'on', off: () => 'off', 'motion-on': () => 'motion on', 'motion-off': () => 'motion off',
  };
  const trackerCommands = {
    'owner-save': () => {
      const key = value('sensor-owner');
      if (!trackerKey.test(key) || /^0+$/.test(key)) throw Error('Enter the owner radio public key (64 hex characters).');
      return 'set tracker.owner ' + key;
    },
    'path-save': () => 'set tracker.path ' + trackerRoute(value('sensor-path')),
    'interval-save': () => 'set tracker.interval ' + unsigned(value('sensor-interval'),60,86400,'a normal interval in seconds'),
    'lost-save': () => 'set tracker.lost.interval ' + unsigned(value('sensor-lost'),60,86400,'a lost interval in seconds'),
    on: () => 'set tracker.mode pet', off: () => 'set tracker.mode off', check: () => 'tracker check',
  };
  let current;
  let kind;
  let tracker;
  const same = (a,b) => a && a.port === b.port && a.generation === b.generation;
  function render() {
    $('pet-sensor-controls').hidden = kind !== 'sensor';
    for (const section of ['fence','tune','hike','phones','radio']) $('pet-collar-' + section).hidden = kind !== 'collar';
    $('pet-tune-title').textContent = kind === 'collar' ? 'Return-home tune' : 'Return-home tune preview';
    const ready = available();
    $('pet-read').disabled = !ready;
    for (const id of Object.keys(collarCommands)) $('pet-' + id).disabled = !ready || kind !== 'collar';
    for (const id of Object.keys(trackerCommands)) {
      $('pet-sensor-' + id).disabled = !ready || kind !== 'sensor' || tracker?.storage !== 'ok'
        || (id === 'check' && tracker.mode !== 'pet') || (id === 'on' && (!tracker.owner || tracker.mode === 'pet'))
        || (id === 'off' && tracker.mode !== 'pet');
    }
  }
  function run(action) {
    return operation(async () => {
      const selected = target();
      const verify = () => {
        if (!selected.port || !same(selected,target())) throw Error('Selected tracker changed. Read its settings again.');
      };
      const withLink = fn => linkOperation(link => fn({async command(text) {
        verify();
        const reply = await link.command(text);
        verify();
        return reply;
      }}));
      try {
        verify();
        await action(withLink, verify);
      } catch (error) {
        if (same(selected,target())) output.textContent = error.message;
        throw error;
      } finally { render(); }
    }, {scrollNextStep:false});
  }
  function showTracker(result, message, field) {
    tracker = result;
    if (!field || field === 'owner-save') $('pet-sensor-owner').value = tracker.owner;
    if (!field || field === 'interval-save') $('pet-sensor-interval').value = tracker.interval;
    if (!field || field === 'lost-save') $('pet-sensor-lost').value = tracker.lostInterval;
    if (!field || field === 'path-save') $('pet-sensor-path').value = '';
    $('pet-sensor-path-current').textContent = tracker.path === 'saved'
      ? `Current route: ${tracker.hops} repeater hop(s)` : 'Current route: ' + tracker.path;
    const lost = {yes:'lost', no:'not lost', unknown:'no confirmed status'}[tracker.lost];
    output.textContent = [message, 'Tracking: ' + (tracker.mode === 'pet' ? 'on' : 'paused'),
      'Owner reply: ' + lost, 'Clock: ' + tracker.clock, 'Storage: ' + tracker.storage,
      tracker.flood === 'locked' && 'Flood fallback: locked'].filter(Boolean).join('\n');
  }

  $('pet-read').onclick = () => run(async (withLink, verify) => {
    kind = undefined;
    tracker = undefined;
    const result = await withLink(async link => {
      const status = collarStatus(await link.command('pet status'));
      if (!status) return {tracker: await readTrackerDetails(link, await readTrackerStatus(link))};
      for (const query of ['hike','phones','tune','fence','motion']) status.push(...await collarCommand(link, query));
      return {collar: status};
    });
    verify();
    if (result.tracker) {
      kind = 'sensor';
      showTracker(result.tracker);
    } else {
      kind = 'collar';
      const report = result.collar;
      const get = pattern => report.map(s => s.match(pattern)).find(Boolean)?.[1];
      $('pet-timeout').value = get(/\btimeout_s=(\d+)/) || '';
      const repeat = get(/^repeat_s=(\d+)/);
      $('pet-repeat').value = repeat === '0' ? '' : repeat || '';
      $('pet-notes').value = report.filter(s => /^\d+:\d+$/.test(s)).join(',');
      $('pet-boundary').value = report.filter(s => /^-?\d+\.\d+ -?\d+\.\d+$/.test(s)).join('\n');
      $('pet-radius').value = get(/^radius_m=(\d+)/) || '100';
      $('pet-owner').value = get(/^owner_radio=([a-fA-F0-9]{64})$/) || '';
      $('pet-radio').value = (get(/^radio_params=(.+)$/) || '').replace(/\.0 /, ' ');
      output.textContent = report.join('\n');
    }
  });
  for (const [id, make] of Object.entries(collarCommands)) {
    $('pet-' + id).onclick = () => run(async (withLink, verify) => {
      if (kind !== 'collar') throw Error('Read settings from a full collar first.');
      const cmd = make();
      if (id === 'fence-off' && !confirmChange('Clear the home boundary and its queued crossing alerts?')) return;
      if (id === 'forget' && !confirmChange('Forget owner phone ' + value('slot') + '? Removing the last phone also ends hike mode.')) return;
      const report = await withLink(async link => {
        await readCollar(link);
        return await collarCommand(link, cmd);
      });
      verify();
      output.textContent = ['Collar acknowledged: ' + cmd, ...report].join('\n');
    });
  }
  for (const [id, make] of Object.entries(trackerCommands)) {
    $('pet-sensor-' + id).onclick = () => run(async (withLink, verify) => {
      if (kind !== 'sensor' || tracker?.storage !== 'ok') throw Error('Read settings from a tracker with working storage first.');
      const cmd = make();
      let acknowledged = false;
      let result;
      try {
        result = await withLink(async link => {
          const status = await readTrackerStatus(link);
          if (status.storage !== 'ok') {
            tracker = {...tracker, ...status};
            throw Error('Tracker storage is not writable.');
          }
          const lines = trackerLines(await link.command(cmd));
          const error = lines.find(line => line.startsWith('ERR:'));
          if (error || !lines.includes(id === 'check' ? 'OK scheduled' : 'OK'))
            throw Error(error || 'No acknowledgement from the tracker. Read its settings before retrying.');
          acknowledged = true;
          return id === 'check' ? {...tracker, ...status} : await readTrackerDetails(link, await readTrackerStatus(link));
        });
      } catch (error) {
        if (acknowledged) {
          kind = undefined;
          throw Error('Tracker acknowledged the command, but readback failed. Read its settings again.');
        }
        throw error;
      }
      verify();
      if (id !== 'check' && (result.storage !== 'ok' || !matchesTrackerWrite(result, cmd))) {
        showTracker(result, '', id);
        throw Error('The tracker did not report the requested setting after saving. Review its settings before retrying.');
      }
      showTracker(result, id === 'check' ? 'GPS check-in scheduled.' : 'Tracker settings saved.', id);
    });
  }
  return {controls() {
    const next = target();
    if (!same(current,next)) {
      kind = undefined;
      tracker = undefined;
      output.textContent = next.port ? 'Read settings from the selected tracker.' : "Choose the tracker's USB port, then read its settings.";
      for (const [id, initial] of Object.entries({boundary:'', radius:'100', notes:'1568:175,0:100,1047:350',
        repeat:'30', timeout:'180', slot:'1', radio:'', owner:'', 'sensor-path':'', 'sensor-owner':'',
        'sensor-interval':'', 'sensor-lost':''})) $('pet-' + id).value = initial;
      current = next;
    }
    render();
  }};
}
