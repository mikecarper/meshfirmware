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

export function tuneCommand(notes, interval) {
  const parts = notes.trim().split(',').map(part => part.trim().split(':'));
  if (parts.length > 8 || parts.some(note => note.length !== 2)) throw Error('Enter up to eight frequency:duration pairs.');
  const parsed = parts.map(([hz, ms]) => {
    const frequency = hz === '0' ? hz : unsigned(hz, 200, 5000, 'a frequency in Hz');
    return frequency + ':' + unsigned(ms, 50, 1000, 'a duration in milliseconds');
  });
  return 'tune ' + unsigned(interval, 1, 3600, 'a repeat interval in seconds') + ' ' + parsed.join(',');
}

const clean = text => text.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '').replace(/\r/g, '\n').split('\n').map(s => s.trim()).filter(Boolean);
export async function readCollar(link) {
  const lines = clean(await link.command('pet status'));
  if (!lines.some(s => /^role=tracker-(sensor|companion)$/.test(s)) ||
      !lines.includes('pet_api=1')) throw Error('Select a combined RAK pet collar with hike and tune support.');
  return lines.filter(s => /^(role|id|radio_params|owner_radio)=/.test(s));
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

export function petPanel({$, operation, linkOperation, target, available, confirmChange}) {
  const value = id => $('pet-' + id).value.trim();
  const output = $('pet-result');
  const commands = {
    read: () => null,
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
  let current;
  const same = (a,b) => a && a.port === b.port && a.generation === b.generation;
  for (const [id, make] of Object.entries(commands)) {
    $('pet-' + id).onclick = () => operation(async () => {
      const selected = target();
      try {
        const cmd = make();
        if (id === 'fence-off' && !confirmChange('Clear the home boundary and its queued crossing alerts?')) return;
        if (id === 'forget' && !confirmChange('Forget owner phone ' + value('slot') + '? Removing the last phone also ends hike mode.')) return;
        const report = await linkOperation(async link => {
          const status = await readCollar(link);
          if (cmd) return ['Collar acknowledged: ' + cmd, ...await collarCommand(link, cmd)];
          for (const query of ['hike','phones','tune','fence','motion']) status.push(...await collarCommand(link, query));
          return status;
        });
        if (!same(selected,target())) throw Error('Selected collar changed. Read its settings again.');
        if (!cmd) {
          const get = pattern => report.map(s => s.match(pattern)).find(Boolean)?.[1];
          $('pet-timeout').value = get(/\btimeout_s=(\d+)/) || '';
          const repeat = get(/^repeat_s=(\d+)/);
          $('pet-repeat').value = repeat === '0' ? '' : repeat || '';
          $('pet-notes').value = report.filter(s => /^\d+:\d+$/.test(s)).join(',');
          $('pet-boundary').value = report.filter(s => /^-?\d+\.\d+ -?\d+\.\d+$/.test(s)).join('\n');
          $('pet-radius').value = get(/^radius_m=(\d+)/) || '100';
          $('pet-owner').value = get(/^owner_radio=([a-fA-F0-9]{64})$/) || '';
          $('pet-radio').value = (get(/^radio_params=(.+)$/) || '').replace(/\.0 /, ' ');
        }
        output.textContent = report.join('\n');
      } catch (error) { output.textContent = error.message; throw error; }
    }, {scrollNextStep:false});
  }
  return {controls() {
    const next = target();
    if (!same(current,next)) {
      output.textContent = next.port ? 'Read settings from the selected collar.' : "Choose the collar's USB port, then read its settings.";
      for (const [id, initial] of Object.entries({boundary:'', radius:'100', notes:'1568:175,0:100,1047:350',
        repeat:'30', timeout:'180', slot:'1', radio:'', owner:''})) $('pet-' + id).value = initial;
      current = next;
    }
    for (const id of Object.keys(commands)) $('pet-' + id).disabled = !available();
  }};
}
