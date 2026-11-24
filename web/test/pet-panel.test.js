import assert from 'node:assert/strict';
import test from 'node:test';
import {boundaryCommand, tuneCommand, parseTuneNotes, installTunePreview, collarCommand, readCollar, petPanel} from '../src/pet-panel.js';

test('boundary and tune controls build one validated shell command', () => {
  assert.equal(boundaryCommand('47.5, -121.3','120'),'fence 47.5 -121.3 120');
  assert.equal(boundaryCommand('47 0\n48 1',''),'fence 47 0 48 1');
  assert.equal(boundaryCommand('47 0\n48 1\n47 1',''),'fence 47 0 48 1 47 1');
  assert.throws(()=>boundaryCommand('47 181','1'));
  assert.throws(()=>boundaryCommand('47 0\npet off','1'));
  assert.equal(tuneCommand('800:100, 0:50,1200:250','30'),'tune 30 800:100,0:50,1200:250');
  assert.throws(()=>tuneCommand('90:100','10'));
  assert.throws(()=>tuneCommand('800:1','10'));
  assert.throws(()=>tuneCommand('800:100\rpet off','10'));
});
test('requires role and feature version and positive shell acknowledgement', async () => {
  const link = reply => ({command:async()=>reply});
  assert.deepEqual(await readCollar(link('uart:~$ pet status\r\nrole=tracker-sensor\r\npet_api=1\r\n')),['role=tracker-sensor']);
  await assert.rejects(readCollar(link('role=tracker-companion\n')));
  await assert.rejects(collarCommand(link('uart:~$ pet tune play\r\n'),'tune play'));
  await assert.rejects(collarCommand(link('Mesh unavailable (-2)\r\nOK\r\n'),'hike on'),/required owner/);
  assert.deepEqual(await collarCommand(link('uart:~$ pet hike\r\nhike=off\r\n\x1b[32mOK\x1b[0m\r\n'),'hike'),['hike=off']);
});

test('browser preview plays draft notes with rests, can stop, and never needs USB', async () => {
  const elements = new Map(), $ = id => {
    if (!elements.has(id)) elements.set(id, { value: '', setAttribute(key, value) { this[key] = value; } });
    return elements.get(id);
  };
  const calls = [], created = [];
  installTunePreview($, () => {
    const oscillator = {
      connect() {}, frequency: { setValueAtTime: (...args) => calls.push(args) },
      start: t => calls.push(['start', t]), stop: t => calls.push(['stop', t]),
    };
    created.push(oscillator);
    return {
      currentTime: 10, resume: async () => {}, close: async () => calls.push(['closed']),
      createOscillator: () => oscillator,
      createGain: () => ({ connect() {}, gain: { setValueAtTime() {}, linearRampToValueAtTime() {} } }),
    };
  });
  const button = $('pet-tune-preview');
  $('pet-notes').value = '900:100,0:50,1200:200';
  assert.deepEqual(parseTuneNotes($('pet-notes').value), [[900,100],[0,50],[1200,200]]);
  await button.onclick();
  assert.equal(button['aria-label'], 'Stop tune preview');
  assert.deepEqual(calls.map(call => call[0]), [900, 1200, 'start', 'stop']);
  assert.ok(Math.abs(calls[1][1] - calls[0][1] - .15) < 1e-8);
  assert.ok(Math.abs(calls[3][1] - calls[2][1] - .35) < 1e-8);
  await button.onclick();
  assert.equal(button['aria-label'], 'Play tune preview');
  assert.deepEqual(calls.at(-1), ['closed']);
  await button.onclick();
  created[0].onended();
  assert.equal(button['aria-label'], 'Stop tune preview');
  created[1].onended();
  assert.equal(button['aria-label'], 'Play tune preview');
  $('pet-notes').value = '0:100';
  await button.onclick();
  assert.match($('pet-preview-status').textContent, /audible note/);
  assert.equal(created.length, 2);
});
test('flasher reads settings, enrolls selected slot and clears old device status', async () => {
  const els = new Map(), $ = id => { if (!els.has(id)) els.set(id,{value:'',textContent:''}); return els.get(id); };
  let generation = 1;
  const replies = {'pet status':'role=tracker-companion\npet_api=1\nradio_params=915000000 125.0 9 5\nowner_radio='+'ab'.repeat(32),'pet hike':'hike=on timeout_s=42 state=nearby','pet phones':'phone1=empty\nphone2=connected',
    'pet tune':'repeat_s=5 notes=2\n800:100\n0:50','pet fence':'fence=armed\n1.0000000 2.0000000\nradius_m=20','pet motion':'motion=on',
    'pet phone 1 enroll':'phone=1 code=123456 expires_s=120'};
  const link = {command:async cmd => {assert.ok(cmd in replies); return replies[cmd]+'\nOK\n';}};
  const panel = petPanel({$,operation:fn=>fn(),linkOperation:fn=>fn(link),target:()=>({port:1,generation}),available:()=>true});
  panel.controls(); await $('pet-read').onclick();
  assert.equal($('pet-radio').value,'915000000 125 9 5'); assert.equal($('pet-owner').value,'ab'.repeat(32));
  assert.equal($('pet-timeout').value,'42'); assert.equal($('pet-repeat').value,'5');
  assert.equal($('pet-notes').value,'800:100,0:50'); assert.equal($('pet-radius').value,'20');
  $('pet-slot').value='1'; await $('pet-enroll').onclick(); assert.match($('pet-result').textContent,/123456/);
  ++generation; panel.controls(); assert.doesNotMatch($('pet-result').textContent,/123456/);
});
