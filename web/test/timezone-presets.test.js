import test from 'node:test';
import assert from 'node:assert/strict';
import { timezonePresetSuggestions, browserTimezonePresetSuggestions } from '../src/timezone-presets.js';

const usa={id:'usa',title:'USA'},socal={id:'socal',title:'USA - Southern California'},canada={id:'canada',title:'Canada'};
test('Pacific timezone offers both broad and local possibilities without making a geographic choice',()=>{
  assert.deepEqual(timezonePresetSuggestions([usa,socal,canada],'America/Los_Angeles'),[usa,socal]);
  assert.deepEqual(timezonePresetSuggestions([usa,socal,canada],'America/New_York'),[usa]);
  assert.deepEqual(timezonePresetSuggestions([usa,socal,canada],'America/Vancouver'),[canada]);
});
test('unknown or imprecise timezone and absent or ambiguous feed entries produce no guessed preset',()=>{
  assert.deepEqual(timezonePresetSuggestions([usa,socal],'PST'),[]);
  assert.deepEqual(timezonePresetSuggestions([usa,socal],'Etc/GMT+8'),[]);
  assert.deepEqual(timezonePresetSuggestions([usa,{...usa,id:'other'},socal],'America/Los_Angeles'),[socal]);
  assert.deepEqual(timezonePresetSuggestions([socal],'America/New_York'),[]);
  assert.deepEqual(timezonePresetSuggestions(null,'America/New_York'),[]);
});
test('the browser time zone is only read locally and failures leave no suggestion',()=>{
  const original=Intl.DateTimeFormat;
  try {
    Intl.DateTimeFormat=()=>({resolvedOptions:()=>({timeZone:'America/Los_Angeles'})});
    assert.deepEqual(browserTimezonePresetSuggestions([usa,socal]),[usa,socal]);
    Intl.DateTimeFormat=()=>{throw Error('unavailable');};
    assert.deepEqual(browserTimezonePresetSuggestions([usa,socal]),[]);
  } finally {Intl.DateTimeFormat=original;}
});
