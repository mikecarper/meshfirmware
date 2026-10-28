import test from 'node:test';
import assert from 'node:assert/strict';
import {CAPABILITY_KEYS,parseSettingCapabilities,validateSettingCapabilities,validateSettingCapabilityRecord,captureSettingCapabilities,settingCapability,shouldSkipSetting} from '../src/setting-capabilities.js';

const hex=value=>value.toString(16).padStart(8,'0');
const manifest=({get=0,set=0,fixed=0,na=0}={})=>`config.cap v1 get=${hex(get)} set=${hex(set)} fixed=${hex(fixed)} na=${hex(na)}`;
const bit=key=>2**CAPABILITY_KEYS.indexOf(key);
const record=value=>({state:'complete',data:parseSettingCapabilities(value)});

test('v1 capability bit order is stable, unique and bounded to the reviewed firmware contract',()=>{
  assert.deepEqual(CAPABILITY_KEYS,['system.watchdog','radio.cad','radio.fem.rxgain','radio.fem.txgain','radio.rxps.rfrx_disabled','bluetooth','bluetooth.name','display.rotation','usb.logging.always','usb.logging','usb.debug','radio.preamble']);
  assert.equal(new Set(CAPABILITY_KEYS).size,12);assert.ok(Object.isFrozen(CAPABILITY_KEYS));assert.equal(manifest().length,66);
});

test('parser preserves supported, fixed, not-applicable and unknown support without inventing values',()=>{
  const data=parseSettingCapabilities(manifest({get:bit('usb.logging')|bit('radio.preamble'),set:bit('usb.logging')|bit('radio.preamble')|bit('system.watchdog'),fixed:bit('radio.cad'),na:bit('bluetooth')}));
  assert.equal(data.version,1);assert.equal(Object.keys(data.settings).length,12);
  assert.deepEqual(data.settings['usb.logging'],{state:'supported',readable:true,writable:true});
  assert.deepEqual(data.settings['radio.cad'],{state:'fixed',readable:false,writable:false});
  assert.deepEqual(data.settings.bluetooth,{state:'not_applicable',readable:false,writable:false});
  assert.deepEqual(data.settings['system.watchdog'],{state:'unknown',readable:false,writable:true});
  assert.deepEqual(data.settings['radio.fem.txgain'],{state:'unknown',readable:false,writable:false});
  assert.ok(Object.isFrozen(data)&&Object.isFrozen(data.settings)&&Object.isFrozen(data.settings.bluetooth));
});

test('a fixed readable diagnostic remains readable and is never promoted to a writable setting',()=>{
  const data=parseSettingCapabilities(manifest({get:bit('radio.cad'),fixed:bit('radio.cad')}));
  assert.deepEqual(data.settings['radio.cad'],{state:'fixed',readable:true,writable:false});
});

test('parser accepts exact plain, echoed and console prompt framing without stripping arbitrary serial lines',()=>{
  const text=manifest({get:bit('radio.preamble')});
  for(const raw of [text,'> '+text,'  -> '+text,'  -> > '+text,'get config.cap\r\n  -> '+text+'\r\n','\nget config.cap\n> '+text+'\n\n'])assert.equal(parseSettingCapabilities(raw)?.settings['radio.preamble'].readable,true,raw);
  assert.equal(parseSettingCapabilities(manifest({get:0xabc})).settings['radio.preamble'].readable,true);
  assert.ok(parseSettingCapabilities(manifest({get:0xabc}).replace('00000abc','00000ABC')));
});

test('legacy unsupported replies and future manifests cannot conceal missing getters',()=>{
  for(const raw of ['',null,{},'Unknown command','get config.cap\n -> Error: unknown setting: config.cap',manifest().replace('v1','v2'),'get config.cap','config.cap v1'])assert.equal(parseSettingCapabilities(raw),null);
});

test('parser rejects truncated, duplicated, reordered or extra fields and noncanonical field names',()=>{
  const text=manifest();
  for(const raw of [text.slice(0,-1),text.replace(' na=00000000',''),text+' get=00000000',text.replace(' set=00000000',' get=00000000'),text.replace(' get=00000000 set=00000000',' set=00000000 get=00000000'),text+' extra',text.toUpperCase(),text.replace('set=','SET='),text.replace('get=00000000','get=0'),text+'\n'+text,'get config.cap\nget config.cap\n'+text])assert.equal(parseSettingCapabilities(raw),null,raw);
});

test('reserved bits, overlapping not-applicable states and writable fixed values fail closed',()=>{
  for(const field of ['get','set','fixed','na'])for(const value of [0x1000,0x80000000,0xffffffff])assert.equal(parseSettingCapabilities(manifest({[field]:value})),null,field);
  const value=bit('usb.logging');for(const flags of [{get:value,na:value},{set:value,na:value},{fixed:value,na:value},{fixed:value,set:value},{get:value,fixed:value,set:value}])assert.equal(parseSettingCapabilities(manifest(flags)),null);
});

test('control characters, ANSI tricks, embedded output and oversize reports are not parsed',()=>{
  const text=manifest();
  for(const raw of ['\0'+text,text+'\0','\x1b[32m'+text+'\x1b[0m','\t'+text,text.replace(' v1 ','\tv1 '),text+'\r',text+'\u2028',text+'\u2029','noise\n'+text,text+'\nget name',' '.repeat(513)+text,'\ufeff'+text])assert.equal(parseSettingCapabilities(raw),null);
});

test('archive metadata validation returns a canonical immutable clone and does not mutate input',()=>{
  const original=JSON.parse(JSON.stringify(parseSettingCapabilities(manifest({get:bit('radio.preamble'),na:bit('bluetooth')})))),before=JSON.stringify(original),checked=validateSettingCapabilities(original);
  assert.notEqual(checked,original);assert.equal(JSON.stringify(original),before);assert.ok(Object.isFrozen(checked.settings['radio.preamble']));
  original.settings['radio.preamble'].state='unknown';assert.equal(checked.settings['radio.preamble'].state,'supported');
});

test('import validation rejects missing or unknown keys, malformed states and inconsistent flags',()=>{
  const base=()=>JSON.parse(JSON.stringify(parseSettingCapabilities(manifest())));
  for(const mutate of [value=>value.version=2,value=>delete value.settings.bluetooth,value=>value.settings['not.real']={state:'not_applicable',readable:false,writable:false},value=>value.settings.bluetooth.state='disabled',value=>value.settings.bluetooth.readable='false',value=>value.settings.bluetooth={state:'supported',readable:false,writable:true},value=>value.settings.bluetooth={state:'unknown',readable:true,writable:false},value=>value.settings.bluetooth={state:'fixed',readable:false,writable:true},value=>value.settings.bluetooth={state:'not_applicable',readable:true,writable:false},value=>value.settings.bluetooth.value='SECRET',value=>value.raw='SECRET',value=>value.settings=[]]){const value=base();mutate(value);assert.throws(()=>validateSettingCapabilities(value),/^Error: Invalid setting capability metadata\.$/);}
});

test('record validation forbids data on failed capture and sanitizes diagnostic reasons',()=>{
  const complete=record(manifest()),checked=validateSettingCapabilityRecord(complete);assert.deepEqual(checked,complete);assert.notEqual(checked,complete);
  for(const state of ['unsupported','error']){const output=validateSettingCapabilityRecord({state,reason:'RAW_SECRET_DIAGNOSTIC'});assert.equal(output.state,state);assert.ok(!output.reason.includes('RAW_SECRET'));assert.ok(Object.isFrozen(output));}
  for(const value of [{state:'partial'},{state:'complete'},{state:'complete',data:complete.data,raw:'SECRET'},{state:'unsupported',data:complete.data},{state:'error',reason:'x'.repeat(257)},{state:'error',reason:'\nsecret'},{state:'error',raw:'secret'}])assert.throws(()=>validateSettingCapabilityRecord(value),/Invalid setting capability metadata/);
});

test('capability lookups skip only positively reported irrelevant or unreadable fixed settings',()=>{
  const value=record(manifest({na:bit('bluetooth'),fixed:bit('radio.cad')|bit('radio.fem.txgain'),get:bit('radio.fem.txgain'),set:bit('system.watchdog')}));
  assert.equal(shouldSkipSetting(value,'get bluetooth'),true);assert.equal(shouldSkipSetting(value,'get radio.cad'),true);
  for(const query of ['get radio.fem.txgain','get system.watchdog','get radio.preamble','set bluetooth on','bluetooth','get __proto__'])assert.equal(shouldSkipSetting(value,query),false,query);
  assert.equal(settingCapability(value,'bluetooth').state,'not_applicable');assert.equal(settingCapability(value,'__proto__'),null);assert.equal(settingCapability({state:'complete',data:{}},'bluetooth'),null);
  for(const input of [null,{state:'unsupported'},{state:'error'},{state:'complete',data:{settings:{bluetooth:{state:'not_applicable'}}}}])assert.equal(shouldSkipSetting(input,'get bluetooth'),false);
});

test('capture sends exactly one bounded read-only query and preserves the returned metadata',async()=>{
  const calls=[],value=manifest({get:bit('radio.preamble')}),link={async command(command,timeout){calls.push([command,timeout]);return 'get config.cap\n -> '+value+'\n';}};
  const result=await captureSettingCapabilities(link);assert.deepEqual(calls,[['get config.cap',700]]);assert.equal(result.state,'complete');assert.equal(result.data.settings['radio.preamble'].readable,true);assert.ok(Object.isFrozen(result));
});

test('capture never exposes raw unsupported replies or transport exception text',async()=>{
  const raw='SECRET_FROM_FIRMWARE';for(const reply of [raw,'Error: unknown setting',manifest().replace('v1','v99')]){const result=await captureSettingCapabilities({command:async()=>reply});assert.equal(result.state,'unsupported');assert.ok(!JSON.stringify(result).includes(raw));}
  const result=await captureSettingCapabilities({command:async()=>{throw Error('SECRET_PORT_ERROR');}});assert.equal(result.state,'error');assert.ok(!JSON.stringify(result).includes('SECRET_PORT_ERROR'));
});

test('capture context checks run before and after the await, and stale context errors are not hidden',async()=>{
  const calls=[];let current=true,checks=0;
  const assertCurrent=()=>{checks++;if(!current)throw Error('Selection changed');};
  await assert.rejects(captureSettingCapabilities({command:async()=>{calls.push('read');current=false;return manifest();}},{assertCurrent}),/Selection changed/);assert.deepEqual(calls,['read']);assert.equal(checks,2);
  current=false;checks=0;calls.length=0;await assert.rejects(captureSettingCapabilities({command:async()=>calls.push('unsafe')},{assertCurrent}),/Selection changed/);assert.equal(checks,1);assert.deepEqual(calls,[]);
  current=true;checks=0;await assert.rejects(captureSettingCapabilities({command:async()=>{current=false;throw Error('Port failed');}},{assertCurrent}),/Selection changed/);assert.equal(checks,2);
});

test('untrusted object accessors cannot leak exception text through archive validators',()=>{
  const value={get version(){throw Error('PRIVATE_VALUE');},settings:{}};
  assert.throws(()=>validateSettingCapabilities(value),error=>error.message==='Invalid setting capability metadata.');
  assert.throws(()=>validateSettingCapabilityRecord({state:'error',get reason(){throw Error('PRIVATE_VALUE');}}),error=>error.message==='Invalid setting capability metadata.');
});
