import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPostFlashSettingsPlan, applyPostFlashSettings } from '../src/post-flash-settings.js';

const primary={enabled:true,frequencyHz:910525000,bandwidthHz:62500,spreadingFactor:7,codingRate:5,preambleSymbols:32,txPowerDbm:null};
const baseline={frequencyHz:869525000,bandwidthHz:125000,spreadingFactor:8,codingRate:5,preambleSymbols:0};
const preset=(range=false)=>({frequencyHz:911150000,bandwidthHz:range?125000:250000,spreadingFactor:7,codingRate:5,preambleSymbols:0,mode:'rxtx'});
function target({preamble=true,radio2=true,tx=true,change=null,radioReply=null}={}){
  const calls=[],state={primary:{...baseline},tx:20,radio2:{mode:'off'},cross:'off',permission:false},tuple=p=>`${Math.fround(p.frequencyHz/1e6).toFixed(7)},${(p.bandwidthHz/1000).toFixed(3)},${p.spreadingFactor},${p.codingRate}`;
  const request=async command=>{
    calls.push(command);const injected=change?.(command,state,calls);if(injected!==undefined)return injected;
    if(command==='get radio')return radioReply?.(state.primary)||'> '+tuple(state.primary);
    if(command==='get radio.preamble')return preamble?'> '+(state.primary.preambleSymbols||'auto'):'Error: unknown config radio.preamble';
    if(command==='get tx')return tx?'> '+state.tx:'Error: unsupported';
    if(command==='get radio2'){
      if(!radio2)return 'Error: unsupported';if(state.radio2.mode==='off')return '> off (automatic allowed)';
      const p=state.radio2;return `> ${(p.frequencyHz/1e6).toFixed(3)},${(p.bandwidthHz/1000).toFixed(3)},${p.spreadingFactor},${p.codingRate},${p.mode},${p.preambleSymbols||32}${p.preambleSymbols?'':' (auto)'}; timing self-test pending`;
    }
    if(command==='get radio2.cross')return radio2?'> '+state.cross:'Error: unknown config radio2.cross';
    if(command.startsWith('set radio ')){
      const [f,bw,sf,cr,p]=command.slice(10).split(',');state.primary={frequencyHz:Math.round(Number(f)*1e6),bandwidthHz:Math.round(Number(bw)*1000),spreadingFactor:Number(sf),codingRate:Number(cr),preambleSymbols:!p||p==='auto'?0:Number(p)};return 'OK - radio params saved; preamble=32';
    }
    if(command.startsWith('set tx ')){state.tx=Number(command.slice(7));return 'OK';}
    if(command==='set radio2 off'){state.radio2={mode:'off'};state.permission=false;return 'OK - single radio in 2s';}
    if(command==='set radio2 mediamesh'||command==='set radio2 mediamesh-range'){state.radio2=preset(command.endsWith('-range'));state.permission=true;return 'OK - radio2 rxtx; preamble=32';}
    if(command.startsWith('set radio2 ')){const [f,bw,sf,cr,mode,p]=command.slice(11).split(',');state.radio2={frequencyHz:Number(f)*1e6,bandwidthHz:Number(bw)*1000,spreadingFactor:Number(sf),codingRate:Number(cr),mode,preambleSymbols:p==='auto'?0:Number(p)};return 'OK - radio2 saved; timing self-test pending';}
    if(command.startsWith('set radio2.cross ')){state.cross=command.slice(17);return 'OK';}
    throw Error('Unexpected command: '+command);
  };
  return {calls,state,request,isCurrent:()=>true};
}
const setters=target=>target.calls.filter(command=>command.startsWith('set '));

test('plans are strict, normalized, immutable and never contain executable user commands',()=>{
  const plan=createPostFlashSettingsPlan({primary,mediaMesh:{preset:'mediamesh-range',cross:'on'}});assert.ok(Object.isFrozen(plan));assert.ok(Object.isFrozen(plan.primary));assert.ok(Object.isFrozen(plan.mediaMesh));assert.equal(typeof plan.summary,'string');assert.match(plan.summary,/910\.525 MHz/);assert.equal(plan.mediaMesh.bandwidthHz,125000);assert.equal(plan.mediaMesh.mode,'rxtx');assert.equal(plan.mediaMesh.preambleSymbols,0);
  assert.deepEqual(createPostFlashSettingsPlan().mediaMesh,{preset:'unchanged',cross:'unchanged'});assert.equal(createPostFlashSettingsPlan().primary,null);assert.equal(createPostFlashSettingsPlan({primary:{enabled:false}}).primary,null);
  const original={...primary};createPostFlashSettingsPlan({primary:original});assert.deepEqual(original,primary);
  for(const input of [null,[],{command:'reboot'},{primary:{...primary,command:'reset'}},{primary:{...primary,frequencyHz:'910.525\nreboot'}},{primary:{...primary,frequencyHz:910525001}},{primary:{...primary,frequencyHz:149999000}},{primary:{...primary,bandwidthHz:126000}},{primary:{...primary,spreadingFactor:4}},{primary:{...primary,codingRate:9}},{primary:{...primary,preambleSymbols:7}},{primary:{...primary,txPowerDbm:41}},{primary:{...primary,enabled:false}},{mediaMesh:{preset:'off',frequencyHz:911150000}},{mediaMesh:{preset:'custom'}},{mediaMesh:{preset:'mediamesh',mode:'rx\nreboot'}},{mediaMesh:{preset:'mediamesh',cross:'all'}}])assert.throws(()=>createPostFlashSettingsPlan(input));
});
test('primary tuple, explicit preamble and optional TX power are preflighted, written once and read back',async()=>{
  const t=target(),result=await applyPostFlashSettings(createPostFlashSettingsPlan({primary:{...primary,txPowerDbm:-9}}),t);
  assert.equal(result.complete,true);assert.deepEqual(t.calls.slice(0,3),['get radio','get radio.preamble','get tx']);assert.deepEqual(setters(t),['set radio 910.525,62.5,7,5,32','set tx -9']);assert.equal(result.applied[0].preambleVerified,true);assert.equal(result.applied[0].txPowerVerified,true);assert.equal(result.errors.length,0);assert.equal(result.writes.length,2);
});
test('all requested primary and MediaMesh getters run before the first mutation',async()=>{
  const t=target(),result=await applyPostFlashSettings(createPostFlashSettingsPlan({primary,mediaMesh:{preset:'mediamesh',cross:'on'}}),t);assert.equal(result.complete,true);assert.deepEqual(t.calls.slice(0,4),['get radio','get radio.preamble','get radio2','get radio2.cross']);assert.deepEqual(setters(t),['set radio 910.525,62.5,7,5,32','set radio2 mediamesh','set radio2.cross on']);assert.equal(t.state.permission,true);assert.equal(t.state.cross,'on');assert.equal(result.applied.length,2);
});
test('null preamble preserves a readable saved value, with no explicit new preamble claim',async()=>{
  const t=target();t.state.primary.preambleSymbols=64;const result=await applyPostFlashSettings(createPostFlashSettingsPlan({primary:{...primary,preambleSymbols:null}}),t);assert.equal(result.complete,true);assert.deepEqual(setters(t),['set radio 910.525,62.5,7,5,64']);assert.equal(t.state.primary.preambleSymbols,64);assert.equal(result.applied[0].preambleVerified,true);assert.equal(t.calls.includes('get tx'),false);
});
test('legacy unsupported preamble only permits a four-field command for a null choice, with an explicit warning',async()=>{
  const t=target({preamble:false}),result=await applyPostFlashSettings(createPostFlashSettingsPlan({primary:{...primary,preambleSymbols:null}}),t);assert.equal(result.complete,true);assert.deepEqual(setters(t),['set radio 910.525,62.5,7,5']);assert.equal(result.applied[0].preambleVerified,false);assert.match(result.warnings[0],/legacy.*firmware-default/);assert.equal(t.calls.filter(command=>command==='get radio.preamble').length,1);
  for(const preambleSymbols of [0,32]){const unsupported=target({preamble:false}),r=await applyPostFlashSettings(createPostFlashSettingsPlan({primary:{...primary,preambleSymbols}}),unsupported);assert.equal(r.complete,false);assert.equal(r.skipped[0].section,'primary');assert.deepEqual(setters(unsupported),[]);assert.deepEqual(r.errors,[]);}
});
test('unreadable or malformed preamble never becomes a legacy compatibility fallback',async()=>{
  for(const reply of ['', '> perhaps', '> auto\n> 32','Error: storage failure']){const t=target({change:command=>command==='get radio.preamble'?reply:undefined}),result=await applyPostFlashSettings(createPostFlashSettingsPlan({primary:{...primary,preambleSymbols:null}}),t);assert.equal(result.complete,false);assert.equal(result.errors.length,1);assert.deepEqual(setters(t),[]);}
});
test('unsupported power or radio2 yields explicit skipped sections without a silent partial claim',async()=>{
  const t=target({tx:false,radio2:false}),result=await applyPostFlashSettings(createPostFlashSettingsPlan({primary:{...primary,txPowerDbm:25},mediaMesh:{preset:'mediamesh'}}),t);assert.equal(result.complete,false);assert.deepEqual(result.skipped.map(row=>row.section),['primary','mediaMesh']);assert.deepEqual(setters(t),[]);assert.deepEqual(result.errors,[]);
  const partial=target({radio2:false}),p=await applyPostFlashSettings(createPostFlashSettingsPlan({primary,mediaMesh:{preset:'mediamesh'}}),partial);assert.equal(p.complete,false);assert.deepEqual(p.applied.map(row=>row.section),['primary']);assert.deepEqual(p.skipped.map(row=>row.section),['mediaMesh']);
});
test('MediaMesh custom RF always establishes the preset permission first, then verifies each tuple and crossing',async()=>{
  const t=target(),mediaMesh={preset:'custom',frequencyHz:911300000,bandwidthHz:500000,spreadingFactor:8,codingRate:7,preambleSymbols:32,mode:'rx',cross:'auto'},result=await applyPostFlashSettings(createPostFlashSettingsPlan({mediaMesh}),t);assert.equal(result.complete,true);assert.deepEqual(setters(t),['set radio2 mediamesh','set radio2 911.3,500,8,7,rx,32','set radio2.cross auto']);assert.equal(t.state.permission,true);assert.deepEqual(t.calls.filter(command=>command==='get radio2'),['get radio2','get radio2','get radio2']);assert.equal(result.applied[0].preset,'custom');
});
test('preset RF overrides retain that preset as the permission base; off is explicitly written even from automatic off',async()=>{
  const t=target(),result=await applyPostFlashSettings(createPostFlashSettingsPlan({mediaMesh:{preset:'mediamesh-range',preambleSymbols:32,mode:'rx'}}),t);assert.equal(result.complete,true);assert.deepEqual(setters(t),['set radio2 mediamesh-range','set radio2 911.15,125,7,5,rx,32']);
  const off=target(),r=await applyPostFlashSettings(createPostFlashSettingsPlan({mediaMesh:{preset:'off'}}),off);assert.equal(r.complete,true);assert.deepEqual(setters(off),['set radio2 off']);assert.equal(off.state.permission,false);
});
test('already matching primary settings avoid writes, while preset intent is still explicitly saved',async()=>{
  const t=target();t.state.primary={...primary};t.state.radio2=preset();const result=await applyPostFlashSettings(createPostFlashSettingsPlan({primary,mediaMesh:{preset:'mediamesh'}}),t);assert.equal(result.complete,true);assert.equal(result.applied[0].unchanged,true);assert.deepEqual(setters(t),['set radio2 mediamesh']);
});
test('cross-only choices do not rewrite RF, and unchanged crossing is checked rather than silently changed',async()=>{
  const t=target(),result=await applyPostFlashSettings(createPostFlashSettingsPlan({mediaMesh:{cross:'on'}}),t);assert.equal(result.complete,true);assert.deepEqual(setters(t),['set radio2.cross on']);
  let crossReads=0;const bad=target({change:command=>command==='get radio2.cross'&&++crossReads===2?'> on':undefined}),r=await applyPostFlashSettings(createPostFlashSettingsPlan({mediaMesh:{preset:'mediamesh'}}),bad);assert.equal(r.complete,false);assert.match(r.errors[0].reason,/crossing changed unexpectedly/);assert.deepEqual(setters(bad),['set radio2 mediamesh']);
});
test('preflight transport failures, malformed replies and automatically owned/pending profiles stop before all writes',async()=>{
  for(const reply of ['> 911.15,250,7,5,rxtx,32 (auto); auto-owned','> radio2 change pending storage commit','> off; MediaMesh scope save pending','> 911.15,250,7,5,rxtx,32 (auto); @123-456','> malformed','> off\n> off']){const t=target({change:command=>command==='get radio2'?reply:undefined}),r=await applyPostFlashSettings(createPostFlashSettingsPlan({primary,mediaMesh:{preset:'mediamesh'}}),t);assert.equal(r.complete,false);assert.equal(r.errors[0].stage,'preflight');assert.deepEqual(setters(t),[]);}
  const t=target({change:command=>{if(command==='get radio2')throw Error('transport');}}),r=await applyPostFlashSettings(createPostFlashSettingsPlan({primary,mediaMesh:{preset:'mediamesh'}}),t);assert.equal(r.complete,false);assert.deepEqual(setters(t),[]);
});
test('setter rejections, ambiguous acknowledgements and failed readbacks stop all later commands without retries',async()=>{
  for(const reply of ['Error: rejected','OK\nError: save failure','OK reboot to apply','OK after reply','']){const t=target({change:command=>command.startsWith('set radio ')?reply:undefined}),r=await applyPostFlashSettings(createPostFlashSettingsPlan({primary,mediaMesh:{preset:'mediamesh'}}),t);assert.equal(r.complete,false);assert.equal(r.errors.length,1);assert.deepEqual(setters(t),['set radio 910.525,62.5,7,5,32']);assert.equal(t.calls.filter(command=>command==='get radio2').length,1);}
  let gets=0;const t=target({change:command=>command==='get radio'&&++gets===2?'> 869.525,125,8,5':undefined}),r=await applyPostFlashSettings(createPostFlashSettingsPlan({primary,mediaMesh:{preset:'mediamesh'}}),t);assert.equal(r.complete,false);assert.equal(r.errors[0].stage,'readback');assert.match(r.errors[0].reason,/readback did not match/);assert.equal(r.writes[0].accepted,true);assert.equal(setters(t).length,1);
});
test('known chirp/spacing diagnostic warning lines are accepted only beside valid success replies and mandatory matching readback',async()=>{
  const t=target(),request=async command=>{const reply=await t.request(command);return command.startsWith('set ')?reply+'\nWARN recommended preamble: radio2=64; short override: radio2; switch=547us\nWARN radio2 overlaps radio1 (6kHz guard); try 911.594MHz':reply;},result=await applyPostFlashSettings(createPostFlashSettingsPlan({primary,mediaMesh:{preset:'mediamesh'}}),{request,isCurrent:()=>true});assert.equal(result.complete,true);assert.equal(result.errors.length,0);assert.equal(result.applied.length,2);
  for(const suffix of ['arbitrary log output','OK second acknowledgement','WARN unknown warning','WARN recommended preamble: radio2=64\nError: save failed']){const bad=target(),r=await applyPostFlashSettings(createPostFlashSettingsPlan({primary}),{isCurrent:()=>true,request:async command=>{const reply=await bad.request(command);return command.startsWith('set ')?reply+'\n'+suffix:reply;}});assert.equal(r.complete,false);assert.equal(setters(bad).length,1);}
});
test('readback accounts for float32 and normal three-decimal formatting but rejects distinguishable RF mismatches',async()=>{
  const t=target({radioReply:p=>`> ${(p.frequencyHz/1e6).toFixed(3)},${p.bandwidthHz/1000},${p.spreadingFactor},${p.codingRate}`}),r=await applyPostFlashSettings(createPostFlashSettingsPlan({primary}),t);assert.equal(r.complete,true);
  let reads=0;const bad=target({change:command=>command==='get radio'&&++reads===2?'> 910.5246,62.500,7,5':undefined}),b=await applyPostFlashSettings(createPostFlashSettingsPlan({primary}),bad);assert.equal(b.complete,false);assert.match(b.errors[0].reason,/readback did not match/);
});
test('stale identity/approval context before or after any request stops further commands including reads',async()=>{
  const none=target();let live=false;const r=await applyPostFlashSettings(createPostFlashSettingsPlan({primary}),{...none,isCurrent:()=>live});assert.equal(r.complete,false);assert.deepEqual(none.calls,[]);
  for(const stop of ['get radio','set radio 910.525,62.5,7,5,32']){const t=target();live=true;const request=async command=>{const reply=await t.request(command);if(command===stop)live=false;return reply;},result=await applyPostFlashSettings(createPostFlashSettingsPlan({primary,mediaMesh:{preset:'mediamesh'}}),{request,isCurrent:()=>live});assert.equal(result.complete,false);assert.equal(t.calls.at(-1),stop);assert.match(result.errors[0].reason,/changed/);}
});
test('invalid or forged plans/adapters reject before request, and an empty plan is a harmless complete no-op',async()=>{
  const t=target();for(const plan of [null,{}, {...createPostFlashSettingsPlan({primary}),primary:{...primary,frequencyHz:'1\nreset'}},{...createPostFlashSettingsPlan(),commands:['reboot']}])await assert.rejects(()=>applyPostFlashSettings(plan,t));await assert.rejects(()=>applyPostFlashSettings(createPostFlashSettingsPlan(),{request:t.request,isCurrent:null}));assert.deepEqual(t.calls,[]);
  const result=await applyPostFlashSettings(createPostFlashSettingsPlan(),t);assert.equal(result.complete,true);assert.deepEqual(t.calls,[]);assert.deepEqual(result.applied,[]);
});
