import test from 'node:test';
import assert from 'node:assert/strict';
import { createPostFlashSettingsPlan } from '../src/post-flash-settings.js';
import { prepareWadameshConfig, applyWadameshConfig } from '../src/wadamesh-config.js';

const primary = {enabled:true,frequencyHz:910525000,bandwidthHz:125000,spreadingFactor:7,codingRate:5,preambleSymbols:null,txPowerDbm:18};
const desired = () => createPostFlashSettingsPlan({primary,mediaMesh:{preset:'mediamesh',cross:'off'}});
function fixture() {
  const state={radio:'910.000,125.000,8,5',tx:10,radio2:'off',cross:'off',temp:'off',schedule:'slots:',tempSchedule:'slots:',current:true}, calls=[];
  const isCurrent=()=>state.current;
  const request=async command=>{
    calls.push(command);
    if(command==='get radio')return '> '+state.radio;
    if(command==='get tx')return '> '+state.tx;
    if(command==='get radio2')return '> '+state.radio2;
    if(command==='get radio2.cross')return '> '+state.cross;
    if(command==='get tempradio2')return '> '+state.temp;
    if(command==='get radioat2')return '> '+state.schedule;
    if(command==='get tempradioat2')return '> '+state.tempSchedule;
    if(command.startsWith('set radio ')){state.radio=command.slice(10);return 'OK - reboot to apply';}
    if(command.startsWith('set tx ')){state.tx=Number(command.slice(7));return 'OK';}
    if(command==='set radio2 off'){state.radio2='off';return 'OK - single radio';}
    if(command.startsWith('set radio2.cross ')){state.cross=command.slice(17);return 'OK';}
    if(command.startsWith('set radio2 ')){
      const parts=command.slice(11).split(',');state.radio2=parts.slice(0,5).join(',')+','+(parts[5]==='auto'?'32 (auto)':parts[5]);
      return `OK - radio2 ${parts[4]}; preamble=32`;
    }
    throw Error('unexpected command '+command);
  };
  return {state,calls,request,isCurrent,maxTxDbm:22};
}
const setters = calls => calls.filter(call=>call.startsWith('set '));

test('review is read-only and confirmed changes use TAK four-field and numeric radio2 commands',async()=>{
  const f=fixture();f.state.cross='on';const prep=await prepareWadameshConfig(desired(),f);
  assert.deepEqual(setters(f.calls),[]);assert.deepEqual(prep.changes.map(change=>change.setting),['radio','tx','cross','radio2']);assert.equal(prep.skipped.length,0);
  assert.match(prep.summary,/Radio crossing: off/);
  const result=await applyWadameshConfig(prep,f);
  assert.equal(result.complete,true);assert.deepEqual(result.errors,[]);assert.equal(result.rebootRequired,true);
  assert.deepEqual(setters(f.calls),['set radio 910.525,125,7,5','set tx 18','set radio2.cross off','set radio2 911.15,250,7,5,rxtx,auto']);assert.equal(f.state.cross,'off');
  assert.ok(result.applied.every(change=>change.readbackMatched));assert.ok(result.applied.find(change=>change.setting==='radio').pendingReboot);
  await assert.rejects(applyWadameshConfig(prep,f),/invalid/);
});

test('crossing must be verified off before MediaMesh is enabled',async()=>{
  for(const fault of ['rejected','no-change']){
    const f=fixture();f.state.cross='on';const original=f.request;
    f.request=async command=>command==='set radio2.cross off'?(f.calls.push(command),fault==='rejected'?'Error: rejected':'OK'):original(command);
    const prep=await prepareWadameshConfig(createPostFlashSettingsPlan({mediaMesh:{preset:'mediamesh'}}),f);
    const result=await applyWadameshConfig(prep,f);
    assert.equal(result.complete,false);assert.equal(result.errors.length,1);assert.deepEqual(setters(f.calls),['set radio2.cross off'],fault);
    assert.equal(f.state.radio2,'off');assert.equal(f.state.cross,'on');
  }
});

test('a radio2 failure reports the previously verified crossing change',async()=>{
  const f=fixture();f.state.cross='on';const original=f.request;
  f.request=async command=>command.startsWith('set radio2 911.')?(f.calls.push(command),'Error: rejected'):original(command);
  const prep=await prepareWadameshConfig(createPostFlashSettingsPlan({mediaMesh:{preset:'mediamesh'}}),f);
  const result=await applyWadameshConfig(prep,f);
  assert.equal(result.complete,false);assert.deepEqual(setters(f.calls),['set radio2.cross off','set radio2 911.15,250,7,5,rxtx,auto']);
  assert.ok(result.applied.some(change=>change.setting==='cross'&&change.readbackMatched));
  assert.match(result.errors[0].reason,/may already have changed/);assert.equal(f.state.cross,'off');assert.equal(f.state.radio2,'off');
});

test('custom MediaMesh may enable crossing after radio2, or leave crossing unchanged',async()=>{
  for(const cross of ['on','auto','unchanged']){
    const f=fixture(),mediaMesh={preset:'custom',frequencyHz:911300000,bandwidthHz:250000,spreadingFactor:7,codingRate:5,preambleSymbols:0,mode:'rxtx',cross};if(cross==='unchanged')f.state.cross='on';
    const prep=await prepareWadameshConfig(createPostFlashSettingsPlan({mediaMesh}),f);
    const result=await applyWadameshConfig(prep,f);
    assert.equal(result.complete,true,cross);
    assert.deepEqual(setters(f.calls),cross==='unchanged'?['set radio2 911.3,250,7,5,rxtx,auto']:['set radio2 911.3,250,7,5,rxtx,auto',`set radio2.cross ${cross}`]);
    assert.equal(f.state.cross,cross==='unchanged'?'on':cross);
  }
});

test('custom MediaMesh requesting crossing off also disables it before radio2',async()=>{
  const f=fixture();f.state.cross='on';
  const mediaMesh={preset:'custom',frequencyHz:911300000,bandwidthHz:250000,spreadingFactor:7,codingRate:5,preambleSymbols:0,mode:'rxtx',cross:'off'};
  const prep=await prepareWadameshConfig(createPostFlashSettingsPlan({mediaMesh}),f),result=await applyWadameshConfig(prep,f);
  assert.equal(result.complete,true);assert.deepEqual(setters(f.calls),['set radio2.cross off','set radio2 911.3,250,7,5,rxtx,auto']);
});

test('custom MediaMesh verifies already-matching crossing after changing radio2',async()=>{
  for(const cross of ['on','auto']){
    const f=fixture();f.state.cross=cross;const original=f.request;
    f.request=async command=>{const reply=await original(command);if(command.startsWith('set radio2 911.'))f.state.cross='off';return reply;};
    const mediaMesh={preset:'custom',frequencyHz:911300000,bandwidthHz:250000,spreadingFactor:7,codingRate:5,preambleSymbols:0,mode:'rxtx',cross};
    const prep=await prepareWadameshConfig(createPostFlashSettingsPlan({mediaMesh}),f);
    assert.ok(!prep.changes.some(change=>change.setting==='cross'));
    const result=await applyWadameshConfig(prep,f);
    assert.equal(result.complete,false);assert.match(result.errors[0].reason,/crossing changed unexpectedly/);
    assert.deepEqual(setters(f.calls),['set radio2 911.3,250,7,5,rxtx,auto']);
  }
});

test('unsupported preamble skips primary without silently discarding the explicit choice',async()=>{
  const f=fixture(),prep=await prepareWadameshConfig(createPostFlashSettingsPlan({primary:{...primary,preambleSymbols:32},mediaMesh:{preset:'mediamesh'}}),f);
  assert.match(prep.skipped[0].reason,/preamble/);assert.ok(!f.calls.includes('get radio'));
  const result=await applyWadameshConfig(prep,f);assert.equal(result.complete,false);assert.deepEqual(setters(f.calls),['set radio2 911.15,250,7,5,rxtx,auto']);
});

test('client repeat, temporary radio2 or scheduled profiles stop before all writes',async()=>{
  for(const [field,value] of [['radio2','off; client repeat is on (radio2 back to rxtx when it is off)'],['temp','911.15,250,7,5,rxtx,32 (auto); 1m left'],['schedule','slots: 1@1234'],['tempSchedule','slots: 1@1234']]){
    const f=fixture();f.state[field]=value;await assert.rejects(prepareWadameshConfig(desired(),f),/Client Repeat|temporary or scheduled/);assert.deepEqual(setters(f.calls),[],field);
  }
});

test('unsupported MediaMesh capability is reported and never receives setters',async()=>{
  const f=fixture(),original=f.request;f.request=async command=>command==='get radio2'?'> Error: unsupported':original(command);
  const prep=await prepareWadameshConfig(desired(),f);assert.match(prep.skipped[0].reason,/MediaMesh/);
  const result=await applyWadameshConfig(prep,f);assert.equal(result.complete,false);assert.ok(setters(f.calls).every(call=>!call.startsWith('set radio2')));
});

test('changes between preflight and confirmation or session change stop all writes',async()=>{
  for(const fault of ['radio','media','context']){
    const f=fixture(),prep=await prepareWadameshConfig(desired(),f);
    if(fault==='radio')f.state.radio='912.000,125.000,8,5';if(fault==='media')f.state.cross='on';if(fault==='context')f.state.current=false;
    const result=await applyWadameshConfig(prep,f);assert.equal(result.complete,false);assert.equal(result.errors.length,1);assert.deepEqual(setters(f.calls),[],fault);
  }
});

test('a setter failure stops immediately and records potentially partial changes without retry',async()=>{
  const f=fixture(),original=f.request;f.request=async command=>command==='set tx 18'?(f.calls.push(command),'Error: rejected'):original(command);
  const prep=await prepareWadameshConfig(desired(),f),result=await applyWadameshConfig(prep,f);
  assert.equal(result.complete,false);assert.equal(result.rebootRequired,true);assert.equal(result.errors.length,1);assert.deepEqual(setters(f.calls),['set radio 910.525,125,7,5','set tx 18']);
  assert.equal(result.writes.at(-1).acknowledged,false);assert.ok(result.applied.some(value=>value.setting==='radio'&&value.pendingReboot));
});

test('a lost radio acknowledgement remains an uncertain change and never retries',async()=>{
  const f=fixture(),original=f.request;f.request=async command=>{if(command.startsWith('set radio ')){f.calls.push(command);throw Error('disconnected after sending');}return original(command);};
  const prep=await prepareWadameshConfig(desired(),f),result=await applyWadameshConfig(prep,f);
  assert.equal(result.complete,false);assert.equal(result.rebootRequired,true);assert.equal(result.writes[0].acknowledged,false);assert.match(result.errors[0].reason,/may already have changed/);
  assert.deepEqual(setters(f.calls),['set radio 910.525,125,7,5']);
});

test('unchanged values do not trigger writes or unrequested region changes',async()=>{
  const f=fixture();f.state.radio='910.525,125.000,7,5';f.state.tx=18;f.state.radio2='911.150,250.000,7,5,rxtx,32 (auto)';f.state.cross='off';
  const prep=await prepareWadameshConfig(desired(),f);assert.equal(prep.changes.length,0);assert.ok(prep.warnings.some(value=>/region permissions are not changed/));
  const result=await applyWadameshConfig(prep,f);assert.equal(result.complete,true);assert.deepEqual(setters(f.calls),[]);
});

test('TX limit fails before any write and a getter with trimmed trailing zeros is accepted',async()=>{
  const limited=fixture();limited.maxTxDbm=12;await assert.rejects(prepareWadameshConfig(desired(),limited),/TX power/);assert.deepEqual(setters(limited.calls),[]);
  const trimmed=fixture();trimmed.state.radio='910.0,125,8,5';const prep=await prepareWadameshConfig(desired(),trimmed);assert.ok(prep.changes.some(value=>value.setting==='radio'));assert.deepEqual(setters(trimmed.calls),[]);
});
