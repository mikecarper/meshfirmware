import test from 'node:test';
import assert from 'node:assert/strict';
import {captureRegions,validateRegions,regionRestorePreview,prepareRegionRestore,restoreRegions} from '../src/regions.js';

const snapshot=(entries=[],extra={})=>({schema:'org.meshfirmware.regions/v1',entries,wildcardFloodAllowed:true,home:'*',default:null,...extra});
const row=(name,parent='*',floodAllowed=true)=>({name,parent,floodAllowed});
function mockRegions(initial=snapshot(),{wrapped=true,hook=null,legacyPut=false}={}){
  const state=structuredClone(initial),calls=[];let saved=false;
  const render=()=>{
    let text='';const walk=(name,depth,allow)=>{text+=' '.repeat(depth)+name+(state.home===name?'^':'')+(allow?' F':'')+'\n';for(const entry of state.entries.filter(entry=>entry.parent===name))walk(entry.name,depth+1,entry.floodAllowed);};walk('*',0,state.wildcardFloodAllowed);return text;
  };
  const response=(command,text)=>wrapped?command+'\r\n  -> '+text+'\r\n':text;
  const entry=name=>name==='*'?{name:'*',parent:'*',floodAllowed:state.wildcardFloodAllowed}:state.entries.find(entry=>entry.name===name);
  const link={calls,state,get saved(){return saved;},async command(command){
    calls.push(command);const override=hook?.(command,link);if(override!==undefined)return override;
    if(command==='region')return response(command,render());
    if(command==='region home')return response(command,'home is '+state.home);
    if(command==='region default')return response(command,'default scope is '+(state.default??'<null>'));
    let match=/^region get (\S+)$/.exec(command);
    if(match){const value=entry(match[1]);return response(command,value?`${value.name}${value.parent==='*'?'':` (${value.parent})`}${value.floodAllowed?' F':''}`:'Err - unknown region');}
    match=/^region put (\S+) (\S+)$/.exec(command);
    if(match){let value=entry(match[1]);if(!value){value=row(match[1]);state.entries.push(value);}value.parent=match[2];value.floodAllowed=!legacyPut;return response(command,legacyPut?'OK':'OK - (flood allowed)');}
    match=/^region (allowf|denyf) (\S+)$/.exec(command);
    if(match){const value=entry(match[2]);if(!value)return response(command,'Err - unknown region');value.floodAllowed=match[1]==='allowf';if(value.name==='*')state.wildcardFloodAllowed=value.floodAllowed;return response(command,'OK');}
    match=/^region home (\S+)$/.exec(command);if(match){if(!entry(match[1]))return response(command,'Err - unknown region');state.home=match[1];return response(command,'home is now '+state.home);}
    match=/^region default (\S+)$/.exec(command);if(match){state.default=match[1]==='<null>'?null:match[1];if(state.default!==null)entry(state.default).floodAllowed=true;return response(command,'default scope is now '+(state.default??'<null>'));}
    if(command==='region save'){saved=true;return response(command,'OK');}
    assert.fail('Unexpected region command');
  }};return link;
}
const mutations=link=>link.calls.filter(command=>!['region','region home','region default'].includes(command)&&!command.startsWith('region get '));

test('complete region capture preserves hierarchy, wildcard flood policy, home and default without writes',async()=>{
  for(const wrapped of [false,true]){
    const expected=snapshot([row('north'),row('west','north',false)],{wildcardFloodAllowed:false,home:'west',default:'north'}),link=mockRegions(expected,{wrapped}),result=await captureRegions(link);
    assert.equal(result.state,'complete');assert.deepEqual(result.data,validateRegions(expected));assert.deepEqual(mutations(link),[]);assert.ok(link.calls.includes('region get *'));assert.ok(link.calls.includes('region get west'));assert.equal(link.calls.filter(command=>command==='region').length,2);
  }
});

test('a console CRLF cannot disguise a truncated exporter body or a saturated buffer',async()=>{
  for(const body of ['*^ F','*^ F\n bad','*^ F\n'+(' '.repeat(153)),'*^ F\n bad\n'+(' '.repeat(147))]){
    const link=mockRegions(snapshot(),{hook:command=>command==='region'?'region\r\n  -> '+body+'\r\n':undefined}),result=await captureRegions(link);assert.equal(result.state,'unsupported',JSON.stringify(body));assert.deepEqual(mutations(link),[]);
  }
  const noOriginalFraming=mockRegions(snapshot(),{hook:command=>command==='region'?'region\n -> *^ F\n':undefined});assert.equal((await captureRegions(noOriginalFraming)).state,'unsupported');
});

test('private transport-key regions and unknown or ambiguous formats stay explicitly unsupported',async()=>{
  for(const body of ['*^ F\n $private F\n','*^ F\n unknown.name F\n','*^ F\n  skipped-parent F\n','* F\n no-home F\n']){
    const link=mockRegions(snapshot(),{hook:command=>command==='region'?body:undefined}),result=await captureRegions(link);assert.equal(result.state,'unsupported');assert.deepEqual(mutations(link),[]);
  }
  const unknown=mockRegions(snapshot(),{hook:command=>command==='region'?'Error: unknown command':undefined});assert.equal((await captureRegions(unknown)).state,'unsupported');
});

test('per-entry responses must match full names and flags, not a convenient prefix match',async()=>{
  const link=mockRegions(snapshot([row('north')]),{hook:command=>command==='region get north'?'northwest F':undefined}),result=await captureRegions(link);assert.equal(result.state,'error');assert.deepEqual(mutations(link),[]);
  const changed=mockRegions(snapshot([row('north')]),{hook:(command,device)=>{if(command==='region home'&&device.calls.filter(value=>value==='region home').length===2)return 'home is north';}});assert.equal((await captureRegions(changed)).state,'error');
});

test('snapshot validation rejects missing policies, parents, aliases, cycles and command injection',()=>{
  for(const invalid of [snapshot([row('a\nregion save')]),snapshot([row('$private')]),snapshot([row('#north')]),snapshot([row('north'),row('north')]),snapshot([row('a','missing')]),snapshot([row('a','b'),row('b','a')]),snapshot([row('a')],{home:'missing'}),snapshot([row('a')],{default:'missing'}),{...snapshot(),wildcardFloodAllowed:null},{...snapshot(),home:undefined},{...snapshot(),default:undefined},snapshot([row('x'.repeat(31))])])assert.throws(()=>validateRegions(invalid),/region|snapshot/i);
  assert.deepEqual(validateRegions(snapshot([row('a'),row('ab')])).entries,[row('a'),row('ab')],'Exact names win over prefixes; abbreviations are never generated');
});

test('region preview contains labels and merge limitations but never replay commands from JSON',()=>{
  const input=snapshot([row('north')]);input.command='region remove *';input.restore_method='region load';const result=regionRestorePreview(input);assert.equal(result.operations.length,1);assert.match(result.operations[0].label,/1 public regions/);assert.ok(result.warnings.some(message=>/unrelated target regions are retained/.test(message)));assert.ok(!JSON.stringify(result).includes('region remove'));
});

test('region restore creates parents first and preserves target extras while saving all source policies',async()=>{
  const link=mockRegions(snapshot([row('extra','*',false)],{default:'extra'})),source=snapshot([row('west','north',false),row('north')],{wildcardFloodAllowed:false,home:'west',default:'north'});
  const token=await prepareRegionRestore(link,source);assert.deepEqual(mutations(link),[]);const result=await restoreRegions(link,source,{prepared:token});
  const writes=mutations(link);assert.ok(writes.indexOf('region put north *')<writes.indexOf('region put west north'));assert.ok(writes.includes('region denyf *'));assert.ok(writes.includes('region denyf west'));assert.ok(writes.includes('region home west'));assert.equal(writes.at(-1),'region save');assert.ok(!writes.some(command=>/load|remove|reboot|erase/.test(command)));
  assert.equal(link.state.entries.find(entry=>entry.name==='extra').floodAllowed,false);assert.equal(link.state.entries.find(entry=>entry.name==='west').parent,'north');assert.equal(link.state.home,'west');assert.equal(link.state.default,'north');assert.equal(link.saved,true);assert.equal(result.saved,true);
});

test('legacy region-put default flood denial is read and safely restored after generic OK',async()=>{
  const link=mockRegions(snapshot(),{legacyPut:true}),source=snapshot([row('north')]);await restoreRegions(link,source);assert.deepEqual(mutations(link),['region put north *','region allowf north','region save']);assert.equal(link.state.entries[0].floodAllowed,true);
});

test('setting default first cannot accidentally re-enable a denied default region in the final map',async()=>{
  const link=mockRegions(snapshot([row('north','*',false)])),source=snapshot([row('north','*',false)],{default:'north'});await restoreRegions(link,source);assert.deepEqual(mutations(link),['region default north','region denyf north','region save']);assert.equal(link.state.entries[0].floodAllowed,false);
});

test('home can return to wildcard and default can explicitly return to null without deleting regions',async()=>{
  const source=snapshot([row('north')]),link=mockRegions(snapshot([row('north')],{home:'north',default:'north'}));await restoreRegions(link,source);assert.deepEqual(mutations(link),['region default <null>','region home *','region save']);assert.equal(link.state.entries.length,1);
});

test('an approved matching RAM map still must be saved and a failed save cannot claim success',async()=>{
  const source=snapshot([row('north')]),link=mockRegions(source),result=await restoreRegions(link,source);assert.deepEqual(mutations(link),['region save']);assert.equal(result.saved,true);assert.equal(result.restored[0].unchanged,true);
  const failed=mockRegions(source,{hook:command=>command==='region save'?'Err - save failed':undefined});await assert.rejects(restoreRegions(failed,source),/Region write.*rejected|confirmed/);assert.deepEqual(mutations(failed),['region save']);
});

test('preflight rejects an unverifiable merged export or capacity overflow before any mutation',async()=>{
  const source=snapshot(Array.from({length:5},(_,index)=>row('source'+index+'x'.repeat(14)))),target=snapshot(Array.from({length:5},(_,index)=>row('target'+index+'x'.repeat(14)))),link=mockRegions(target);
  await assert.rejects(prepareRegionRestore(link,source),error=>error.regionsUnsupported===true&&/merged region map/.test(error.message));assert.deepEqual(mutations(link),[]);
  const many=mockRegions(snapshot(Array.from({length:17},(_,index)=>row('t'+index))));await assert.rejects(prepareRegionRestore(many,snapshot(Array.from({length:17},(_,index)=>row('s'+index)))),/32-entry capacity/);assert.deepEqual(mutations(many),[]);
});

test('preflight approval is bound to its original link, source and unchanged target snapshot',async()=>{
  const source=snapshot([row('north')]),link=mockRegions(),token=await prepareRegionRestore(link,source),other=mockRegions();await assert.rejects(restoreRegions(other,source,{prepared:token}),/does not match/);assert.deepEqual(other.calls,[]);
  await assert.rejects(restoreRegions(link,snapshot([row('south')]),{prepared:token}),/does not match/);assert.deepEqual(mutations(link),[]);
  link.state.wildcardFloodAllowed=false;await assert.rejects(restoreRegions(link,source,{prepared:token}),/changed after preflight/);assert.deepEqual(mutations(link),[]);
});

test('selection guards run before and after serial reads and before each mutation',async()=>{
  let checks=0,current=true;const link=mockRegions(snapshot(),{hook:()=>{current=false;}}),result=await captureRegions(link,{assertCurrent:()=>{checks++;if(!current)throw Error('selection changed');}});assert.equal(result.state,'error');assert.equal(checks,2);assert.equal(link.calls.length,1);assert.deepEqual(mutations(link),[]);
  const source=snapshot([row('north')]),target=mockRegions();let identityChecks=0;await assert.rejects(restoreRegions(target,source,{beforeWrite:async()=>{identityChecks++;throw Error('identity changed');}}),/identity changed/);assert.equal(identityChecks,1);assert.deepEqual(mutations(target),[]);
});

test('readback mismatch or rejected region setter stops without automatic retries or final save',async()=>{
  const source=snapshot([row('north')]),rejected=mockRegions(snapshot(),{hook:command=>command.startsWith('region put ')?'Err - unable to put':undefined});await assert.rejects(restoreRegions(rejected,source),/Region write/);assert.deepEqual(mutations(rejected),['region put north *']);
  const mismatch=mockRegions(snapshot(),{hook:command=>command.startsWith('region put ')?'OK':undefined});await assert.rejects(restoreRegions(mismatch,source),/Region command|readback/);assert.deepEqual(mutations(mismatch),['region put north *']);
});

test('reparenting a reversed target hierarchy proceeds in a safe parent-first order',async()=>{
  const link=mockRegions(snapshot([row('a'),row('b','a')])),source=snapshot([row('a','b'),row('b')]);await restoreRegions(link,source);assert.deepEqual(mutations(link),['region put b *','region put a b','region save']);assert.equal(link.state.entries.find(entry=>entry.name==='b').parent,'*');
});
