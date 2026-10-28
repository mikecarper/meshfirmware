import test from 'node:test';
import assert from 'node:assert/strict';
import {commonCliRestorePreview,restoreCommonCli} from '../src/common-cli.js';

const key='11'.repeat(32);
const regions=()=>({schema:'org.meshfirmware.regions/v1',entries:[],wildcardFloodAllowed:false,home:'*',default:null});
const source=(data=regions())=>({role:'common-cli',publicKey:key,replies:{'get role':'> repeater',board:'Board','get name':'> Same',region:'*^ F\n'},regions:{state:'complete',data}});
function radio({truncated=false,failSave=false,changeIdentity=false,changeName=false}={}){
  const state={key,name:'Same',wildcardFloodAllowed:true,home:'*',default:null,entries:[]},calls=[];
  const find=name=>name==='*'?{name:'*',parent:'*',floodAllowed:state.wildcardFloodAllowed}:state.entries.find(row=>row.name===name);
  const tree=()=>{let text='';const visit=(name,depth)=>{const row=find(name);text+=' '.repeat(depth)+name+(state.home===name?'^':'')+(row.floodAllowed?' F':'')+'\n';for(const child of state.entries.filter(item=>item.parent===name))visit(child.name,depth+1);};visit('*',0);return text;};
  return {calls,state,async command(command){
    calls.push(command);if(command==='get public.key')return '> '+state.key;if(command==='get role')return '> repeater';if(command==='board')return 'Board';if(command==='get name')return '> '+state.name;
    if(command==='region')return 'region\r\n  -> '+(truncated?'x'.repeat(159):tree())+'\r\n';
    if(command==='region home')return 'home is '+state.home;if(command==='region default')return 'default scope is '+(state.default??'<null>');
    if(command.startsWith('region get ')){const row=find(command.slice(11));return row?' '+row.name+(row.parent==='*'?'':` (${row.parent})`)+(row.floodAllowed?' F':''):'Err - unknown region';}
    if(command.startsWith('region list ')){const all=[find('*'),...state.entries],allowed=command.endsWith('allowed');return all.filter(row=>row.floodAllowed===allowed).map(row=>row.name).join(',')||'-none-';}
    if(command.startsWith('set name ')){state.name=command.slice(9);return 'OK';}
    if(command.startsWith('region ')){
      if(changeName)state.name='Changed';if(changeIdentity)state.key='22'.repeat(32);
      const [,verb,name,parent='*']=command.split(' ');
      if(verb==='save')return failSave?'Err - save failed':'OK';
      if(verb==='put'){const row=find(name);if(name==='*')throw Error('Wildcard must not be recreated');if(row){row.parent=parent;row.floodAllowed=true;}else state.entries.push({name,parent,floodAllowed:true});return 'OK - (flood allowed)';}
      if(verb==='allowf'||verb==='denyf'){const row=find(name);assert.ok(row);if(name==='*')state.wildcardFloodAllowed=verb==='allowf';else row.floodAllowed=verb==='allowf';return 'OK';}
      if(verb==='home'){state.home=name;return 'home is now '+name;}
      if(verb==='default'){state.default=name==='<null>'?null:name;if(state.default)find(state.default).floodAllowed=true;return 'default scope is now '+name;}
    }
    throw Error('Unexpected test command');
  }};
}
const setters=link=>link.calls.filter(command=>/^(?:region (?:put |allowf |denyf |home |default |save$)|set )/.test(command));

test('typed regions replace the legacy manual-only report and precede radio settings in the restore plan',()=>{
  const preview=commonCliRestorePreview(source());assert.deepEqual(preview.operations.map(row=>row.id),['regions','name']);assert.ok(!preview.skipped.some(row=>row.id==='region'));assert.ok(preview.warnings.some(text=>/merg/i.test(text)));
});

test('regions are preflighted and saved first; subsequent values are reread rather than skipped from stale evidence',async()=>{
  const link=radio({changeName:true}),result=await restoreCommonCli(link,source());assert.ok(result.restored.some(row=>row.id==='regions'));assert.ok(result.restored.some(row=>row.id==='name'));assert.equal(link.state.wildcardFloodAllowed,false);assert.equal(link.state.name,'Same');
  const firstMutation=link.calls.findIndex(command=>setters({calls:[command]}).length);assert.ok(link.calls.indexOf('get name')<firstMutation);assert.ok(link.calls.indexOf('region save')<link.calls.indexOf('set name Same'));assert.ok(link.calls.filter(command=>command==='get name').length>=3);
});

test('an unsupported or truncated target region export is skipped without region writes while other settings can restore',async()=>{
  const link=radio({truncated:true});link.state.name='Before';const result=await restoreCommonCli(link,source());assert.ok(result.skipped.some(row=>row.id==='regions'));assert.deepEqual(setters(link),['set name Same']);assert.equal(link.state.name,'Same');
});

test('region save failures stop the later scalar setters and do not claim restore success',async()=>{
  const link=radio({failSave:true});link.state.name='Before';await assert.rejects(restoreCommonCli(link,source()),/region|save/i);assert.ok(link.calls.includes('region save'));assert.ok(!link.calls.includes('set name Same'));
});

test('region mutations retain the CommonCLI target identity guard before the next write',async()=>{
  const link=radio({changeIdentity:true});await assert.rejects(restoreCommonCli(link,source()),/identity changed/);assert.equal(setters(link).length,1);assert.ok(!link.calls.includes('region save'));assert.ok(!link.calls.includes('set name Same'));
});
