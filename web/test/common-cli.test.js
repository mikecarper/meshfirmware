import test from 'node:test';
import assert from 'node:assert/strict';
import {ed25519} from '@noble/curves/ed25519';
import {bytesToHex} from '@noble/hashes/utils.js';
import {COMMON_CLI_COMMANDS,COMMON_CLI_OPTIONAL_COMMANDS,commonCliReplyState,commonCliRestorePreview,restoreCommonCli} from '../src/common-cli.js';

const publicKey=bytesToHex(ed25519.ExtendedPoint.BASE.toRawBytes()),otherKey='22'.repeat(32),privateKey='01'+'00'.repeat(63);
const reply=(command,value)=>`${command}\r\n  -> > ${value}\r\n`;
const snapshot=(replies={},extra={})=>({role:'common-cli',publicKey,replies:{'get role':reply('get role','repeater'),board:'board\nHeltec V4.2 none detected',...replies},...extra});
function mockLink(values={},hook=null){
  const state={'get public.key':publicKey,'get role':'repeater',board:'Heltec V4.2 none detected',...values},calls=[];
  const api={calls,state,async command(command){calls.push(command);const overridden=hook?.(command,api);if(overridden!==undefined)return overridden;
    if(command.startsWith('get ')||command==='board')return reply(command,Object.hasOwn(state,command)?state[command]:'Error: unsupported');
    if(command.startsWith('set prv.key '))return `${command}\n  -> OK, reboot to apply! New pubkey: ${publicKey}`;
    if(command.startsWith('password ')){state['get password']=command.slice(9);return `${command}\n  -> password now: ${state['get password']}`;}
    if(command.startsWith('powersaving ')){state['get powersaving']=command.slice(12);return `${command}\n  -> OK - powersaving ${state['get powersaving']}`;}
    if(command.startsWith('setperm ')){const [,key,permissions]=command.split(' '),row=`${Number(permissions).toString(16).padStart(2,'0')} ${key}`;state['get acl']=(state['get acl']||'ACL:')+'\n'+row;return command+'\n -> OK';}
    const match=/^set ([^ ]+) (.*)$/.exec(command);assert.ok(match,'Only reviewed setters may execute');state['get '+match[1]]=match[2];
    return command+'\n -> '+(match[1].startsWith('wifi.')?'OK - WiFi setting saved; reboot to apply':'OK');
  }};return api;
}
const writes=link=>link.calls.filter(command=>!command.startsWith('get ')&&command!=='board');

test('capture inventory includes expanded exposed settings but never destructive or consuming commands',()=>{
  assert.equal(new Set(COMMON_CLI_COMMANDS).size,COMMON_CLI_COMMANDS.length);
  for(const command of ['get radio2','get radio2.cross','board','get radio.rxgain','get radio.cad','get usb.logging','get radio.rxps.config','get password','get guest.password','get wifi.pwd'])assert.ok(COMMON_CLI_COMMANDS.includes(command),command);
  assert.ok(COMMON_CLI_OPTIONAL_COMMANDS.includes('get system.watchdog'));assert.ok(!COMMON_CLI_COMMANDS.includes('get public.key'));
  assert.ok(COMMON_CLI_COMMANDS.every(command=>command.startsWith('get ')||['board','ver','region'].includes(command)));
  assert.ok(!COMMON_CLI_COMMANDS.some(command=>/message|reboot|erase|reset|set |prv\.key /.test(command)));
});

test('reply classification removes exact legacy echoes and prompts without treating errors as complete',()=>{
  assert.deepEqual(commonCliReplyState(reply('get name','Radio'),'get name'),{state:'complete',text:'Radio'});
  for(const raw of ['get system.watchdog\n -> Error: unsupported on this platform','unknown config','Unknown command: get radio.rxgain','Error: unknown setting: usb.logging','Error, unknown command'])assert.equal(commonCliReplyState(raw,'get system.watchdog').state,'unsupported');
  for(const raw of ['get name\n -> Error: query failed','','\0bad','x'.repeat(8193)])assert.equal(commonCliReplyState(raw,'get name').state,'error');
  assert.equal(commonCliReplyState('\x1b[32m> off\x1b[0m','get usb.logging').text,'off');
  assert.equal(commonCliReplyState('get wifi.pwd\n -> > \n','get wifi.pwd').state,'complete');
  assert.equal(commonCliReplyState('get guest.password\n -> > \n','get guest.password').text,'');
  assert.equal(commonCliReplyState('get name\n -> > \n','get name').state,'error');
});

test('preview creates only reviewed inverse commands and reports unsupported and manual snapshots',()=>{
  const plan=commonCliRestorePreview(snapshot({'get name':reply('get name','Restored radio'),'get lat':'> 47.6','get radio':'> 911.3,500,8,7','get system.watchdog':'> Error: unsupported','get acl':'ACL:','region':'region tree','reboot':'erase'}));
  assert.deepEqual(plan.operations.map(row=>row.id),['name','lat','radio']);assert.deepEqual(plan.operations[0].commands,['set name Restored radio']);assert.deepEqual(plan.operations[2].commands,['set radio 911.3,500,8,7']);
  assert.ok(plan.warnings.some(message=>/automatic preamble/.test(message)));assert.ok(plan.skipped.some(row=>row.label==='Regions'));assert.ok(plan.skipped.some(row=>row.id==='reboot'));assert.ok(!plan.operations.some(row=>/erase|reboot/.test(row.commands.join(' '))));
});

test('malicious known values and malformed numbers fail before opening USB',()=>{
  for(const [command,value] of [['get name','safe\nreboot'],['get name','bad\tname'],['get lat','999'],['get radio','911,125,10,5;erase'],['get radio2.cross','on\nset name hacked'],['get tx','1e8'],['get display.rotation','45']])assert.throws(()=>commonCliRestorePreview(snapshot({[command]:reply(command,value)})),/invalid|nothing was restored/i,command);
  assert.throws(()=>commonCliRestorePreview(snapshot({'get prv.key':'> '+'00'.repeat(64)})),/private identity/i);
  assert.throws(()=>commonCliRestorePreview(snapshot({'get prv.key':'> '+privateKey},{publicKey:otherKey})),/private identity/i);
});

test('expanded structured values use exact reviewed setter syntax without metadata suffixes',()=>{
  const plan=commonCliRestorePreview(snapshot({'get radio2':'> 911.300,500.000,8,7,rxtx,32 (auto); WARN preamble recommendation','get radio2.cross':'> auto','get radio.rxps.config':'> on,level=4,preamble=32,rx=8192,sleep=1000','get radio.cad':'radio.cad on, scan=auto(12) ms, retry=50 ms, max=500 ms, busy=3','get display.rotation':'display.rotation default','get flood.channel.data':'> on h>3','get bluetooth.name':'> MeshCore radio (default from node name)'}));
  assert.deepEqual(plan.operations.find(row=>row.id==='radio2').commands,['set radio2 911.3,500,8,7,rxtx,auto']);
  assert.deepEqual(plan.operations.find(row=>row.id==='radio.rxps.config').commands,['set radio.rxps level 4 preamble 32']);
  assert.deepEqual(plan.operations.find(row=>row.id==='radio.cad').commands,['set radio.cad timings auto 50 500','set radio.cad on']);
  assert.deepEqual(plan.operations.find(row=>row.id==='display.rotation').commands,['set display.rotation 0']);
  assert.deepEqual(plan.operations.find(row=>row.id==='flood.channel.data').commands,['set flood.channel.data.hops 3','set flood.channel.data on']);
  assert.deepEqual(plan.operations.find(row=>row.id==='bluetooth.name').commands,['set bluetooth.name default']);
});

test('automatic-owned radio2 and masked or whitespace-ambiguous credentials remain manual',()=>{
  for(const value of ['off (automatic allowed)','911,125,10,5,rx,32; auto-owned'])assert.ok(commonCliRestorePreview(snapshot({'get radio2':'> '+value})).skipped.some(row=>row.id==='radio2'));
  for(const [command,value] of [['get wifi.ssid','(not configured)'],['get wifi.pwd','******** (local connection only)'],['get password',' secret ']]){
    const plan=commonCliRestorePreview(snapshot({[command]:reply(command,value)}));assert.equal(plan.operations.length,0);assert.ok(plan.skipped.length);
  }
});

test('moving hardware preserves board-specific settings while retaining transferable name and radio tuple',()=>{
  const p=snapshot({'get name':'> Name','get tx':'> 22','get radio.rxgain':'> on','get display.rotation':'display.rotation 90','get powersaving':'> on','get radio':'> 911.3,125,10,5'}),plan=commonCliRestorePreview(p,{newHardware:true});
  assert.deepEqual(plan.operations.map(row=>row.id),['name','radio']);for(const id of ['tx','radio.rxgain','display.rotation','powersaving'])assert.ok(plan.skipped.some(row=>row.id===id&&/Hardware-specific/.test(row.reason)));
});

test('restore probes every target setting before any setter and verifies each readback',async()=>{
  const link=mockLink({'get name':'Before','get lat':'0','get repeat':'off'}),p=snapshot({'get repeat':'> on','get lat':'> 47.6','get name':'> After'}),result=await restoreCommonCli(link,p);
  assert.deepEqual(writes(link),['set name After','set lat 47.6','set repeat on']);const first=link.calls.indexOf('set name After');for(const get of ['get repeat','get lat','get name'])assert.ok(link.calls.indexOf(get)<first);
  assert.deepEqual(result.restored.map(row=>row.id),['name','lat','repeat']);assert.equal(result.identityPendingReboot,false);assert.equal(link.state['get public.key'],publicKey);
});

test('unchanged values are verified without writes and unsupported targets are explicit skips',async()=>{
  const link=mockLink({'get name':'Same'}),result=await restoreCommonCli(link,snapshot({'get name':'> Same','get radio.rxgain':'> on'}));assert.deepEqual(writes(link),[]);assert.equal(result.restored[0].unchanged,true);assert.ok(result.skipped.some(row=>row.id==='radio.rxgain'));
  const noSupport=mockLink(),none=await restoreCommonCli(noSupport,snapshot({'get name':'> Name'}));assert.equal(none.restored.length,0);assert.ok(none.warnings.some(message=>/No target settings were changed/.test(message)));assert.deepEqual(writes(noSupport),[]);
});

test('target automatic secondary radio ownership is kept without blocking unrelated supported settings',async()=>{
  const link=mockLink({'get name':'Old','get radio2':'off (automatic allowed)'}),result=await restoreCommonCli(link,snapshot({'get name':'> New','get radio2':'> off'}));
  assert.deepEqual(writes(link),['set name New']);assert.ok(result.skipped.some(row=>row.id==='radio2'&&/automatic/.test(row.reason)));assert.equal(link.state['get radio2'],'off (automatic allowed)');
});

test('identity and role gates reject companion, wrong role, absent identity, or unauthorized replacement before mutation',async()=>{
  for(const [state,error] of [[{'get role':'companionFull'},/CommonCLI role/],[{'get role':'sensor'},/roles differ/],[{'get public.key':'not a key'},/CommonCLI application/],[{'get public.key':otherKey},/replacement approval/]]){
    const link=mockLink({'get name':'Old',...state});await assert.rejects(restoreCommonCli(link,snapshot({'get name':'> New'})),error);assert.deepEqual(writes(link),[]);
  }
  const link=mockLink({'get public.key':otherKey});await assert.rejects(restoreCommonCli(link,snapshot({'get name':'> New'}),{replaceIdentity:true}),/private key is unavailable/);assert.deepEqual(writes(link),[]);
});

test('captured board mismatch needs explicit hardware migration; catalog hints are not physical board proof',async()=>{
  const source=snapshot({'get name':'> New'}),link=mockLink({board:'RAK4631','get name':'Old'});await assert.rejects(restoreCommonCli(link,source),/Moving to different hardware/);assert.deepEqual(writes(link),[]);
  const result=await restoreCommonCli(link,source,{newHardware:true});assert.equal(result.restored[0].id,'name');
  const hinted=snapshot({'get name':'> New'},{nativeSource:{deviceHint:'Heltec v4'}});delete hinted.replies.board;const advisory=mockLink({'get name':'Old'});assert.ok((await restoreCommonCli(advisory,hinted)).warnings.some(message=>/board identity could not be compared/.test(message)));
});

test('private identity is staged last with explicit replacement and exact echoed ACK, never rebooted',async()=>{
  const source=snapshot({'get name':'> New','get prv.key':'> '+privateKey}),link=mockLink({'get public.key':otherKey,'get name':'Old'}),result=await restoreCommonCli(link,source,{replaceIdentity:true});
  assert.deepEqual(writes(link),['set name New','set prv.key '+privateKey]);assert.equal(result.identityPendingReboot,true);assert.equal(result.restartRequired,true);assert.equal(link.state['get public.key'],otherKey);assert.ok(result.warnings.some(message=>/not active or startup-verified/.test(message)));assert.ok(!link.calls.includes('reboot'));
});

test('identity save confirmation mismatch exposes no private key and never reboots',async()=>{
  const link=mockLink({'get public.key':otherKey},command=>command.startsWith('set prv.key ')?command+'\n -> OK, reboot to apply! New pubkey: '+otherKey:undefined);
  await assert.rejects(restoreCommonCli(link,snapshot({'get prv.key':'> '+privateKey}),{replaceIdentity:true}),error=>/not confirmed/.test(error.message)&&!error.message.includes(privateKey));assert.ok(!link.calls.includes('reboot'));
});

test('credential setters use correct console verbs; saved Wi-Fi changes are not claimed active',async()=>{
  const source=snapshot({'get password':reply('get password','secret123'),'get guest.password':reply('get guest.password',''),'get wifi.ssid':reply('get wifi.ssid','Network name'),'get wifi.pwd':reply('get wifi.pwd','wifi secret')}),link=mockLink({'get password':'old','get guest.password':'old','get wifi.ssid':'old','get wifi.pwd':'old'}),result=await restoreCommonCli(link,source);
  assert.deepEqual(writes(link),['password secret123','set guest.password ','set wifi.ssid Network name','set wifi.pwd wifi secret']);assert.equal(result.restartRequired,true);assert.ok(result.warnings.some(message=>/later manual reboot/.test(message)));assert.ok(!link.calls.includes('reboot'));
});

test('ACL restore merges only full-key permission rows without deleting existing entries',async()=>{
  const source=snapshot({'get acl':`ACL:\n03 ${otherKey}`}),link=mockLink({'get acl':`ACL:\n01 ${'33'.repeat(32)}`}),result=await restoreCommonCli(link,source);
  assert.deepEqual(writes(link),[`setperm ${otherKey} 3`]);assert.equal(result.restored[0].id,'acl');assert.ok(link.state['get acl'].includes('33'.repeat(32)));assert.ok(result.warnings.some(message=>/merged/.test(message)));
  for(const raw of [`ACL 1/2\n03 ${otherKey}`,`ACL:\n03 ${otherKey.slice(0,20)}`,`ACL:\n00 ${otherKey}`])assert.ok(!commonCliRestorePreview(snapshot({'get acl':raw})).operations.length);
});

test('archive insertion order cannot enable logging before core or ACL restoration',()=>{
  const plan=commonCliRestorePreview(snapshot({'get usb.logging':'> on','get acl':`ACL:\n01 ${otherKey}`,'get name':'> Name'}));assert.deepEqual(plan.operations.map(row=>row.id),['name','acl','usb.logging']);
});

test('preflight errors, setter rejections, readback mismatches and identity changes stop without retry',async()=>{
  const source=snapshot({'get name':'> New','get lat':'> 47.6'});
  const unreadable=mockLink({'get name':'Old','get lat':'Error: query failed'});await assert.rejects(restoreCommonCli(unreadable,source),/No settings were written/);assert.deepEqual(writes(unreadable),[]);
  const rejected=mockLink({'get name':'Old','get lat':'0'},command=>command.startsWith('set name ')?command+'\n -> Error: rejected':undefined);await assert.rejects(restoreCommonCli(rejected,source),/was rejected/);assert.deepEqual(writes(rejected),['set name New']);
  const mismatch=mockLink({'get name':'Old','get lat':'0'},command=>command.startsWith('set name ')?command+'\n -> OK':undefined);await assert.rejects(restoreCommonCli(mismatch,source),/readback did not match/);assert.deepEqual(writes(mismatch),['set name New']);
  const switched=mockLink({'get name':'Old','get lat':'0'},(command,link)=>{if(command==='set name New')link.state['get public.key']=otherKey;});await assert.rejects(restoreCommonCli(switched,source),/Target identity changed/);assert.deepEqual(writes(switched),['set name New']);
});

test('context guard runs on both sides of every request and stale selections cannot write',async()=>{
  let current=true,checks=0;const link=mockLink({'get name':'Old'},()=>{current=false;});await assert.rejects(restoreCommonCli(link,snapshot({'get name':'> New'}),{assertCurrent:()=>{checks++;if(!current)throw Error('Selection changed');}}),/Selection changed/);assert.equal(checks,2);assert.equal(link.calls.length,1);assert.deepEqual(writes(link),[]);
});

test('transport failures and rejected secret setters never expose archived secrets in errors',async()=>{
  const secret='private-words',source=snapshot({'get password':reply('get password',secret)}),link=mockLink({'get password':'old'},command=>{if(command.startsWith('password '))throw Error(command+' denied');});
  await assert.rejects(restoreCommonCli(link,source),error=>!error.message.includes(secret)&&/Serial request failed/.test(error.message));
});

test('diagnostics-only archives cannot claim a supported-settings restore',async()=>{
  const link=mockLink();await assert.rejects(restoreCommonCli(link,snapshot({ver:'v1.18.0','region':'Regions:'})),/no supported settings/);assert.deepEqual(link.calls,[]);
});
