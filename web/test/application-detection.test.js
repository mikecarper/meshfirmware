import test from 'node:test';
import assert from 'node:assert/strict';
import {detectApplication} from '../src/application-detection.js';
const request=[0x94,0xc3,0,4,0x18,0xac,0x9e,4];
const wake=Array(32).fill(0xc3);
const frame=value=>[0x94,0xc3,value.length>>8,value.length&255,...value];
const identity=Uint8Array.from([...frame([0x1a,2,8,9]),...frame([0x6a,9,0x0a,5,...new TextEncoder().encode('2.7.4'),0x48,69])]);
const options={meshCoreTimeoutMs:1,meshtasticTimeoutMs:10};
function radio(){
  const commands=[],writes=[],queue=[],buffer=[];
  return {commands,writes,buffer,command:async command=>{commands.push(command);return 'Unknown command';},write:async value=>{writes.push([...value]);if(value[0]===0x94)queue.push(identity);},read:async ms=>{if(queue.length)return queue.shift();await new Promise(resolve=>setTimeout(resolve,Math.min(ms,1)));return new Uint8Array();}};
}

test('existing MeshCore identity takes precedence without sending a Meshtastic query',async()=>{
  const link=radio();link.command=async command=>command==='get public.key'?'> '+'11'.repeat(32):command==='get name'?'> My MeshCore':command==='board'?'> Heltec T114':command==='get role'?'> repeater':'> v1.18.0';
  const events=[],result=await detectApplication(link,{...options,onProgress:event=>events.push(event)});assert.equal(result.firmwareFamily,'meshcore');assert.equal(result.model,'Heltec T114');assert.equal(result.role,'common-cli');assert.equal(link.writes.length,0);assert.deepEqual(events,[{stage:'meshcore'}]);
});

test('Meshtastic fallback uses the same selected serial connection and returns only its local identity',async()=>{
  const link=radio(),events=[],result=await detectApplication(link,{...options,onProgress:event=>events.push(event)});assert.equal(result.firmwareFamily,'meshtastic');assert.equal(result.meshtasticHardware,69);assert.equal(result.publicKey,null);assert.equal(result.nodeNum,9);assert.deepEqual(link.writes.slice(-2),[wake,request]);assert.ok(!link.commands.some(command=>/^set |reboot/.test(command)));assert.deepEqual(events,[{stage:'meshcore'},{stage:'meshtastic',elapsedSeconds:0,timeoutSeconds:1}]);
});

test('progress errors are not protocol failures and never start a fallback or retry',async()=>{
  const first=radio();let calls=0;await assert.rejects(detectApplication(first,{...options,onProgress:()=>{calls++;throw Error('UI stopped');}}),/UI stopped/);assert.equal(calls,1);assert.equal(first.commands.length,0);assert.equal(first.writes.length,0);
  const later=radio(),events=[];await assert.rejects(detectApplication(later,{...options,onProgress:event=>{events.push(event);if(event.stage==='meshtastic')throw Error('UI stopped');}}),/UI stopped/);assert.deepEqual(events.map(event=>event.stage),['meshcore','meshtastic']);assert.deepEqual(later.writes.slice(-2),[wake,request]);
  const invalid=radio();await assert.rejects(detectApplication(invalid,{...options,onProgress:null}),/progress callback/);assert.equal(invalid.commands.length,0);assert.equal(invalid.writes.length,0);
});

test('a stale progress callback cannot revive a changed selection or launch any probe',async()=>{
  const link=radio(),events=[];let current=true;
  await assert.rejects(detectApplication(link,{...options,assertCurrent:()=>{if(!current)throw Error('Selection changed');},onProgress:event=>{events.push(event);current=false;}}),/Selection changed/);assert.deepEqual(events,[{stage:'meshcore'}]);assert.equal(link.commands.length,0);assert.equal(link.writes.length,0);
  const lost=radio(),lostEvents=[];lost.command=async()=>{throw Error('Port disconnected');};await assert.rejects(detectApplication(lost,{...options,onProgress:event=>lostEvents.push(event)}),/Port disconnected/);assert.deepEqual(lostEvents,[{stage:'meshcore'}]);
});

test('a Meshtastic startup log containing a public key is not mistaken for MeshCore CommonCLI',async()=>{
  for(const reply of ['INFO Loaded public key '+ '11'.repeat(32)+'\r\n','DEBUG signing key='+ '22'.repeat(32),'not-a-getter: '+ '33'.repeat(32)]){
    const link=radio();link.command=async command=>{link.commands.push(command);return command==='get public.key'?reply:'Unknown command';};
    const result=await detectApplication(link,options);assert.equal(result.firmwareFamily,'meshtastic');assert.equal(result.meshtasticHardware,69);assert.ok(!link.commands.includes('get name'));assert.ok(!link.commands.includes('board'));
  }
});

test('genuine transport failures never launch a fallback probe on a disconnected or locked port',async()=>{
  for(const stage of ['command','read']){
    const link=radio();link[stage]=async()=>{throw Error('Port unavailable');};await assert.rejects(detectApplication(link,options),/Port unavailable/);assert.ok(!link.writes.some(value=>value[0]===0x94));
  }
});

test('context changes stop detection before a fallback query or before accepting a result',async()=>{
  const before=radio();await assert.rejects(detectApplication(before,{...options,assertCurrent:()=>{throw Error('Selection changed');}}),/Selection changed/);assert.equal(before.commands.length,0);assert.equal(before.writes.length,0);
  const mid=radio();let current=true;mid.command=async()=>{current=false;return 'Unknown command';};await assert.rejects(detectApplication(mid,{...options,assertCurrent:()=>{if(!current)throw Error('Selection changed');}}),/Selection changed/);assert.equal(mid.writes.length,0);
  const late=radio(),write=late.write;current=true;late.write=async value=>{await write(value);if(value[0]===0x94)current=false;};await assert.rejects(detectApplication(late,{...options,assertCurrent:()=>{if(!current)throw Error('Selection changed');}}),/Selection changed/);
});

test('an unidentified application remains manual with a useful error rather than an assumed board',async()=>{
  const link=radio();link.write=async value=>{link.writes.push([...value]);};await assert.rejects(detectApplication(link,options),error=>error.code==='APPLICATION_UNIDENTIFIED'&&/No supported MeshCore or Meshtastic application/.test(error.message));
});
