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
  for(const stage of ['command','read','write'])for(const name of ['NotAllowedError','SecurityError','NetworkError','NotFoundError','Error']){
    const link=radio(),original=Object.assign(Error('Port unavailable'),{name});link[stage]=async()=>{throw original;};
    await assert.rejects(detectApplication(link,options),error=>{assert.equal(error,original);assert.equal(Object.hasOwn(error,'usbSerialAvailable'),false);return true;});
    assert.ok(!link.writes.some(value=>value[0]===0x94));
  }
});

test('context changes stop detection before a fallback query or before accepting a result',async()=>{
  const before=radio();await assert.rejects(detectApplication(before,{...options,assertCurrent:()=>{throw Error('Selection changed');}}),/Selection changed/);assert.equal(before.commands.length,0);assert.equal(before.writes.length,0);
  const mid=radio();let current=true;mid.command=async()=>{current=false;return 'Unknown command';};await assert.rejects(detectApplication(mid,{...options,assertCurrent:()=>{if(!current)throw Error('Selection changed');}}),/Selection changed/);assert.equal(mid.writes.length,0);
  const late=radio(),write=late.write;current=true;late.write=async value=>{await write(value);if(value[0]===0x94)current=false;};await assert.rejects(detectApplication(late,{...options,assertCurrent:()=>{if(!current)throw Error('Selection changed');}}),/Selection changed/);
});

test('an unidentified application remains manual with a useful error rather than an assumed board',async()=>{
  const link=radio();link.write=async value=>{link.writes.push([...value]);};
  await assert.rejects(detectApplication(link,options),error=>{
    assert.equal(error.code,'APPLICATION_UNIDENTIFIED');
    assert.equal(error.usbSerialAvailable,true);
    assert.match(error.message,/USB serial communication is available.*running firmware could not be identified/);
    assert.match(error.message,/No supported MeshCore or Meshtastic application/);
    assert.match(error.message,/serial driver is available because this USB port opened/);
    assert.match(error.message,/Standalone firmware such as Ripple Ultra may not expose these supported USB APIs/);
    assert.match(error.message,/may not provide a USB API.*BLE-only Companion/);
    assert.match(error.message,/exact hardware manually.*matching USB-enabled firmware/);
    assert.match(error.message,/No reset or firmware write was sent/);
    assert.doesNotMatch(error.message,/INFO_UF2|bootloader drive|install.*driver/i);
    assert.doesNotMatch(error.message,/Ripple Ultra (?:detected|identified)|T-Deck (?:detected|identified)/i);
    return true;
  });
  assert.ok(!link.commands.some(command=>/^set |reboot/.test(command)));
});

function bootingRadio({observedRomBoot=true,meshCoreAt=Infinity,meshtasticAt=Infinity,conflictingKeys=false,failure=null,failureStage=null}={}){
  let elapsed=0;
  const calls=[],commands=[],writes=[],queue=[],events=[],buffer=[];
  const advance=ms=>{assert.ok(Number.isFinite(ms)&&ms>=0,`invalid fake wait ${ms}`);elapsed+=ms;};
  const link={buffer,startupEvidence:Object.freeze({observedRomBoot}),
    command:async(command,ms)=>{
      calls.push({kind:'command',command,at:elapsed,ms});commands.push(command);advance(ms);
      if(failureStage==='command')throw failure;
      if(elapsed<meshCoreAt)return '';
      if(command==='get public.key')return '11'.repeat(32)+(conflictingKeys?'\r\n'+'22'.repeat(32):'');
      return {'get name':'Booted radio',ver:'v1.18.0',board:'Heltec V3','get role':'repeater'}[command]||'Unknown command';
    },
    write:async bytes=>{
      const kind=bytes[0]===0x3c?'meshcore':bytes[0]===0x94?'meshtastic-request':bytes.length===32&&bytes.every(byte=>byte===0xc3)?'meshtastic-wake':'full-terminal';
      calls.push({kind,at:elapsed,bytes:[...bytes]});writes.push([...bytes]);
      if(failureStage==='write')throw failure;
      if(kind==='meshtastic-request'&&elapsed>=meshtasticAt)queue.push(identity);
    },
    read:async ms=>{
      calls.push({kind:'read',at:elapsed,ms});advance(ms);
      if(failureStage==='read')throw failure;
      return queue.shift()||new Uint8Array();
    },
  };
  return {link,calls,commands,writes,events,now:()=>elapsed,delay:async ms=>{calls.push({kind:'delay',at:elapsed,ms});advance(ms);},progress:event=>events.push({...event})};
}
const bootOptions=f=>({now:f.now,delay:f.delay,onProgress:f.progress});
const mtRequests=f=>f.calls.filter(call=>call.kind==='meshtastic-request');
function assertStartupOnly(events){
  assert.ok(events.length>0);
  assert.ok(events.every(event=>event.stage==='startup'&&event.timeoutSeconds===25));
  assert.equal(events[0].elapsedSeconds,0);
  assert.ok(events.every((event,index)=>Number.isInteger(event.elapsedSeconds)&&event.elapsedSeconds>=0&&event.elapsedSeconds<=25&&(!index||event.elapsedSeconds>events[index-1].elapsedSeconds)));
}

test('observed-ROM detection tries Meshtastic early on the same link rather than sleeping through its startup',async()=>{
  const f=bootingRadio({meshtasticAt:0}),result=await detectApplication(f.link,bootOptions(f));
  assert.equal(result.firmwareFamily,'meshtastic');assert.equal(result.meshtasticHardware,69);
  assert.equal(mtRequests(f).length,1);assert.ok(f.now()<4000,`ready Meshtastic took ${f.now()}ms`);
  assert.equal(f.commands.filter(command=>command==='get public.key').length,1);
  assertStartupOnly(f.events);
  assert.ok(!f.commands.some(command=>/^set |reboot|erase/.test(command)));
});

test('an immediate MeshCore identity with ROM evidence wins without sending Meshtastic packets',async()=>{
  const f=bootingRadio({meshCoreAt:0}),result=await detectApplication(f.link,bootOptions(f));
  assert.equal(result.firmwareFamily,'meshcore');assert.equal(result.model,'Heltec V3');assert.equal(result.publicKey,'11'.repeat(32));
  assert.equal(result.catalogRole,'repeater');assert.deepEqual(f.writes,[]);
  assert.deepEqual(f.commands,['get public.key','get name','ver','board','get role']);assertStartupOnly(f.events);
});

test('a late MeshCore application can identify within the one ROM-startup budget without another port open',async()=>{
  const f=bootingRadio({meshCoreAt:15000}),result=await detectApplication(f.link,bootOptions(f));
  assert.equal(result.firmwareFamily,'meshcore');assert.equal(result.model,'Heltec V3');
  assert.ok(f.commands.filter(command=>command==='get public.key').length>1);
  assert.ok(mtRequests(f).length>0);assert.ok(f.now()>=15000&&f.now()<=25000);
  const metadata=f.calls.find(call=>call.kind==='command'&&call.command==='get name');
  assert.ok(metadata);assert.ok(mtRequests(f).every(call=>call.at<metadata.at));assertStartupOnly(f.events);
});

test('ROM silence has one 25-second total deadline with bounded MeshCore, Full-terminal and Meshtastic phases',async()=>{
  const f=bootingRadio();
  await assert.rejects(detectApplication(f.link,bootOptions(f)),error=>error.code==='APPLICATION_UNIDENTIFIED'&&error.usbSerialAvailable===true);
  assert.ok(f.now()<=25000,`startup exceeded its total budget: ${f.now()}ms`);
  assert.ok(f.now()>=24000,`startup stopped unexpectedly early: ${f.now()}ms`);
  assert.ok(mtRequests(f).length>1,'the same budget should alternate read-only protocols');
  assertStartupOnly(f.events);assert.equal(f.events.at(-1).elapsedSeconds,25);
  const transfers=f.calls.filter(call=>['meshcore','full-terminal','meshtastic-wake','meshtastic-request'].includes(call.kind));
  for(let index=1;index<transfers.length;index++){
    const previous=transfers[index-1],current=transfers[index];
    if(previous.kind==='meshcore'&&current.kind==='full-terminal')assert.ok(current.at-previous.at<=1500,'a MeshCore request exceeded 1500ms');
    if(previous.kind==='full-terminal'&&current.kind==='meshtastic-wake')assert.ok(current.at-previous.at<=700,'raw Full-terminal recovery exceeded 700ms');
    if(previous.kind==='meshtastic-request'&&current.kind==='meshcore')assert.ok(current.at-previous.at<=1500,'Meshtastic acquired a second long wait');
  }
  for(let index=0;index<f.calls.length;index++)if(f.calls[index].kind==='meshtastic-wake'){
    const nextMeshCore=f.calls.slice(index+1).find(call=>call.kind==='command'&&call.command==='get public.key');
    if(nextMeshCore)assert.ok(nextMeshCore.at-f.calls[index].at<=1100,'Meshtastic wake and read phases exceeded their 1000ms budget plus the inter-probe 100ms pause');
  }
  assert.ok(f.calls.filter(call=>call.kind==='read').every(call=>call.ms<=1500));
});

test('without observed ROM evidence normal detection remains one MeshCore attempt then its normal Meshtastic fallback',async()=>{
  for(const evidence of [undefined,Object.freeze({observedRomBoot:false})]){
    const link=radio(),events=[];link.startupEvidence=evidence;let elapsed=0;
    const result=await detectApplication(link,{meshCoreTimeoutMs:1,now:()=>elapsed,delay:async ms=>{elapsed+=ms;},onProgress:event=>events.push(event)});
    assert.equal(result.firmwareFamily,'meshtastic');assert.equal(link.commands.filter(command=>command==='get public.key').length,1);
    assert.equal(link.writes.filter(bytes=>bytes[0]===0x94).length,1);
    assert.deepEqual(events.map(event=>event.stage),['meshcore','meshtastic']);
    assert.equal(events.at(-1).timeoutSeconds,25,'a non-ROM port retains the normal Meshtastic wait window');
    assert.ok(!events.some(event=>event.stage==='startup'));
  }
});

test('an identified MeshCore identity conflict never retries or launches Meshtastic during startup',async()=>{
  const f=bootingRadio({meshCoreAt:0,conflictingKeys:true});
  await assert.rejects(detectApplication(f.link,bootOptions(f)),error=>error.meshcoreApplicationIdentified===true&&error.code==='MESHCORE_IDENTITY_CONFLICT');
  assert.deepEqual(f.commands,['get public.key']);assert.deepEqual(f.writes,[]);assertStartupOnly(f.events);
});

test('fatal command, read and write errors preserve the original failure and never acquire adaptive retry authority',async()=>{
  for(const failureStage of ['command','read','write'])for(const name of ['NotAllowedError','SecurityError','NetworkError','NotFoundError','Error']){
    const original=Object.assign(new Error('Synthetic port unavailable'),{name}),f=bootingRadio({failure:original,failureStage});
    await assert.rejects(detectApplication(f.link,bootOptions(f)),error=>{assert.equal(error,original);assert.equal(Object.hasOwn(error,'usbSerialAvailable'),false);return true;});
    assert.equal(f.commands.filter(command=>command==='get public.key').length,1);
    assert.equal(mtRequests(f).length,0);assert.ok(f.writes.length<=1,`${failureStage}/${name} allowed a later write`);assertStartupOnly(f.events);
  }
});

test('stale selection or a startup progress failure stops the adaptive run without issuing another operation',async()=>{
  const stale=bootingRadio(),original=Error('Selection changed');let current=true;
  const command=stale.link.command;stale.link.command=async(...args)=>{const result=await command(...args);current=false;return result;};
  await assert.rejects(detectApplication(stale.link,{...bootOptions(stale),assertCurrent:()=>{if(!current)throw original;}}),error=>{assert.equal(error,original);assert.equal(Object.hasOwn(error,'usbSerialAvailable'),false);return true;});
  assert.deepEqual(stale.commands,['get public.key']);assert.deepEqual(stale.writes,[]);
  for(const failureAt of [0,1]){
    const f=bootingRadio(),progressError=Error('Startup display stopped');let callsAtFailure=-1;
    await assert.rejects(detectApplication(f.link,{...bootOptions(f),onProgress:event=>{
      f.progress(event);if(event.elapsedSeconds>=failureAt){callsAtFailure=f.calls.length;throw progressError;}
    }}),error=>error===progressError);
    assert.ok(callsAtFailure>=0);assert.equal(f.calls.length,callsAtFailure);assert.equal(mtRequests(f).length,0);
  }
});

test('MeshCore-only detection never sends Meshtastic and only observed ROM permits bounded repeated MeshCore attempts',async()=>{
  const boot=bootingRadio();
  await assert.rejects(detectApplication(boot.link,{...bootOptions(boot),meshCoreOnly:true}),error=>error.code==='APPLICATION_UNIDENTIFIED');
  assert.ok(boot.commands.filter(command=>command==='get public.key').length>1);assert.ok(boot.now()<=25000);
  assert.equal(mtRequests(boot).length,0);assertStartupOnly(boot.events);
  const awake=radio();awake.startupEvidence={observedRomBoot:false};awake.write=async bytes=>awake.writes.push([...bytes]);
  await assert.rejects(detectApplication(awake,{...options,meshCoreOnly:true}),/MeshCore|companion|response|timed out/i);
  assert.equal(awake.commands.filter(command=>command==='get public.key').length,1);
  assert.ok(!awake.writes.some(bytes=>bytes[0]===0x94||bytes.length===32&&bytes.every(byte=>byte===0xc3)));
});
