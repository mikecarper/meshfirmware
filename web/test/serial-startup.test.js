import test from 'node:test';
import assert from 'node:assert/strict';
import {SerialLink} from '../src/serial.js';
import {detectApplication} from '../src/application-detection.js';

const encode=value=>new TextEncoder().encode(value);
const settle=async()=>{for(let i=0;i<5;i++)await Promise.resolve();};
function fixture({usbInfo={usbVendorId:0x10c4,usbProductId:0xea60},onDelay=async()=>{}}={}){
  const calls=[],delays=[],written=[],received=[];let controller,cancellations=0;
  const readable=new ReadableStream({start(value){controller=value;},cancel(){cancellations++;}});
  const port={
    getInfo:()=>usbInfo,readable,
    open:async options=>calls.push(['open',options]),
    setSignals:async value=>calls.push(['signals',value]),
    close:async()=>calls.push(['close']),
    writable:{getWriter:()=>({write:async value=>written.push([...value]),releaseLock(){}})},
  };
  const link=new SerialLink(port),f={port,link,calls,delays,written,received,
    get cancellations(){return cancellations;},
    async enqueue(value){const bytes=typeof value==='string'?encode(value):value;received.push(...bytes);controller.enqueue(bytes);await settle();},
    async readerError(error){controller.error(error);await settle();},
    async delay(ms){assert.equal(readable.locked,true,'the passive guard must start after the owned reader');delays.push(ms);await onDelay(ms,f);await settle();},
  };
  return f;
}
const uartOpenCalls=[['open',{baudRate:115200,flowControl:'none',bufferSize:65536}],['signals',{dataTerminalReady:false,requestToSend:false}]];
function assertPassiveUart(f){
  assert.deepEqual(f.calls.slice(0,2),uartOpenCalls);
  assert.equal(f.calls.filter(([kind])=>kind==='signals').length,1);
  assert.deepEqual(f.written,[],'startup waiting must never transmit a command or wakeup');
  assert.deepEqual(f.link.buffer,f.received,'startup inspection must preserve all received bytes');
}
async function close(f){await f.link.close();assert.equal(f.port.readable.locked,false);assert.equal(f.link.reader,null);}

test('fragmented ROM prefixes capture immutable startup evidence after only the passive UART guard',async()=>{
  for(const chunks of [['ESP-','ROM:esp32s3-20210327\r\n'],['\r\net','s Jun  8 2016 00:22:57\r\n']]){
    const f=fixture({onDelay:async(_ms,current)=>{
      if(current.delays.length===1)for(const chunk of chunks)await current.enqueue(chunk);
      else await current.enqueue(`app startup ${current.delays.length}\r\n`);
    }});
    await f.link.open(115200,{application:true,delay:f.delay});
    assert.deepEqual(f.delays,[100]);
    assert.deepEqual(f.link.startupEvidence,{observedRomBoot:true});assert.equal(Object.isFrozen(f.link.startupEvidence),true);
    assertPassiveUart(f);assert.equal(f.port.readable.locked,true);await close(f);assertPassiveUart(f);
  }
});

test('later repeated ROM banners do not extend open or replace its immutable startup evidence',async()=>{
  const f=fixture({onDelay:async(_ms,current)=>current.enqueue('ESP-ROM:repeated reboot\r\n')});
  await f.link.open(115200,{application:true,delay:f.delay});
  const evidence=f.link.startupEvidence;await f.enqueue('ESP-ROM:another reboot\r\n');
  assert.deepEqual(f.delays,[100]);assert.equal(f.link.startupEvidence,evidence);
  assertPassiveUart(f);await close(f);
});

test('an awake UART bridge gets only the initial 100ms passive guard with no startup progress',async()=>{
  for(const [usbVendorId,usbProductId] of [[0x10c4,0xea60],[0x1a86,0x7523],[0x0403,0x6001]]){
    const f=fixture({usbInfo:{usbVendorId,usbProductId},onDelay:async(_ms,current)=>current.enqueue('MeshCore is already running\r\n')});
    await f.link.open(115200,{application:true,delay:f.delay});
    assert.deepEqual(f.delays,[100]);assert.equal(f.link.startupEvidence,null);assertPassiveUart(f);await close(f);
  }
});

test('ROM markers must occur at a line prefix, not inside application logs, names or partial lookalikes',async()=>{
  for(const text of ['node name ESP-ROM:radio\r\n','INFO ets Jun  8 2016\r\n',' ESP-ROM:esp32s3\r\n','ESP-ROMx:esp32s3\r\n','ets unknown message\r\n','pets Jun 8 2016\r\n']){
    const f=fixture({onDelay:async(_ms,current)=>current.enqueue(text)});
    await f.link.open(115200,{application:true,delay:f.delay});
    assert.deepEqual(f.delays,[100],text);assert.equal(f.link.startupEvidence,null);assertPassiveUart(f);await close(f);
  }
});

test('native USB, DFU, unknown IDs and non-application opens do not acquire a UART startup delay',async()=>{
  for(const {usbInfo,application,dtr} of [
    {usbInfo:{usbVendorId:0x303a,usbProductId:0x1001},application:true,dtr:true},
    {usbInfo:{usbVendorId:0x239a,usbProductId:0x0029},application:true,dtr:false},
    {usbInfo:{usbVendorId:0x1234,usbProductId:0x5678},application:true,dtr:false},
    {usbInfo:{},application:true,dtr:false},
    {usbInfo:{usbVendorId:0x10c4,usbProductId:0xea60},application:false,dtr:false},
  ]){
    const f=fixture({usbInfo});await f.enqueue('ESP-ROM:must not change this connection path\r\n');
    await f.link.open(115200,{application,delay:f.delay});await settle();
    assert.deepEqual(f.delays,[]);assert.deepEqual(f.written,[]);
    assert.equal(f.link.startupEvidence,null);
    assert.deepEqual(f.calls,[['open',{baudRate:115200,flowControl:'none',bufferSize:65536}],['signals',{dataTerminalReady:dtr,requestToSend:false}]]);
    assert.deepEqual(f.link.buffer,f.received);await close(f);
  }
});

test('a banner arriving after the initial awake guard does not start a second wait',async()=>{
  const f=fixture();await f.link.open(115200,{application:true,delay:f.delay});
  await f.enqueue('ESP-ROM:late application output\r\n');
  assert.deepEqual(f.delays,[100]);assert.equal(f.link.startupEvidence,null);assertPassiveUart(f);await close(f);
});

test('invalid startup delays fail before opening or signaling a port',async()=>{
  for(const options of [{delay:null},{delay:1}]){
    const f=fixture();await assert.rejects(f.link.open(115200,{application:true,...options}),/startup|callback|delay/i);
    assert.deepEqual(f.calls,[]);assert.equal(f.port.readable.locked,false);assert.deepEqual(f.written,[]);
  }
});

test('each open clears stale boot evidence and bytes before observing this connection',async()=>{
  const f=fixture();f.link.startupEvidence=Object.freeze({observedRomBoot:true});f.link.buffer.push(...encode('ESP-ROM:previous open\r\n'));
  await f.link.open(115200,{application:true,delay:f.delay});
  assert.equal(f.link.startupEvidence,null);assert.deepEqual(f.delays,[100]);assertPassiveUart(f);await close(f);
});

test('a passive guard delay failure closes ownership and retains the original error',async()=>{
  for(const failureAt of [1]){
    const original=new Error('injected delay failed'),f=fixture({onDelay:async(_ms,current)=>{
      if(current.delays.length===1)await current.enqueue('ESP-ROM:esp32s3\r\n');
      if(current.delays.length===failureAt)throw original;
    }});
    await assert.rejects(f.link.open(115200,{application:true,delay:f.delay}),error=>error===original);
    assert.equal(f.calls.filter(([kind])=>kind==='close').length,1);assert.equal(f.cancellations,1);
    assert.equal(f.port.readable.locked,false);assert.equal(f.link.reader,null);assertPassiveUart(f);
    assert.equal(f.delays.length,failureAt);
  }
});

test('a reader failure during the passive guard propagates unchanged and closes the port',async()=>{
  for(const failureAt of [1]){
    const original=Object.assign(new Error('synthetic serial reader failed'),{name:'NetworkError'});
    const f=fixture({onDelay:async(_ms,current)=>{
      if(current.delays.length===1)await current.enqueue('ESP-ROM:esp32s3\r\n');
      if(current.delays.length===failureAt)await current.readerError(original);
    }});
    await assert.rejects(f.link.open(115200,{application:true,delay:f.delay}),error=>error===original);
    assert.equal(f.calls.filter(([kind])=>kind==='close').length,1);
    assert.equal(f.port.readable.locked,false);assert.equal(f.link.reader,null);assertPassiveUart(f);
    assert.equal(f.delays.length,failureAt);
  }
});

test('observed UART boots with API readiness at 5601ms or 15715ms use one bounded adaptive window on the same real SerialLink',async()=>{
  for(const readyAtMs of [5601,15715]){
  let elapsedMs=0,bootSent=false,identifiedAt=null;const bootEvents=[],probes=[],stages=[];
  const f=fixture({onDelay:async(ms,current)=>{
    const next=elapsedMs+ms;
    if(!bootSent&&next>=31){elapsedMs=31;bootSent=true;bootEvents.push(elapsedMs);await current.enqueue('ESP-ROM:esp32s3-20210327\r\n');}
    elapsedMs=next;
  }});
  const publicKey='52'.repeat(32),self=new Uint8Array(66),info=new Uint8Array(82);
  self.set([5,1,22,22]);self.set(Uint8Array.from({length:32},()=>0x52),4);self.set(encode('TestV3'),58);
  info.set([13,14,50,40]);info.set(encode('24-Oct-2026'),8);info.set(encode('Heltec V3'),20);info.set(encode('v1.18.0-81dbae5'),60);
  const framed=payload=>Uint8Array.from([0x3e,payload.length&255,payload.length>>8,...payload]);
  const meshtasticProbes=[];
  f.port.writable={getWriter:()=>({
    async write(bytes){
      f.written.push([...bytes]);probes.push({elapsedMs,bytes:[...bytes]});
      if((bytes[0]===0x94&&bytes[1]===0xc3)||(bytes.length===32&&bytes.every(byte=>byte===0xc3))){meshtasticProbes.push(elapsedMs);return;}
      if(elapsedMs<readyAtMs)return; // The measured device ignores premature API requests.
      if(bytes[0]!==0x3c)return; // Stock binary mode ignores the read-only text/Full probes.
      const command=bytes[3];assert.ok([1,22,66].includes(command),'Only read-only Companion identity requests are allowed');
      if(command===1)identifiedAt=elapsedMs;
      if(command===66)assert.equal(new TextDecoder().decode(bytes.subarray(4)),'version');
      await f.enqueue(framed(command===1?self:command===22?info:Uint8Array.from([29,...encode('Unknown command')])));
    },
    releaseLock(){},
  })};
  await f.link.open(115200,{application:true,delay:f.delay});
  assert.deepEqual(bootEvents,[31]);assert.equal(elapsedMs,100);assertPassiveUart(f);
  // Retain the real streams, reader and byte buffer; replace only wall-clock
  // waits with a virtual clock. This would fail if probing stopped at 8s.
  f.link.command=async function(command,ms){this.buffer.length=0;await this.write(encode(command+'\r\n'));elapsedMs+=ms;await settle();return new TextDecoder().decode(await SerialLink.prototype.read.call(this,0));};
  f.link.read=async function(ms){const bytes=await SerialLink.prototype.read.call(this,0);if(bytes.length)return bytes;elapsedMs+=ms;await settle();return new Uint8Array();};
  const device=await detectApplication(f.link,{now:()=>elapsedMs,delay:f.delay,onProgress:event=>stages.push(event)});
  assert.equal(device.firmwareFamily,'meshcore');assert.equal(device.role,'companion');assert.equal(device.publicKey,publicKey);assert.equal(device.model,'Heltec V3');
  assert.ok(probes.length>0);assert.equal(probes[0].elapsedMs,100);assert.ok(identifiedAt>=readyAtMs&&identifiedAt<25000);
  assert.ok(meshtasticProbes.length>0);assert.ok(meshtasticProbes[0]<4000,'Meshtastic gets an early short probe instead of waiting for the whole boot window');
  assert.ok(meshtasticProbes.every(time=>time<identifiedAt),'No other protocol may run after MeshCore is identified');
  assert.ok(stages.every(event=>event.stage==='startup'&&event.timeoutSeconds===25));assert.equal(stages[0].elapsedSeconds,0);
  assert.deepEqual(f.calls.slice(0,2),uartOpenCalls);assert.equal(f.calls.filter(([kind])=>kind==='open').length,1);
  assert.equal(f.calls.filter(([kind])=>kind==='signals').length,1);await close(f);
  }
});
