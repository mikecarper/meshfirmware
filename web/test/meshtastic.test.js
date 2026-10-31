import {test} from 'node:test';
import assert from 'node:assert/strict';
import {detectMeshtastic} from '../src/meshtastic.js';

const utf8=value=>new TextEncoder().encode(value);
const concat=(...parts)=>Uint8Array.from(parts.flatMap(value=>Array.from(value)));
const varint=value=>{let n=BigInt(value),out=[];do{let b=Number(n&127n);n>>=7n;if(n)b|=128;out.push(b);}while(n);return Uint8Array.from(out);};
const number=(id,value)=>concat(varint(id*8),varint(value));
const bytes=(id,value)=>concat(varint(id*8+2),varint(value.length),value);
const frame=payload=>concat([0x94,0xc3,payload.length>>8,payload.length&255],payload);
const local=(node,extras=[])=>frame(bytes(3,concat(number(1,node),extras)));
const meta=(hardware=69,version='2.7.4.abc123',extras=[])=>frame(bytes(13,concat(bytes(1,utf8(version)),number(9,hardware),extras)));
const nodeInfo=(node,{name='Local node',shortName='LC',hardware=69}={})=>frame(bytes(4,concat(number(1,node),bytes(2,concat(bytes(2,utf8(name)),bytes(3,utf8(shortName)),number(5,hardware))))));
const request=[0x94,0xc3,0,4,0x18,0xac,0x9e,4];
const wake=Array(32).fill(0xc3),noDelay=async ms=>{assert.equal(ms,100);};
function fixture(chunks,buffer=[]){
  const queue=chunks.map(chunk=>chunk instanceof Error?chunk:Uint8Array.from(chunk)),writes=[];let reads=0;
  return {buffer:[...buffer],writes,get reads(){return reads;},async write(value){writes.push([...value]);},async read(ms){reads++;const value=queue.shift();if(value instanceof Error)throw value;if(value)return value;await new Promise(resolve=>setTimeout(resolve,ms));return new Uint8Array();}};
}
const detect=(link,options={})=>detectMeshtastic(link,{timeoutMs:15,delay:noDelay,...options});

test('minimal nodeless config request reads the local T114 identity without settings, reset or RF commands',async()=>{
  const link=fixture([local(0x12345678),nodeInfo(0x12345678),meta()]);
  const result=await detect(link);assert.deepEqual(link.writes,[wake,request]);assert.equal(link.reads,3);
  assert.deepEqual(result,{firmwareFamily:'meshtastic',role:'meshtastic',meshtasticHardware:69,meshtasticRole:0,meshtasticRoleName:'CLIENT',model:'Meshtastic hardware 69',nodeNum:0x12345678,name:'Local node',version:'2.7.4.abc123',catalogRole:null,publicKey:null});
});

test('the same read-only local metadata query reports every Meshtastic role without fetching configuration',async()=>{
  const names=['CLIENT','CLIENT_MUTE','ROUTER','ROUTER_CLIENT','REPEATER','TRACKER','SENSOR','TAK','CLIENT_HIDDEN','LOST_AND_FOUND','TAK_TRACKER','ROUTER_LATE','CLIENT_BASE'];
  for(const [role,name] of names.entries()){
    const link=fixture([concat(local(9),meta(69,'2.7.15',number(7,role))),new Error('No additional role query or reads needed')]),result=await detect(link);
    assert.equal(result.meshtasticRole,role);assert.equal(result.meshtasticRoleName,name);assert.equal(result.role,'meshtastic');assert.equal(result.catalogRole,null);assert.deepEqual(link.writes,[wake,request]);assert.equal(link.reads,1);
  }
});

test('an omitted role is CLIENT per proto3 and an unknown future enum is retained without guessing a known role',async()=>{
  for(const extras of [[],number(7,0)]){
    const result=await detect(fixture([meta(69,'2.7.15',extras),local(9)]));assert.equal(result.meshtasticRole,0);assert.equal(result.meshtasticRoleName,'CLIENT');
  }
  const result=await detect(fixture([local(9),meta(69,'2.8.0',number(7,12345))]));assert.equal(result.meshtasticRole,12345);assert.equal(result.meshtasticRoleName,'Unknown role 12345');assert.equal(result.catalogRole,null);
});

test('local role metadata survives fragmented frames and is not taken from a node name or other configuration',async()=>{
  const stream=concat(local(9),nodeInfo(77,{name:'ROUTER_LATE'}),nodeInfo(9,{name:'CLIENT_BASE'}),frame(bytes(5,utf8('ROUTER'))),meta(69,'2.7.15',number(7,1)));
  for(let split=1;split<stream.length;split++){
    const result=await detect(fixture([stream.subarray(0,split),stream.subarray(split)]));assert.equal(result?.meshtasticRole,1,`split ${split}`);assert.equal(result.meshtasticRoleName,'CLIENT_MUTE');
  }
});

test('conflicting or malformed local device roles do not become a firmware-selection hint',async()=>{
  assert.equal(await detect(fixture([meta(69,'2.7.15',number(7,2)),meta(69,'2.7.15',number(7,11)),local(9)])),null);
  for(const extras of [bytes(7,[2]),concat(number(7,2),number(7,12)),number(7,0x80000000),number(7,0x100000000n)])assert.equal(await detect(fixture([local(9),meta(69,'2.7.15',extras)])),null);
});

test('official SDK my_info fixture and device metadata identity are compatible',async()=>{
  // my_info bytes from the native hermetic test were serialized by the official
  // installed Meshtastic SDK. The metadata hardware byte is T114 enum69.
  const info=Uint8Array.from(Buffer.from('1a1c08f8acd191016a1473656565645f7869616f5f6e726635325f6b6974','hex'));
  const metadata=Uint8Array.from(Buffer.from('6a100a0c322e372e342e6162633132334845','hex'));
  const result=await detect(fixture([frame(info),frame(metadata)]));assert.equal(result.nodeNum,0x12345678);assert.equal(result.meshtasticHardware,69);assert.equal(result.version,'2.7.4.abc123');
  assert.equal(result.meshtasticPioEnv,'seeed_xiao_nrf52_kit');
});

test('the local compiled target distinguishes a legacy RAK3401 image without a second query',async()=>{
  const info=local(9,bytes(13,utf8('rak3401-1watt'))),metadata=meta(9,'2.7.11.47bf2b4a');
  for(const stream of [concat(info,metadata),concat(metadata,info)]){
    for(let split=1;split<stream.length;split++){
      const link=fixture([stream.subarray(0,split),stream.subarray(split)]),result=await detect(link);
      assert.equal(result?.meshtasticPioEnv,'rak3401-1watt');assert.equal(result.meshtasticHardware,9);assert.equal(result.nodeNum,9);assert.equal(link.reads,2);assert.deepEqual(link.writes,[wake,request]);
    }
  }
});

test('missing or empty build targets preserve old firmware support and remote display names cannot supply one',async()=>{
  for(const info of [local(9),local(9,bytes(13,[]))]){
    const result=await detect(fixture([info,nodeInfo(9,{name:'rak3401-1watt'}),nodeInfo(77,{name:'rak3401-1watt'}),meta(9)]));
    assert.equal(result.meshtasticHardware,9);assert.equal(Object.hasOwn(result,'meshtasticPioEnv'),false);
  }
});

test('malformed, ambiguous or conflicting local build targets cannot become selection evidence',async()=>{
  for(const extras of [number(13,9),bytes(13,utf8('x'.repeat(41))),bytes(13,[0xc3,0x28]),bytes(13,utf8('rak3401-1watt\n')),bytes(13,utf8(' rak3401-1watt')),bytes(13,utf8('../rak3401-1watt')),concat(bytes(13,utf8('rak3401-1watt')),bytes(13,utf8('rak4631')))]){
    assert.equal(await detect(fixture([local(9,extras),meta(9)])),null);
  }
  const first=local(9,bytes(13,utf8('rak3401-1watt'))),other=local(9,bytes(13,utf8('rak4631')));
  assert.equal(await detect(fixture([first,other,meta(9)])),null);
  for(const reports of [[first,first],[local(9),first],[first,local(9)]]){
    const result=await detect(fixture([...reports,meta(9)]));assert.equal(result?.meshtasticPioEnv,'rak3401-1watt');
  }
});

test('official wake bytes resynchronize the Meshtastic firmware receiver before asking for identity',async()=>{
  const receiver=()=>{
    let pending=[0x94]; // Firmware was left waiting for START2 by a prior client.
    const queue=[],writes=[];
    return {buffer:[],writes,async write(value){
      writes.push([...value]);
      for(const byte of value){
        if(!pending.length){if(byte===0x94)pending=[byte];continue;}
        if(pending.length===1){pending=byte===0xc3?[...pending,byte]:[];continue;}
        pending.push(byte);
        if(pending.length<4)continue;
        const length=pending[2]*256+pending[3];
        if(length>512){pending=[];continue;}
        if(pending.length===length+4){
          if(pending.join(',')===request.join(','))queue.push(concat(local(9),meta(110,'2.7.15.567b8ea')));
          pending=[];
        }
      }
    },async read(){return queue.shift()||new Uint8Array();}};
  };
  const control=receiver();await control.write(request);assert.equal((await control.read()).length,0,'a query alone is swallowed by the partial firmware framing state');
  const link=receiver(),delays=[];
  const result=await detect(link,{delay:async ms=>{delays.push(ms);assert.deepEqual(link.writes,[wake]);}});
  assert.equal(result?.meshtasticHardware,110);assert.equal(result.version,'2.7.15.567b8ea');assert.deepEqual(delays,[100]);assert.deepEqual(link.writes,[wake,request]);
});

test('a slow Meshtastic 2.7.15 native-USB console can answer after its twenty-second idle poll',async()=>{
  let elapsed=0,reads=0;const writes=[];
  const link={buffer:[],async write(value){writes.push([...value]);},async read(ms){reads++;elapsed+=ms;return elapsed>=20000?concat(local(9),meta(110,'2.7.15.567b8ea')):new Uint8Array();}};
  const result=await detectMeshtastic(link,{now:()=>elapsed,delay:noDelay});assert.equal(result?.meshtasticHardware,110);assert.equal(elapsed,20000);assert.equal(reads,200);assert.deepEqual(writes,[wake,request]);
  elapsed=0;reads=0;assert.equal(await detectMeshtastic(link,{timeoutMs:1800,now:()=>elapsed,delay:noDelay}),null);assert.equal(elapsed,1800);assert.equal(reads,18);
  elapsed=0;reads=0;link.read=async ms=>{reads++;elapsed+=ms;return new Uint8Array();};assert.equal(await detectMeshtastic(link,{now:()=>elapsed,delay:noDelay}),null);assert.equal(elapsed,25000);assert.equal(reads,250);
});

test('normal Meshtastic replies still return immediately without waiting for the longer deadline',async()=>{
  let elapsed=0;const link=fixture([concat(local(9),meta())]);
  const result=await detectMeshtastic(link,{delay:noDelay,now:()=>elapsed});assert.equal(result?.nodeNum,9);assert.equal(link.reads,1);assert.equal(elapsed,0);
});

test('progress reports elapsed seconds from the actual query window and clamps a late read to the deadline',async()=>{
  const events=[],times=[1000,2000,27000];let elapsed=0,reads=0;
  const link=fixture([]);link.read=async()=>{reads++;elapsed=times.shift();return new Uint8Array();};
  assert.equal(await detectMeshtastic(link,{now:()=>elapsed,delay:noDelay,onProgress:event=>events.push(event)}),null);
  assert.deepEqual(events,[0,1,2,25].map(elapsedSeconds=>({stage:'meshtastic',elapsedSeconds,timeoutSeconds:25})));assert.equal(reads,3);assert.deepEqual(link.writes,[wake,request]);
  await new Promise(resolve=>setImmediate(resolve));assert.equal(events.length,4,'no background timer can emit after completion');
});

test('progress emits at most once per second, including the final timeout tick without extra reads',async()=>{
  const events=[];let elapsed=0,reads=0;
  const link=fixture([]);link.read=async ms=>{reads++;elapsed+=ms;return new Uint8Array();};
  assert.equal(await detectMeshtastic(link,{now:()=>elapsed,delay:noDelay,onProgress:event=>events.push(event)}),null);
  assert.deepEqual(events.map(event=>event.elapsedSeconds),Array.from({length:26},(_,index)=>index));assert.ok(events.every(event=>event.timeoutSeconds===25));assert.equal(reads,250);assert.equal(elapsed,25000);
});

test('a fast identity only reports zero seconds and never waits for a progress tick',async()=>{
  const events=[],link=fixture([concat(local(9),meta())]);let elapsed=0;
  const result=await detectMeshtastic(link,{delay:async ms=>{assert.equal(ms,100);assert.equal(events.length,0);assert.deepEqual(link.writes,[wake]);},now:()=>elapsed,onProgress:event=>{assert.deepEqual(link.writes,[wake,request]);events.push(event);}});
  assert.equal(result.nodeNum,9);assert.deepEqual(events,[{stage:'meshtastic',elapsedSeconds:0,timeoutSeconds:25}]);assert.equal(link.reads,1);
});

test('progress callback failures and stale context cannot emit later ticks or trigger retries',async()=>{
  const failed=fixture([]),events=[];
  await assert.rejects(detect(failed,{onProgress:event=>{events.push(event);throw Error('Progress stopped');}}),/Progress stopped/);assert.equal(failed.reads,0);assert.deepEqual(failed.writes,[wake,request]);assert.equal(events.length,1);
  const later=fixture([]),laterEvents=[];let elapsed=0;later.read=async()=>{elapsed=1000;return new Uint8Array();};
  await assert.rejects(detectMeshtastic(later,{delay:noDelay,now:()=>elapsed,onProgress:event=>{laterEvents.push(event);if(event.elapsedSeconds)throw Error('Progress stopped');}}),/Progress stopped/);assert.deepEqual(laterEvents.map(event=>event.elapsedSeconds),[0,1]);assert.deepEqual(later.writes,[wake,request]);
  const stale=fixture([concat(local(9),meta())]);let current=true;
  await assert.rejects(detect(stale,{assertCurrent:()=>{if(!current)throw Error('Selection changed');},onProgress:()=>{current=false;}}),/Selection changed/);assert.equal(stale.reads,0);
  const lost=fixture([new Error('Port disconnected')]),lostEvents=[];
  await assert.rejects(detect(lost,{onProgress:event=>lostEvents.push(event)}),/Port disconnected/);assert.equal(lostEvents.length,1);await new Promise(resolve=>setImmediate(resolve));assert.equal(lostEvents.length,1);
});

test('serial frames survive fragmentation at every byte boundary, leading logs and concatenation',async()=>{
  const stream=concat(utf8('DEBUG start\r\n'),local(0x12345678),nodeInfo(0x12345678),meta());
  for(let split=1;split<stream.length;split++){
    const result=await detect(fixture([stream.subarray(0,split),stream.subarray(split)]));assert.equal(result?.meshtasticHardware,69,`split ${split}`);
  }
  assert.equal((await detect(fixture([...stream].map(byte=>[byte]))))?.nodeNum,0x12345678);
});

test('future fields and uninterpreted configuration payloads do not hide the local identity',async()=>{
  const unknown=concat(number(100,150),varint(101*8+1),new Uint8Array(8),varint(102*8+5),new Uint8Array(4),bytes(103,utf8('future')));
  const link=fixture([concat(local(9),frame(bytes(5,utf8('configuration-not-decoded'))),meta(69,'2.8.0.preview',unknown))]);
  assert.equal((await detect(link)).meshtasticHardware,69);assert.deepEqual(link.writes,[wake,request]);
});

test('remote node names and hardware can never select the attached board',async()=>{
  const link=fixture([nodeInfo(77,{hardware:43,name:'Remote V3'}),local(9),nodeInfo(77,{hardware:43,name:'Remote V3'}),meta(69)]),result=await detect(link);
  assert.equal(result.meshtasticHardware,69);assert.equal(result.nodeNum,9);assert.equal(result.name,'');
  assert.equal(await detect(fixture([local(9),nodeInfo(77,{hardware:69}),frame(number(7,69420))])),null);
});

test('an invalid optional local display name cannot obscure valid board metadata',async()=>{
  for(const name of [' Local node','Line\nBreak','\0']){
    const result=await detect(fixture([local(9),nodeInfo(9,{name}),meta()]));assert.equal(result?.meshtasticHardware,69);assert.equal(result.name,'');
  }
  const result=await detect(fixture([local(9),frame(bytes(4,[0xff])),meta()]));assert.equal(result?.nodeNum,9);
});

test('metadata first still requires a local node and unknown hardware remains a reported enum, never a guess',async()=>{
  const result=await detect(fixture([meta(123456),local(9)]));assert.equal(result.meshtasticHardware,123456);assert.equal(result.name,'');
  for(const packets of [[meta()],[local(9)],[frame(number(7,69420))],[],[utf8('MeshCore ready\r\n')]])assert.equal(await detect(fixture(packets)),null);
});

test('preexisting input is cleared before sending the query and cannot satisfy identity discovery',async()=>{
  const link=fixture([local(9)],[...meta()]);assert.equal(await detect(link),null);assert.deepEqual(link.buffer,[]);assert.deepEqual(link.writes,[wake,request]);
});

test('stops once identity is sufficient without requesting, parsing or logging subsequent inventory/packets',async()=>{
  const secret='PRIVATE_CHANNEL_SECRET',link=fixture([concat(local(9),meta(),frame(bytes(5,utf8(secret))),frame(bytes(2,utf8(secret)))),new Error('Must not drain further packets')]);
  const result=await detect(link);assert.equal(link.reads,1);assert.ok(!JSON.stringify(result).includes(secret));assert.deepEqual(link.writes,[wake,request]);
});

test('re-synchronizes corrupted framing lengths while bounding absent or truncated frames',async()=>{
  assert.equal((await detect(fixture([concat([0x94,0xc3,0,0,0x94,0xc3,0xff,0xff],local(9),meta())])))?.meshtasticHardware,69);
  for(const raw of [[0x94,0xc3,0,20,8],new Array(9000).fill(0x41)])assert.equal(await detect(fixture([raw])),null);
  assert.equal((await detect(fixture([concat(local(9),meta(),new Uint8Array(10000))])))?.nodeNum,9);
});

test('malformed protobuf wire fields, invalid identity numbers and ambiguous payloads fail closed',async()=>{
  const badPayloads=[
    [0], [0x80], [0x1a,0x80], [0x1a,3,8], [9,1], [13,1], [14,1],
    [8,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,2],
    concat(bytes(3,number(1,9)),bytes(13,concat(bytes(1,utf8('2.7.4')),number(9,69)))),
    bytes(3,number(1,0)),bytes(3,number(1,0xffffffff)),bytes(3,number(1,0x100000000n)),bytes(3,concat(number(1,9),number(1,10))),
    bytes(3,bytes(1,[9])),bytes(13,concat(bytes(1,utf8('2.7.4')),number(9,0))),
    bytes(13,concat(bytes(1,utf8('2.7.4')),number(9,69),number(9,43))),
    bytes(13,concat(bytes(1,[0xc3,0x28]),number(9,69))),bytes(13,concat(bytes(1,utf8('2.7.4\nreboot')),number(9,69))),
  ];
  for(const payload of badPayloads)assert.equal(await detect(fixture([frame(payload),local(9),meta()])),null,Buffer.from(payload).toString('hex'));
});

test('conflicting local identities or metadata before completion cannot choose a board',async()=>{
  assert.equal(await detect(fixture([local(9),local(10),meta()])),null);
  assert.equal(await detect(fixture([meta(69),meta(43),local(9)])),null);
  assert.equal(await detect(fixture([meta(69,'2.7.4'),meta(69,'2.7.5'),local(9)])),null);
});

test('receive flood limits are bounded and do not produce a partial identity',async()=>{
  const ignored=frame(bytes(6,utf8('log'))),frames=concat(...Array.from({length:513},()=>ignored));
  assert.equal(await detect(fixture([frames,local(9),meta()])),null);
  assert.equal(await detect(fixture([new Uint8Array(128*1024+1),local(9),meta()])),null);
});

test('transport and context failures propagate before any later serial request',async()=>{
  const writeFailure=fixture([]);writeFailure.write=async()=>{throw Error('Port gone');};await assert.rejects(detect(writeFailure),/Port gone/);
  await assert.rejects(detect(fixture([new Error('Read failed')])),/Read failed/);
  const before=fixture([]);await assert.rejects(detect(before,{assertCurrent:()=>{throw Error('Selection changed');}}),/Selection changed/);assert.equal(before.writes.length,0);
  const afterWrite=fixture([]);let checks=0;await assert.rejects(detect(afterWrite,{assertCurrent:()=>{if(++checks===2)throw Error('Selection changed');}}),/Selection changed/);assert.equal(afterWrite.reads,0);
  const duringWake=fixture([]);let current=true;await assert.rejects(detect(duringWake,{delay:async ms=>{assert.equal(ms,100);current=false;},assertCurrent:()=>{if(!current)throw Error('Selection changed');}}),/Selection changed/);assert.deepEqual(duringWake.writes,[wake]);assert.equal(duringWake.reads,0);
  const configFailure=fixture([]);configFailure.write=async value=>{configFailure.writes.push([...value]);if(value[0]===0x94)throw Error('Port gone before query');};await assert.rejects(detect(configFailure),/Port gone before query/);assert.deepEqual(configFailure.writes,[wake,request]);assert.equal(configFailure.reads,0);
  const afterRead=fixture([concat(local(9),meta())]),read=afterRead.read;let stillCurrent=true;afterRead.read=async(...args)=>{const value=await read(...args);stillCurrent=false;return value;};await assert.rejects(detect(afterRead,{assertCurrent:()=>{if(!stillCurrent)throw Error('Selection changed');}}),/Selection changed/);assert.equal(afterRead.reads,1);
});

test('invalid API arguments are rejected before any serial write',async()=>{
  const link=fixture([]);for(const timeoutMs of [0,-1,NaN,Infinity,30001])await assert.rejects(detect(link,{timeoutMs}),/timeout/);
  for(const options of [{delay:null},{now:null},{now:()=>NaN},{now:()=>Infinity}])await assert.rejects(detect(link,options),/clock/);
  for(const onProgress of [null,{},false])await assert.rejects(detect(link,{onProgress}),/progress callback/);
  await assert.rejects(detectMeshtastic({}),/serial connection/);assert.equal(link.writes.length,0);
});
