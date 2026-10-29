import {test} from 'node:test';
import assert from 'node:assert/strict';
import {detectMeshtastic} from '../src/meshtastic.js';

const utf8=value=>new TextEncoder().encode(value);
const concat=(...parts)=>Uint8Array.from(parts.flatMap(value=>Array.from(value)));
const varint=value=>{let n=BigInt(value),out=[];do{let b=Number(n&127n);n>>=7n;if(n)b|=128;out.push(b);}while(n);return Uint8Array.from(out);};
const number=(id,value)=>concat(varint(id*8),varint(value));
const bytes=(id,value)=>concat(varint(id*8+2),varint(value.length),value);
const frame=payload=>concat([0x94,0xc3,payload.length>>8,payload.length&255],payload);
const local=node=>frame(bytes(3,number(1,node)));
const meta=(hardware=69,version='2.7.4.abc123',extras=[])=>frame(bytes(13,concat(bytes(1,utf8(version)),number(9,hardware),extras)));
const nodeInfo=(node,{name='Local node',shortName='LC',hardware=69}={})=>frame(bytes(4,concat(number(1,node),bytes(2,concat(bytes(2,utf8(name)),bytes(3,utf8(shortName)),number(5,hardware))))));
const request=[0x94,0xc3,0,4,0x18,0xac,0x9e,4];
function fixture(chunks,buffer=[]){
  const queue=chunks.map(chunk=>chunk instanceof Error?chunk:Uint8Array.from(chunk)),writes=[];let reads=0;
  return {buffer:[...buffer],writes,get reads(){return reads;},async write(value){writes.push([...value]);},async read(ms){reads++;const value=queue.shift();if(value instanceof Error)throw value;if(value)return value;await new Promise(resolve=>setTimeout(resolve,ms));return new Uint8Array();}};
}
const detect=(link,options={})=>detectMeshtastic(link,{timeoutMs:15,...options});

test('minimal nodeless config request reads the local T114 identity without settings, reset or RF commands',async()=>{
  const link=fixture([local(0x12345678),nodeInfo(0x12345678),meta()]);
  const result=await detect(link);assert.deepEqual(link.writes,[request]);assert.equal(link.reads,3);
  assert.deepEqual(result,{firmwareFamily:'meshtastic',role:'meshtastic',meshtasticHardware:69,model:'Meshtastic hardware 69',nodeNum:0x12345678,name:'Local node',version:'2.7.4.abc123',catalogRole:null,publicKey:null});
});

test('official SDK my_info fixture and device metadata identity are compatible',async()=>{
  // my_info bytes from the native hermetic test were serialized by the official
  // installed Meshtastic SDK. The metadata hardware byte is T114 enum69.
  const info=Uint8Array.from(Buffer.from('1a1c08f8acd191016a1473656565645f7869616f5f6e726635325f6b6974','hex'));
  const metadata=Uint8Array.from(Buffer.from('6a100a0c322e372e342e6162633132334845','hex'));
  const result=await detect(fixture([frame(info),frame(metadata)]));assert.equal(result.nodeNum,0x12345678);assert.equal(result.meshtasticHardware,69);assert.equal(result.version,'2.7.4.abc123');
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
  assert.equal((await detect(link)).meshtasticHardware,69);assert.deepEqual(link.writes,[request]);
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
  const link=fixture([local(9)],[...meta()]);assert.equal(await detect(link),null);assert.deepEqual(link.buffer,[]);assert.deepEqual(link.writes,[request]);
});

test('stops once identity is sufficient without requesting, parsing or logging subsequent inventory/packets',async()=>{
  const secret='PRIVATE_CHANNEL_SECRET',link=fixture([concat(local(9),meta(),frame(bytes(5,utf8(secret))),frame(bytes(2,utf8(secret)))),new Error('Must not drain further packets')]);
  const result=await detect(link);assert.equal(link.reads,1);assert.ok(!JSON.stringify(result).includes(secret));assert.deepEqual(link.writes,[request]);
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
  const afterRead=fixture([concat(local(9),meta())]);checks=0;await assert.rejects(detect(afterRead,{assertCurrent:()=>{if(++checks===4)throw Error('Selection changed');}}),/Selection changed/);assert.equal(afterRead.reads,1);
});

test('invalid API arguments are rejected before any serial write',async()=>{
  const link=fixture([]);for(const timeoutMs of [0,-1,NaN,Infinity,10001])await assert.rejects(detect(link,{timeoutMs}),/timeout/);
  await assert.rejects(detectMeshtastic({}),/serial connection/);assert.equal(link.writes.length,0);
});
