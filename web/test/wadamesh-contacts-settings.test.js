import test from 'node:test';
import assert from 'node:assert/strict';
import { hashtagChannel, readChannels, saveChannel, deleteChannel, readAutoAdd, saveAutoAdd } from '../src/wadamesh-contacts-settings.js';

function fixture() {
  const key='a5'.repeat(32),self=new Uint8Array(59),info=new Uint8Array(80),channels=[new Uint8Array(50),new Uint8Array(50)];
  self.set([5,1]);self.fill(0xa5,4,36);self.set([3,2,1,0x81],44);info[0]=13;info[3]=channels.length;
  for(const [index,record] of channels.entries()){record[0]=18;record[1]=index;}
  channels[0].set(new TextEncoder().encode('Main'),2);channels[0].fill(0x55,34);
  const state={self,info,channels,auto:Uint8Array.of(25,0xe3,5),writes:[]};
  const core={async self(){return state.self.slice();},async info(){return state.info.slice();},async request(command,response){
    const [code,index]=command;
    if(code===31&&response===18)return state.channels[index].slice();
    if(code===59&&response===25)return state.auto.slice();
    if(code===32&&response===0){state.writes.push(32);state.channels[index]=Uint8Array.from([18,...command.slice(1)]);return Uint8Array.of(0);}
    if(code===58&&response===0){state.writes.push(58);state.auto=Uint8Array.from([25,...command.slice(1)]);return Uint8Array.of(0);}
    if(code===38&&response===0){state.writes.push(38);state.self.set([command[4],command[3],command[2],command[1]],44);return Uint8Array.of(0);}
    throw new Error('Unexpected command');
  }};
  return {state,core,options:{publicKey:key,assertCurrent:()=>{}}};
}
test('hashtag channel derivation matches TAK normalization and reviewed SHA-256 vector',()=>{
  assert.deepEqual(hashtagChannel('##Te st'),{name:'#test',secretHex:'9cd8fcf22a47333b591d96a2b848b73f'});
  for(const input of ['', '#', '#r2-test', '#R2-Foo', '#'.concat('a'.repeat(31)), '#é', '#a\nb', ' '.repeat(3)])assert.throws(()=>hashtagChannel(input));
});
test('channel listing checks capacity and name changes retain the unexposed key with exact readback',async()=>{
  const {state,core,options}=fixture(),rows=await readChannels(core,options);
  assert.deepEqual(rows.map(({index,name,hasSecret})=>({index,name,hasSecret})),[{index:0,name:'Main',hasSecret:true},{index:1,name:'',hasSecret:false}]);
  const saved=await saveChannel(core,{expected:rows[0],name:'Local'},options);
  assert.equal(saved.name,'Local');assert.deepEqual(state.writes,[32]);assert.ok(state.channels[0].subarray(34).every(value=>value===0x55));
});
test('channel edits reject stale snapshots, absent keys and changed radio identity before writing',async()=>{
  const {state,core,options}=fixture(),rows=await readChannels(core,options);
  await assert.rejects(saveChannel(core,{expected:rows[1],name:'New'},options),/needs a channel key/);
  state.channels[0][2]=0x58;await assert.rejects(saveChannel(core,{expected:rows[0],name:'New'},options),/changed since/);
  state.self[4]=0;await assert.rejects(saveChannel(core,{expected:rows[1],name:'New',secretHex:'33'.repeat(16)},options),/identity changed/);
  assert.deepEqual(state.writes,[]);
});
test('channel names containing controls cannot inject lines into a review',async()=>{
  const {state,core,options}=fixture();state.channels[0][2]=10;
  await assert.rejects(readChannels(core,options),/Invalid channel name/);assert.deepEqual(state.writes,[]);
});
test('channel setter acknowledgement followed by identity change reports uncertain save without retry',async()=>{
  const {state,core,options}=fixture(),rows=await readChannels(core,options),request=core.request;
  core.request=async(...args)=>{const value=await request(...args);if(args[0][0]===32)state.self[4]=0;return value;};
  await assert.rejects(saveChannel(core,{expected:rows[0],name:'Local'},options),/may have changed/);assert.deepEqual(state.writes,[32]);
});
test('channel removal checks the snapshot and identity, clears its name and key, and verifies readback',async()=>{
  const {state,core,options}=fixture(),rows=await readChannels(core,options);
  const removed=await deleteChannel(core,{expected:rows[0]},options);
  assert.deepEqual({index:removed.index,name:removed.name,hasSecret:removed.hasSecret},{index:0,name:'',hasSecret:false});
  assert.ok(state.channels[0].subarray(2).every(value=>value===0));assert.deepEqual(state.writes,[32]);
  await assert.rejects(deleteChannel(core,{expected:rows[0]},options),/changed since/);assert.deepEqual(state.writes,[32]);
});
test('channel removal stops for identity mismatch and reports uncertain post-write failure',async()=>{
  const {state,core,options}=fixture(),rows=await readChannels(core,options);
  state.self[4]=0;await assert.rejects(deleteChannel(core,{expected:rows[0]},options),/identity changed/);assert.deepEqual(state.writes,[]);
  state.self[4]=0xa5;const request=core.request;core.request=async(...args)=>{const value=await request(...args);if(args[0][0]===32)state.self[4]=0;return value;};
  await assert.rejects(deleteChannel(core,{expected:rows[0]},options),/may have changed/);assert.deepEqual(state.writes,[32]);
});
test('auto-add preserves unknown flags and other settings and verifies both writes',async()=>{
  const {state,core,options}=fixture(),expected=await readAutoAdd(core,options);
  assert.equal(expected.manual,true);assert.equal(expected.maxHops,5);
  const result=await saveAutoAdd(core,{expected,manual:false,overwrite:false,chat:true,repeater:true,room:false,sensor:true,maxHops:2},options);
  assert.deepEqual(state.writes,[58,38]);assert.deepEqual([...state.auto],[25,0xf6,2]);assert.deepEqual([...state.self.subarray(44,48)],[3,2,1,0x80]);assert.equal(result.manual,false);
});
test('auto-add failure after one attempted write reports partial result; unsupported hop value is preserved',async()=>{
  const {state,core,options}=fixture();state.auto=Uint8Array.of(25,2);const expected=await readAutoAdd(core,options);
  await assert.rejects(saveAutoAdd(core,{expected,manual:true,overwrite:false,chat:true,repeater:false,room:false,sensor:false,maxHops:1},options),/unsupported/);
  const request=core.request;core.request=async(...args)=>{if(args[0][0]===38)throw Error('I/O failure');return request(...args);};
  await assert.rejects(saveAutoAdd(core,{expected,manual:false,overwrite:false,chat:false,repeater:false,room:false,sensor:false,maxHops:null},options),/may have been saved/);
  assert.deepEqual(state.writes,[58]);
});
