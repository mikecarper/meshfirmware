import test from 'node:test';
import assert from 'node:assert/strict';
import { MeshCore, publicFromPrivate, sealBackup, verifyBackup } from '../src/meshcore.js';
import { nativePayloadFromWeb } from '../src/backup-native.js';

const enc=value=>new TextEncoder().encode(value),hex=value=>Buffer.from(value).toString('hex');
function payload() {
  const key=new Uint8Array(64);key[0]=1;
  const self=new Uint8Array(62),v=new DataView(self.buffer),info=new Uint8Array(82),iv=new DataView(info.buffer);
  self.set([5,1,20,22]);self.set(Buffer.from(publicFromPrivate(key),'hex'),4);self.set(enc('test'),58);self[56]=10;self[57]=5;v.setUint32(48,910525,true);v.setUint32(52,125000,true);
  info.set([13,14,2,1]);iv.setUint32(4,123456,true);info.set(enc('test-build'),8);info.set(enc('test-model'),20);info.set(enc('v1.18.0'),60);
  const channel=new Uint8Array(50);channel[0]=18;
  return {role:'companion',publicKey:publicFromPrivate(key),self:hex(self),info:hex(info),privateKey:'0e'+hex(key),channels:[hex(channel)],contacts:[],options:{},cli:{},safeForWipe:false};
}
function target(p,{actualPower=5,maxPower=22}={}) {
  const core=new MeshCore({}),live=Buffer.from(p.self,'hex'),commands=[],cliCommands=[];live[2]=actualPower&255;live[3]=maxPower&255;
  core.self=async()=>live;core.info=async()=>Buffer.from(p.info,'hex');core.contacts=async()=>[];
  core.cli=async command=>{cliCommands.push(command);return command==='get usb.logging'?'> usb.logging off':'> bluetooth off';};
  core.request=async command=>{commands.push(command);if(command[0]===12)live[2]=command[1];return command[0]===31?Buffer.from(p.channels[0],'hex'):Uint8Array.of(0);};
  return {core,live,commands,cliCommands};
}
function contact() {
  const b=new Uint8Array(148);b[0]=3;b[1]=1;b[33]=1;b[35]=255;b.set(enc('valid contact'),100);return b;
}

test('negative TX powers restore as signed dBm while retaining their raw wire byte and native JSON value',async()=>{
  for(const power of [-9,-1,0,22]) {
    const p=payload(),self=Buffer.from(p.self,'hex');self[2]=power&255;p.self=hex(self);
    const {core,live,commands}=target(p);await core.restore(sealBackup(p));
    assert.equal(commands.find(c=>c[0]===12)[1],power&255);assert.equal(live[2],power&255);
    const native=nativePayloadFromWeb(sealBackup(p),{usbIdentity:{usbVendorId:0x2886,usbProductId:0x8044}});
    assert.equal(native.sections.self_info.data.tx_power,power&255);
  }
});
test('actual TX over-maximum, below firmware minimum and negative target maximum are checked as signed values before mutations',async()=>{
  for(const [power,maxPower] of [[23,22],[-10,22],[-1,-2],[0,-10]]) {
    const p=payload(),self=Buffer.from(p.self,'hex');self[2]=power&255;p.self=hex(self);
    const {core,commands,cliCommands}=target(p,{maxPower});await assert.rejects(()=>core.restore(sealBackup(p)),/TX power.*hardware range/);
    assert.equal(commands.length,0);assert.equal(cliCommands.length,0);
  }
});
test('legacy contact semantic validation rejects malformed coordinates/path/name before even reading the target',async()=>{
  const mutations=[
    b=>new DataView(b.buffer).setInt32(136,91000000,true),
    b=>new DataView(b.buffer).setInt32(136,-90000001,true),
    b=>new DataView(b.buffer).setInt32(140,180000001,true),
    b=>new DataView(b.buffer).setInt32(140,-181000000,true),
    b=>{b[35]=(3<<6)|17;}, // 17 four-byte hashes exceed the 64-byte path.
    b=>{b[100]=0xc3;b[101]=0x28;}, // Invalid UTF-8, despite a valid archive hash.
    b=>{b.fill(0x61,100,132);b[131]=0xc3;}
  ];
  for(const mutate of mutations) {
    const p=payload(),b=contact();mutate(b);p.contacts=[hex(b)];const archive=sealBackup(p),core=new MeshCore({});let access=0;
    core.self=async()=>{access++;};core.request=async()=>{access++;};core.cli=async()=>{access++;};
    assert.throws(()=>verifyBackup(archive),/contact/i);await assert.rejects(()=>core.restore(archive),/contact/i);assert.equal(access,0);
  }
});
test('legacy contacts preserve native uint8 type/flags, uint32 timestamps, coordinate boundaries and all valid packed path modes',()=>{
  for(const [packed,length] of [[255,0],[0,0],[63,63],[(1<<6)|32,64],[(2<<6)|21,63],[(3<<6)|16,64]]) {
    const p=payload(),b=contact(),v=new DataView(b.buffer);b[33]=255;b[34]=255;b[35]=packed;b.fill(7,36,36+length);v.setUint32(132,0xffffffff,true);v.setUint32(144,0x80000000,true);v.setInt32(136,-90000000,true);v.setInt32(140,180000000,true);p.contacts=[hex(b)];
    assert.equal(verifyBackup(sealBackup(p)).contacts[0],hex(b));
  }
});
test('unused flood-path and NUL-terminated name padding are not interpreted as active metadata',()=>{
  const p=payload(),b=contact();b.fill(255,36,100);b[104]=0;b.fill(255,105,132);p.contacts=[hex(b)];assert.equal(verifyBackup(sealBackup(p)).contacts.length,1);
});
