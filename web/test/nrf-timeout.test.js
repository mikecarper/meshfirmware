import test from 'node:test';
import assert from 'node:assert/strict';
import {zipSync} from 'fflate';
import {crc16,nrfPackage} from '../src/firmware.js';
import {flashNrf,slipDecode,slipEncode} from '../src/serial.js';

function firmware(){
  const bin=new Uint8Array(256),dat=new Uint8Array(12),view=new DataView(dat.buffer);view.setUint16(0,0x52,true);view.setUint16(10,crc16(bin),true);
  return nrfPackage('app.zip',zipSync({'manifest.json':new TextEncoder().encode(JSON.stringify({manifest:{dfu_version:.5,application:{bin_file:'app.bin',dat_file:'app.dat'}}})),'app.bin':bin,'app.dat':dat}));
}
function transport({startDelay=0,respond=true}={}){
  let tick=0,ready=0,pending=null;const sent=[];
  const link={buffer:[],port:{setSignals:async()=>{}},async write(packet){
    const frame=slipDecode(packet.subarray(1,-1)),command=new DataView(frame.buffer,frame.byteOffset).getUint32(4,true),ack=((frame[0]&7)+1)&7;
    sent.push(command);pending=slipEncode([ack<<3,0,0,(-(ack<<3))&255]);ready=tick+(command===3?startDelay:0);
  },async read(ms){tick+=ms;if(respond&&pending&&tick>=ready){const result=pending;pending=null;return result;}return new Uint8Array();}};
  return {link,sent,now:()=>tick};
}
test('default DFU timeout accepts an older bootloader START acknowledgement after seven seconds',async()=>{
  const io=transport({startDelay:7000});await flashNrf(io.link,firmware(),()=>{},{delay:async()=>{},now:io.now});
  assert.deepEqual(io.sent,[3,1,4,5]);assert.ok(io.now()>=7000);
});
test('DFU timeout is configurable and remains bounded with no reset or activation after failure',async()=>{
  const io=transport({respond:false});await assert.rejects(flashNrf(io.link,firmware(),()=>{},{delay:async()=>{},now:io.now,ackTimeoutMs:1000}),/did not acknowledge/);
  assert.deepEqual(io.sent,[3,3,3]);assert.equal(io.now(),3000);
});
test('invalid DFU acknowledgement timeouts fail before any serial signals or writes',async()=>{
  for(const ackTimeoutMs of [0,-1,1.5,60001,Infinity])await assert.rejects(flashNrf({},firmware(),()=>{},{ackTimeoutMs}),/timeout/);
});
