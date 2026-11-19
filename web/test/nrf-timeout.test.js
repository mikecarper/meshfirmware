import test from 'node:test';
import assert from 'node:assert/strict';
import {zipSync} from 'fflate';
import {crc16,nrfPackage} from '../src/firmware.js';
import {flashNrf,slipDecode,slipEncode} from '../src/serial.js';

function firmware(size=256){
  const bin=new Uint8Array(size),dat=new Uint8Array(12),view=new DataView(dat.buffer);view.setUint16(0,0x52,true);view.setUint16(10,crc16(bin),true);
  return nrfPackage('app.zip',zipSync({'manifest.json':new TextEncoder().encode(JSON.stringify({manifest:{dfu_version:.5,application:{bin_file:'app.bin',dat_file:'app.dat'}}})),'app.bin':bin,'app.dat':dat}));
}
function transport({startDelay=0,respond=true,drop=()=>false}={}){
  let tick=0,ready=0,pending=null;const sent=[];
  const link={buffer:[],port:{setSignals:async()=>{}},async write(packet){
    const frame=slipDecode(packet.subarray(1,-1)),command=new DataView(frame.buffer,frame.byteOffset).getUint32(4,true),ack=((frame[0]&7)+1)&7;
    sent.push(command);pending=drop(command,sent)?null:slipEncode([ack<<3,0,0,(-(ack<<3))&255]);ready=tick+(command===3?startDelay:0);
  },async read(ms){tick+=ms;if(respond&&pending&&tick>=ready){const result=pending;pending=null;return result;}return new Uint8Array();}};
  return {link,sent,now:()=>tick};
}
test('default DFU timeout accepts an older bootloader START acknowledgement after seven seconds',async()=>{
  const io=transport({startDelay:7000});await flashNrf(io.link,firmware(),()=>{},{delay:async()=>{},now:io.now});
  assert.deepEqual(io.sent,[3,1,4,5]);assert.ok(io.now()>=7000);
});
test('DFU timeout is configurable and remains bounded with no reset or activation after failure',async()=>{
  const io=transport({respond:false});await assert.rejects(flashNrf(io.link,firmware(),()=>{},{delay:async()=>{},now:io.now,ackTimeoutMs:1000}),error=>{
    assert.match(error.message,/DFU did not acknowledge packet 1\. No reset will be attempted\./);
    assert.equal(error.code,'NRF_DFU_ACK_TIMEOUT');assert.deepEqual(error.nrfDfu,{stage:'start',acknowledgedBytes:0,totalBytes:256,sequence:1,kind:'application',erase:false,activationWaitMs:910});assert.ok(Object.isFrozen(error.nrfDfu));return true;
  });
  assert.deepEqual(io.sent,[3,3,3]);assert.equal(io.now(),3000);
});
test('DFU timeout describes the failing phase and previously acknowledged payload only',async()=>{
  for(const [failure,drop,expected,sequence] of [
    ['init',command=>command===1,0,2],
    ['data',(command,sent)=>command===4&&sent.filter(value=>value===4).length>=2,512,4],
    ['activate',command=>command===5,1300,6],
  ]){
    const io=transport({drop});await assert.rejects(flashNrf(io.link,firmware(1300),()=>{},{delay:async()=>{},now:io.now,ackTimeoutMs:1000}),error=>{
      assert.equal(error.code,'NRF_DFU_ACK_TIMEOUT');assert.deepEqual(error.nrfDfu,{stage:failure,acknowledgedBytes:expected,totalBytes:1300,sequence,kind:'application',erase:false,activationWaitMs:910});return true;
    });
    assert.deepEqual(io.sent.slice(-3),Array(3).fill(failure==='init'?1:failure==='data'?4:5));
    if(failure!=='activate')assert.ok(!io.sent.includes(5),'No activation after a failed transfer packet.');
  }
});
test('unacknowledged activation waits its full safety interval before reporting failure',async()=>{
  const io=transport({drop:command=>command===5}),events=[],delays=[];
  const write=io.link.write;io.link.write=async packet=>{events.push('write');await write(packet);};
  let activationChecks=0;
  await assert.rejects(flashNrf(io.link,firmware(1300),(_value,message)=>events.push(message),{
    delay:async ms=>{delays.push(ms);events.push(`wait:${ms}`);},now:io.now,ackTimeoutMs:1000,activationCheck:async()=>{activationChecks++;return true;}
  }),error=>{events.push('rejected');assert.equal(error.code,'NRF_DFU_ACK_TIMEOUT');assert.equal(error.nrfDfu.stage,'activate');return true;});
  assert.deepEqual(io.sent,[3,1,4,4,4,5,5,5]);assert.equal(activationChecks,0);
  assert.equal(delays.at(-1),910);assert.match(events.at(-3),/Activation unconfirmed; waiting before closing USB/);
  assert.equal(events.at(-2),'wait:910');assert.equal(events.at(-1),'rejected');
});
test('activation write, read, and malformed ACK failures wait before propagating the original failure',async()=>{
  for(const mode of ['write','read','malformed']){
    const io=transport(),events=[],signal=new Error(`${mode} failure`),originalWrite=io.link.write,originalRead=io.link.read;
    io.link.write=async packet=>{
      await originalWrite.call(io.link,packet);
      if(mode==='write'&&io.sent.at(-1)===5)throw signal;
    };
    io.link.read=async ms=>{
      if(io.sent.at(-1)===5){if(mode==='read')throw signal;if(mode==='malformed')return slipEncode([0,0,0,1]);}
      return originalRead.call(io.link,ms);
    };
    await assert.rejects(flashNrf(io.link,firmware(1300),(_value,message)=>events.push(message),{delay:async ms=>events.push(`wait:${ms}`),now:io.now,ackTimeoutMs:1000}),error=>{
      events.push('rejected');if(mode==='malformed')assert.match(error.message,/Invalid DFU acknowledgement/);else assert.equal(error,signal);
      assert.equal(error.nrfDfuUncertain,true);assert.ok(Object.isFrozen(error.nrfDfu));assert.equal(error.nrfDfu.stage,'activate');assert.equal(error.nrfDfu.acknowledgedBytes,1300);return true;
    });
    assert.equal(io.sent.filter(command=>command===5).length,1,'No automatic retry after a serial/parse error.');
    assert.match(events.at(-3),/Activation unconfirmed; waiting before closing USB/);assert.equal(events.at(-2),'wait:910');assert.equal(events.at(-1),'rejected');
  }
});
test('failed START waits the full preparation interval before reporting an unknown outcome',async()=>{
  for(const mode of ['timeout','write','read','malformed']){
    const io=transport({drop:command=>mode==='timeout'&&command===3}),events=[],signal=new Error(`${mode} failure`),originalWrite=io.link.write,originalRead=io.link.read;
    io.link.write=async packet=>{await originalWrite.call(io.link,packet);if(mode==='write')throw signal;};
    io.link.read=async ms=>{if(mode==='read')throw signal;if(mode==='malformed')return slipEncode([0,0,0,1]);return originalRead.call(io.link,ms);};
    await assert.rejects(flashNrf(io.link,firmware(1300),(_value,message)=>events.push(message),{delay:async ms=>events.push(`wait:${ms}`),now:io.now,ackTimeoutMs:1000}),error=>{
      events.push('rejected');if(mode==='timeout')assert.equal(error.code,'NRF_DFU_ACK_TIMEOUT');else {if(mode==='malformed')assert.match(error.message,/Invalid DFU acknowledgement/);else assert.equal(error,signal);assert.equal(error.nrfDfuUncertain,true);}
      assert.ok(Object.isFrozen(error.nrfDfu));assert.equal(error.nrfDfu.stage,'start');assert.equal(error.nrfDfu.acknowledgedBytes,0);return true;
    });
    assert.deepEqual(io.sent,Array(mode==='timeout'?3:1).fill(3));assert.match(events.at(-3),/Preparation unconfirmed; waiting before closing USB/);assert.equal(events.at(-2),'wait:500');assert.equal(events.at(-1),'rejected');
  }
});
test('non-extensible START and activation errors retain their message, name, code and original cause',async()=>{
  for(const [command,stage,bytes] of [[3,'start',0],[5,'activate',1300]]){
    const io=transport(),cause=new Error('underlying'),signal=new Error('Serial connection closed',{cause});signal.name='NetworkError';signal.code='SERIAL_CLOSED';Object.freeze(signal);
    const originalWrite=io.link.write;io.link.write=async packet=>{await originalWrite.call(io.link,packet);if(io.sent.at(-1)===command)throw signal;};
    await assert.rejects(flashNrf(io.link,firmware(1300),()=>{},{delay:async()=>{},now:io.now,ackTimeoutMs:1000}),error=>{
      assert.notEqual(error,signal);assert.equal(error.name,'NetworkError');assert.equal(error.message,'Serial connection closed');assert.equal(error.code,'SERIAL_CLOSED');assert.equal(error.cause,signal);assert.equal(error.cause.cause,cause);
      assert.equal(error.nrfDfuUncertain,true);assert.ok(Object.isFrozen(error.nrfDfu));assert.equal(error.nrfDfu.stage,stage);assert.equal(error.nrfDfu.acknowledgedBytes,bytes);return true;
    });
    assert.equal(io.sent.filter(value=>value===command).length,1);
  }
});
test('earlier unacknowledged phases do not add an activation wait or send STOP',async()=>{
  for(const failure of [3,1,4]){
    const io=transport({drop:command=>command===failure}),messages=[];
    await assert.rejects(flashNrf(io.link,firmware(256),(_value,message)=>messages.push(message),{delay:async()=>{},now:io.now,ackTimeoutMs:1000}),error=>error.code==='NRF_DFU_ACK_TIMEOUT');
    assert.ok(!messages.some(message=>message.startsWith('Activation unconfirmed')));assert.ok(!io.sent.includes(5));
  }
});
test('invalid DFU acknowledgement timeouts fail before any serial signals or writes',async()=>{
  for(const ackTimeoutMs of [0,-1,1.5,60001,Infinity])await assert.rejects(flashNrf({},firmware(),()=>{},{ackTimeoutMs}),/timeout/);
});
