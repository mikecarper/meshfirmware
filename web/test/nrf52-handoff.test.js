import test from 'node:test';
import assert from 'node:assert/strict';
import {touch1200} from '../src/serial.js';

function mockPort({openError=null,signalErrorAt=0,signalError=null,delayError=null,closeError=null}={}){
  const calls=[];let count=0;
  const port={
    async open(options){calls.push(['open',options]);if(openError)throw openError;},
    async setSignals(signals){calls.push(['signals',signals]);if(++count===signalErrorAt)throw signalError;},
    async close(){calls.push(['close']);if(closeError)throw closeError;},
    get readable(){throw Error('A baud touch cannot read or prove DFU.');},
    get writable(){throw Error('A baud touch cannot write firmware.');},
  };
  return {port,calls,delay:async ms=>{calls.push(['delay',ms]);if(delayError)throw delayError;}};
}
const sequence=[['open',{baudRate:1200}],['signals',{dataTerminalReady:true,requestToSend:false}],['delay',100],['signals',{dataTerminalReady:false,requestToSend:false}],['close']];
const touch=mock=>touch1200(mock.port,'nrf52',{delay:mock.delay});

test('nRF52 touch keeps the exact single 1200-baud falling-DTR sequence',async()=>{
  const mock=mockPort();assert.equal(await touch(mock),undefined);assert.deepEqual(mock.calls,sequence);
});

test('only an interrupted final nRF52 DTR drop can carry pending-handoff evidence',async()=>{
  const failures=[
    Object.assign(Error("Failed to execute 'setSignals' on 'SerialPort': Failed to set control signals."),{name:'NetworkError'}),
    Object.assign(Error('The device was removed'),{name:'NotFoundError'}),
    Object.assign(Error('The USB device disconnected'),{name:'InvalidStateError'}),
    Error('Failed to set control signals'),Error('USB endpoint disconnected'),
  ];
  for(const original of failures){
    Object.freeze(original);
    const mock=mockPort({signalErrorAt:2,signalError:original,closeError:Error('USB disconnected while closing')});
    await assert.rejects(touch(mock),error=>{
      assert.notEqual(error,original);assert.equal(error.cause,original);assert.equal(error.name,original.name);assert.equal(error.message,original.message);
      assert.equal(error.nrf52HandoffPending,true);assert.equal(error.tinyUsbHandoffPending,undefined);
      assert.deepEqual(error.nrf52HandoffEvidence,{sequence:'1200-dtr-fall',phase:'final-dtr-low',operation:'control-lines',baudRate:1200,priorPhasesComplete:true,dfuVerified:false});
      assert.ok(Object.isFrozen(error.nrf52HandoffEvidence));return true;
    });
    assert.deepEqual(mock.calls,sequence);assert.equal(original.nrf52HandoffPending,undefined);
  }
});

test('nRF52 open, initial-DTR and delay failures remain unchanged and are never retried',async()=>{
  for(const phase of ['open','initial','delay']){
    const original=Object.assign(Error('USB endpoint disconnected'),{name:'NetworkError'});
    const mock=mockPort({...(phase==='open'?{openError:original}:phase==='initial'?{signalErrorAt:1,signalError:original}:{delayError:original}),closeError:Error('Cleanup failed')});
    await assert.rejects(touch(mock),error=>error===original&&error.nrf52HandoffPending===undefined&&error.nrf52HandoffEvidence===undefined);
    assert.deepEqual(mock.calls,[...sequence.slice(0,phase==='open'?1:phase==='initial'?2:3),['close']]);
  }
});

test('nRF52 permission/access errors never become pending handoffs, including final DTR',async()=>{
  const failures=[
    ...['NotAllowedError','SecurityError','PermissionDeniedError','AccessDeniedError'].map(name=>Object.assign(Error('Failed to set control signals'),{name})),
    ...['Access is denied','Access denied','Permission denied','Operation not allowed','Security restriction','EACCES','EPERM','Unauthorized'].map(message=>Object.assign(Error(message),{name:'NetworkError'})),
  ];
  for(const original of failures){
    const mock=mockPort({signalErrorAt:2,signalError:original});
    await assert.rejects(touch(mock),error=>error===original&&error.nrf52HandoffPending===undefined&&error.nrf52HandoffEvidence===undefined);
    assert.deepEqual(mock.calls,sequence);
  }
});

test('unrelated final-DTR errors are not misrepresented as a completed nRF52 reset',async()=>{
  for(const original of [Error('Unexpected failure'),new TypeError('Invalid signals'),Object.assign(Error('Operation aborted'),{name:'AbortError'})]){
    const mock=mockPort({signalErrorAt:2,signalError:original});
    await assert.rejects(touch(mock),error=>error===original&&error.nrf52HandoffPending===undefined);
    assert.deepEqual(mock.calls,sequence);
  }
});

test('a close-only disconnect does not repeat nRF52 reset or claim DFU verification',async()=>{
  const mock=mockPort({closeError:Error('USB disconnected')});assert.equal(await touch(mock),undefined);assert.deepEqual(mock.calls,sequence);
});
