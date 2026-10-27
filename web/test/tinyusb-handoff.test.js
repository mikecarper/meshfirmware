import test from 'node:test';
import assert from 'node:assert/strict';
import {enterTinyUsbBootloader,touch1200} from '../src/serial.js';

function mockPort({openError=null,signalErrorAt=0,closeError=null}={}) {
  const calls=[];let signalCount=0;
  const port={
    async open(options){calls.push(['open',options]);if(openError)throw openError;},
    async setSignals(signals){calls.push(['signals',signals]);if(++signalCount===signalErrorAt)throw new Error('USB endpoint disconnected');},
    async close(){calls.push(['close']);if(closeError)throw closeError;},
    get writable(){throw new Error('A handoff must never write serial data.');},
    get readable(){throw new Error('A handoff must not claim a ROM response.');},
  };
  return {port,calls,delay:async milliseconds=>calls.push(['delay',milliseconds])};
}

function expectedHandoff(){
  const calls=[['open',{baudRate:115200,flowControl:'none'}]];
  for(const [dataTerminalReady,requestToSend] of [[false,false],[false,true],[true,true],[true,false],[false,false]])calls.push(['signals',{dataTerminalReady,requestToSend}],['signals',{dataTerminalReady}],['delay',100]);
  return [...calls,['close']];
}

test('TinyUSB handoff uses exact 115200 control sequence with a separate Windows DTR flush after every phase',async()=>{
  const mock=mockPort();
  assert.equal(await enterTinyUsbBootloader(mock.port,{delay:mock.delay}),undefined);
  assert.deepEqual(mock.calls,expectedHandoff());
  assert.equal(mock.calls.filter(([action])=>action==='open').length,1);
  assert.equal(mock.calls.filter(([action])=>action==='close').length,1);
});

test('every partial TinyUSB signal failure closes once and never repeats or falls back to 1200',async()=>{
  for(let signalErrorAt=1;signalErrorAt<=10;signalErrorAt++){
    const mock=mockPort({signalErrorAt});
    await assert.rejects(enterTinyUsbBootloader(mock.port,{delay:mock.delay}),/USB endpoint disconnected/);
    const expected=expectedHandoff(),failureIndex=expected.map(([action])=>action).reduce((indices,action,index)=>action==='signals'?[...indices,index]:indices,[])[signalErrorAt-1];
    assert.deepEqual(mock.calls,[...expected.slice(0,failureIndex+1),['close']]);
    assert.equal(mock.calls.some(([action,options])=>action==='open'&&options.baudRate===1200),false);
  }
});

test('TinyUSB open failure still attempts cleanup without sending control lines',async()=>{
  const error=new Error('Access to selected serial port failed'),mock=mockPort({openError:error});
  await assert.rejects(enterTinyUsbBootloader(mock.port,{delay:mock.delay}),value=>value===error);
  assert.deepEqual(mock.calls,[['open',{baudRate:115200,flowControl:'none'}],['close']]);
});

test('TinyUSB delay failure aborts immediately and cleanup cannot hide the primary handoff error',async()=>{
  const mock=mockPort({closeError:new Error('Port disappeared while closing')}),error=new Error('Handoff interrupted');
  await assert.rejects(enterTinyUsbBootloader(mock.port,{delay:async()=>{throw error;}}),value=>value===error);
  assert.deepEqual(mock.calls,[['open',{baudRate:115200,flowControl:'none'}],['signals',{dataTerminalReady:false,requestToSend:false}],['signals',{dataTerminalReady:false}],['close']]);
});

test('an expected close disconnect does not trigger a repeated TinyUSB reset or imply ROM success',async()=>{
  const mock=mockPort({closeError:new Error('USB disconnected')});
  assert.equal(await enterTinyUsbBootloader(mock.port,{delay:mock.delay}),undefined);
  assert.deepEqual(mock.calls,expectedHandoff());
});

test('the existing TinyUSB entry point dispatches to 115200 signal handoff, never baud-touch',async()=>{
  const mock=mockPort();await touch1200(mock.port,'tinyusb');
  assert.deepEqual(mock.calls.filter(([action])=>action!=='delay'),expectedHandoff().filter(([action])=>action!=='delay'));
});

test('nRF52 retains its original 1200-baud touch and DTR order',async()=>{
  const mock=mockPort();await touch1200(mock.port,'nrf52');
  assert.deepEqual(mock.calls,[['open',{baudRate:1200}],['signals',{dataTerminalReady:true,requestToSend:false}],['signals',{dataTerminalReady:false,requestToSend:false}],['close']]);
});

test('an unknown handoff kind is rejected before any USB operation',async()=>{
  for(const kind of [undefined,null,'','usb_reset','uart','nRF52',0,{}]){
    const mock=mockPort();await assert.rejects(touch1200(mock.port,kind),/explicit nRF52 or TinyUSB/);assert.deepEqual(mock.calls,[]);
  }
});
