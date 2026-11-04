import test from 'node:test';
import assert from 'node:assert/strict';
import {ESPError} from 'esptool-js';
import {EspSession} from '../src/esp.js';

// Actual runStub/readFlashId implementations with register replies supplied
// locally. No SerialPort method may open, reset or write a physical device.
function fixture({reuseStub=true,loggingFailure=false}={}) {
  const messages=[],calls=[];
  const port={
    getInfo:()=>({usbVendorId:0x10c4,usbProductId:0xea60}),
    open:async()=>{throw Error('Unexpected serial open');},
    setSignals:async()=>{throw Error('Unexpected reset');},
  };
  const session=new EspSession(port,message=>{
    messages.push(message);
    if(loggingFailure&&String(message).startsWith('ESP32 connection stage:'))throw Error('Diagnostic output failed');
  }),loader=session.loader,chip=loader.romFromChipId(9);
  loader.detectChip=async()=>{calls.push('detect');loader.chip=chip;loader.syncStubDetected=reuseStub;};
  loader.getSecurityInfo=async()=>({parsedFlags:{SECURE_BOOT_EN:false,SECURE_DOWNLOAD_ENABLE:false},flashCryptCnt:0});
  loader.readReg=async address=>{
    calls.push(['read',address]);
    if(address===chip.MAC_EFUSE_REG)return 0x11223344;
    if(address===chip.MAC_EFUSE_REG+4)return 0x5566;
    if(address===chip.SPI_REG_BASE+chip.SPI_W0_OFFS)return 0x160000;
    return 0;
  };
  loader.writeReg=async(address,value)=>calls.push(['register-write',address,value]);
  if(!reuseStub)loader.runStub=async()=>{calls.push('stub');loader.IS_STUB=true;};
  return {session,loader,chip,messages,calls};
}

test('a reused stub connects normally and the real flash-ID query still verifies physical capacity',async()=>{
  const {session,loader,messages,calls}=fixture();
  const result=await session.connect('no_reset',{singleReset:true});
  assert.equal(result.chip,'ESP32-S3');assert.equal(result.mac,'55:66:11:22:33:44');assert.equal(result.flashBytes,4<<20);
  assert.equal(loader.IS_STUB,true);
  assert.ok(messages.includes('Stub is already running. No upload is necessary.'));
  assert.ok(calls.some(call=>call[0]==='register-write'),'The real SPI flash-ID transaction must execute');
  assert.ok(!messages.some(message=>String(message).startsWith('ESP32 connection stage:')));
});

test('post-stub flash-ID silence reports the exact stage without replacing its error or permitting retries and writes',async()=>{
  const {session,loader,chip,messages,calls}=fixture();
  const originalRead=loader.readReg;let original;
  loader.readReg=async address=>{
    if(address!==chip.SPI_REG_BASE+chip.SPI_USR_OFFS)return originalRead(address);
    calls.push('silent-flash-id');
    try {await session.transport.read(1);}catch(error){
      original=Object.freeze(Object.assign(error,{code:'FLASH_ID_TEST',romHandshakeFailed:false,detail:Object.freeze({untouched:true})}));
      throw original;
    }
  };
  await assert.rejects(session.connect('no_reset',{singleReset:true}),error=>{
    assert.equal(error,original);assert.ok(error instanceof ESPError);
    assert.equal(error.message,'Serial data stream stopped: Possible serial noise or corruption.');
    assert.equal(error.code,'FLASH_ID_TEST');assert.equal(error.romHandshakeFailed,false);assert.deepEqual(error.detail,{untouched:true});
    return true;
  });
  assert.ok(messages.includes('Stub is already running. No upload is necessary.'));
  assert.ok(messages.some(message=>/physical flash-ID inspection failed after reusing the running stub/.test(message)));
  assert.equal(calls.filter(call=>call==='detect').length,1);assert.equal(calls.filter(call=>call==='silent-flash-id').length,1);
  assert.equal(session.flashBytes,0);assert.equal(session.connectMode,null);assert.equal(session.plan,null);
  const before=structuredClone(calls);
  await assert.rejects(session.flash({},()=>{}),/Firmware changed after confirmation/);
  await assert.rejects(session.finish(false),/completely verified write/);
  assert.deepEqual(calls,before);assert.ok(!calls.some(call=>call[0]==='register-write'));
});

test('even failed diagnostic output cannot replace a post-stub error or alter its flags',async()=>{
  const {session,loader,messages,calls}=fixture({reuseStub:false,loggingFailure:true});
  const original=Object.freeze(Object.assign(new ESPError('Flash-ID command timed out'),{code:'UNCHANGED',romHandshakeFailed:false}));
  loader.readFlashId=async()=>{calls.push('flash-id');throw original;};
  await assert.rejects(session.connect('no_reset'),error=>error===original&&error.code==='UNCHANGED'&&error.romHandshakeFailed===false);
  assert.ok(messages.some(message=>/physical flash-ID inspection failed after starting the stub/.test(message)));
  assert.equal(calls.filter(call=>call==='detect').length,1);assert.equal(calls.filter(call=>call==='stub').length,1);assert.equal(calls.filter(call=>call==='flash-id').length,1);
  assert.equal(session.flashBytes,0);assert.equal(session.plan,null);
});
