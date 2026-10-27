import {test} from 'node:test';
import assert from 'node:assert/strict';
import {ESPError} from 'esptool-js';
import {EspSession} from '../src/esp.js';

// Real ESPLoader reset factories/connection fallback, but no serial hardware.
function session({usb=false}={}) {
  const signals=[],calls=[],port={getInfo:()=>usb?{usbVendorId:0x303a,usbProductId:0x1001}:{usbVendorId:0x10c4,usbProductId:0xea60},setSignals:async value=>signals.push(value)};
  const session=new EspSession(port,()=>{}),loader=session.loader;
  const chip={IMAGE_CHIP_ID:5,CHIP_NAME:'ESP32-C3',readMac:async()=> 'aa:bb:cc:dd:ee:ff'};
  loader.getSecurityInfo=async()=>({parsedFlags:{SECURE_BOOT_EN:false,SECURE_DOWNLOAD_ENABLE:false},flashCryptCnt:0});
  loader.runStub=async()=>calls.push('stub');loader.readFlashId=async()=>0x160000;
  loader.transport.connect=async()=>calls.push('open');loader.transport.readLoop=()=>{};
  loader.transport.peek=()=>new Uint8Array();loader.transport.flushInput=()=>{};loader.transport.disconnect=async()=>calls.push('close');
  loader.sync=async()=>[0];loader.identifyChip=async()=>chip;loader.identifyChipByMagic=async()=>chip;
  const detectChip=loader.detectChip;
  loader.detectChip=function(...args){calls.push({detect:args});return Reflect.apply(detectChip,this,args);};
  return {session,loader,chip,port,signals,calls,original:loader.resetConstructors};
}
const make=(loader,key)=>loader.resetConstructors[key](loader.transport,key==='customReset'?'D0|R1|W1|D1|R0':0);

test('approved classic or USB-JTAG ROM entry has one reset and restores every original factory',async()=>{
  for(const usb of [false,true]){
    const fixture=session({usb}),{session:s,loader,signals,calls,original}=fixture;
    const result=await s.connect(usb?'usb_reset':'default_reset',{singleReset:true});
    assert.equal(result.mac,'aa:bb:cc:dd:ee:ff');assert.equal(result.flashBytes,4<<20);
    assert.deepEqual(calls.find(value=>value?.detect)?.detect,[usb?'usb_reset':'default_reset',1]);
    assert.equal(signals.filter(value=>value.requestToSend===true).length,usb?2:1);
    assert.equal(loader.resetConstructors,original);
    for(const key of Object.keys(original))assert.equal(loader.resetConstructors[key],original[key]);
    assert.equal(calls.filter(value=>value==='stub').length,1);
  }
});
test('all reset strategies share one budget, including preconstructed and repeated strategies',async()=>{
  for(const first of ['classicReset','usbJTAGSerialReset','customReset','hardReset']){
    const {session:s,loader,signals,original}=session();let countAfterFirst=0;
    loader.detectChip=async function(mode,attempts){
      assert.equal(mode,'default_reset');assert.equal(attempts,1);
      const a=make(this,first),b=make(this,first==='customReset'?'usbJTAGSerialReset':'customReset');
      await a.reset();countAfterFirst=signals.length;
      await assert.rejects(a.reset(),/one reset/);
      await b.reset();
    };
    await assert.rejects(s.connect('default_reset',{singleReset:true}),/one reset/);
    assert.ok(countAfterFirst>0);assert.equal(signals.length,countAfterFirst,first);assert.equal(loader.resetConstructors,original);
  }
});
test('real chip-identification fallback cannot issue a second automatic reset',async()=>{
  const {session:s,loader,signals,calls,original}=session();let magic=0;
  loader.identifyChip=async()=>{throw new ESPError('Uncertain chip-identification response');};
  loader.identifyChipByMagic=async()=>{magic++;return {};};
  await assert.rejects(s.connect('default_reset',{singleReset:true}),/one reset/);
  assert.equal(calls.filter(value=>value==='open').length,2,'The real loader attempted its fallback connection');
  assert.equal(signals.filter(value=>value.requestToSend===true).length,1,'Only the first hardware reset was delivered');
  assert.equal(magic,0);assert.ok(!calls.includes('stub'));assert.equal(loader.resetConstructors,original);
});
test('a failed or still-pending first reset consumes the budget before its first await',async()=>{
  {
    const {session:s,loader,port,signals,original}=session();
    port.setSignals=async value=>{signals.push(value);throw new Error('Control request delivery uncertain');};
    loader.detectChip=async function(){
      await assert.rejects(make(this,'classicReset').reset(),/delivery uncertain/);
      await make(this,'customReset').reset();
    };
    await assert.rejects(s.connect('default_reset',{singleReset:true}),/one reset/);
    assert.equal(signals.length,1);assert.equal(loader.resetConstructors,original);
  }
  {
    const {session:s,loader,port,signals,original}=session();let release;
    port.setSignals=async value=>{signals.push(value);if(signals.length===1)await new Promise(resolve=>{release=resolve;});};
    loader.detectChip=async function(){
      const pending=make(this,'customReset').reset();
      await assert.rejects(make(this,'classicReset').reset(),/one reset/);
      assert.equal(signals.length,1);release();await pending;
      throw new Error('End pending-reset test');
    };
    await assert.rejects(s.connect('default_reset',{singleReset:true}),/End pending-reset test/);
    assert.equal(loader.resetConstructors,original);
  }
});
test('approved no-reset connections and chip-detect fallback never acquire a reset budget',async()=>{
  const {session:s,loader,chip,signals,calls,original}=session();
  loader.identifyChip=async()=>{throw new ESPError('Use read-only magic fallback');};loader.identifyChipByMagic=async()=>chip;
  await s.connect('no_reset',{singleReset:true});
  assert.deepEqual(calls.find(value=>value?.detect)?.detect,['no_reset',1]);assert.equal(calls.filter(value=>value==='open').length,2);assert.deepEqual(signals,[]);assert.equal(loader.resetConstructors,original);
  loader.detectChip=async function(){await make(this,'customReset').reset();};
  await assert.rejects(s.connect('no_reset',{singleReset:true}),/No reset retry/);assert.deepEqual(signals,[]);assert.equal(loader.resetConstructors,original);
});
test('ordinary callers retain the loader default reset/retry behavior',async()=>{
  const {session:s,loader,signals,calls,original}=session();
  loader.identifyChip=async()=>{throw new ESPError('Original identification fallback');};
  await s.connect('default_reset');
  assert.deepEqual(calls.find(value=>value?.detect)?.detect,['default_reset']);
  assert.equal(signals.filter(value=>value.requestToSend===true).length,2);assert.equal(loader.resetConstructors,original);
});
test('reset factories are restored after loader errors and later checks; finish reset remains independent',async()=>{
  for(const stage of ['detect','security']){
    const {session:s,loader,signals,original}=session();
    if(stage==='detect')loader.detectChip=async()=>{throw new Error('Detection failed');};
    else loader.getSecurityInfo=async()=>({parsedFlags:{SECURE_BOOT_EN:true,SECURE_DOWNLOAD_ENABLE:false},flashCryptCnt:0});
    await assert.rejects(s.connect('default_reset',{singleReset:true}),stage==='detect'?/Detection failed/:/Secure boot/);
    assert.equal(loader.resetConstructors,original);
    const before=signals.length;await make(loader,'hardReset').reset();assert.ok(signals.length>before,'An independently authorized finish can still use the restored original factory');
  }
});
test('missing loader reset hooks and malformed options fail before automatic detection',async()=>{
  const {session:s,loader,calls,signals}=session();loader.resetConstructors=null;
  await assert.rejects(s.connect('default_reset',{singleReset:true}),/guarded reset constructors/);
  await assert.rejects(s.connect('default_reset',{singleReset:'yes'}),/boolean/);
  assert.deepEqual(calls,[]);assert.deepEqual(signals,[]);
});
