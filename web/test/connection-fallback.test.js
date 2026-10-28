import test from 'node:test';
import assert from 'node:assert/strict';
import {tryNativeUsbFallback} from '../src/connection-fallback.js';

const noSync=()=>Object.assign(new Error('Failed to connect with the device'),{romHandshakeFailed:true});
function fixture({results=[],onConnect,onClose,onTouch}={}){
  const calls=[],sessions=[],info={chip:'ESP32-S3',mac:'aa:bb:cc:dd:ee:ff',flashBytes:4<<20};
  let current=true,available=true,index=0;
  const options={
    connect:async(mode,settings)=>{calls.push(['connect',mode,settings]);onConnect?.(mode,index);const result=results[index++];if(result instanceof Error)throw result;const session={mode,index};sessions.push(session);return {session,info};},
    close:async()=>{calls.push(['close']);await onClose?.();},
    touch:async()=>{calls.push(['touch']);await onTouch?.();},
    isCurrent:()=>current,portAvailable:()=>available,log:message=>calls.push(['log',message]),
  };
  return {options,calls,sessions,info,setCurrent:value=>{current=value;},setAvailable:value=>{available=value;}};
}
const steps=fixture=>fixture.calls.filter(call=>call[0]!=='log').map(([name,mode])=>mode?name+':'+mode:name);

test('native fallback tries no-reset first and retains its successful verified session without a reset or close',async()=>{
  const f=fixture(),result=await tryNativeUsbFallback(f.options);
  assert.deepEqual(steps(f),['connect:no_reset']);assert.equal(result.session,f.sessions[0]);assert.equal(result.info,f.info);assert.equal(result.mode,'no_reset');assert.deepEqual(f.calls.find(call=>call[0]==='connect')[2],{singleReset:true});
  const messages=f.calls.filter(call=>call[0]==='log').map(call=>call[1]);assert.match(messages[0],/already waiting.*no reset/);assert.match(messages.at(-1),/verified.*retaining/);
});

test('only a closed genuine no-sync attempt can advance to one guarded USB-JTAG attempt',async()=>{
  const f=fixture({results:[noSync()]}),result=await tryNativeUsbFallback(f.options);
  assert.deepEqual(steps(f),['connect:no_reset','close','connect:usb_reset']);assert.equal(result.mode,'usb_reset');assert.equal(result.session,f.sessions[0]);assert.ok(f.calls.filter(call=>call[0]==='connect').every(call=>call[2].singleReset===true));
  assert.ok(f.calls.find(call=>call[0]==='log'&&/one guarded hardware/.test(call[1])));
});

test('TinyUSB handoff is attempted once, followed only by a no-reset sync on the same still-available endpoint',async()=>{
  const f=fixture({results:[noSync(),noSync()]}),result=await tryNativeUsbFallback(f.options);
  assert.deepEqual(steps(f),['connect:no_reset','close','connect:usb_reset','close','touch','connect:no_reset']);assert.equal(result.mode,'no_reset');assert.equal(f.calls.filter(call=>call[0]==='touch').length,1);
});

test('a re-enumerating TinyUSB endpoint returns handoff without touching, scanning or opening another port',async()=>{
  let f;f=fixture({results:[noSync(),noSync()],onTouch:()=>f.setAvailable(false)});
  assert.deepEqual(await tryNativeUsbFallback(f.options),{handoff:true});assert.deepEqual(steps(f),['connect:no_reset','close','connect:usb_reset','close','touch']);
});

test('disappearance during a failed attempt requests handoff but never tries another reset',async()=>{
  let f;f=fixture({results:[noSync()],onConnect:()=>f.setAvailable(false)});
  assert.deepEqual(await tryNativeUsbFallback(f.options),{handoff:true});assert.deepEqual(steps(f),['connect:no_reset','close']);
  const absent=fixture();absent.setAvailable(false);assert.deepEqual(await tryNativeUsbFallback(absent.options),{handoff:true});assert.deepEqual(steps(absent),[]);
});

test('permission, security, MAC, chip, stub, flash and arbitrary failures never authorize another mode',async()=>{
  for(const original of [new Error('Secure boot enabled'),new Error('MAC changed'),new Error('Unsupported chip family'),new Error('RAM stub failed'),new Error('Flash ID unavailable'),new Error('Unknown failure'),Object.assign(noSync(),{name:'NotAllowedError'}),Object.assign(noSync(),{name:'NetworkError'}),Object.assign(noSync(),{message:'Access denied'})]){
    const f=fixture({results:[original]});await assert.rejects(tryNativeUsbFallback(f.options),error=>error===original);assert.deepEqual(steps(f),['connect:no_reset','close'],original.message);
  }
});

test('uncertain touch and uncertain transport close stop testing with no hidden retry',async()=>{
  const touchError=new Error('Control transfer delivery uncertain'),f=fixture({results:[noSync(),noSync()],onTouch:()=>{throw touchError;}});
  await assert.rejects(tryNativeUsbFallback(f.options),error=>error===touchError);assert.deepEqual(steps(f),['connect:no_reset','close','connect:usb_reset','close','touch']);
  const original=noSync(),closed=fixture({results:[original],onClose:()=>{throw Error('close failed');}});
  await assert.rejects(tryNativeUsbFallback(closed.options),error=>error===original);assert.deepEqual(steps(closed),['connect:no_reset','close']);
  let lost;lost=fixture({onConnect:()=>lost.setAvailable(false),onClose:()=>{throw Error('Successful sync lost its endpoint; close uncertain');}});
  await assert.rejects(tryNativeUsbFallback(lost.options),/close uncertain/);assert.deepEqual(steps(lost),['connect:no_reset','close']);
});

test('stale selected-device or image context fails before the next reset and closes a successful stale session',async()=>{
  const before=fixture();before.setCurrent(false);await assert.rejects(tryNativeUsbFallback(before.options),/changed/);assert.deepEqual(steps(before),[]);
  let during;during=fixture({onConnect:()=>during.setCurrent(false)});await assert.rejects(tryNativeUsbFallback(during.options),/changed/);assert.deepEqual(steps(during),['connect:no_reset','close']);
  let closed;closed=fixture({results:[noSync()],onClose:()=>closed.setCurrent(false)});await assert.rejects(tryNativeUsbFallback(closed.options),/changed/);assert.deepEqual(steps(closed),['connect:no_reset','close']);
});

test('exhausted bounded methods leave manual selection as the final fallback',async()=>{
  const f=fixture({results:[noSync(),noSync(),noSync()]});await assert.rejects(tryNativeUsbFallback(f.options),error=>error.connectionFallbackExhausted===true&&/manually/.test(error.message));
  assert.deepEqual(steps(f),['connect:no_reset','close','connect:usb_reset','close','touch','connect:no_reset','close']);assert.ok(!steps(f).some(step=>/default_reset|1200|nrf52/.test(step)));
});

test('bad callback contracts and empty successful sessions fail without a fallback reset',async()=>{
  await assert.rejects(tryNativeUsbFallback(),TypeError);
  const f=fixture();f.options.connect=async()=>({info:f.info});await assert.rejects(tryNativeUsbFallback(f.options),/verified chip session/);assert.deepEqual(steps(f),['close']);
});
