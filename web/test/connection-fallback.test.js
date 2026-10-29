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

test('TinyUSB preference tests that handoff before hardware reset but only after no-reset fails',async()=>{
  const f=fixture({results:[noSync()]}),result=await tryNativeUsbFallback({...f.options,preferredMode:'tinyusb'});
  assert.deepEqual(steps(f),['connect:no_reset','close','touch','connect:no_reset']);assert.equal(result.mode,'no_reset');assert.equal(result.session,f.sessions[0]);
  const ready=fixture();assert.equal((await tryNativeUsbFallback({...ready.options,preferredMode:'tinyusb'})).mode,'no_reset');assert.deepEqual(steps(ready),['connect:no_reset']);
  const hardware=fixture({results:[noSync()]});assert.equal((await tryNativeUsbFallback({...hardware.options,preferredMode:'usb_reset'})).mode,'usb_reset');assert.deepEqual(steps(hardware),['connect:no_reset','close','connect:usb_reset']);
});

test('a wrong TinyUSB recommendation can fall through once to the actual working hardware method',async()=>{
  const f=fixture({results:[noSync(),noSync()]}),result=await tryNativeUsbFallback({...f.options,preferredMode:'tinyusb'});
  assert.deepEqual(steps(f),['connect:no_reset','close','touch','connect:no_reset','close','connect:usb_reset']);assert.equal(result.mode,'usb_reset');assert.equal(f.calls.filter(call=>call[0]==='touch').length,1);
  assert.ok(f.calls.filter(call=>call[0]==='connect').every(call=>call[2].singleReset===true));
});

test('preferred TinyUSB never tries hardware after an uncertain touch, reconnect, or non-handshake failure',async()=>{
  for(const stage of ['touch','reconnect','permission','security','responded']){
    const original=Object.assign(Error(stage==='permission'?'Access denied':stage==='security'?'Secure boot is enabled':'ROM replied but chip identification failed'),stage==='permission'?{name:'NotAllowedError'}:{});
    let f;f=fixture({results:[noSync(),original],onTouch:()=>{if(stage==='touch')throw original;if(stage==='reconnect')f.setAvailable(false);}});
    const pending=tryNativeUsbFallback({...f.options,preferredMode:'tinyusb'});
    if(stage==='reconnect')assert.deepEqual(await pending,{handoff:true});else await assert.rejects(pending,error=>error===original);
    assert.ok(!steps(f).includes('connect:usb_reset'),stage);assert.equal(f.calls.filter(call=>call[0]==='touch').length,1,stage);
  }
});

test('preferred TinyUSB exhaustion is bounded to one handoff and one hardware reset attempt',async()=>{
  const f=fixture({results:[noSync(),noSync(),noSync()]});await assert.rejects(tryNativeUsbFallback({...f.options,preferredMode:'tinyusb'}),error=>error.connectionFallbackExhausted===true);
  assert.deepEqual(steps(f),['connect:no_reset','close','touch','connect:no_reset','close','connect:usb_reset','close']);assert.equal(f.calls.filter(call=>call[0]==='touch').length,1);assert.equal(f.calls.filter(call=>call[0]==='connect'&&call[1]==='usb_reset').length,1);
});

test('unsupported preferred methods fail before any connection, touch, or reset',async()=>{
  for(const preferredMode of ['no_reset','default_reset','nrf52','auto',true,{},undefined]){
    // Omission/undefined use the normal default; all supplied other methods
    // must be rejected instead of broadening eligible reset strategies.
    if(preferredMode===undefined)continue;
    const f=fixture();await assert.rejects(tryNativeUsbFallback({...f.options,preferredMode}),TypeError);assert.deepEqual(f.calls,[]);
  }
});

test('a marked final-phase TinyUSB interruption waits for handoff even before the disconnect event arrives',async()=>{
  const original=Object.assign(new Error('USB endpoint disappeared during the final signal'),{name:'NetworkError',tinyUsbHandoffPending:true});
  const f=fixture({results:[noSync()],onTouch:()=>{throw original;}});
  assert.deepEqual(await tryNativeUsbFallback({...f.options,preferredMode:'tinyusb'}),{handoff:true});
  assert.deepEqual(steps(f),['connect:no_reset','close','touch']);
  assert.equal(f.options.portAvailable(),true);
  const log=f.calls.filter(call=>call[0]==='log').at(-1)[1];
  assert.match(log,/interrupted/);assert.match(log,/Delivery is uncertain/);assert.match(log,/No further synchronization or reset/);
  // A delayed browser event changes availability only; it cannot trigger a
  // second touch, reset, no-reset synchronization or different-port scan.
  const previous=[...steps(f)];f.setAvailable(false);await Promise.resolve();
  assert.deepEqual(steps(f),previous);
});

test('marked TinyUSB interruptions return handoff for both available and already disconnected ports, in either ordering',async()=>{
  for(const preferredMode of [null,'tinyusb'])for(const disconnected of [false,true]){
    const original=Object.assign(new Error('Final control-line transfer interrupted'),{tinyUsbHandoffPending:true});
    let f;f=fixture({results:preferredMode==='tinyusb'?[noSync()]:[noSync(),noSync()],onTouch:()=>{if(disconnected)f.setAvailable(false);throw original;}});
    assert.deepEqual(await tryNativeUsbFallback({...f.options,preferredMode}),{handoff:true});
    assert.deepEqual(steps(f),preferredMode==='tinyusb'?['connect:no_reset','close','touch']:['connect:no_reset','close','connect:usb_reset','close','touch']);
    assert.equal(f.calls.filter(call=>call[0]==='touch').length,1);
    assert.equal(f.calls.filter(call=>call[0]==='connect'&&call[1]==='no_reset').length,1);
  }
});

test('a marked interruption never overrides a changed selected-radio or firmware snapshot',async()=>{
  const original=Object.assign(new Error('Final signal interrupted'),{tinyUsbHandoffPending:true});
  let f;f=fixture({results:[noSync()],onTouch:()=>{f.setCurrent(false);throw original;}});
  await assert.rejects(tryNativeUsbFallback({...f.options,preferredMode:'tinyusb'}),/selected radio or firmware changed/);
  assert.deepEqual(steps(f),['connect:no_reset','close','touch']);
  assert.equal(f.calls.some(call=>call[0]==='log'&&/Delivery is uncertain/.test(call[1])),false);
});

test('permission/security failures cannot be disguised as a pending TinyUSB handoff',async()=>{
  const errors=[
    Object.assign(new Error('Control transfer failed'),{name:'NotAllowedError'}),
    Object.assign(new Error('Control transfer failed'),{name:'SecurityError'}),
    Object.assign(new Error('Control transfer failed'),{name:'PermissionDeniedError'}),
    Object.assign(new Error('Control transfer failed'),{name:'AccessDeniedError'}),
    Object.assign(new Error('Control transfer failed'),{name:'InvalidAccessError'}),
    new Error('Access denied'),new Error('Permission was revoked'),new Error('Operation is not allowed'),
    new Error('Security policy blocked this operation'),new Error('Secure boot is enabled'),new Error('Encryption is enabled'),
  ];
  for(const original of errors){
    original.tinyUsbHandoffPending=true;
    const f=fixture({results:[noSync()],onTouch:()=>{throw original;}});
    await assert.rejects(tryNativeUsbFallback({...f.options,preferredMode:'tinyusb'}),error=>error===original);
    assert.deepEqual(steps(f),['connect:no_reset','close','touch']);
    assert.equal(f.calls.some(call=>call[0]==='log'&&/Delivery is uncertain/.test(call[1])),false);
  }
});

test('unmarked or non-boolean touch interruption evidence remains a failure, even if the port disconnects',async()=>{
  for(const marker of [undefined,false,'true',1]){
    const original=Object.assign(new Error('USB endpoint disconnected'),{tinyUsbHandoffPending:marker});
    let f;f=fixture({results:[noSync()],onTouch:()=>{f.setAvailable(false);throw original;}});
    await assert.rejects(tryNativeUsbFallback({...f.options,preferredMode:'tinyusb'}),error=>error===original);
    assert.deepEqual(steps(f),['connect:no_reset','close','touch']);
  }
});
