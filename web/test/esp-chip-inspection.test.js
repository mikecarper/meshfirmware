import test from 'node:test';
import assert from 'node:assert/strict';
import {EspSession} from '../src/esp.js';

// Every ROM/stub response and port operation is local. These tests must never
// request a browser port, open a physical device, erase flash, or write firmware.
function fixture({chipId=9}={}) {
  const calls=[],port={
    getInfo:()=>({usbVendorId:0x303a,usbProductId:0x1001}),
    open:async()=>assert.fail('No physical port may be opened'),
    setSignals:async signals=>calls.push(['signals',signals]),
  };
  const session=new EspSession(port,()=>{}),loader=session.loader;
  let physicalMac='aa:bb:cc:dd:ee:ff';
  const chip={IMAGE_CHIP_ID:chipId,CHIP_NAME:({0:'ESP32',2:'ESP32-S2',5:'ESP32-C3',9:'ESP32-S3',13:'ESP32-C6'})[chipId],readMac:async()=>{calls.push(['mac']);return physicalMac;}};
  loader.detectChip=async()=>{calls.push(['detect']);loader.chip=chip;};
  loader.getSecurityInfo=async()=>({parsedFlags:{SECURE_BOOT_EN:false,SECURE_DOWNLOAD_ENABLE:false},flashCryptCnt:0});
  loader.readReg=async()=>0;
  loader.writeReg=async(...args)=>calls.push(['register',...args]);
  loader.runStub=async()=>calls.push(['stub']);
  loader.readFlashId=async()=>0x180000;
  loader.writeFlash=async()=>assert.fail('Chip inspection must not write firmware');
  loader.eraseFlash=async()=>assert.fail('Chip inspection must not erase flash');
  session.transport.disconnect=async()=>calls.push(['close']);
  return {session,loader,chip,port,calls,setMac:value=>{physicalMac=value;}};
}
const resets=calls=>calls.filter(call=>['signals','register'].includes(call[0]));
const inspected=async options=>{const f=fixture(options);await f.session.connect('no_reset',{singleReset:true});return f;};

test('chip-only connection returns the verified silicon family and physical flash size without a firmware package or plan',async()=>{
  for(const chipId of [0,2,5,9,13]) {
    const {session,chip,calls}=fixture({chipId});
    assert.deepEqual(await session.connect('no_reset',{singleReset:true}),{chip:chip.CHIP_NAME,chipId,mac:'aa:bb:cc:dd:ee:ff',flashBytes:16<<20});
    assert.equal(session.plan,null);assert.equal(session.connectMode,'no_reset');
    assert.equal(calls.filter(call=>call[0]==='stub').length,1);assert.deepEqual(resets(calls),[]);
    await assert.rejects(session.finish(true),/completely verified write/);
    assert.deepEqual(resets(calls),[]);
  }
});

test('inspection completion grants exactly one application reset without enabling verified-write finish',async()=>{
  const {session,calls}=await inspected();
  await session.finishInspection(false);
  assert.deepEqual(resets(calls),[
    ['signals',{dataTerminalReady:false,requestToSend:true}],
    ['signals',{dataTerminalReady:false,requestToSend:false}],
  ]);
  assert.equal(session.plan,null);
  await assert.rejects(session.finishInspection(false),/only once/);
  await assert.rejects(session.finish(false),/completely verified write/);
  assert.equal(resets(calls).length,2);
});

test('native S2 and S3 inspection completion uses the same guarded volatile watchdog reset as verified-write finish',async()=>{
  for(const [chipId,addresses] of [
    [2,[0x3f408128,0x3f4080ac,0x3f408098,0x3f408094]],
    [9,[0x6000812c,0x600080b0,0x6000809c,0x60008098]],
  ]) {
    const {session,calls}=await inspected({chipId}),[force,protect,timeout,config]=addresses;
    await session.finishInspection(true);
    assert.deepEqual(resets(calls),[
      ['register',force,0,1],['register',protect,0x50d83aa1],
      ['register',timeout,2000],['register',config,0xd0000102],['register',protect,0],
    ]);
    await assert.rejects(session.finishInspection(true),/only once/);
    await assert.rejects(session.finish(true),/completely verified write/);
  }
});

test('missing or failed chip inspection never grants a reset, including a failed reconnection after success',async()=>{
  const fresh=fixture();await assert.rejects(fresh.session.finishInspection(false),/successfully inspected/);
  for(const stage of ['detect','security','mac','stub','flash','options']) {
    const f=await inspected(),original=f.loader.detectChip;
    if(stage==='detect')f.loader.detectChip=async()=>{throw Error('Detection failed');};
    if(stage==='security')f.loader.getSecurityInfo=async()=>{throw Error('Security failed');};
    if(stage==='mac')f.setMac('00:00:00:00:00:00');
    if(stage==='stub')f.loader.runStub=async()=>{throw Error('Stub failed');};
    if(stage==='flash')f.loader.readFlashId=async()=>0;
    await assert.rejects(f.session.connect('no_reset',{singleReset:stage==='options'?'yes':true}));
    await assert.rejects(f.session.finishInspection(false),/successfully inspected/);
    assert.deepEqual(resets(f.calls),[],stage);
    f.loader.detectChip=original;
  }
});

test('planning, attempted writing, recovery, and close permanently revoke an inspection reset',async()=>{
  const actions={
    prepare:s=>s.prepare({architecture:'nrf52'}),
    recordPlan:s=>s.recordPlan({addresses:[0x10000],parts:[],mac:s.mac}),
    recordCompatiblePlan:s=>s.recordCompatiblePlan({},{}),
    flash:s=>s.flash({},()=>{}),
    recoverBridge:s=>s.recoverBridge({}),
    close:s=>s.close({strict:true}),
  };
  for(const [name,action] of Object.entries(actions)) {
    const {session,calls}=await inspected();
    try{await action(session);}catch{}
    // Clearing the public plan cannot manufacture the revoked capability.
    session.plan=null;
    await assert.rejects(session.finishInspection(false),/successfully inspected/,name);
    assert.deepEqual(resets(calls),[],name);
  }
});

test('inspection reset is bound to the exact port, loader, chip, MAC, capacity, connection mode, and empty-plan session',async()=>{
  const changes={
    port:f=>{f.session.port={};},
    loader:f=>{f.session.loader={...f.loader};},
    transport:f=>{f.session.transport={...f.session.transport};},
    loaderTransport:f=>{f.loader.transport={};},
    transportPort:f=>{f.session.transport.device={};},
    chip:f=>{f.loader.chip={...f.chip};},
    chipId:f=>{f.chip.IMAGE_CHIP_ID=5;},
    mac:f=>{f.session.mac='11:22:33:44:55:66';},
    capacity:f=>{f.session.flashBytes=4<<20;},
    connectionMode:f=>{f.session.connectMode='usb_reset';},
    publicPlan:f=>{f.session.plan={};},
  };
  for(const [name,change] of Object.entries(changes)) {
    const f=await inspected();change(f);
    await assert.rejects(f.session.finishInspection(false),/unchanged/,name);
    assert.deepEqual(resets(f.calls),[],name);
  }
});

test('a changed physical MAC consumes inspection completion before any reset and cannot be retried',async()=>{
  const {session,calls,setMac}=await inspected();setMac('11:22:33:44:55:66');
  await assert.rejects(session.finishInspection(false),/Physical chip MAC changed/);
  setMac('aa:bb:cc:dd:ee:ff');
  await assert.rejects(session.finishInspection(false),/only once/);
  assert.deepEqual(resets(calls),[]);
});

test('concurrent close or preparation during final MAC inspection revokes reset before its first control-line operation',async()=>{
  for(const action of [s=>s.close({strict:true}),s=>s.prepare({architecture:'nrf52'})]) {
    const {session,chip,calls}=await inspected();let release;
    chip.readMac=()=>new Promise(resolve=>{release=resolve;});
    const finishing=session.finishInspection(false);
    try{await action(session);}catch{}
    release('aa:bb:cc:dd:ee:ff');
    await assert.rejects(finishing,/unchanged/);
    assert.deepEqual(resets(calls),[]);
  }
});

test('a changed session while connecting cannot grant an inspection reset',async()=>{
  for(const change of [s=>s.close({strict:true}),s=>{s.port={};}]) {
    const {session,loader,calls}=fixture();let release;
    loader.readFlashId=()=>new Promise(resolve=>{release=resolve;});
    const connecting=session.connect('no_reset',{singleReset:true});
    while(!release)await Promise.resolve();
    await change(session);release(0x180000);
    await assert.rejects(connecting,/session changed/);
    await assert.rejects(session.finishInspection(false),/successfully inspected/);
    assert.deepEqual(resets(calls),[]);
  }
});

test('uncertain reset delivery consumes inspection completion and forbids another reset or write finish',async()=>{
  for(const nativeUsb of [false,true]) {
    const {session,loader,port,calls}=await inspected();
    const original=Error('USB reset delivery uncertain');
    if(nativeUsb)loader.writeReg=async(...args)=>{calls.push(['register',...args]);throw original;};
    else port.setSignals=async signals=>{calls.push(['signals',signals]);throw original;};
    await assert.rejects(session.finishInspection(nativeUsb),error=>error===original);
    assert.equal(resets(calls).length,1);
    await assert.rejects(session.finishInspection(nativeUsb),/only once/);
    await assert.rejects(session.finish(nativeUsb),/completely verified write/);
    assert.equal(resets(calls).length,1);
  }
});

test('inspection reset rejects malformed reset choices without sending device operations',async()=>{
  const {session,calls}=await inspected();
  for(const value of [undefined,null,'true',1,{}])await assert.rejects(session.finishInspection(value),/boolean/);
  assert.deepEqual(resets(calls),[]);
  await session.finishInspection(false);
  assert.equal(resets(calls).length,2);
});
