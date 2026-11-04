import test from 'node:test';
import assert from 'node:assert/strict';
import {createNrfActivationCheck} from '../src/nrf-activation.js';

const publicKey='11'.repeat(32),fullVersion='v1.18.0.2-halo-keymind-cascade-dev-cdd3955a';
const port=(vendor,product)=>({getInfo:()=>({usbVendorId:vendor,usbProductId:product})});
function fakeClock(){
  let tick=0;const timers=new Set();
  return {
    now:()=>tick,
    set(value){tick=value;},
    delay(ms,{signal}={}){
      assert.ok(Number.isFinite(ms)&&ms>=0);
      return new Promise((resolve,reject)=>{
        const timer={at:tick+ms,finish(){timers.delete(timer);signal?.removeEventListener('abort',abort);resolve();}};
        const abort=()=>{timers.delete(timer);reject(Object.assign(Error('Timer aborted'),{name:'AbortError'}));};
        if(signal?.aborted){abort();return;}
        signal?.addEventListener('abort',abort,{once:true});timers.add(timer);
      });
    },
    next(){
      assert.ok(timers.size,'No test clock timer can settle this operation');
      tick=Math.max(tick,Math.min(...[...timers].map(timer=>timer.at)));
      for(const timer of [...timers])if(timer.at<=tick)timer.finish();
    },
  };
}
async function settle(promise,clock){
  let finished=false,value,failure;promise.then(result=>{finished=true;value=result;},error=>{finished=true;failure=error;});
  for(let step=0;step<100;step++){
    for(let turn=0;turn<24;turn++)await Promise.resolve();
    if(finished){if(failure)throw failure;return value;}
    clock.next();
  }
  assert.fail('Activation check did not finish within its fake-clock budget');
}
function fixture({packageChanges={},deviceChanges={},hardware='Seeed Studio SenseCAP T1000-E',role='companion'}={}){
  const calls=[],clock=fakeClock(),appPort=port(0x239a,0x8029),dfuPort=port(0x2886,0x0057);
  const pkg={name:`t1000e_companion_radio_full-${fullVersion}.zip`,architecture:'nrf52',kind:'application',mode:4,sdSize:0,blSize:0,appSize:613912,erase:false,expert:false,destructive:false,sha256:'a'.repeat(64),payloadHash:'b'.repeat(64),metadataHash:'c'.repeat(64),...packageChanges};
  const device={firmwareFamily:'meshcore',model:'Seeed Tracker T1000-E',role:'companion',publicKey,version:'v1.18.0.1',bootloaderVersion:'OTAFIX2.4.12-preview.142',...deviceChanges};
  const known={port:appPort,publicKey,available:false};
  const fresh={firmwareFamily:'meshcore',model:device.model,role:'companion',publicKey,version:`Companion ${fullVersion} (protocol 14, build 04-Nov-2026)`};
  const context={current:true};
  const options={pkg,device,knownApplicationPort:known,hardware,expectedRole:role,readApplication:async(actual,details)=>{
    calls.push({kind:'read',port:actual,details});assert.equal(actual,appPort,'Never substitute an ID lookalike');return {...fresh};
  },isCurrent:()=>context.current,delay:clock.delay,now:clock.now,log:message=>calls.push({kind:'log',message})};
  const link={port:dfuPort,close:async()=>calls.push({kind:'close'})};
  const invoke=(check=createNrfActivationCheck(options),more={})=>{
    assert.equal(typeof check,'function');return check({link,pkg,maxWaitMs:45000,onProgress:(fraction,message)=>calls.push({kind:'progress',fraction,message}),...more});
  };
  return {calls,clock,pkg,device,known,fresh,options,link,appPort,dfuPort,context,invoke};
}

test('known native T1000 application proof ends activation early on the exact old app object without reset or a write',async()=>{
  const io=fixture(),check=createNrfActivationCheck(io.options);
  assert.equal(await settle(io.invoke(check),io.clock),true);
  assert.equal(io.clock.now(),0);assert.equal(io.calls.filter(call=>call.kind==='close').length,1);
  assert.equal(io.calls.filter(call=>call.kind==='read').length,1);assert.equal(io.calls.find(call=>call.kind==='read').port,io.appPort);
  assert.equal(io.calls.find(call=>call.kind==='read').details.timeoutMs,3000);
  assert.ok(io.calls.every(call=>['close','read','progress','log'].includes(call.kind)));
  assert.match(io.calls.find(call=>call.kind==='log').message,/expected identity and complete firmware version/);
  assert.equal(await io.invoke(check),false,'An activation check is one-shot');
  assert.equal(io.calls.filter(call=>call.kind==='close').length,1);
});

test('only reviewed native T1000 application and bootloader contexts qualify, never version-as-bank evidence',()=>{
  const mutations=[
    io=>{io.options.pkg=null;},io=>{io.pkg.architecture='esp32';},io=>{io.pkg.kind='bootloader';},io=>{io.pkg.kind='softdevice';},
    io=>{io.pkg.mode=1;},io=>{io.pkg.sdSize=152000;},io=>{io.pkg.blSize=42000;},io=>{io.pkg.erase=true;},io=>{io.pkg.expert=true;},io=>{io.pkg.destructive=true;},
    io=>{io.pkg.name=io.pkg.name.replace('_full-','_full-with-bootloader-2.4.12-');},io=>{io.pkg.includesBootloader=true;},io=>{io.pkg.embeddedSoftdevice=true;},
    io=>{io.pkg.appSize=0;},io=>{io.pkg.appSize=1<<21;},io=>{io.pkg.sha256='invalid';},
    io=>{io.device.role='common-cli';},io=>{io.options.expectedRole='common-cli';},io=>{io.device.firmwareFamily='meshtastic';},
    io=>{io.device.model='RAK 4631';},io=>{io.options.hardware='Seeed Studio Xiao nRF52 WIO';},
    io=>{io.device.publicKey=null;},io=>{io.known.publicKey='22'.repeat(32);},io=>{io.known.port=port(0x2886,0x0057);},io=>{io.known.port=port(0x239a,0x802a);},
    io=>{io.device.bootloaderVersion='0.4.3';},io=>{io.device.bootloaderVersion='OTAFIX2.4.12-preview.143';},io=>{io.device.bootloaderVersion='OTAFIX2.4.12-dualbank';},
    io=>{io.pkg.name='unknown.zip';},io=>{io.pkg.firmwareIdentity={versionText:'v1.18.0.3'};},
    io=>{io.options.readApplication=null;},io=>{io.options.isCurrent=null;},
  ];
  for(const mutate of mutations){const io=fixture();mutate(io);assert.equal(createNrfActivationCheck(io.options),null,String(mutate));assert.deepEqual(io.calls,[]);}
});

test('reviewed bootloader print forms and exact firmware-footer fallback qualify without assuming bank mode',async()=>{
  for(const reported of ['OTAFIX2.4.12','OTAFIX2.4.12-preview.142','0.11.0-OTAFIX2.4.12','v0.11.0-OTAFIX2.4.12-preview.142']){
    const io=fixture({deviceChanges:{bootloaderVersion:reported}});io.known.publicKey=publicKey.toUpperCase();io.fresh.publicKey=publicKey.toUpperCase();io.fresh.version=fullVersion;
    assert.equal(await settle(io.invoke(),io.clock),true,reported);
  }
  const io=fixture({packageChanges:{name:'renamed.zip',firmwareIdentity:{versionText:'v1.18.0.2'}}});io.fresh.version='v1.18.0.2';
  assert.equal(await settle(io.invoke(),io.clock),true);
});

test('unreviewed DFU interface, different package or invalid time budget never closes or probes any device',async()=>{
  for(const scenario of ['wrong-dfu','lookalike','different-pkg','short-budget','unbounded','nan','stale']){
    const io=fixture(),check=createNrfActivationCheck(io.options),more={};
    if(scenario==='wrong-dfu')io.link.port=port(0x239a,0x002a);
    if(scenario==='lookalike')io.link.port=port(0x239a,0x8029);
    if(scenario==='different-pkg')more.pkg={...io.pkg};
    if(scenario==='short-budget')more.maxWaitMs=2999;
    if(scenario==='unbounded')more.maxWaitMs=Infinity;
    if(scenario==='nan')more.maxWaitMs=NaN;
    if(scenario==='stale')io.context.current=false;
    assert.equal(await settle(io.invoke(check,more),io.clock),false,scenario);assert.deepEqual(io.calls,[],scenario);
  }
});

test('only read-only readiness errors retry sequentially, still using the same exact app object',async()=>{
  for(const failure of [Object.assign(Error('Not present'),{name:'NotFoundError'}),Object.assign(Error('Reconnecting'),{name:'NetworkError'}),Object.assign(Error('Not ready'),{name:'TimeoutError'}),Error('MeshCore command timed out.')]){
    const io=fixture();let attempts=0,active=0;
    io.options.readApplication=async(actual)=>{
      assert.equal(actual,io.appPort);assert.equal(active++,0);io.calls.push({kind:'read'});
      try{if(++attempts<3)throw failure;return {...io.fresh};}finally{active--;}
    };
    assert.equal(await settle(io.invoke(),io.clock),true,failure.name);assert.equal(attempts,3);assert.equal(io.clock.now(),500);assert.equal(io.calls.filter(call=>call.kind==='close').length,1);
  }
});

test('wrong public identity, model, role, complete version, or truncated replies stop without retries or false success',async()=>{
  for(const [field,value] of [['publicKey','22'.repeat(32)],['publicKey',null],['model','Seeed Xiao-nrf52'],['role','common-cli'],['firmwareFamily','meshtastic'],['version','v1.18.0.1'],['version','v1.18.0.2-halo-keymi'],['version',fullVersion+'…'],['version',fullVersion+' extra'],['version',undefined]]){
    const io=fixture();io.fresh[field]=value;
    assert.equal(await settle(io.invoke(),io.clock),false,field+':'+value);assert.equal(io.calls.filter(call=>call.kind==='read').length,1);assert.equal(io.calls.filter(call=>call.kind==='log').length,0);
  }
});

test('permission/security and unexpected adapter failures retain the conservative wait without a second probe',async()=>{
  for(const failure of [Object.assign(Error('Access denied'),{name:'NotAllowedError'}),Object.assign(Error('Security policy'),{name:'SecurityError'}),Object.assign(Error('Permission denied'),{name:'NotFoundError'}),Error('Bad identity record')]){
    const io=fixture();let attempts=0;io.options.readApplication=async()=>{attempts++;throw failure;};
    assert.equal(await settle(io.invoke(),io.clock),false,failure.name);assert.equal(attempts,1);assert.equal(io.clock.now(),0);
  }
});

test('an unbounded adapter is aborted at its read budget and never overlaps a subsequent probe',async()=>{
  const io=fixture();let signal,attempts=0;
  io.options.readApplication=(_port,options)=>{attempts++;signal=options.signal;return new Promise(()=>{});};
  assert.equal(await settle(io.invoke(),io.clock),false);assert.equal(io.clock.now(),3000);assert.equal(signal.aborted,true);assert.equal(attempts,1);
});

test('owned DFU close failures/timeouts never lead to an application probe',async()=>{
  for(const pending of [false,true]){
    const io=fixture();io.link.close=async()=>{io.calls.push({kind:'close'});if(pending)return new Promise(()=>{});throw Error('Close failed');};
    assert.equal(await settle(io.invoke(),io.clock),false);assert.deepEqual(io.calls,[{kind:'close'}]);assert.equal(io.clock.now(),pending?1000:0);
  }
});

test('stale context or changed exact package/key after close/read cannot end the activation wait',async()=>{
  for(const phase of ['close','read'])for(const mutation of ['context','sha','name','known-port','known-key']){
    const io=fixture();const change=()=>{
      if(mutation==='context')io.context.current=false;
      if(mutation==='sha')io.pkg.sha256='d'.repeat(64);
      if(mutation==='name')io.pkg.name='changed.zip';
      if(mutation==='known-port')io.known.port=port(0x239a,0x8029);
      if(mutation==='known-key')io.known.publicKey='22'.repeat(32);
    };
    if(phase==='close')io.link.close=async()=>{io.calls.push({kind:'close'});change();};
    else io.options.readApplication=async()=>{io.calls.push({kind:'read'});change();return {...io.fresh};};
    assert.equal(await settle(io.invoke(),io.clock),false,phase+':'+mutation);assert.equal(io.calls.filter(call=>call.kind==='read').length,phase==='close'?0:1);
  }
});

test('the absolute deadline and read-attempt cap cannot be extended by late fresh replies or clock changes',async()=>{
  for(const tick of [45000,45001,-1]){
    const io=fixture();io.options.readApplication=async()=>{io.clock.set(tick);return {...io.fresh};};
    assert.equal(await settle(io.invoke(),io.clock),false,String(tick));
  }
  const io=fixture();let attempts=0;io.options.readApplication=async()=>{attempts++;throw Object.assign(Error('Waiting'),{name:'NotFoundError'});};
  assert.equal(await settle(io.invoke(),io.clock),false);assert.equal(attempts,16);assert.ok(io.clock.now()<45000);
  const short=fixture();short.options.readApplication=async()=>{short.clock.set(500);throw Object.assign(Error('Waiting'),{name:'NetworkError'});};
  assert.equal(await settle(short.invoke(undefined,{maxWaitMs:3500}),short.clock),false);assert.equal(short.clock.now(),500,'Do not start a read which cannot fit the required budget');
});
