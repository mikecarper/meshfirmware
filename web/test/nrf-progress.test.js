import test from 'node:test';
import assert from 'node:assert/strict';
import {zipSync} from 'fflate';
import {crc16,nrfPackage,nrfMetadataHash} from '../src/firmware.js';
import {flashNrf,slipDecode,slipEncode} from '../src/serial.js';

function firmware(length){
  const bin=new Uint8Array(length),dat=new Uint8Array(12),view=new DataView(dat.buffer);
  view.setUint16(0,0x52,true);view.setUint16(10,crc16(bin),true);
  return nrfPackage('app.zip',zipSync({'manifest.json':new TextEncoder().encode(JSON.stringify({manifest:{dfu_version:.5,application:{bin_file:'app.bin',dat_file:'app.dat'}}})),'app.bin':bin,'app.dat':dat}));
}
function transport({failDelayPhase=null}={}){
  let waited=0,pending=null,phase='',phaseDelays=0;
  const events=[],failure=Error('Bootloader wait interrupted');
  const link={buffer:[],port:{async setSignals(signals){events.push({type:'signals',signals,at:waited});}},async write(packet){
    const frame=slipDecode(packet.subarray(1,-1)),command=new DataView(frame.buffer,frame.byteOffset).getUint32(4,true),ack=((frame[0]&7)+1)&7;
    events.push({type:'write',command,at:waited});pending=slipEncode([ack<<3,0,0,(-(ack<<3))&255]);
  },async read(){const result=pending;pending=null;return result||new Uint8Array();}};
  return {link,events,failure,waited:()=>waited,onProgress(value,label){
    const next=label.startsWith('Preparing DFU')?'prepare':label.startsWith('Activating firmware')?'activate':'other';
    if(next!==phase){phase=next;phaseDelays=0;}events.push({type:'progress',value,label,phase,at:waited});
  },async delay(ms){
    events.push({type:'delay',ms,phase,at:waited});phaseDelays++;
    if(phase===failDelayPhase&&phaseDelays===2)throw failure;
    waited+=ms;
  }};
}

test('DFU wait countdowns update at most one second apart without shortening safe waits or moving writes',async()=>{
  for(const length of [256,128*1024,900*1024]){
    const pkg=firmware(length),io=transport(),pages=Math.ceil(length/4096)+1;
    const eraseWait=Math.min(30000,Math.max(500,Math.ceil(pages*89.7))),activationWait=eraseWait+Math.ceil(pages*204.8),chunks=Math.ceil(length/512);
    const total=eraseWait+205+Math.floor(chunks/8)*205+205+activationWait;
    await flashNrf(io.link,pkg,io.onProgress,{delay:io.delay});
    const writes=io.events.filter(event=>event.type==='write');
    assert.deepEqual(writes.map(event=>event.command),[3,1,...Array(chunks).fill(4),5]);
    assert.equal(writes[0].at,0);assert.equal(writes[1].at,eraseWait);assert.equal(writes[2].at,eraseWait+205);
    assert.equal(writes.at(-1).at,total-activationWait);
    assert.equal(io.waited(),total);assert.equal(io.events.filter(event=>event.type==='delay').reduce((sum,event)=>sum+event.ms,0),total);
    for(const [phase,ms,value,start] of [['prepare',eraseWait,0,0],['activate',activationWait,.96,total-activationWait]]){
      const updates=io.events.filter(event=>event.type==='progress'&&event.phase===phase&&/remaining/.test(event.label));
      assert.equal(updates.length,Math.ceil(ms/1000));
      updates.forEach((event,index)=>{
        assert.equal(event.value,value);assert.equal(event.at,start+index*1000);
        assert.match(event.label,new RegExp(`about ${Math.ceil((ms-index*1000)/1000)}s remaining`));
        assert.match(event.label,/Keep USB and power connected/);
      });
      const delays=io.events.filter(event=>event.type==='delay'&&event.phase===phase&&event.at>=start&&event.at<start+ms);
      assert.ok(delays.every(event=>event.ms>0&&event.ms<=1000));
      assert.equal(delays.reduce((sum,event)=>sum+event.ms,0),ms);
    }
    const completed=io.events.filter(event=>event.type==='progress'&&event.value===1);
    assert.equal(completed.length,1);assert.equal(completed[0].at,total);assert.equal(completed[0],io.events.at(-1));
  }
});

test('an interrupted preparation wait cannot send init/data/activation or report completion',async()=>{
  const io=transport({failDelayPhase:'prepare'});
  await assert.rejects(flashNrf(io.link,firmware(128*1024),io.onProgress,{delay:io.delay}),error=>error===io.failure);
  assert.deepEqual(io.events.filter(event=>event.type==='write').map(event=>event.command),[3]);
  assert.equal(io.events.some(event=>event.type==='progress'&&event.value===1),false);
  assert.equal(io.waited(),1000);
});

test('an interrupted activation wait preserves the failure without repeating writes or claiming DONE',async()=>{
  const io=transport({failDelayPhase:'activate'}),pkg=firmware(128*1024),chunks=Math.ceil(pkg.payload.length/512);
  await assert.rejects(flashNrf(io.link,pkg,io.onProgress,{delay:io.delay}),error=>error===io.failure);
  assert.deepEqual(io.events.filter(event=>event.type==='write').map(event=>event.command),[3,1,...Array(chunks).fill(4),5]);
  assert.equal(io.events.some(event=>event.type==='progress'&&event.value===1),false);
  assert.equal(io.events.filter(event=>event.type==='progress'&&event.phase==='activate').length,2);
});

test('qualified application readiness can end only the post-transfer wait, after the settings guard',async()=>{
  const pkg=firmware(600*1024),io=transport(),pages=Math.ceil(pkg.payload.length/4096)+1;
  const eraseWait=Math.min(30000,Math.ceil(pages*89.7)),activationWait=eraseWait+Math.ceil(pages*204.8);
  let checked=0,stopAt;
  await flashNrf(io.link,pkg,io.onProgress,{delay:io.delay,now:io.waited,activationCheck:async args=>{
    checked++;stopAt=io.events.findLast(event=>event.type==='write').at;
    assert.equal(args.link,io.link);assert.equal(args.pkg,pkg);assert.equal(args.maxWaitMs,activationWait-250);
    assert.equal(io.waited()-stopAt,250);assert.equal(io.events.some(event=>event.type==='progress'&&event.value===1),false);
    args.onProgress('Checking the same returning application…');await io.delay(1500);return true;
  }});
  assert.equal(checked,1);assert.equal(io.waited()-stopAt,1750);
  assert.deepEqual(io.events.filter(event=>event.type==='write').map(event=>event.command),[3,1,...Array(Math.ceil(pkg.payload.length/512)).fill(4),5]);
  assert.equal(io.events.filter(event=>event.type==='progress'&&event.value===1).length,1);
  assert.equal(io.events.at(-1).at,stopAt+1750);assert.match(io.events.at(-1).label,/remains unverified/);
});

test('unproven or failed optional readiness retains the remaining conservative activation budget',async()=>{
  for(const outcome of ['false','throw','truthy']){
    const pkg=firmware(128*1024),io=transport(),pages=Math.ceil(pkg.payload.length/4096)+1;
    const activationWait=Math.max(500,Math.ceil(pages*89.7))+Math.ceil(pages*204.8);let stopAt;
    await flashNrf(io.link,pkg,io.onProgress,{delay:io.delay,now:io.waited,activationCheck:async()=>{
      stopAt=io.events.findLast(event=>event.type==='write').at;await io.delay(1200);
      if(outcome==='throw')throw Error('Application readiness unavailable');return outcome==='truthy'?{connected:true}:false;
    }});
    assert.equal(io.waited()-stopAt,activationWait,outcome);assert.equal(io.events.filter(event=>event.type==='progress'&&event.value===1).length,1,outcome);
    assert.equal(io.events.filter(event=>event.type==='write'&&event.command===5).length,1,outcome);
  }
});

test('components, erase utilities and updater wrappers never invoke the optional fast readiness path',async()=>{
  for(const variant of ['bootloader','softdevice','softdevice_bootloader','erase','expert','wrapper','recovery']){
    const pkg=firmware(64*1024),io=transport();
    if(['bootloader','softdevice','softdevice_bootloader'].includes(variant)){
      pkg.kind=variant;pkg.appSize=0;pkg.sdSize=variant==='bootloader'?0:variant==='softdevice'?pkg.payload.length:pkg.payload.length/2;pkg.blSize=pkg.payload.length-pkg.sdSize;pkg.mode={bootloader:2,softdevice:1,softdevice_bootloader:3}[variant];
    }
    if(variant==='erase')pkg.erase=true;if(variant==='expert')pkg.expert=true;
    if(variant==='wrapper')pkg.name='t1000e-with-bootloader-2.4.12.zip';if(variant==='recovery')pkg.name='R_t1000e.zip';
    pkg.metadataHash=nrfMetadataHash(pkg);
    await flashNrf(io.link,pkg,io.onProgress,{delay:io.delay,now:io.waited,activationCheck:async()=>assert.fail('No fast path for '+variant)});
    assert.ok(io.events.some(event=>event.type==='progress'&&event.phase==='activate'),variant);
  }
});

test('invalid activation callbacks fail before signals, erases or writes',async()=>{
  for(const activationCheck of [true,123,{},'ready']){
    const io=transport();await assert.rejects(flashNrf(io.link,firmware(256),io.onProgress,{delay:io.delay,activationCheck}),/activation check/);assert.deepEqual(io.events,[]);
  }
});
