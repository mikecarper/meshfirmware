import test from 'node:test';
import assert from 'node:assert/strict';
import {MeshCore,publicFromPrivate,sealBackup} from '../src/meshcore.js';

const encode=value=>new TextEncoder().encode(value),hex=value=>Buffer.from(value).toString('hex');
function payload(){
  const key=new Uint8Array(64);key[0]=1;
  const self=new Uint8Array(62),view=new DataView(self.buffer),info=new Uint8Array(82),channel=new Uint8Array(50);
  self.set([5,1,20,22]);self.set(Buffer.from(publicFromPrivate(key),'hex'),4);self.set(encode('test'),58);self.set([10,5],56);view.setUint32(48,910525,true);view.setUint32(52,125000,true);
  info.set([13,14,2,1]);new DataView(info.buffer).setUint32(4,123456,true);info.set(encode('test-model'),20);channel[0]=18;
  return {role:'companion',publicKey:publicFromPrivate(key),self:hex(self),info:hex(info),privateKey:'0e'+hex(key),channels:[hex(channel)],contacts:[],options:{},cli:{},safeForWipe:false};
}
function target(p,{protocol=14,cli}={}){
  const core=new MeshCore({}),info=Buffer.from(p.info,'hex'),commands=[],cliCommands=[];info[1]=protocol;
  core.self=async()=>Buffer.from(p.self,'hex');core.info=async()=>info;core.contacts=async()=>[];
  core.request=async command=>{commands.push(command);return command[0]===31?Buffer.from(p.channels[0],'hex'):Uint8Array.of(0);};
  core.cli=async command=>{cliCommands.push(command);return cli?cli(command):command==='get usb.logging'?'> usb.logging off':'> bluetooth off';};
  return {core,commands,cliCommands};
}
const withOptionalSettings=p=>{p.cli={'get usb.logging':'> usb.logging on','get bluetooth.name':{name:'MeshCore-custom',default:false},'get radio.cad':'> radio.cad on, scan=auto(3) ms, retry=auto ms, max=auto ms'};return p;};

test('protocol-13 core restore sends no unsupported CLI commands and reports each skipped optional setting',async()=>{
  const p=withOptionalSettings(payload()),{core,commands,cliCommands}=target(p,{protocol:13,cli:()=>{throw new Error('CLI must not be attempted');}});
  const result=await core.restore(sealBackup(p));
  assert.ok(commands.some(command=>command[0]===8));assert.equal(cliCommands.length,0);assert.equal(result.warnings.length,4);
  for(const key of ['usbLogging','bluetooth','bluetoothName','radioCad'])assert.equal(result.optional[key].state,'unsupported');assert.equal(result.optional.radioPreamble.state,'not-in-backup');
  assert.ok(!result.warnings.some(w=>/successfully restored/i.test(w)));
});

test('explicit unsupported optional commands do not block verified core restore or trigger optional writes',async()=>{
  const p=withOptionalSettings(payload()),{core,commands,cliCommands}=target(p,{cli:()=>'> Unknown command'}),result=await core.restore(sealBackup(p));
  assert.equal(result.warnings.length,4);assert.ok(commands.some(command=>command[0]===11));
  assert.ok(cliCommands.every(command=>command.startsWith('get ')));for(const key of ['usbLogging','bluetooth','bluetoothName','radioCad'])assert.equal(result.optional[key].state,'unsupported');assert.equal(result.optional.radioPreamble.state,'not-in-backup');
});

test('explicit unsupported CLI protocol result is distinguished from genuine protocol errors',async()=>{
  for(const code of [1,4,5,6]){
    const p=payload(),{core,commands,cliCommands}=target(p),error=new Error('CLI protocol error');Object.assign(error,{meshcoreCommand:66,meshcoreResponseCode:1,meshcoreErrorCode:code});
    core.cli=async command=>{cliCommands.push(command);throw error;};
    if(code===1){const result=await core.restore(sealBackup(p));assert.equal(result.optional.usbLogging.state,'unsupported');assert.equal(result.optional.bluetooth.state,'unsupported');assert.deepEqual(cliCommands,['get usb.logging']);}
    else{await assert.rejects(()=>core.restore(sealBackup(p)),/CLI protocol error/);assert.equal(commands.length,0);}
  }
  const core=new MeshCore({});core.send=async()=>{};core.frame=async()=>Uint8Array.of(1,1);
  await assert.rejects(()=>core.request([66,1],29),error=>error.meshcoreCommand===66&&error.meshcoreResponseCode===1&&error.meshcoreErrorCode===1);
});

test('supported logging remains fail-closed on timeout, unparseable state, unsafe disable or lost readback',async()=>{
  for(const mode of ['timeout','unknown','disable','readback']){
    const p=payload();let reads=0;const {core,commands}=target(p,{cli:command=>{
      if(command==='get usb.logging'){
        reads++;if(mode==='timeout')throw new Error('logging transport timeout');if(mode==='unknown')return 'logging state unavailable';
        if(mode==='readback'&&reads>=3)return 'Unknown command';return mode==='disable'?'> usb.logging on':'> usb.logging off';
      }
      return command==='set usb.logging off'?'ERROR - save failed':'> bluetooth off';
    }});
    await assert.rejects(()=>core.restore(sealBackup(p)),/logging|USB logging/i);
    if(mode!=='readback')assert.equal(commands.length,0);
  }
});

test('supported logging defaults off and Bluetooth is cycled only when its verified initial state was on',async()=>{
  for(const initial of ['on','off']){
    const p=payload();let logging='on',bluetooth=initial;const {core,cliCommands}=target(p,{cli:command=>{
      if(command==='get usb.logging')return `> usb.logging ${logging}`;
      if(command.startsWith('set usb.logging ')){logging=command.split(' ').pop();return `OK - USB logging ${logging} (saved)`;}
      if(command==='get bluetooth')return `> bluetooth ${bluetooth}`;
      if(command.startsWith('set bluetooth ')){bluetooth=command.split(' ').pop();return `OK - Bluetooth ${bluetooth}`;}
      throw new Error('Unexpected optional command');
    }}),result=await core.restore(sealBackup(p));
    assert.equal(logging,'off');assert.equal(result.optional.usbLogging.value,'off');assert.equal(result.optional.bluetooth.state,initial==='on'?'resynced':'unchanged');
    assert.equal(cliCommands.includes('set bluetooth off'),initial==='on');assert.equal(cliCommands.includes('set bluetooth on'),initial==='on');assert.equal(bluetooth,initial);assert.equal(result.warnings.length,0);
  }
});

test('Full Companion keeps supported Bluetooth-name/CAD readbacks and restores an explicit logging-on preference last',async()=>{
  const p=withOptionalSettings(payload());let logging='on',bluetooth='on',name='MeshCore-original',cad=['off','1','2','3'];
  const {core,cliCommands}=target(p,{cli:command=>{
    if(command==='get usb.logging')return `> usb.logging ${logging}`;
    if(command.startsWith('set usb.logging ')){logging=command.split(' ').pop();return `OK - USB logging ${logging} (saved)`;}
    if(command==='get bluetooth')return `> bluetooth ${bluetooth}`;
    if(command.startsWith('set bluetooth ')){bluetooth=command.split(' ').pop();return `OK - Bluetooth ${bluetooth}`;}
    if(command==='get bluetooth.name')return `> ${name} (custom)`;
    if(command.startsWith('set bluetooth.name ')){name=command.slice('set bluetooth.name '.length);return 'OK - Bluetooth name changed';}
    if(command==='get radio.cad')return `> radio.cad ${cad[0]}, scan=${cad[1]} ms, retry=${cad[2]} ms, max=${cad[3]} ms`;
    if(command.startsWith('set radio.cad timings ')){cad=[cad[0],...command.slice('set radio.cad timings '.length).split(' ')];return 'OK';}
    if(command.startsWith('set radio.cad ')){cad[0]=command.split(' ').pop();return 'OK';}
    throw new Error('Unexpected command');
  }});
  const request=core.request;core.request=async command=>{assert.equal(logging,'off','binary restore settings require logging off');return request(command);};
  const result=await core.restore(sealBackup(p));
  assert.equal(name,'MeshCore-custom');assert.deepEqual(cad,['on','auto','auto','auto']);assert.equal(logging,'on');assert.equal(bluetooth,'on');
  assert.equal(result.optional.bluetoothName.state,'restored');assert.equal(result.optional.radioCad.state,'restored');assert.equal(result.optional.usbLogging.value,'on');assert.equal(result.warnings.length,0);
  assert.ok(cliCommands.indexOf('set usb.logging on')>cliCommands.indexOf('set bluetooth on'));
});

test('a failed Bluetooth-off acknowledgement still attempts to re-enable a previously enabled target',async()=>{
  const p=payload(),{core,cliCommands}=target(p,{cli:command=>command==='get usb.logging'?'> usb.logging off':command==='get bluetooth'?'> bluetooth on':command==='set bluetooth off'?'ERROR - could not disable':'OK - Bluetooth on'});
  await assert.rejects(()=>core.restore(sealBackup(p)),/Bluetooth off was not confirmed/);
  assert.ok(cliCommands.includes('set bluetooth on'));
});

const start=count=>Uint8Array.from([2,count&255,count>>>8&255,0,0]);
const end=()=>Uint8Array.of(4,0,0,0,0);
function inventory(frames,{timeoutMs=7000}={}){
  const core=new MeshCore({},{timeoutMs}),sent=[];core.send=async command=>sent.push(command);core.frame=async()=>{assert.ok(frames.length,'No unexpected frame request');return frames.shift();};return {core,sent};
}
test('contact inventory ignores unsolicited pushes before start and between contact/end frames',async()=>{
  const row=new Uint8Array(148);row[0]=3;row[1]=1;
  const raw=new Uint8Array(11);raw.set(start(1),3);
  const {core,sent}=inventory([Uint8Array.of(0x83),Uint8Array.of(0x80,1),raw.subarray(3,8),Uint8Array.of(0x8a,2),row,Uint8Array.of(0x81),end()]);
  assert.deepEqual(await core.contacts(),[row]);assert.deepEqual(sent,[[4]]);assert.equal(core.busy,false);
});

test('contact inventory still rejects malformed starts, protocol errors, duplicate/count mismatches and invalid ends',async()=>{
  const row=new Uint8Array(148);row[0]=3;row[1]=1;
  for(const frames of [
    [Uint8Array.of(2)], [Uint8Array.of(1,4)], [Uint8Array.of(15)], [start(511)], [Uint8Array.of(13)],
    [start(1),Uint8Array.of(1,5)], [start(1),end()], [start(0),row], [start(2),row,row], [start(0),Uint8Array.of(4)], [start(0),Uint8Array.of(2,0,0,0,0)]
  ]){
    const {core}=inventory(frames);await assert.rejects(()=>core.contacts(),/Contact|contact|rejected/);assert.equal(core.busy,false);
  }
});

test('continuous unsolicited pushes cannot extend contact start or inventory beyond their time limits',async()=>{
  const realNow=Date.now;let now=1000;Date.now=()=>now;
  try{
    const core=new MeshCore({},{timeoutMs:50});core.send=async()=>{};core.frame=async()=>{now+=25;return Uint8Array.of(0x83);};
    await assert.rejects(()=>core.contacts(),/start timed out/);assert.equal(core.busy,false);
    let first=true;core.frame=async()=>{if(first){first=false;return start(0);}now+=10000;return Uint8Array.of(0x83);};
    await assert.rejects(()=>core.contacts(),/inventory timed out/);assert.equal(core.busy,false);
  }finally{Date.now=realNow;}
});
