import test from 'node:test';
import assert from 'node:assert/strict';
import {chooseConnection,parseUsbMode,captureNrfDfuEvidence,nrfDfuEvidenceCurrent} from '../src/connection-choice.js';
import {zipSync} from 'fflate';
import {crc16,nrfPackage} from '../src/firmware.js';
const usb=(usbVendorId,usbProductId)=>({usbVendorId,usbProductId});

test('USB mode parser accepts only a complete canonical bounded reply',()=>{
  for(const mode of ['hardware-cdc-jtag','tinyusb','uart','unknown'])assert.equal(parseUsbMode('usb.mode '+mode),mode);
  for(const reply of [null,{},'', 'tinyusb','> usb.mode tinyusb','get usb.mode','USB.MODE tinyusb','usb.mode TinyUSB','usb.mode tinyusb extra','usb.mode tinyusb\n','usb.mode tinyusb\nusb.mode hardware-cdc-jtag','Unknown command','x'.repeat(129),'usb.mode __proto__'])assert.equal(parseUsbMode(reply),null,String(reply));
});

test('the current responding application can resolve shared native USB through its exact reported mode',()=>{
  const usbInfo=usb(0x303a,0x1001);
  for(const [usbMode,mode] of [['hardware-cdc-jtag','usb_reset'],['tinyusb','tinyusb']]){
    const chosen=chooseConnection({usbInfo,device:{model:'Heltec V4.2 none detected',architecture:'esp32',usbMode}});assert.equal(chosen.mode,mode);assert.equal(chosen.source,'application-report');assert.equal(chosen.alreadyBootloader,false);
  }
  for(const usbMode of [null,undefined,'unknown','usb.mode tinyusb','TinyUSB','unsupported'])assert.equal(chooseConnection({usbInfo,device:{model:'Heltec v4',architecture:'esp32',usbMode}}).mode,null);
});

test('report conflicts and unqualified interfaces never become an automatic reset',()=>{
  const device={model:'Heltec v4',architecture:'esp32'};
  for(const [usbMode,usbDescription] of [['tinyusb','USB Serial/JTAG'],['hardware-cdc-jtag','TinyUSB CDC'],['uart','']])assert.equal(chooseConnection({usbInfo:usb(0x303a,0x1001),device:{...device,usbMode},usbDescription}).mode,null);
  for(const usbInfo of [usb(0x303a,0x0002),usb(0x2886,0x0059)])assert.equal(chooseConnection({usbInfo,device:{...device,usbMode:'hardware-cdc-jtag'}}).mode,null);
  for(const usbInfo of [usb(0x303a,0x1002),usb(0x2886,0x8059),usb(0x1234,0x5678),{}])for(const usbMode of ['tinyusb','hardware-cdc-jtag'])assert.equal(chooseConnection({usbInfo,device:{...device,usbMode}}).mode,null);
  for(const device of [{usbMode:'hardware-cdc-jtag'},{model:'Heltec v4',usbMode:'hardware-cdc-jtag'}])assert.equal(chooseConnection({usbInfo:usb(0x303a,0x1001),device,packageArchitecture:'esp32'}).mode,null);
});

test('known DFU, explicit handoff, nRF runtime and UART bridges keep precedence over USB reports',()=>{
  const device={model:'Heltec v4',architecture:'esp32',usbMode:'tinyusb'};
  assert.equal(chooseConnection({usbInfo:usb(0x2886,0x0044),device}).mode,'nrf52');
  assert.equal(chooseConnection({usbInfo:usb(0x303a,0x1001),device,handoff:true}).mode,'no_reset');
  assert.equal(chooseConnection({usbInfo:usb(0x303a,0x1001),device,alreadyBootloader:true}).mode,'no_reset');
  assert.equal(chooseConnection({usbInfo:usb(0x2886,0x8044),device:{model:'XIAO nRF52',architecture:'nrf52',usbMode:'tinyusb'}}).mode,'nrf52');
  assert.equal(chooseConnection({usbInfo:usb(0x1a86,0x7523),device}).mode,'default_reset');
});

test('reviewed running-firmware history is secondary to live reports and cannot override conflicting USB evidence',()=>{
  const usbInfo=usb(0x303a,0x1001),device={model:'Heltec v4',architecture:'esp32',usbModeStatus:'unsupported',usbModeFallback:{source:'firmware-map',usbMode:'hardware-cdc-jtag',reason:'Exact running build mapped.'}};
  assert.equal(chooseConnection({usbInfo,device}).mode,'usb_reset');assert.equal(chooseConnection({usbInfo,device}).source,'firmware-map');
  assert.equal(chooseConnection({usbInfo,device:{...device,usbMode:'tinyusb'}}).mode,'tinyusb');
  assert.equal(chooseConnection({usbInfo,device,usbDescription:'TinyUSB CDC'}).mode,null);
  assert.equal(chooseConnection({usbInfo:usb(0x303a,0x0002),device}).source,'conflict');
  for(const usbModeStatus of ['unknown','malformed','reported',undefined])assert.equal(chooseConnection({usbInfo,device:{...device,usbModeStatus}}).mode,null);
  assert.equal(chooseConnection({usbInfo,device:{...device,usbModeFallback:{source:'guessed-image',usbMode:'hardware-cdc-jtag'}}}).mode,null);
  const tiny={...device,usbModeFallback:{...device.usbModeFallback,usbMode:'tinyusb'}};
  assert.equal(chooseConnection({usbInfo,device:tiny}).mode,'tinyusb');assert.equal(chooseConnection({usbInfo,device:tiny,usbDescription:'USB Serial/JTAG'}).source,'conflict');
});

test('known exact nRF52 DFU selects serial DFU without another touch',()=>{
  for(const [vid,pid] of [[0x2886,0x0057],[0x2886,0x0044],[0x239a,0x0029],[0x4251,0x8695],[0x239a,0x0081]]){
    const selected=chooseConnection({usbInfo:usb(vid,pid)});assert.equal(selected.mode,'nrf52');assert.equal(selected.alreadyBootloader,true);assert.equal(selected.source,'dfu-usb');assert.match(selected.reason,/not physical-board proof/);assert.equal(Object.hasOwn(selected,'hardware'),false);
  }
});
test('running nRF52 architecture selects guarded serial-DFU handoff, not already DFU',()=>{
  const selected=chooseConnection({usbInfo:usb(0x2886,0x8044),device:{model:'Seeed Xiao-nrf52',architecture:'nrf52'}});assert.equal(selected.mode,'nrf52');assert.equal(selected.alreadyBootloader,false);
});
test('explicit ESP ROM or same-device handoff selects no reset, never infers from silence',()=>{
  for(const flag of ['alreadyBootloader','handoff']){const selected=chooseConnection({usbInfo:usb(0x303a,0x1001),[flag]:true});assert.equal(selected.mode,'no_reset');assert.equal(selected.alreadyBootloader,true);}
  assert.equal(chooseConnection({usbInfo:usb(0x303a,0x0002)}).mode,null);
});
test('explicit nRF handoff remains serial DFU even when USB IDs were omitted',()=>{
  for(const more of [{device:{architecture:'nrf52'}},{packageArchitecture:'nrf52'}])assert.equal(chooseConnection({handoff:true,...more}).mode,'nrf52');
});
test('reviewed UART bridge pairs select DTR/RTS strategy without assuming a physical board',()=>{
  for(const [vid,pid] of [[0x1a86,0x7523],[0x10c4,0xea60],[0x0403,0x6001]]){const selected=chooseConnection({usbInfo:usb(vid,pid)});assert.equal(selected.mode,'default_reset');assert.equal(selected.alreadyBootloader,false);}
  assert.equal(chooseConnection({usbInfo:usb(0x1a86,0x7524)}).mode,null);
});
test('shared303a1001 never infers reset method from running model or proposed image',()=>{
  for(const device of [null,{model:'Heltec v4',architecture:'esp32'}])assert.equal(chooseConnection({usbInfo:usb(0x303a,0x1001),device,packageArchitecture:'esp32'}).mode,null);
});
test('same-port TinyUSB and hardware JTAG descriptors disambiguate shared ID',()=>{
  const usbInfo=usb(0x303a,0x1001);
  assert.equal(chooseConnection({usbInfo,usbDescription:'TinyUSB Serial'}).mode,'tinyusb');
  assert.equal(chooseConnection({usbInfo,usbDescription:'USB JTAG/serial debug unit'}).mode,'usb_reset');
  assert.equal(chooseConnection({usbInfo,usbDescription:'USB Serial/JTAG'}).mode,'usb_reset');
  assert.equal(chooseConnection({usbInfo,usbDescription:'TinyUSB USB JTAG/serial debug unit'}).mode,null);
});
test('responding ESP32 application on0002 selects software CDC but unproven ID and proposed image do not',()=>{
  const usbInfo=usb(0x303a,0x0002),device={model:'Heltec v4',architecture:'esp32'};
  assert.equal(chooseConnection({usbInfo,device}).mode,'tinyusb');assert.equal(chooseConnection({usbInfo,device}).alreadyBootloader,false);
  assert.equal(chooseConnection({usbInfo,packageArchitecture:'esp32'}).mode,null);
  assert.equal(chooseConnection({usbInfo,device:{model:'Heltec v4'}}).mode,null);
});
test('XIAO S3 application endpoint can use software CDC but neighboring Seeed IDs are not generalized',()=>{
  const device={model:'Xiao S3',architecture:'esp32'};assert.equal(chooseConnection({usbInfo:usb(0x2886,0x0059),device}).mode,'tinyusb');assert.equal(chooseConnection({usbInfo:usb(0x2886,0x8059),device}).mode,null);
});
test('invalid USB inputs and unrelated descriptors leave the method manual',()=>{
  for(const usbInfo of [null,{},usb('303a',2),usb(0x303a,-1),usb(0x10000,2)])assert.equal(chooseConnection({usbInfo}).mode,null);
  assert.equal(chooseConnection({usbInfo:usb(0x1234,0x5678),usbDescription:'TinyUSB Serial'}).mode,null);
});

function nrfEvidencePackage(){
  const payload=new Uint8Array(1300),init=new Uint8Array(12),view=new DataView(init.buffer);view.setUint16(0,0x52,true);view.setUint16(10,crc16(payload),true);
  return nrfPackage('example.zip',zipSync({'manifest.json':new TextEncoder().encode(JSON.stringify({manifest:{dfu_version:.5,application:{bin_file:'app.bin',dat_file:'app.dat'}}})),'app.bin':payload,'app.dat':init}));
}
function ackTimeout(pkg,{stage='init',acknowledgedBytes=0,sequence=2,...overrides}={}){
  return {code:'NRF_DFU_ACK_TIMEOUT',nrfDfu:Object.freeze({stage,acknowledgedBytes,totalBytes:pkg.payload.length,sequence,kind:pkg.kind,erase:pkg.erase===true,activationWaitMs:910,...overrides})};
}
test('only a prior acknowledged nRF packet provides a same-session DFU connection hint',()=>{
  const pkg=nrfEvidencePackage(),info=usb(0x1234,0x5678),port={getInfo:()=>info},generation=4;
  for(const error of [ackTimeout(pkg),ackTimeout(pkg,{stage:'data',sequence:3}),ackTimeout(pkg,{stage:'data',acknowledgedBytes:512,sequence:4})]){
    const evidence=captureNrfDfuEvidence({error,port,generation,pkg});assert.ok(evidence);assert.ok(Object.isFrozen(evidence));
    assert.equal(nrfDfuEvidenceCurrent({evidence,port,generation,pkg}),true);
    const choice=chooseConnection({usbInfo:info,nrfDfuEvidence:evidence,port,generation,pkg});
    assert.equal(choice.mode,'nrf52');assert.equal(choice.alreadyBootloader,true);assert.equal(choice.source,'dfu-ack');assert.match(choice.reason,/not physical-board proof or permission to retry/);
    const conflict=chooseConnection({usbInfo:info,device:{architecture:'esp32'},nrfDfuEvidence:evidence,port,generation,pkg});assert.equal(conflict.source,'conflict');assert.equal(conflict.mode,null);
  }
});
test('missing ACK, inconsistent packet metadata or a proposed package alone cannot manufacture evidence',()=>{
  const pkg=nrfEvidencePackage(),port={getInfo:()=>usb(0x1234,0x5678)},generation=4;
  for(const error of [null,{},ackTimeout(pkg,{stage:'start',sequence:1}),ackTimeout(pkg,{stage:'activate',sequence:6,acknowledgedBytes:1300}),ackTimeout(pkg,{stage:'data',sequence:2}),ackTimeout(pkg,{totalBytes:42}),ackTimeout(pkg,{kind:'bootloader'}),{code:'NRF_DFU_ACK_TIMEOUT',nrfDfu:{stage:'init',acknowledgedBytes:0,totalBytes:1300,sequence:2,kind:'application',erase:false}}])
    assert.equal(captureNrfDfuEvidence({error,port,generation,pkg}),null);
  assert.equal(chooseConnection({usbInfo:port.getInfo(),port,generation,pkg,packageArchitecture:'nrf52'}).mode,null);
  assert.equal(nrfDfuEvidenceCurrent({evidence:{},port,generation,pkg}),false);
});
test('ACK evidence cannot follow a port, selection generation, package, USB identity or image mutation',()=>{
  const pkg=nrfEvidencePackage(),info=usb(0x1234,0x5678),port={getInfo:()=>info},generation=4,evidence=captureNrfDfuEvidence({error:ackTimeout(pkg),port,generation,pkg});
  const valid={evidence,port,generation,pkg};assert.equal(nrfDfuEvidenceCurrent(valid),true);
  for(const changes of [{port:{getInfo:()=>info}},{generation:5},{pkg:{...pkg}},{pkg:null}])assert.equal(nrfDfuEvidenceCurrent({...valid,...changes}),false);
  assert.equal(chooseConnection({usbInfo:usb(0x1234,0x9999),nrfDfuEvidence:evidence,port,generation,pkg}).mode,null);
  info.usbProductId=0x9999;assert.equal(nrfDfuEvidenceCurrent(valid),false);info.usbProductId=0x5678;
  pkg.payload[0]^=1;assert.equal(nrfDfuEvidenceCurrent(valid),false);pkg.payload[0]^=1;
  pkg.init[0]^=1;assert.equal(nrfDfuEvidenceCurrent(valid),false);pkg.init[0]^=1;
  const digest=pkg.sha256;pkg.sha256='a'.repeat(64);assert.equal(nrfDfuEvidenceCurrent(valid),false);pkg.sha256=digest;
  pkg.kind='bootloader';assert.equal(nrfDfuEvidenceCurrent(valid),false);
});
