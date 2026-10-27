import test from 'node:test';
import assert from 'node:assert/strict';
import {chooseConnection} from '../src/connection-choice.js';
const usb=(usbVendorId,usbProductId)=>({usbVendorId,usbProductId});

test('known exact nRF52 DFU selects serial DFU without another touch',()=>{
  for(const [vid,pid] of [[0x2886,0x0057],[0x2886,0x0044],[0x239a,0x0029]]){
    const selected=chooseConnection({usbInfo:usb(vid,pid)});assert.equal(selected.mode,'nrf52');assert.equal(selected.alreadyBootloader,true);
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
