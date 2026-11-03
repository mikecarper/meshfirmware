import test from 'node:test';
import assert from 'node:assert/strict';
import {xiaoBootloaderSnapshot} from './fixtures/xiao-bootloader.js';
import {xiaoInstalledStatus,xiaoInfoProfile,xiaoBootloaderItem} from '../src/xiao-bootloader.js';
import {parseBootloaderInfo} from '../src/bootloader-info.js';

const snapshot=xiaoBootloaderSnapshot();
const item={hardware:'Seeed Studio Xiao nRF52 WIO',architecture:'nrf52'};
const info=sense=>parseBootloaderInfo(`UF2 Bootloader 0.6.2\nModel: Seeed XIAO nRF52840\nBoard-ID: nRF52840-SeeedXiao${sense?'Sense':''}-v1\n`);
const usb=pid=>({usbVendorId:0x2886,usbProductId:pid});
const status=(board,target=board,name='XIAO_DFU')=>`BL board=${board} target=${target} name=${name} crc=6F9BE280 abi=3 caps=0E | staged:none mid=-- hash=--`;

test('exact reported board and target distinguish installed XIAO loaders',()=>{
  assert.equal(xiaoInstalledStatus(status('28860044')),'xiao_nrf52840_ble');
  assert.equal(xiaoInstalledStatus(status('28860045')),'xiao_nrf52840_ble_sense');
  for(const value of ['',status('28860044','28860045'),status('28860044','28860044','SCAP_DFU'),status('28860045','28860045','R_XIAO_DFU'),'XIAO_DFU'])assert.equal(xiaoInstalledStatus(value),null);
});
test('complete file identity and same DFU USB PID are required',()=>{
  assert.equal(xiaoInfoProfile(info(false),usb(0x0044)),'xiao_nrf52840_ble');
  assert.equal(xiaoInfoProfile(info(true),usb(0x0045)),'xiao_nrf52840_ble_sense');
  assert.equal(xiaoInfoProfile(info(true),usb(0x0044)),null);
  assert.equal(xiaoInfoProfile(info(false),usb(0x8044)),null);
  assert.equal(xiaoInfoProfile({...info(true),version:'R_0x12345678'},usb(0x0045)),null);
  assert.equal(xiaoInfoProfile({model:'Seeed XIAO nRF52840',boardId:'nRF52840-SeeedXiaoSense-v1'},usb(0x0045)),null);
});
test('only matching verified stable release profile is suggested',()=>{
  for(const profile of ['xiao_nrf52840_ble','xiao_nrf52840_ble_sense']){
    const selected=xiaoBootloaderItem({item,snapshot,profile});
    assert.equal(selected.bootloaderInfo.profile,profile);assert.match(selected.bootloaderInfo.sha256,/^[0-9a-f]{64}$/);assert.equal(selected.bootloader[0],selected.bootloaderInfo.url);
  }
  assert.equal(xiaoBootloaderItem({item:{...item,hardware:'Seeed Studio SenseCAP Solar'},snapshot,profile:'xiao_nrf52840_ble'}),null);
  assert.equal(xiaoBootloaderItem({item,snapshot,profile:'sensecap_solar_p1'}),null);
  const bad=structuredClone(snapshot);bad.manifest.profiles.find(p=>p.id==='xiao_nrf52840_ble_sense').files.zip.sha256='0'.repeat(64);
  assert.equal(xiaoBootloaderItem({item,snapshot:bad,profile:'xiao_nrf52840_ble_sense'}),null);
  const missing=structuredClone(snapshot);missing.manifest.profiles=missing.manifest.profiles.filter(p=>p.id!=='xiao_nrf52840_ble_sense');
  assert.equal(xiaoBootloaderItem({item,snapshot:missing,profile:'xiao_nrf52840_ble_sense'}),null);
});
