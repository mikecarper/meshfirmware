import test from 'node:test';
import assert from 'node:assert/strict';
import {postFlashBleAdvice} from '../src/post-flash-advice.js';

const application=(more={})=>({architecture:'nrf52',kind:'application',name:'t1000e_companion_radio_full-v1.18.0.1-halo-keymind-cascade.zip',...more});
const artifact=(more={})=>({name:application().name,provider:'Keymind Cascade',hardware:'Seeed Studio SenseCAP T1000-E',role:'companionFull',...more});

test('Keymind T1000-E Full and BLE completion advice covers catalog and custom files',()=>{
  for(const role of ['full','ble']){
    const pkg=application({name:`t1000e_companion_radio_${role}-v1.18.0.1-halo-keymind-cascade.zip`});
    for(const item of [null,artifact({name:pkg.name,role:role==='full'?'companionFull':'companionBle'})]){
      const advice=postFlashBleAdvice(pkg,item);
      assert.match(advice,/Bluetooth \(BLE\) stays off.*computer by USB/);
      assert.match(advice,/Finish any USB verification, then unplug USB/);
      assert.match(advice,/if enabled in settings/);
    }
  }
  assert.ok(postFlashBleAdvice(application({name:'release.zip'}),artifact({name:'release.zip'})));
  assert.ok(postFlashBleAdvice(application({name:'release.zip'}),artifact({name:'release.zip',provider:'Keymind Cascade Logging'})));
  assert.ok(postFlashBleAdvice(application({name:'t1000e_companion_radio_full-with-bootloader-2.4.12-v1.18.0.1-keymind-cascade.zip'})));
});

test('stock, USB-only, other boards and non-application writes do not get unplug-to-enable advice',()=>{
  const stock=application({name:'t1000e_companion_radio_ble-v1.17.1.zip'});
  assert.equal(postFlashBleAdvice(stock,artifact({name:stock.name,provider:'MeshCore'})),'');
  for(const more of [{kind:'bootloader'},{kind:'softdevice'},{erase:true},{expert:true},{architecture:'esp32'},{architecture:'uf2'}])assert.equal(postFlashBleAdvice(application(more),artifact()),'');
  for(const target of ['t1000e_companion_radio_usb','t1000e_repeater','t1000e_room_server','t1000e_sensor','Xiao_nrf52_companion_radio_full','RAK_4631_companion_radio_full','t1000e2_companion_radio_full','R_t1000e_companion_radio_full','erase_t1000e_companion_radio_full']){
    assert.equal(postFlashBleAdvice(application({name:target+'-v1.18.0.1-keymind-cascade.zip'})),'',target);
  }
  for(const role of ['companionUsb','repeater','roomServer','sensor'])assert.equal(postFlashBleAdvice(application(),artifact({role})),'',role);
  assert.equal(postFlashBleAdvice(application(),artifact({hardware:'Seeed Studio Xiao nRF52 WIO'})),'');
  for(const suffix of ['with-bootloader-keymind','with-bootloader-2.4.12.1.5-keymind','with-bootloader-2.4.12-bootloader-keymind'])assert.equal(postFlashBleAdvice(application({name:`t1000e_companion_radio_full-${suffix}.zip`})),'');
  assert.equal(postFlashBleAdvice(application({kind:'bootloader',name:'t1000e_companion_radio_full-with-bootloader-2.4.12-v1.18.0.1-keymind.zip'})),'');
});

test('metadata from another artifact or a prior connected radio cannot create the reminder',()=>{
  assert.equal(postFlashBleAdvice(application({name:'custom.zip'}),artifact()),'');
  assert.equal(postFlashBleAdvice(application({name:'custom.zip'}),{hardware:artifact().hardware,provider:'Keymind Cascade',role:'companionFull'}),'');
  assert.equal(postFlashBleAdvice(null,artifact()),'');
  assert.equal(postFlashBleAdvice(application({name:null}),artifact()),'');
});
