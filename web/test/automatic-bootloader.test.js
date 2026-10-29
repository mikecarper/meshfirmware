import test from 'node:test';
import assert from 'node:assert/strict';
import {chooseFirmware} from '../src/automatic.js';
import {chooseConnection} from '../src/connection-choice.js';
const application=(more={})=>({project:'MeshCore',hardware:'Heltec T114',architecture:'nrf52',provider:'Keymind Cascade',role:'companionFull',action:'flash',version:'v1.18.0',name:'Heltec_t114_companion_radio_full-v1.18.0.zip',url:'https://example.test/t114.zip',...more});
const device={firmwareFamily:'bootloader',role:'bootloader',architecture:'nrf52',model:'HT-n5262',version:'0.11.0-OTAFIX2.4.12',publicKey:null};
const choose=(items,more={})=>chooseFirmware({items,hardware:'Heltec T114',device,...more});

test('a reviewed bootloader-file board hint selects the same safe Companion application policy',()=>{
  const items=[application(),application({role:'repeater'}),application({role:'companionBle',provider:'MeshCore'})],result=choose(items);assert.equal(result.artifactIndex,0);assert.equal(result.selections.role,'companionFull');assert.equal(result.warning,'');assert.equal(result.downgrade,false);assert.match(result.reason,/Bootloader-file identity matched/);assert.match(result.reason,/does not prove physical hardware/);
  const stock=choose([items[2]]);assert.equal(stock.artifactIndex,0);assert.equal(stock.selections.provider,'MeshCore');
});

test('bootloader versions/role hints are not application versions or proof of the previous role',()=>{
  const items=[application(),application({role:'repeater'})],result=choose(items,{device:{...device,version:'99.1.0',catalogRole:'repeater'}});assert.equal(result.artifactIndex,0);assert.equal(result.warning,'');assert.equal(choose(items,{role:'repeater'}).artifactIndex,1);
});

test('file-based selection never silently chooses erase, embedded bootloader or an ambiguous variant',()=>{
  const embedded=application({name:'Heltec_t114_with-bootloader-v1.18.0.zip'}),variant=application({name:'t114_alternate_screen-v1.18.0.zip',url:'https://example.test/alternate.zip'});assert.equal(choose([embedded,application()]).artifactIndex,1);assert.equal(choose([application(),variant]).artifactIndex,null);assert.equal(choose([application()],{hardware:''}).artifactIndex,null);assert.equal(choose([application()],{provider:'MeshCore'}).artifactIndex,null);
});

test('a bootloader info file cannot cause a reset or prove the selected serial port is DFU',()=>{
  for(const usbInfo of [{},{usbVendorId:0x239a,usbProductId:0x8029},{usbVendorId:0x10c4,usbProductId:0xea60},{usbVendorId:0x303a,usbProductId:0x1001}]){
    const result=chooseConnection({usbInfo,device});assert.equal(result.mode,null);assert.equal(result.alreadyBootloader,false);assert.equal(result.source,'bootloader-file');assert.match(result.reason,/No reset is inferred/);
  }
  const dfu=chooseConnection({usbInfo:{usbVendorId:0x239a,usbProductId:0x0071},device});assert.equal(dfu.mode,'nrf52');assert.equal(dfu.alreadyBootloader,true);
  const explicit=chooseConnection({usbInfo:{},device,alreadyBootloader:true});assert.equal(explicit.mode,'nrf52');assert.equal(explicit.alreadyBootloader,true);
});
