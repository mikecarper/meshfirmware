import test from 'node:test';
import assert from 'node:assert/strict';
import {chooseFirmware} from '../src/automatic.js';

const version='v1.18.0.1-halo-keymind';
const device={firmwareFamily:'meshtastic',role:'meshtastic',meshtasticRole:2};
const item=(hardware,target,profile,role='repeater')=>({project:'MeshCore',provider:'Keymind Cascade',hardware,architecture:'nrf52',role,action:'flash',version,name:`${target}-${profile}-${version}.zip`,url:`https://example.test/${target}-${profile}.zip`,releaseNotes:`EXACT TARGET - ${target}.`});
const cases=[
  ['Seeed Studio SenseCAP Solar','SenseCap_Solar_repeater','repeater'],
  ['Seeed Studio SenseCAP Solar','SenseCap_Solar_room_server_lora_ota','roomServer'],
  ['Seeed SenseCAP MeshTracker X1','MeshTracker_X1_repeater_lora_ota_no_external_sensors','repeater'],
  ['Seeed SenseCAP MeshTracker X1','MeshTracker_X1_room_server_lora_ota_no_external_sensors','roomServer'],
];

test('new Meshtastic/bootloader installations prefer reviewed same-target Full OTA over Reduced without depending on order',()=>{
  for(const [hardware,target,role] of cases)for(const origin of [device,{firmwareFamily:'bootloader',role:'bootloader'}]){
    const full=item(hardware,target,'full-ota',role),reduced=item(hardware,target,'reduced-ota',role);
    for(const items of [[full,reduced],[reduced,full]]){
      const result=chooseFirmware({items,hardware,device:origin,role});assert.equal(items[result.artifactIndex].name,full.name);assert.match(result.reason,/Standard Full OTA/);
      const explicit=chooseFirmware({items,hardware,device:{...origin,exactTarget:target},role});assert.equal(explicit.artifactIndex,null);
    }
  }
});

test('profile defaults do not change a running MeshCore target, choose a different environment, or defeat provider/version boundaries',()=>{
  for(const [hardware,target,role] of cases){
    const full=item(hardware,target,'full-ota',role),reduced=item(hardware,target,'reduced-ota',role);
    const choose=(items,more={})=>chooseFirmware({items,hardware,device,role,...more});
    assert.equal(choose([full,reduced],{device:{firmwareFamily:'meshcore',role:'common-cli'}}).artifactIndex,null);
    assert.equal(choose([full,reduced,item(hardware,target+'_different_radio','full-ota',role)]).artifactIndex,null);
    assert.equal(choose([full,{...full,url:'https://example.test/conflicting-payload.zip'},reduced]).artifactIndex,null);
    assert.equal(choose([full,reduced].map(i=>({...i,provider:'MeshCore'})),{provider:'MeshCore'}).artifactIndex,null);
    assert.equal(choose([full,reduced],{version:'v9.0.0'}).artifactIndex,null);
  }
});
