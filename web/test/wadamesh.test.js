import test from 'node:test';
import assert from 'node:assert/strict';
import {isWadamesh,wadameshDisplayAssessment,WADAMESH_PROVIDER,WADAMESH_INSTALL_NOTICE,WADAMESH_STARTUP_NOTICE} from '../src/wadamesh.js';

const item={provider:WADAMESH_PROVIDER,hardware:'Heltec v4',requiredDisplay:'tft'};
test('Wadamesh provider identity is explicit and accepts item or state-like inputs',()=>{
  for(const value of [WADAMESH_PROVIDER,item,{item},{provider:WADAMESH_PROVIDER}])assert.equal(isWadamesh(value),true);
  for(const value of [null,undefined,{},'wadamesh tak','MeshCore','Keymind Cascade',{name:'Wadamesh TAK'},{provider:'MeshCore',item},{url:'https://github.com/jade-on-mesh/wadamesh-tak/releases/latest'}])assert.equal(isWadamesh(value),false);
});
test('explicit V4 OLED reports require an overridable TFT mismatch warning',()=>{
  for(const model of ['Heltec V4 OLED','Heltec V4.2 OLED','Heltec V4.3 OLED','Heltec V4 R8 OLED']){
    const assessment=wadameshDisplayAssessment({item,device:{model}});
    assert.equal(assessment.status,'mismatch',model);assert.equal(assessment.requiresOverride,true);assert.equal(assessment.reportedDisplay,'oled');assert.equal(assessment.requiredDisplay,'tft');assert.match(assessment.warning,/requires a TFT.*OLED.*not add OLED support/);
  }
});
test('matching TFT report is configuration evidence only, not independent hardware proof',()=>{
  for(const model of ['Heltec V4 TFT','Heltec V4.3 TFT','Heltec V4 R8 TFT']){
    const assessment=wadameshDisplayAssessment({item,device:{model}});
    assert.equal(assessment.status,'match');assert.equal(assessment.requiresOverride,false);assert.equal(assessment.warning,'');assert.match(assessment.reason,/not independently prove/);
  }
});
test('generic names, bootloader labels and similarly named boards do not prove the display',()=>{
  for(const device of [undefined,{}, {model:'Heltec v4'},{model:'HELTEC_V4'},{model:'Heltec V4.3 OLED other'},{model:'Heltec V4.4 OLED'},{model:'Heltec V4.3 OLED',firmwareFamily:'bootloader'},{model:'Heltec V4.3 TFT',role:'bootloader'}]){
    const assessment=wadameshDisplayAssessment({item,device});assert.equal(assessment.status,'unknown');assert.equal(assessment.requiresOverride,false);assert.equal(assessment.reportedDisplay,null);assert.match(assessment.warning,/requires the TFT/);
  }
});
test('other providers and non-TFT Wadamesh targets retain independent board checks',()=>{
  for(const selected of [undefined,{...item,provider:'MeshCore'},{...item,requiredDisplay:undefined},{...item,requiredDisplay:'oled'}]){
    const assessment=wadameshDisplayAssessment({item:selected,device:{model:'Heltec V4.3 OLED'}});assert.equal(assessment.status,'not-applicable');assert.equal(assessment.requiresOverride,false);
  }
});
test('assessment does not mutate caller metadata or persist approval',()=>{
  const selected=Object.freeze({...item}),device=Object.freeze({model:'Heltec V4.3 OLED'}),before=JSON.stringify({selected,device});
  assert.equal(wadameshDisplayAssessment({item:selected,device}).requiresOverride,true);assert.equal(JSON.stringify({selected,device}),before);assert.equal(Object.isFrozen(wadameshDisplayAssessment({item:selected,device})),true);
});
test('notices distinguish our destructive USB install and unverified standalone startup',()=>{
  assert.match(WADAMESH_INSTALL_NOTICE,/whole-chip erase.*identity.*not promised.*Plain application/);
  assert.match(WADAMESH_STARTUP_NOTICE,/transfer was verified.*startup are not verified/);
});
