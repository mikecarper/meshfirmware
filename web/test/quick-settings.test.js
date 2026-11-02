import test from 'node:test';
import assert from 'node:assert/strict';
import {quickSettingPlan,quickHotspotUrl} from '../src/quick-settings.js';

test('hotspot endpoint preserves the reported Companion port and excludes surrounding login text',()=>{
  for(const port of ['',':80',':8080'])assert.equal(quickHotspotUrl(`Started: http://192.168.4.1${port}/update; Login: admin / node admin password`),`http://192.168.4.1${port===':80'?'':port}/update`);
  assert.equal(quickHotspotUrl('Started: http://192.168.10.1:8080/update (OPEN compatibility)'),'http://192.168.10.1:8080/update');
});

test('hotspot endpoints cannot contain credentials, arbitrary hosts, queries, hashes or unreviewed ports',()=>{
  for(const url of ['https://192.168.4.1/update','http://example.test/update','http://admin:secret@192.168.4.1/update','http://192.168.4.1:1234/update','http://192.168.4.1/update?password=secret','http://192.168.4.1/update#secret','http://192.168.4.999/update','http://0192.168.4.1/update','http://0.0.0.0/update','javascript:alert(1)'])assert.throws(()=>quickHotspotUrl('Started: '+url),error=>!error.message.includes('secret')&&/recognized update address/.test(error.message));
});

test('logging shortcuts use explicit saved master commands, not reboot or continuous-log overrides',()=>{
  for(const [action,command] of [['logging-on','set usb.logging on'],['logging-off','set usb.logging off']]){
    const p=quickSettingPlan(action);assert.deepEqual(p.commands,[command]);assert.equal(p.secret,false);
    assert.doesNotMatch(p.commands.join(' '),/reboot|always|stream/);
    if(action==='logging-on')assert.match(p.warning,/Companion from binary to text mode/);
  }
});

test('Wi-Fi switches distinguish boot-only infrastructure control from saved Companion enablement',()=>{
  for(const [action,on] of [['wifi-on',true],['wifi-off',false]]){
    const common=quickSettingPlan(action,{role:'common-cli'}),companion=quickSettingPlan(action,{role:'companion'});
    assert.deepEqual(common.commands,[`set wifi ${on?'on':'off'}`]);assert.match(common.warning,/this boot only/);
    assert.deepEqual(companion.commands,[`set wifi.enabled ${on?1:0}`]);assert.match(companion.warning,/manual reboot/);
    for(const p of [common,companion]){assert.equal(p.disconnects,true);assert.doesNotMatch(p.commands.join(' '),/force|2\.4ghz|reboot/);}
  }
  assert.deepEqual(quickSettingPlan('wifi-status').commands,['get wifi.status']);
  assert.deepEqual(quickSettingPlan('wifi-ota-ap').commands,['start ota ap']);
  assert.match(quickSettingPlan('wifi-ota-ap').warning,/hotspot.*interrupt/i);
});

test('node names fit both firmware roles without silently truncating UTF-8',()=>{
  assert.deepEqual(quickSettingPlan('name',{name:'My radio é'}).commands,['set name My radio é']);
  assert.doesNotThrow(()=>quickSettingPlan('name',{name:'a'.repeat(31)}));
  assert.doesNotThrow(()=>quickSettingPlan('name',{name:'é'.repeat(15)+'a'}));
  for(const name of ['', ' ', 'a'.repeat(32), 'é'.repeat(16), ...[...'[]/\\:,?*'].map(character=>'Name'+character)])assert.throws(()=>quickSettingPlan('name',{name}),/Name/);
});

test('administrator password changes use the established secret setter and preserve supplied spacing',()=>{
  const p=quickSettingPlan('password',{password:' a b '});
  assert.deepEqual(p.commands,['password  a b ']);assert.equal(p.secret,true);assert.equal(p.label,'Save admin password');
  assert.match(p.warning,/sign in again/);assert.doesNotThrow(()=>quickSettingPlan('password',{password:'a'.repeat(15)}));
  assert.doesNotThrow(()=>quickSettingPlan('password',{password:'é'.repeat(7)+'a'}));
  for(const password of ['', 'a'.repeat(16), 'é'.repeat(8)])assert.throws(()=>quickSettingPlan('password',{password}),/Admin password/);
});

test('Wi-Fi credentials save password before SSID and never read back or enable Wi-Fi',()=>{
  const p=quickSettingPlan('wifi-save',{ssid:'My network',password:'private-code'});
  assert.deepEqual(p.commands,['set wifi.pwd private-code','set wifi.ssid My network']);assert.equal(p.secret,true);assert.equal(p.disconnects,true);
  assert.match(p.warning,/separate saves/);assert.doesNotMatch(p.commands.join('\n'),/get |enabled|set wifi on|reboot/);
  assert.doesNotThrow(()=>quickSettingPlan('wifi-save',{ssid:'s'.repeat(31),password:'p'.repeat(63)}));
  for(const values of [{ssid:'s'.repeat(32),password:'valid'},{ssid:'é'.repeat(16),password:'valid'},{ssid:'valid',password:'p'.repeat(64)}])assert.throws(()=>quickSettingPlan('wifi-save',values),/Wi-Fi/);
});

test('blank Wi-Fi password preserves the saved secret; opening a network needs a separate explicit choice',()=>{
  for(const values of [{ssid:'Network',password:''},{ssid:'Network'}]){
    const p=quickSettingPlan('wifi-save',values);assert.deepEqual(p.commands,['set wifi.ssid Network']);assert.match(p.warning,/password is unchanged/);
  }
  const open=quickSettingPlan('wifi-save',{ssid:'Public',password:'',openNetwork:true});
  assert.deepEqual(open.commands,['set wifi.pwd','set wifi.ssid Public']);assert.match(open.warning,/open Wi-Fi network/);
  assert.throws(()=>quickSettingPlan('wifi-save',{ssid:'Public',password:'has-password',openNetwork:true}),/open network/i);
  assert.throws(()=>quickSettingPlan('wifi-save',{ssid:'Public',openNetwork:'yes'}),/explicit/);
});

test('all value-bearing shortcuts reject serial line/control/bidi/invisible/lone-surrogate injection',()=>{
  const samples=['ok\nreboot','ok\rerase','ok\0bad','ok\tbad','ok\x1b[31m','ok\x7fbad','ok\x85bad','ok\u2028reboot','ok\u2029reboot','ok\u202ebad','ok\u2066bad','ok\u200bbad','ok\ufeffbad','ok\ud800bad'];
  for(const value of samples)for(const [action,values] of [['name',{name:value}],['password',{password:value}],['wifi-save',{ssid:value,password:'safe'}],['wifi-save',{ssid:'safe',password:value}]]){
    assert.throws(()=>quickSettingPlan(action,values),/single line/);
  }
});

test('labels, warnings and validation errors never include supplied passwords or SSIDs',()=>{
  for(const [action,values] of [['password',{password:'Secret123'}],['wifi-save',{ssid:'PrivateSSID',password:'Secret123'}]]){
    const p=quickSettingPlan(action,values),metadata=JSON.stringify({...p,commands:[]});
    for(const value of Object.values(values))assert.ok(!metadata.includes(value));
    assert.ok(p.commands.some(command=>command.includes('Secret123')),'The transport still needs the actual secret');
  }
  const secret='TOP-SECRET-PRIVATE-PASSWORD';
  let error;try{quickSettingPlan('password',{password:secret});}catch(e){error=e;}
  assert.ok(error);assert.ok(!error.message.includes(secret));
});

test('only reviewed action names and object value records are accepted',()=>{
  for(const action of ['reboot','erase','set name Anything',null,{},'constructor'])assert.throws(()=>quickSettingPlan(action),/supported/);
  for(const values of [null,[],true,'x'])assert.throws(()=>quickSettingPlan('password',values),/Invalid/);
  for(const password of [true,123,{},null])assert.throws(()=>quickSettingPlan('password',{password}),/single line/);
});
