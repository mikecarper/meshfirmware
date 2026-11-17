import test from 'node:test';
import assert from 'node:assert/strict';
import { sha512 } from '@noble/hashes/sha2.js';
import { unzipSync } from 'fflate';
import { MeshCore, publicFromPrivate, sealBackup, verifyBackup, parseBackup, backupSummary } from '../src/meshcore.js';
import { SerialLink } from '../src/serial.js';
import { companionContactCapacity,isWadameshTakTouchProfile } from '../src/wadamesh-profile.js';
import { commonCliReplyState } from '../src/common-cli.js';
import { backupCoverage } from '../src/backup-coverage.js';
import { addWadameshFiles, wadameshFilesZip, wadameshSettingsImport } from '../src/wadamesh-backup.js';

const hex=value=>Buffer.from(value).toString('hex'),enc=value=>new TextEncoder().encode(value);
const version='Meshcomod v2.4\nbuild Nov 16 2026 (code 12)';
const summary='name: test\nfreq: 910.525 MHz\nbw: 125.0 kHz\nsf: 10\ncr: 5\ntx: -3 dBm\nlat: 51.50000\nlon: -0.12500';
const file=(path,bytes)=>({name:path.split('/').at(-1),webkitRelativePath:path,size:bytes.length,arrayBuffer:async()=>Uint8Array.from(bytes).buffer});
function payload(count=0){
  const key=sha512(new Uint8Array(32).fill(29));key[0]&=248;key[31]&=63;key[31]|=64;
  const self=new Uint8Array(62),info=new Uint8Array(82),view=new DataView(self.buffer);
  const pub=publicFromPrivate(key);self.set([5,1,253,22]);self.set(Buffer.from(pub,'hex'),4);self.set([1,2,27,1],44);self.set([10,5],56);self.set(enc('test'),58);
  view.setInt32(36,51500000,true);view.setInt32(40,-125000,true);view.setUint32(48,910525,true);view.setUint32(52,125000,true);
  info.set([13,12,232,40]);new DataView(info.buffer).setUint32(4,123456,true);info.set(enc('Nov 16 2026'),8);info.set(enc('T-Deck'),20);info.set(enc('v2.4'),60);info.set([1,2],80);
  const channels=Array.from({length:40},(_,i)=>{const row=new Uint8Array(50);row.set([18,i]);if(i===4){row.set(enc('fifth'),2);row.fill(7,34);}return hex(row);});
  const contacts=Array.from({length:count},(_,i)=>{const row=new Uint8Array(148),v=new DataView(row.buffer);row[0]=3;v.setUint32(1,i+1,true);row.set([1,3,1,9],33);row.set(enc('Peer '+i),100);v.setInt32(136,-37000000,true);v.setInt32(140,145000000,true);v.setUint32(144,1234,true);return hex(row);});
  return {role:'companion',publicKey:pub,privateKey:'0e'+hex(key),self:hex(self),info:hex(info),channels,contacts,options:{autoadd:'190703',tuning:'1702000000b80b0000',scope:'1c',custom:'15'+hex(enc('gps:1,gps_interval:60'))},cli:{version},wadamesh:{version:1,files:[],filesExcluded:0},safeForWipe:false};
}
function device(p,{repeat=0,pathMode=0,stuckRepeat=false,stuckPath=false,cliVersion=version}={}){
  const core=new MeshCore({}),self=Buffer.from(p.self,'hex'),info=Buffer.from(p.info,'hex'),channels=p.channels.slice(),contacts=p.contacts.slice(),sent=[],cliSent=[];
  info[80]=repeat;info[81]=pathMode;
  core.self=async()=>self.slice();core.info=async()=>info.slice();
  core.contacts=async options=>{assert.equal(options.maxContacts,companionContactCapacity(info,cliVersion));return contacts.map(row=>Buffer.from(row,'hex'));};
  core.cli=async command=>{cliSent.push(command);return command==='version'?cliVersion:summary;};
  core.request=async command=>{
    sent.push([...command]);const bytes=Uint8Array.from(command);
    switch(bytes[0]){
      case 23:return Buffer.from(p.privateKey,'hex');
      case 31:return Buffer.from(channels[bytes[1]],'hex');
      case 32:channels[bytes[1]]=hex(Uint8Array.from([18,...bytes.subarray(1)]));break;
      case 9:{const row=Uint8Array.from([3,...bytes.subarray(1),0,0,0,0]),id=hex(row.subarray(1,33)),at=contacts.findIndex(raw=>raw.slice(2,66)===id);if(at<0)contacts.push(hex(row));else contacts[at]=hex(row);break;}
      case 8:self.set(bytes.subarray(1),58);break;
      case 14:self.set(bytes.subarray(1,9),36);break;
      case 12:self[2]=bytes[1];break;
      case 11:self.set(bytes.subarray(1,11),48);if(!stuckRepeat)info[80]=bytes[11]||0;break;
      case 61:if(!stuckPath)info[81]=bytes[2];break;
      case 38:self.set([bytes[4],bytes[3],bytes[2],bytes[1]],44);break;
      case 37:info.set(bytes.subarray(1),4);break;
      case 59:return Buffer.from(p.options.autoadd,'hex');
      case 43:return Buffer.from(p.options.tuning,'hex');
      case 40:return Buffer.from(p.options.custom,'hex');
      case 64:return Buffer.from(p.options.scope,'hex');
      case 20:return Uint8Array.of(12,160,15);
      case 58:case 21:case 41:case 63:break;
      default:throw Error('Unexpected command '+bytes[0]);
    }
    return Uint8Array.of(0);
  };
  return {core,sent,cliSent,info};
}

test('generic Wadamesh get summaries do not claim optional settings, including credentials',()=>{
  for(const command of ['get bluetooth.name','get usb.logging','get bluetooth','get password','get wifi.pwd'])assert.equal(commonCliReplyState(summary,command).state,'unsupported');
  assert.equal(commonCliReplyState(summary,'get').state,'complete');
});
test('TAK touch profile requires the exact reviewed wire layout and matching version reply',()=>{
  const info=new Uint8Array(82);info.set([13,27,232,40]);info.set(enc('v1.18.0.1-touch'),60);
  const reply='v1.18.0.1-touch (Build: Nov 17 2026)';assert.equal(isWadameshTakTouchProfile(info,reply),true);
  for(const index of [0,1,2,3,60]){const changed=info.slice();changed[index]^=1;assert.equal(isWadameshTakTouchProfile(changed,reply),false);}
  for(const bad of ['v1.18.0.1-touch','v1.18.0.1 (Build: Nov 17 2026)','Unknown command','v1.18.0.1-touch (Build: Nov 17 2026)\nextra'])assert.equal(isWadameshTakTouchProfile(info,bad),false);
});
test('TAK release profile accepts its truncated device-info field only when the full version agrees',()=>{
  const info=new Uint8Array(82);info.set([13,27,232,40]);info.set(enc('wadamesh-tak beta_105.8'.slice(0,19)),60);
  assert.equal(isWadameshTakTouchProfile(info,'wadamesh-tak beta_105.8 (Build: Nov 17 2026)'),true);
  for(const version of ['wadamesh-tak beta_205.8 (Build: Nov 17 2026)','other beta_105.8 (Build: Nov 17 2026)','wadamesh-tak beta_105.8','wadamesh-tak beta_105.8 (Build: x)\nextra'])assert.equal(isWadameshTakTouchProfile(info,version),false);
});
test('Wadamesh capture preserves a 2,000-contact inventory and unsupported queries without native schema truncation',async()=>{
  const p=payload(2000),{core}=device(p);
  const archive=await core.backup(),captured=verifyBackup(archive);
  assert.equal(captured.contacts.length,2000);assert.equal(captured.channels.length,40);assert.ok(captured.wadamesh);
  assert.equal(captured.cli.version,version);assert.equal(captured.cli['get bluetooth.name'],summary);
  assert.deepEqual(verifyBackup(await parseBackup(JSON.stringify(archive))),captured);
  assert.match(backupSummary(archive).reasons.join(' '),/UI and Wi-Fi/);
  assert.match(backupCoverage(archive).notIncludedText,/Bluetooth name.*not supported/);
});
test('large contact capacity requires firmware identity and its reviewed wire layout',()=>{
  const p=payload(465),info=Buffer.from(p.info,'hex');assert.equal(companionContactCapacity(info,version),2000);
  for(const v of [null,'Companion v1.20','Wadamesh']){assert.equal(companionContactCapacity(info,v),464);assert.throws(()=>verifyBackup(sealBackup({...p,cli:{version:v}})),/inventories/);}
  info[3]=39;assert.equal(companionContactCapacity(info,version),464);
});
test('live target identity, rather than the backup tag, authorizes a large restore',async()=>{
  const p=payload(465),{core,sent}=device(p,{cliVersion:'Companion v1.20'});
  await assert.rejects(core.restore(sealBackup(p)),/cannot hold/);assert.equal(sent.length,0);
  const target=device(p);target.core.cli=async()=>{throw Error('USB disconnected');};
  await assert.rejects(target.core.restore(sealBackup(p)),/USB disconnected/);assert.equal(target.sent.length,0);
});
test('Wadamesh restores core, routes, extended auto-add, sensors, repeat and path hash with readback',async()=>{
  const p=payload(2000),{core,sent,cliSent,info}=device(p),result=await core.restore(sealBackup(p));
  assert.equal(sent.filter(command=>command[0]===9).length,2000);
  assert.deepEqual(sent.find(command=>command[0]===11).slice(-1),[1]);assert.equal(info[80],1);
  assert.deepEqual(sent.find(command=>command[0]===61),[61,0,2]);assert.equal(info[81],2);
  assert.deepEqual(sent.find(command=>command[0]===58),[58,7,3]);
  assert.equal(result.optional.usbLogging.state,'unsupported');assert.equal(result.optional.bluetooth.state,'unsupported');
  assert.ok(cliSent.every(command=>command==='version'||command.startsWith('get ')),'Do not send unsupported CLI setters');
});
test('repeat/path acknowledgements cannot substitute for actual readback and false repeat clears true',async()=>{
  const p=payload();
  await assert.rejects(device(p,{stuckRepeat:true}).core.restore(sealBackup(p)),/repeating readback/);
  await assert.rejects(device(p,{stuckPath:true}).core.restore(sealBackup(p)),/Path hash mode readback/);
  const source=Buffer.from(p.info,'hex');source[80]=0;p.info=hex(source);
  const target=device(p,{repeat:1});await target.core.restore(sealBackup(p));assert.equal(target.info[80],0);assert.equal(target.sent.find(command=>command[0]===11).length,11);
});
test('a full native USB contact burst is drained in bounded pieces without losing records',async()=>{
  const p=payload(2000),rows=[Uint8Array.of(2,208,7,0,0),...p.contacts.map(raw=>Buffer.from(raw,'hex')),Uint8Array.of(4,0,0,0,0)];
  const link=new SerialLink({});link.write=async()=>{};
  for(const row of rows)for(const byte of [62,row.length&255,row.length>>>8,...row])link.buffer.push(byte);
  const core=new MeshCore(link);let received=0;const contacts=await core.contacts({maxContacts:2000,onProgress:n=>received=n});
  assert.equal(contacts.length,2000);assert.equal(received,2000);assert.equal(link.buffer.length,0);assert.equal(core.bytes.length,0);
  link.buffer.push(1,2,3,4);assert.deepEqual(await link.read(1,2),Uint8Array.of(1,2));assert.deepEqual(await link.read(1),Uint8Array.of(3,4));
});
test('settings folders preserve UI/Wi-Fi/original bytes and skip history, maps and oversized files',async()=>{
  const p=payload(),identity=Buffer.from(p.publicKey+p.privateKey.slice(2),'hex');
  const files=[file('SD/meshcomod/touch.kv',enc('screen+keyboard')),file('SD/meshcomod/wifi.kv',enc('test fixture only')),file('SD/meshcomod/identity/_main.id',identity),file('SD/meshcomod/msgs/a',enc('excluded')),file('SD/meshcomod/maps/tile',enc('excluded')),file('SD/meshcomod/battery.log',enc('excluded')),{...file('SD/meshcomod/huge.bin',new Uint8Array()),size:(1<<20)+1,arrayBuffer:()=>assert.fail('Excluded file must not be read')}];
  const enriched=await addWadameshFiles(p,files);assert.equal(enriched.wadamesh.files.length,3);assert.equal(enriched.wadamesh.filesExcluded,4);
  const more=await addWadameshFiles(enriched,[file('prefs/touch.alt',enc('previous UI preferences'))]);assert.equal(more.wadamesh.files.length,4);
  const restored=unzipSync(wadameshFilesZip(verifyBackup(sealBackup(more))));
  assert.deepEqual(restored['meshcomod/touch.kv'],enc('screen+keyboard'));assert.deepEqual(restored['meshcomod/identity/_main.id'],new Uint8Array(identity));assert.ok(restored['prefs/touch.alt']);
  assert.match(backupCoverage(sealBackup(more)).included.join(' '),/4 original Wadamesh/);
  const noKey={...p};delete noKey.privateKey;assert.equal((await addWadameshFiles(noKey,[files[2]])).privateKey,p.privateKey);
  const different=payload();different.publicKey='00'.repeat(32);await assert.rejects(addWadameshFiles(different,[files[2]]),/does not match/);
});
test('saved settings integrity and safe original paths are checked before any restore access',async()=>{
  const p=await addWadameshFiles(payload(),[file('prefs/touch.kv',enc('ui'))]);
  for(const mutate of [p=>p.wadamesh.files[0].path='prefs/../escape',p=>p.wadamesh.files[0].sha256='0'.repeat(64),p=>p.wadamesh.files[0].data='AA==',p=>p.wadamesh.files.push({...p.wadamesh.files[0]}),p=>p.wadamesh.version=2]){
    const bad=structuredClone(p);mutate(bad);const core=new MeshCore({});core.self=async()=>assert.fail('Invalid archive must not touch a device');
    await assert.rejects(core.restore(sealBackup(bad)),/Invalid|Duplicate|integrity|supported settings/);
  }
  for(const path of ['prefs/../escape','prefs/CON.txt','prefs/foo.','prefs/part\\escape'])await assert.rejects(addWadameshFiles(payload(),[file(path,enc('bad'))]));
});
test('on-device Wadamesh settings export keeps empty channel slots, signed TX, contacts and verified identity',()=>{
  const p=payload(1),out=wadameshSettingsImport(verifyBackup(sealBackup(p)));
  assert.equal(out.private_key,p.privateKey.slice(2));assert.equal(out.public_key,p.publicKey);assert.equal(out.radio_settings.tx_power,-3);assert.equal(out.radio_settings.frequency,910.525);
  assert.equal(out.position_settings.longitude,-0.125);assert.equal(out.channels.length,40);assert.equal(out.channels[0].name,'');assert.equal(out.channels[4].name,'fifth');
  assert.equal(out.contacts[0].latitude,'-37');assert.equal(out.contacts[0].out_path,null);assert.equal(out.contacts[0].flags,3);
  assert.deepEqual(Object.keys(out),['name','public_key','private_key','radio_settings','position_settings','channels','contacts']);
  const padded=structuredClone(p),channel=Buffer.from(padded.channels[0],'hex'),contact=Buffer.from(padded.contacts[0],'hex');channel[20]=255;contact[130]=255;padded.channels[0]=hex(channel);padded.contacts[0]=hex(contact);
  assert.equal(wadameshSettingsImport(verifyBackup(sealBackup(padded))).channels[0].name,'');
  assert.throws(()=>wadameshSettingsImport({...p,publicKey:'00'.repeat(32)}),/identity mismatch/);
});
