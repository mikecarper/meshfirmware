import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sealBackup,verifyBackup,parseBackup,MeshCore,publicFromPrivate,bluetoothName,loggingState,enterCompanionBinary,backupCommonCli } from '../src/meshcore.js';
import { words } from '../src/firmware.js';
const enc=s=>new TextEncoder().encode(s),hex=b=>Buffer.from(b).toString('hex');
function payload() {
  const key=new Uint8Array(64);key[0]=1;
  const self=new Uint8Array(62),v=new DataView(self.buffer),info=new Uint8Array(82),iv=new DataView(info.buffer);
  self.set([5,1,20,22]);self.set(Buffer.from(publicFromPrivate(key),'hex'),4);self[56]=10;self[57]=5;self.set(enc('test'),58);v.setUint32(48,910525,true);v.setUint32(52,125000,true);
  info.set([13,14,2,1]);iv.setUint32(4,123456,true);info.set(enc('test-model'),20);
  const channel=new Uint8Array(50);channel[0]=18;
  return {role:'companion',publicKey:publicFromPrivate(key),self:hex(self),info:hex(info),privateKey:'0e'+hex(key),channels:[hex(channel)],contacts:[],options:{},cli:{},safeForWipe:false};
}
test('every optional binary record is prevalidated before any device access or write',async()=>{
  for(const [name,value] of [['autoadd','19000000'],['tuning','1700'],['scope','1c00'],['custom','15'+hex(enc('same:1,same:2'))]]) {
    const p=payload();p.options[name]=value;const core=new MeshCore({});let calls=0;core.self=async()=>{calls++;};
    await assert.rejects(()=>core.restore(sealBackup(p)),/Invalid|invalid/);assert.equal(calls,0);
  }
});
test('all identity, RF, contact and inventory fields are verified even with a recomputed archive checksum',()=>{
  const p=payload();assert.equal(verifyBackup(sealBackup(p)).role,'companion');
  for(const mutate of [q=>q.privateKey='0e'+'00'.repeat(64),q=>q.channels=[],q=>{const b=Buffer.from(q.self,'hex');b[56]=0;q.self=b.toString('hex');},q=>q.contacts=['03'+'00'.repeat(147),'03'+'00'.repeat(147)]]) { const q=structuredClone(p);mutate(q);assert.throws(()=>verifyBackup(sealBackup(q))); }
});
test('Bluetooth names contain no command prompt or default metadata and reject command injection',()=>{
  assert.deepEqual(bluetoothName('> MeshCore-test (default from node name)'),{name:'MeshCore-test',default:true});
  assert.deepEqual(bluetoothName({name:'mcarper',default:false}),{name:'mcarper',default:false});
  assert.throws(()=>bluetoothName({name:'name\nreboot',default:false}),/Invalid/);
  assert.equal(loggingState('> usb.logging off'),'off');assert.equal(loggingState('unknown command'),null);
});
test('text-to-binary handoff requires explicit acknowledgement when logging is on',async()=>{
  const sent=[],link={command:async c=>{sent.push(c);return c==='get usb.logging'?'> usb.logging on':'OK';}};
  await assert.rejects(()=>enterCompanionBinary(link),/permission/);assert.deepEqual(sent,['+++MESHCORE-TERM-START','get usb.logging']);
  sent.length=0;link.command=async c=>{sent.push(c);return c==='get usb.logging'?'> usb.logging on':c==='set usb.logging off'?'OK - USB logging off (saved)':'OK - Binary mode';};
  assert.deepEqual(await enterCompanionBinary(link,{allowLoggingChange:true}),{originalLogging:'on'});
  assert.deepEqual(sent,['+++MESHCORE-TERM-START','get usb.logging','set usb.logging off','+++MESHCORE-TERM-STOP']);
});
test('Python archive import never silently falls back to JavaScript numeric canonicalization',async()=>{
  const raw='{"schema":"org.meshfirmware.meshcore-backup/v1","payload":{"value":0.0}}';
  await assert.rejects(()=>parseBackup(raw),/exact/);
  let received;await assert.rejects(()=>parseBackup(raw,{validatePython:async args=>{received=args.text;throw new Error('Exact validator refused');}}),/Exact validator refused/);
  assert.equal(received,raw);
});
test('different model and over-capacity restore are refused before mutating commands',async()=>{
  const p=payload(),core=new MeshCore({});let writes=0;
  core.self=async()=>Buffer.from(p.self,'hex');core.info=async()=>{const b=Buffer.from(p.info,'hex');b.fill(0,20,60);b.set(enc('other'),20);return b;};core.request=async()=>{writes++;};
  await assert.rejects(()=>core.restore(sealBackup(p)),/Different hardware/);assert.equal(writes,0);
});
test('contact union capacity is checked before any identity/channel/settings writes',async()=>{
  const p=payload(),core=new MeshCore({});let writes=0;const existing=[];
  for(let i=0;i<4;i++){const row=new Uint8Array(148);row[0]=3;row[1]=i+1;existing.push(row);}
  const row=new Uint8Array(148);row[0]=3;row[1]=7;p.contacts=[hex(row)];
  core.self=async()=>Buffer.from(p.self,'hex');core.info=async()=>Buffer.from(p.info,'hex');core.contacts=async()=>existing;core.request=async()=>{writes++;};
  await assert.rejects(()=>core.restore(sealBackup(p)),/Existing plus restored/);assert.equal(writes,0);
});
test('restore reads back structured options, clears scope with the short command, and defaults logging off',async()=>{
  const p=payload();p.options={autoadd:'190103',tuning:'17'+hex(words(10,2000)),scope:'1c',custom:'15'+hex(enc('gps:1'))};p.cli['get bluetooth.name']={name:'mcarper',default:false};
  const core=new MeshCore({}),commands=[],cliCommands=[];let logging='on',name='mcarper';
  core.self=async()=>Buffer.from(p.self,'hex');core.info=async()=>Buffer.from(p.info,'hex');core.contacts=async()=>[];
  core.request=async command=>{commands.push(command);if(command[0]===31)return Buffer.from(p.channels[0],'hex');if(command[0]===59)return Buffer.from(p.options.autoadd,'hex');if(command[0]===43)return Buffer.from(p.options.tuning,'hex');if(command[0]===40)return Buffer.from(p.options.custom,'hex');if(command[0]===64)return Uint8Array.of(28);return Uint8Array.of(0);};
  core.cli=async command=>{cliCommands.push(command);if(command==='get usb.logging')return `> usb.logging ${logging}`;if(command.startsWith('set usb.logging ')){logging=command.split(' ').at(-1);return `OK - USB logging ${logging} (saved)`;}if(command.startsWith('set bluetooth.name ')){name=command.slice(19);return 'OK - Bluetooth name saved';}if(command==='get bluetooth.name')return `> ${name} (custom)`;if(command==='get bluetooth')return '> bluetooth off';throw new Error('Unexpected command');};
  await core.restore(sealBackup(p));assert.equal(logging,'off');assert.deepEqual(commands.find(c=>c[0]===63),[63]);assert(commands.some(c=>c[0]===41));assert(!cliCommands.includes('set bluetooth on'));assert(!commands.some(c=>c[0]===10));
});
test('CommonCLI backup uses repeater verbs and proves identity stability without settings writes',async()=>{
  const p=payload(),commands=[],link={async command(command){commands.push(command);if(command==='get public.key')return `> ${p.publicKey}`;if(command==='get prv.key')return `> ${p.privateKey.slice(2)}`;return '> value';}};
  const archive=await backupCommonCli(link);assert.equal(verifyBackup(archive).publicKey,p.publicKey);assert(commands.includes('ver'));assert(commands.includes('region'));assert(!commands.includes('version'));assert.equal(commands.filter(c=>c==='get public.key').length,2);assert(!commands.some(c=>c.startsWith('set ')||c==='reboot'));assert.equal(archive.payload.safeForWipe,false);
  link.command=async command=>command==='get public.key'?'> '+'11'.repeat(32):command==='get prv.key'?'> '+p.privateKey.slice(2):'> value';await assert.rejects(()=>backupCommonCli(link),/identity mismatch/);
});
