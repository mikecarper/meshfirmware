import test from 'node:test';
import assert from 'node:assert/strict';
import {selectionLink} from '../src/selection-link.js';
const sample={provider:'Keymind Cascade',hardware:'Meshnology W12',role:'companionFull',version:'v1.18.0.1-halo-keymind-cascade-dev-03214a16',mode:'update',build:'meshnology_w12_companion_radio_full-v1.18.0.1-halo-keymind-cascade-dev-03214a16.bin'};

test('the complete current selection becomes a canonical production link with exact URL-decoded choices',()=>{
  const url=new URL(selectionLink(sample));assert.equal(url.origin,'https://mikecarper.github.io');assert.equal(url.pathname,'/meshfirmware/');assert.equal(url.hash,'#firmware-choices');assert.deepEqual(Object.fromEntries(url.searchParams),sample);
});

test('any hardware may share only its current filters without requiring a port, version or exact build',()=>{
  for(const hardware of ['Heltec T114','Heltec v2','RAK WisBlock / WisMesh (RAK 4631)','LilyGo LoRa32 V2.1_1.6','Board A&B + variant']){
    const url=new URL(selectionLink({hardware,role:'companionFull'}));assert.equal(url.searchParams.get('hardware'),hardware);assert.equal(url.searchParams.get('provider'),'Keymind Cascade');assert.equal(url.searchParams.get('role'),'companionFull');assert.ok(!url.searchParams.has('version'));assert.ok(!url.searchParams.has('build'));
  }
});

test('stock provider, historical Keymind alias, and explicit installation choices round-trip',()=>{
  const stock=new URL(selectionLink({...sample,provider:'MeshCore',mode:'install',build:'board-v1.18.0-merged.bin'}));assert.equal(stock.searchParams.get('provider'),'MeshCore');assert.equal(stock.searchParams.get('mode'),'install');assert.equal(new URL(selectionLink({...sample,provider:'Keymind Cascade Logging'})).searchParams.get('provider'),'Keymind Cascade');
});

test('sharing never forwards private context, current-page parameters, permissions or backup skips',()=>{
  const input={...sample,publicKey:'PRIVATE_NODE_KEY',nodeName:'PRIVATE_NODE_NAME',password:'PRIVATE_PASSWORD',usbIdentity:{serialNumber:'PRIVATE_SERIAL'},skipBackup:true,alreadyBootloader:true,authorization:'PRIVATE_APPROVAL',href:'https://private.example/?secret=PRIVATE_QUERY',baseUrl:'http://localhost:5173/private/path',extra:'PRIVATE_EXTRA'},before=structuredClone(input),link=selectionLink(input);
  assert.deepEqual(input,before);for(const secret of ['PRIVATE','localhost','skipBackup','alreadyBootloader','authorization','password','usbIdentity'])assert.ok(!link.includes(secret));assert.deepEqual([...new URL(link).searchParams.keys()],['provider','hardware','role','version','mode','build']);
});

test('query delimiters and fragments are encoded as values, not executable parameters or navigation',()=>{
  const hardware='Board &skipBackup=true#console',build='filename?secret=value&mode=install.bin',url=new URL(selectionLink({...sample,hardware,build}));assert.equal(url.searchParams.get('hardware'),hardware);assert.equal(url.searchParams.get('build'),build);assert.equal(url.searchParams.get('mode'),'update');assert.ok(!url.searchParams.has('skipBackup'));assert.equal(url.hash,'#firmware-choices');
});

test('missing hardware, controls, oversized values, invalid modes and path-like filenames produce no link',()=>{
  assert.equal(selectionLink(),null);
  for(const value of ['',null,42,{},' Board','Board ','Board\nreboot','Board\0','Board\u2028private','Board\ud800','x'.repeat(513)])assert.equal(selectionLink({...sample,hardware:value}),null);
  for(const mode of ['',null,'erase','update&skipBackup=1'])assert.equal(selectionLink({...sample,mode}),null);
  for(const field of ['provider','role','version','build'])assert.equal(selectionLink({...sample,[field]:'bad\rvalue'}),null);
  for(const build of ['../file.bin','C:\\private\\file.bin','https://private.example/file.bin','.','..'])assert.equal(selectionLink({...sample,build}),null);
});
