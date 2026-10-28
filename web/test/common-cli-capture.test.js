import test from 'node:test';
import assert from 'node:assert/strict';
import {backupCommonCli,backupSummary,parseBackup,publicFromPrivate,sealBackup,verifyBackup} from '../src/meshcore.js';
import {nativePayloadFromWeb} from '../src/backup-native.js';

const key=new Uint8Array(64);key[0]=1;
const publicKey=publicFromPrivate(key),privateHex=Buffer.from(key).toString('hex');
const common=(replies={})=>sealBackup({role:'common-cli',publicKey,safeForWipe:false,replies:{'get public.key':`> ${publicKey}`,'get prv.key':`> ${privateHex}`,ver:'> MeshCore Repeater v1.18.0.1','get role':'> repeater','get name':'> Bench','get radio':'> 910.525,125,10,5','get acl':'> ACL:','region':'> 0: Global',...replies}});
const exportOptions={usbIdentity:{vendor_id:0x303a,product_id:0x1001},deviceHint:'Bench board'};
const regionSnapshot=()=>({schema:'org.meshfirmware.regions/v1',entries:[{name:'north',parent:'*',floodAllowed:true},{name:'west',parent:'north',floodAllowed:false}],wildcardFloodAllowed:true,home:'*',default:'north'});

test('CommonCLI capture queries expanded exposed preferences without changing logging or reading messages',async()=>{
  const commands=[],link={async command(command){commands.push(command);if(command==='get public.key')return `> ${publicKey}`;if(command==='get prv.key')return `> ${privateHex}`;if(command==='get usb.logging')return '> usb.logging off';return '> value';}};
  const archive=await backupCommonCli(link);
  for(const command of ['get bluetooth','get bluetooth.name','get usb.logging','get radio.cad','get radio.rxgain','get radio.fem.rxgain','get radio.fem.txgain','get radio.rxps.config','get display.rotation','get powersaving','get radio2','get radio2.cross'])assert.ok(commands.includes(command),command);
  assert.equal(commands.filter(command=>command==='get public.key').length,2);assert.equal(archive.payload.replies['get usb.logging'],'> usb.logging off');assert.ok(!commands.some(command=>/^set |reboot|reset|erase|msg|message/i.test(command)));assert.equal(verifyBackup(archive).publicKey,publicKey);
});

test('CommonCLI query failures and unsupported settings are reported honestly in summary and typed export',()=>{
  const archive=common({'get name':'get name\n -> Error: query failed','get system.watchdog':'get system.watchdog\n -> Error: unsupported on this platform','get usb.logging':'> usb.logging off','get radio.rxgain':'get radio.rxgain\n -> Error: query failed','get bluetooth.name':'get bluetooth.name\n -> > MeshCore-Bench (default from node name)'});
  const summary=backupSummary(archive),native=nativePayloadFromWeb(archive,exportOptions);
  assert.equal(summary.complete,false);assert.equal(summary.privateIdentity,true);assert.ok(summary.queryErrors.includes('get name'));assert.ok(summary.queryErrors.includes('get radio.rxgain'));assert.ok(summary.unsupportedQueries.includes('get system.watchdog'));assert.ok(!summary.reasons.some(reason=>/cannot be automatically restored/i.test(reason)));
  assert.equal(native.sections.settings.state,'error');assert.equal(native.sections.settings.query_states['get name'].state,'error');assert.equal(native.sections.system_watchdog.state,'unsupported');assert.equal(native.sections.radio_rxgain.state,'error');assert.equal(native.sections.usb_logging.state,'complete');assert.deepEqual(native.sections.bluetooth_name.data,{name:'MeshCore-Bench',default:true});
  assert.equal(native.sections.contacts.state,'not_applicable');assert.equal(native.sections.channels.state,'not_applicable');assert.ok(native.completeness.missing_required.includes('settings'));assert.ok(native.completeness.optional_errors.includes('radio_rxgain'));assert.equal(native.completeness.safe_for_wipe,false);assert.equal(native.completeness.safe_for_restore,false);
  assert.ok(!Object.hasOwn(native.sections.settings.data,'get prv.key'));assert.ok(!Object.hasOwn(native.sections.settings.data,'get public.key'));assert.equal(native.sections.identity_private_key.data.private_key,privateHex);
});

test('CommonCLI ACL/region error replies are not mislabeled as complete',()=>{
  const native=nativePayloadFromWeb(common({'get acl':'> Error: query failed',region:'region\n -> Unknown command'}),exportOptions);
  assert.equal(native.sections.acl.state,'error');assert.equal(native.sections.regions.state,'unsupported');assert.ok(native.completeness.missing_required.includes('acl'));assert.ok(native.completeness.missing_required.includes('regions'));
});

test('legacy native CommonCLI sections reconstruct private identity, ACL and region into a validated restore snapshot',async()=>{
  for(const shape of ['browser','script']){
    const wrap=value=>shape==='script'?{ok:true,text:value}:value;
    const payload={source:{capture_api:'meshcore-cli-common-cli',node:{public_key:publicKey,role:'repeater',device_hint:'Bench board'}},sections:{settings:{state:'complete',data:{'get name':wrap('> Bench'),'get usb.logging':wrap('> usb.logging off'),reboot:'never execute','get tx':shape==='script'?{ok:false,text:'> 20'}:'> 20'}},identity_private_key:{state:'complete',data:{private_key:privateHex}},acl:{state:'complete',data:shape==='script'?{raw:'> ACL:'}:{text:'> ACL:'}},regions:{state:'complete',data:shape==='script'?{raw:'> 0: Global'}:{text:'> 0: Global'}},bluetooth_name:{state:'complete',data:{name:'MeshCore-Bench',default:true}}},completeness:{status:'partial',safe_for_wipe:false,safe_for_restore:false,missing_required:[],optional_errors:[],reasons:['Logical only']}};
    const raw=JSON.stringify({schema:'org.meshfirmware.meshcore-backup/v1',payload}),archive=await parseBackup(raw,{validatePython:async args=>{assert.equal(args.text,raw);return {payload};}}),p=verifyBackup(archive);
    assert.equal(p.role,'common-cli');assert.equal(p.publicKey,publicKey);assert.equal(p.replies['get public.key'],`> ${publicKey}`);assert.equal(p.replies['get prv.key'],`> ${privateHex}`);assert.equal(p.replies['get acl'],'> ACL:');assert.equal(p.replies.region,'> 0: Global');assert.equal(p.replies['get bluetooth.name'],'> MeshCore-Bench (default from node name)');assert.ok(!Object.hasOwn(p.replies,'reboot'));assert.deepEqual(p.nativeSource,{role:'repeater',deviceHint:'Bench board'});assert.deepEqual(p.nativeCompleteness,payload.completeness);
    if(shape==='script')assert.match(p.replies['get tx'],/^Error:/);else assert.equal(p.replies['get tx'],'> 20');
    assert.notEqual(p.nativeCompleteness,payload.completeness);assert.ok(!Object.values(p.replies).some(value=>value&&typeof value==='object'));
  }
});

test('CommonCLI imports fail closed on oversized values, malformed identity or wrong private/public keys',()=>{
  for(const mutate of [p=>p.publicKey='not a key',p=>p.replies['get name']='x'.repeat(8193),p=>p.replies['get tx']={text:'20'},p=>p.replies['get prv.key']='> '+'00'.repeat(64),p=>p.replies['get name\nreboot']='x']){
    const payload=structuredClone(common().payload);mutate(payload);assert.throws(()=>verifyBackup(sealBackup(payload)),/identity|snapshot|key/i);
  }
});

test('CommonCLI capture saves a verified typed region tree and selections before final identity stability check',async()=>{
  for(const wrapped of [false,true]){
    const commands=[],regionReplies={region:wrapped?'region\r\n  -> *^ F\n north F\n  west\n\r\n':'*^ F\n north F\n  west\n','region home':'home is *','region default':'default scope is north','region get *':' * F','region get north':' north F','region get west':' west (north)','region list allowed':'*,north','region list denied':'west'};
    const link={async command(command){commands.push(command);if(command==='get public.key')return `> ${publicKey}`;if(command==='get prv.key')return `> ${privateHex}`;if(Object.hasOwn(regionReplies,command))return regionReplies[command];return '> value';}};
    const archive=await backupCommonCli(link),p=verifyBackup(archive);assert.equal(p.regions.state,'complete',wrapped?'framed console':'direct reply');assert.deepEqual(p.regions.data,regionSnapshot());assert.equal(commands.at(-1),'get public.key');
    for(const command of ['region','region home','region default'])assert.ok(commands.includes(command));assert.ok(!commands.some(command=>/^(?:region (?:put|def|allowf|denyf|save|load|remove)(?: |$)|set |reboot(?: |$))/.test(command)));
  }
});

test('typed region exports keep snapshot proof separate from bounded legacy raw text',()=>{
  const p=structuredClone(common().payload);p.regions={state:'complete',data:regionSnapshot()};const native=nativePayloadFromWeb(sealBackup(p),exportOptions);
  assert.equal(native.sections.regions.state,'complete');assert.equal(native.sections.regions.required,true);assert.deepEqual(native.sections.regions.data.snapshot,regionSnapshot());assert.equal(native.sections.regions.data.raw,p.replies.region);assert.ok(!native.completeness.missing_required.includes('regions'));
  const legacy=nativePayloadFromWeb(common(),exportOptions);assert.equal(legacy.sections.regions.state,'unsupported');assert.equal(legacy.sections.regions.data.raw,common().payload.replies.region);assert.ok(legacy.completeness.missing_required.includes('regions'));
});

test('truncated or private region captures remain explicitly unavailable without a restorable snapshot',()=>{
  for(const state of ['unsupported','error']){
    const p=structuredClone(common().payload);p.regions={state,reason:'The region export is truncated or contains unavailable private keys.'};const native=nativePayloadFromWeb(sealBackup(p),exportOptions);
    assert.equal(native.sections.regions.state,state);assert.equal(native.sections.regions.required,true);assert.equal(native.sections.regions.data.snapshot,undefined);assert.match(native.sections.regions.reason,/truncated/);assert.ok(backupSummary(sealBackup(p)).reasons.some(reason=>/Regions:.*truncated/.test(reason)));
  }
});

test('native region snapshots round-trip without inventing state for older raw-only archives',async()=>{
  const p=structuredClone(common().payload);p.regions={state:'complete',data:regionSnapshot()};const native=nativePayloadFromWeb(sealBackup(p),exportOptions);
  const parse=payload=>parseBackup(JSON.stringify({schema:'org.meshfirmware.meshcore-backup/v1',payload}),{validatePython:async()=>({payload})});
  const restored=verifyBackup(await parse(native));assert.deepEqual(restored.regions,{state:'complete',data:regionSnapshot()});
  delete native.sections.regions.data.snapshot;const legacy=verifyBackup(await parse(native));assert.equal(legacy.regions.state,'unsupported');assert.equal(legacy.regions.data,undefined);assert.equal(legacy.replies.region,p.replies.region);
});

test('malformed region snapshots or state cannot pass import validation even after recomputing the web checksum',async()=>{
  for(const mutate of [p=>p.regions.state='unknown',p=>{p.regions.state='unsupported';},p=>p.regions.data.schema='not a region schema',p=>p.regions.data.entries[0].name='north\nreboot',p=>p.regions.data.entries[1].parent='west',p=>p.regions.data.entries[0].name='$private']){
    const p=structuredClone(common().payload);p.regions={state:'complete',data:regionSnapshot()};mutate(p);assert.throws(()=>verifyBackup(sealBackup(p)),/region|name|cycle|snapshot|hierarch/i);
  }
  const native=nativePayloadFromWeb(common(),exportOptions);native.sections.regions.data.snapshot=regionSnapshot();native.sections.regions.state='unsupported';
  await assert.rejects(parseBackup(JSON.stringify({schema:'org.meshfirmware.meshcore-backup/v1',payload:native}),{validatePython:async()=>({payload:native})}),/complete capture state/);
});
