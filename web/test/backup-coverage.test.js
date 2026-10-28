import test from 'node:test';
import assert from 'node:assert/strict';
import {backupCoverage} from '../src/backup-coverage.js';

const common=(overrides={})=>({payload:{role:'common-cli',publicKey:'11'.repeat(32),replies:{'get public.key':'> '+'11'.repeat(32),'get prv.key':'> '+'01'+'00'.repeat(63),'get name':'> Bench','get radio':'> 911.3,125,10,5'},regions:{state:'complete',data:{}},...overrides}});
const native=sections=>({payload:{source:{capture_api:'meshcore-cli-common-cli'},sections,completeness:{status:'partial',safe_for_wipe:false,safe_for_restore:false,missing_required:[],optional_errors:[]},excluded:{messages:'excluded',logs:'excluded',unexposed_preferences:'not exposed'}}});
const labels=result=>result.notIncluded.map(item=>item.label);

test('common configuration lists captured values and normal exclusions without companion-only inventories',()=>{
  const archive=common(),metadata=native({identity_private_key:{state:'complete'},regions:{state:'complete'},contacts:{state:'not_applicable'},channels:{state:'not_applicable'}}),before=JSON.stringify({archive,metadata});
  const result=backupCoverage(archive,metadata);
  for(const label of ['Public identity','Private identity','Node name','Primary radio settings','Region hierarchy, flood permissions, home and default scope'])assert.ok(result.included.includes(label),label);
  for(const label of ['Firmware and bootloader files','Stored messages','Runtime logs'])assert.ok(labels(result).includes(label),label);
  assert.ok(!labels(result).includes('Preferences without an export command'));
  assert.ok(!labels(result).includes('Contacts'));assert.ok(!labels(result).includes('Channels and channel secrets'));assert.deepEqual(result.failed,[]);
  assert.doesNotMatch(JSON.stringify(result),/partial|incomplete|wipe.safe|not protected|automatic restore is unavailable/i);assert.match(result.notIncludedText,/^Not backed up:/);assert.equal(result.summaryText,'Captured values are saved in the JSON.');assert.equal(JSON.stringify({archive,metadata}),before);
  assert.match(result.notIncludedText,/Firmware and bootloader files; Stored messages; Runtime logs/);assert.doesNotMatch(result.notIncludedText,/not firmware images|queue is not read|Logs are not exported/);
});

test('native query states identify exact omitted values and deduplicate typed sections',()=>{
  const archive=common({replies:{'get system.watchdog':'get system.watchdog\n -> Error: unsupported on this platform','get radio.rxgain':'> on'}});
  const metadata=native({settings:{state:'error',data:{'get radio.rxgain':'> on'},query_states:{'get system.watchdog':{state:'unsupported'},'get radio.rxgain':{state:'error'}}},system_watchdog:{command:'get system.watchdog',state:'unsupported'},radio_rxgain:{command:'get radio.rxgain',state:'error'},identity_private_key:{state:'unsupported'},contacts:{state:'not_applicable'},channels:{state:'not_applicable'}});
  metadata.payload.completeness.missing_required=['settings'];metadata.payload.completeness.optional_errors=['radio_rxgain'];
  const result=backupCoverage(archive,metadata);assert.equal(labels(result).filter(value=>value==='System watchdog setting').length,1);assert.equal(labels(result).filter(value=>value==='RX gain').length,1);assert.ok(!labels(result).includes('Core node settings'));assert.ok(!result.included.includes('RX gain'));assert.deepEqual(result.failed,[{label:'RX gain',reason:'The read failed; no value was saved.'}]);
  assert.match(result.notIncludedText,/System watchdog setting \(not supported by firmware\)/);assert.match(result.notIncludedText,/RX gain \(read failed; no value saved\)/);
});

test('genuine required-section failures remain failures even when listed as missing required',()=>{
  const metadata=native({regions:{state:'error',reason:'Secret debug response must never be displayed'},identity_private_key:{state:'error'}});metadata.payload.completeness.missing_required=['regions','identity_private_key'];
  const result=backupCoverage(common(),metadata);assert.ok(result.failed.some(item=>item.label==='Private identity'));assert.ok(result.failed.some(item=>item.label.startsWith('Region hierarchy')));assert.doesNotMatch(JSON.stringify(result),/Secret debug response/);
});

test('a contradictory complete typed section cannot conceal its own failed query state',()=>{
  const metadata=native({settings:{state:'error',query_states:{'get usb.logging':{state:'error'}},data:{'get usb.logging':'> off'}},usb_logging:{state:'complete',command:'get usb.logging'}});
  const result=backupCoverage(common(),metadata);assert.ok(result.failed.some(item=>item.label==='USB logging preference'));assert.ok(!result.included.includes('USB logging preference'));
});

test('private identity omissions are explicit instead of an unexplained backup-quality label',()=>{
  const result=backupCoverage(common({replies:{'get name':'> Bench'}}));assert.ok(labels(result).includes('Private identity'));assert.ok(!result.included.includes('Private identity'));assert.deepEqual(result.failed,[]);
});

test('companion captures report unavailable options and diagnostics without exposing stored values',()=>{
  const archive={payload:{role:'companion',publicKey:'11'.repeat(32),self:'05',info:'0d',contacts:[],channels:[],options:{autoadd:{unavailable:'private debug data'},tuning:'17',custom:'15',scope:'1c'},cli:{'get bluetooth.name':{name:'Do not display this name',default:false},'get usb.logging':null,'get radio.rxgain':'unsupported'},batteryAndStorage:{unavailable:'sensitive response'}}};
  const result=backupCoverage(archive);assert.ok(labels(result).includes('Private identity'));assert.ok(labels(result).includes('Automatic contact-add preferences'));assert.ok(result.included.includes('Contacts'));assert.ok(result.included.includes('Channels and channel secrets'));assert.ok(result.included.includes('Bluetooth name'));assert.ok(result.failed.some(item=>item.label==='USB logging preference'));assert.ok(result.failed.some(item=>item.label==='Battery and storage information'));assert.doesNotMatch(JSON.stringify(result),/private debug data|Do not display this name|sensitive response/);
});

test('complete region snapshots are not listed as missing',()=>{
  const result=backupCoverage(common(),native({regions:{state:'complete'}}));assert.ok(result.included.some(label=>label.startsWith('Region hierarchy')));assert.ok(!labels(result).some(label=>/region/i.test(label)));
});

test('truncated and legacy region omissions use specific safe explanations',()=>{
  for(const [reason,expected] of [['Region map may be truncated; 160-byte buffer','export limit'],['No complete typed region snapshot was captured','Tree, home and default-scope']]){
    const result=backupCoverage(common({regions:{state:'unsupported',reason}})),region=result.notIncluded.find(item=>item.label.startsWith('Region hierarchy'));assert.match(region.reason,new RegExp(expected));assert.deepEqual(result.failed,[]);
  }
});

test('private-region exclusion explains both absent keys and omitted region snapshot without echoing keys',()=>{
  const secret='cd'.repeat(16),result=backupCoverage(common({regions:{state:'unsupported',reason:`Private region transport keys ${secret} are not exported`}}));assert.ok(labels(result).includes('Private-region transport keys'));assert.ok(result.notIncluded.find(item=>item.label.startsWith('Region hierarchy')).reason.includes('private-key regions'));assert.ok(!JSON.stringify(result).includes(secret));
});

test('not-applicable inventories are ignored while disabled exports remain concrete omissions',()=>{
  const result=backupCoverage(common(),native({contacts:{state:'not_applicable'},channels:{state:'not_applicable'},usb_debug:{command:'get usb.debug',state:'disabled'},regions:{state:'complete'}}));assert.ok(!labels(result).some(label=>/Contacts|Channels/.test(label)));assert.ok(labels(result).includes('USB debug preference'));assert.match(result.notIncludedText,/USB debug preference \(export disabled by firmware\)/);assert.deepEqual(result.failed,[]);
});

test('disabled private identity and applicable companion inventories are reported without pretending the read failed',()=>{
  const archive={payload:{source:{capture_api:'companion-api'},sections:{identity_private_key:{state:'disabled'},contacts:{state:'disabled'},channels:{state:'complete'}},completeness:{missing_required:['identity_private_key','contacts'],optional_errors:[]}}};
  const result=backupCoverage(archive);assert.ok(labels(result).includes('Private identity'));assert.ok(labels(result).includes('Contacts'));assert.ok(result.included.includes('Channels and channel secrets'));assert.match(result.notIncludedText,/Private identity \(export disabled by firmware\)/);assert.deepEqual(result.failed,[]);
});

test('native archives can be summarized directly, including script reply wrappers',()=>{
  const metadata=native({identity_public_key:{state:'complete'},identity_private_key:{state:'complete'},settings:{state:'complete',data:{'get name':{ok:true,text:'> Bench'},'get tx':{ok:false,text:'> 20'}}},regions:{state:'complete'}});
  const result=backupCoverage(metadata);assert.ok(result.included.includes('Node name'));assert.ok(result.failed.some(item=>item.label==='TX power'));assert.ok(!result.included.includes('TX power'));
});

test('secret values, raw archived errors and unfamiliar metadata never become displayed coverage text',()=>{
  const secret='sensitive password 123',metadata=native({settings:{state:'complete',data:{'get password':`> ${secret}`},query_states:{'get password':{state:'error',reason:secret}}},unfamiliar:{state:'error',reason:secret,command:secret},radio_rxgain:{state:'error',reason:secret}});
  metadata.payload.completeness.optional_errors=['radio_rxgain','unfamiliar'];const result=backupCoverage(common({replies:{'get password':`Error: ${secret}`}}),metadata);assert.ok(labels(result).includes('Administrator password'));assert.ok(!JSON.stringify(result).includes(secret));assert.ok(!labels(result).includes('unfamiliar'));
});

test('empty or missing input makes no positive configuration claim and remains presentation-only',()=>{
  for(const input of [null,undefined,{}, {payload:{}}]){
    const result=backupCoverage(input);assert.deepEqual(result.included,[]);assert.deepEqual(result.failed,[]);assert.equal(result.summaryText,'No configuration values were captured.');assert.deepEqual(labels(result),['Firmware and bootloader files','Stored messages','Runtime logs']);
  }
});

test('object-prototype names in imported metadata cannot select or execute a presentation rule',()=>{
  const metadata=JSON.parse('{"payload":{"source":{"capture_api":"meshcore-cli-common-cli"},"sections":{"__proto__":{"state":"error"},"toString":{"state":"error","command":"toString"},"settings":{"state":"complete","data":{"constructor":"reboot"}}},"completeness":{"missing_required":["constructor"],"optional_errors":["__proto__"]}}}');
  assert.doesNotThrow(()=>backupCoverage(common(),metadata));assert.ok(!JSON.stringify(backupCoverage(common(),metadata)).includes('reboot'));
});
