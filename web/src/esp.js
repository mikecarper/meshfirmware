import { ESPLoader, Transport } from 'esptool-js';
import { fail, hash, md5hex, partitionTable, activeOta, text, sleep, validateEspImage } from './firmware.js';
import { assessEspCompatibility } from './esp-compatibility.js';

const RECOVERY_FORMAT='meshfirmware-esp-write-recovery-v1';
const RECOVERY_CHUNK=16384;
const MAX_RECOVERY_ATTEMPTS=3;
const interruptedTransport=error=>/NetworkError|NotFoundError|TimeoutError|InvalidStateError/.test(error?.name||'')||/disconnect|device (?:lost|removed)|port.*closed|closed.*port|timed? ?out|timeout|serial.*(?:exception|stopped|error)|no more data|stream.*(?:closed|stopped)|packet.*(?:stopped|header)|lost connection/i.test(error?.message||'');
const quietStreamMessage='Serial data stream stopped: Possible serial noise or corruption.';
const handshakeReadiness=error=>['Error','ESPError','TimeoutError'].includes(error?.name||'Error')&&!/permission|denied|not.?allowed|security|disconnect|device (?:lost|removed)|port.*closed|not open|invalid state/i.test(error?.message||'')&&(error?.message===quietStreamMessage||/timeout|timed out|no response|no serial data|invalid head of packet|failed to connect with the device/i.test(error?.message||''));
async function detectForConnection(loader,mode,singleReset){
  const originalSync=loader.sync,originalCommand=loader.command;
  const transport=loader.transport,originalReadLoop=transport?.readLoop;
  let attempted=false,responded=false,blocked=false;
  let readerStopped=false,readerFailure=null;
  if(singleReset&&typeof originalReadLoop==='function')transport.readLoop=function(...args){
    let running;
    try{running=Reflect.apply(originalReadLoop,this,args);}
    catch(error){readerStopped=true;readerFailure=error;throw error;}
    // esptool's readLoop swallows fatal reader errors and EOF. An ordinary
    // empty application port keeps it pending; a settled loop is NOT silence
    // that may authorize another reset, even if read() later reports timeout.
    if(running&&typeof running.then==='function')void running.then(()=>{readerStopped=true;},error=>{readerStopped=true;readerFailure=error;});
    return running;
  };
  if(typeof originalSync==='function')loader.sync=async function(...args){
    attempted=true;
    try{const result=await Reflect.apply(originalSync,this,args);responded=true;return result;}
    catch(error){if(!handshakeReadiness(error))blocked=true;throw error;}
  };
  if(typeof originalCommand==='function')loader.command=async function(operation,...args){
    const result=await Reflect.apply(originalCommand,this,[operation,...args]);
    // A valid first SYNC response is enough proof that this method reached a
    // ROM/stub. Losing later ACKs must not authorize another reset method.
    if(operation===0x08)responded=true;
    return result;
  };
  try{
    if(singleReset)await detectWithSingleReset(loader,mode);
    else await loader.detectChip(mode);
  }catch(error){
    // The loader collapses exhausted pre-sync timeouts to a generic ESPError.
    // Never mark permission failures or failures after even one valid reply.
    if(singleReset&&!responded&&readerStopped)throw readerFailure||new Error('USB serial reader stopped before ROM synchronization. Reconnect the same radio; no automatic reset retry was sent.');
    if(singleReset&&attempted&&!responded&&!blocked&&!readerStopped&&handshakeReadiness(error)){
      const failure=new Error(error.message,{cause:error});failure.name=error.name;failure.romHandshakeFailed=true;throw failure;
    }
    throw error;
  }finally{
    if(typeof originalSync==='function')loader.sync=originalSync;
    if(typeof originalCommand==='function')loader.command=originalCommand;
    if(singleReset&&typeof originalReadLoop==='function')transport.readLoop=originalReadLoop;
  }
}
async function detectWithSingleReset(loader,mode) {
  const original=loader.resetConstructors;
  if(!original||typeof original!=='object')fail('The ESP loader does not expose guarded reset constructors. No automatic ROM entry is permitted.');
  let consumed=mode==='no_reset';
  const guarded={...original};
  for(const key of ['classicReset','usbJTAGSerialReset','customReset','hardReset']){
    const factory=original[key];
    if(typeof factory!=='function')continue;
    guarded[key]=(...args)=>{
      const strategy=Reflect.apply(factory,original,args);
      if(!strategy||typeof strategy.reset!=='function')fail('Invalid ESP reset strategy. No automatic ROM entry is permitted.');
      return {reset:async(...resetArgs)=>{
        if(consumed)fail('Automatic ROM entry already used its one reset. No reset retry was sent.');
        consumed=true; // Delivery may be uncertain even when the first await rejects.
        return Reflect.apply(strategy.reset,strategy,resetArgs);
      }};
    };
  }
  loader.resetConstructors=guarded;
  try {await loader.detectChip(mode,1);}
  finally {loader.resetConstructors=original;}
}
function writeProgram(pkg,plan,flashBytes) {
  const bridge=!!(plan.needed&&!plan.verified),payload=bridge?Uint8Array.from(plan.bridge):pkg.payload;
  const segments=(plan.segments||plan.addresses.map(address=>({address,sourceOffset:0,length:payload.length,payloadHash:hash(payload)}))).map(part=>({address:part.address,sourceOffset:part.sourceOffset||0,length:part.length,payloadHash:part.payloadHash}));
  return {mac:plan.mac,sha256:pkg.sha256,payloadHash:pkg.payloadHash,chipId:pkg.chipId,flashBytes,stage:bridge?'bridge':pkg.merged?'merged':pkg.expert?'component':'application',merged:!!plan.merged,expert:!!plan.expert,bridgeHash:bridge?plan.bridge_sha256:null,partitionHash:bridge?plan.source_table_sha256:hash(new TextEncoder().encode(JSON.stringify(plan.parts||[]))),revisionProof:plan.revisionProof,segments};
}
export function validateEspWriteRecovery(value) {
  const hex=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
  if(!value||value.format!==RECOVERY_FORMAT||!/^([a-f0-9]{2}:){5}[a-f0-9]{2}$/.test(value.mac)||!hex(value.sha256)||!hex(value.payloadHash)||!hex(value.partitionHash)||!hex(value.revisionProof)||!Number.isInteger(value.chipId)||![0,2,5,9,13].includes(value.chipId)||!Number.isInteger(value.flashBytes)||value.flashBytes<(1<<18)||value.flashBytes>(128<<20)||!['bridge','merged','component','application'].includes(value.stage)||typeof value.merged!=='boolean'||typeof value.expert!=='boolean'||typeof value.eraseComplete!=='boolean'||!Number.isInteger(value.attempts)||value.attempts<0||value.attempts>MAX_RECOVERY_ATTEMPTS||!Array.isArray(value.segments)||!value.segments.length||value.segments.length>32||!value.segments.every(s=>s&&Number.isInteger(s.address)&&s.address>=0&&s.address%4096===0&&Number.isInteger(s.sourceOffset)&&s.sourceOffset>=0&&Number.isInteger(s.length)&&s.length>0&&s.length<=(64<<20)&&s.address+Math.ceil(s.length/4)*4<=value.flashBytes&&hex(s.payloadHash))||new Set(value.segments.map(s=>s.address)).size!==value.segments.length||(value.stage==='bridge'?!hex(value.bridgeHash):value.bridgeHash!==null))fail('Invalid ESP write-recovery descriptor.');
  if(!Number.isInteger(Math.log2(value.flashBytes))||value.merged!==(value.stage==='merged')||value.expert!==(value.stage==='component')||value.segments.some(s=>s.sourceOffset+s.length>(64<<20)))fail('Invalid ESP recovery stage or geometry.');
  return value;
}
function bindWriteRecovery(value,program) {
  validateEspWriteRecovery(value);
  for(const key of Object.keys(program))if(JSON.stringify(value[key])!==JSON.stringify(program[key]))fail('Interrupted ESP write belongs to a different chip, firmware, partition layout or write stage.');
  if(value.merged&&!value.eraseComplete)fail('The previous whole-chip erase was not confirmed. Chunk recovery cannot skip an uncertain erase. Use Discard ESP retry record, then explicitly authorize a fresh full install and wipe.');
  if(value.attempts>=MAX_RECOVERY_ATTEMPTS)fail('Three interrupted chunk-recovery attempts were exhausted. Inspect the USB connection; use Discard ESP retry record before explicitly authorizing a fresh write.');
  return Object.freeze({...program,format:RECOVERY_FORMAT,eraseComplete:value.eraseComplete,attempts:value.attempts,segments:Object.freeze(program.segments.map(s=>Object.freeze({...s})))});
}

export async function assertSecurity(loader) {
  if (loader.secureDownloadMode) fail('Secure download mode: this browser does not perform encrypted or secure-boot updates.');
  if (loader.chip.IMAGE_CHIP_ID === 0) {
    const cryptWord=await loader.readReg(0x3ff5a000),secureWord=await loader.readReg(0x3ff5a018);
    if (![cryptWord,secureWord].every(value=>Number.isInteger(value) && value>=0 && value<=0xffffffff)) fail('ROM security state could not be verified. No RAM stub or flash write permitted.');
    const crypt = cryptWord & 0x7f00000;
    const secure = secureWord & 0x30;
    if (secure || crypt.toString(2).replace(/0/g,'').length % 2) fail('Secure boot or flash encryption is enabled. No RAM stub or flash write permitted.');
  } else {
    const info = await loader.getSecurityInfo(false);
    if (!info?.parsedFlags || !Number.isInteger(info.flashCryptCnt) || info.flashCryptCnt<0 || typeof info.parsedFlags.SECURE_BOOT_EN!=='boolean' || typeof info.parsedFlags.SECURE_DOWNLOAD_ENABLE!=='boolean') fail('ROM security state could not be verified. No RAM stub or flash write permitted.');
    if (info.parsedFlags.SECURE_BOOT_EN || info.parsedFlags.SECURE_DOWNLOAD_ENABLE || info.flashCryptCnt.toString(2).replace(/0/g,'').length % 2) fail('Secure boot, secure download, or flash encryption is enabled. No RAM stub or flash write permitted.');
  }
}

export async function stabilizeS3Jtag(loader) {
  if(loader.chip.IMAGE_CHIP_ID!==9 || ((await loader.readReg(0x3fcef14c)) & 255)!==4) return;
  // USB-JTAG ROM entry does not reset the RTC/SWD watchdogs. Keep them from
  // resetting the chip midway through a flash; never infer this from USB IDs.
  await loader.writeReg(0x600080b0,0x50d83aa1);
  await loader.writeReg(0x60008098,0);
  await loader.writeReg(0x600080b0,0);
  const swd=await loader.readReg(0x600080b4);
  await loader.writeReg(0x600080b8,0x8f1d312a);
  await loader.writeReg(0x600080b4,(swd | 0x80000000) >>> 0);
  await loader.writeReg(0x600080b8,0);
}

export function appWriteOrder(parts, otaBytes = null) {
  const apps=parts.filter(part=>part.type===0),factories=apps.filter(part=>part.subtype===0),otaApps=apps.filter(part=>part.subtype>=0x10&&part.subtype<=0x1f),otas=parts.filter(part=>part.type===1&&part.subtype===0);
  if(!apps.length||factories.length>1||new Set(apps.map(part=>part.subtype)).size!==apps.length||apps.length!==factories.length+otaApps.length) fail('Application layout has missing, duplicate or unsupported slot identities.');
  let active;
  if(otaApps.length) {if(otas.length!==1||otas[0].size<8192||!(otaBytes instanceof Uint8Array)||otaBytes.length!==8192)fail('Actual OTA metadata is required to safely order application writes.');active=activeOta(parts,otaBytes);}
  else if(factories.length===1)active=factories[0].offset;
  else fail('No supported bootable application slot.');
  return apps.slice().sort((a,b)=>a.subtype-b.subtype).map(part=>part.offset).filter(offset=>offset!==active).concat(active);
}

export function mergedMirrorSegments(pkg, parts, populated) {
  const ota=parts.filter(part=>part.type===0&&part.subtype>=0x10&&part.subtype<=0x1f).sort((a,b)=>a.subtype-b.subtype);
  const missing=ota.filter(part=>!populated.has(part.offset));
  if(ota.length<2||!missing.length)return [];
  if(ota.map(part=>part.subtype).some((subtype,index)=>subtype!==0x10+index))fail('Merged OTA identities are not unique and contiguous.');
  const source=ota[0];
  if(!populated.has(source.offset)||pkg.payload.length>source.offset+source.size)fail('Cannot safely identify the exact merged primary application boundary for fallback mirroring. Select a complete compatible merged image.');
  // As in the Linux flasher, preserve the entire original app including its
  // EndF trailer/padding; never invent a boundary from only the ESP checksum.
  const app=pkg.payload.subarray(source.offset);
  validateEspImage(app);
  if(missing.some(part=>app.length>part.size))fail('Embedded application does not fit every secondary OTA slot.');
  return missing.map(part=>({address:part.offset,sourceOffset:source.offset,length:app.length,payloadHash:hash(app)}));
}

export class EspSession {
  #planProof = null;
  #written = false;
  #writeRecovery = null;
  constructor(port, log) {
    this.transport = new Transport(port);
    this.loader = new ESPLoader({ transport: this.transport, baudrate: 115200, romBaudrate: 115200, terminal: { clean() {}, writeLine: log, write: log } });
    this.port = port; this.mac = null; this.flashBytes = 0; this.plan = null; this.connectMode=null;
  }
  async connect(mode,{singleReset=false}={}) {
    if (!['no_reset','usb_reset','default_reset'].includes(mode)) fail('Choose a qualified ESP32 bootloader/reset mode.');
    if(typeof singleReset!=='boolean')fail('The single-reset option must be a boolean.');
    this.mac=null; this.flashBytes=0; this.plan=null; this.#planProof=null; this.#written=false; this.#writeRecovery=null; this.connectMode=null;
    // Never infer TinyUSB versus hardware JTAG from shared VID/PID 303a:1001.
    // attempts=1 alone is insufficient: chip-identification fallback can open
    // and reset again. Share one consumed budget across every reset factory.
    await detectForConnection(this.loader,mode,singleReset);
    if (![0,2,5,9,13].includes(this.loader.chip.IMAGE_CHIP_ID)) fail('This browser build does not support the detected ESP chip family.');
    await assertSecurity(this.loader); // Before RAM stub upload/register changes.
    this.mac = (await this.loader.chip.readMac(this.loader)).toLowerCase();
    if (!/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(this.mac) || /^(00:){5}00$|^(ff:){5}ff$/.test(this.mac)) fail('Physical chip MAC could not be verified.');
    await stabilizeS3Jtag(this.loader);
    await this.assertMac();
    await this.loader.runStub();
    const id = await this.loader.readFlashId(), exponent = (id >>> 16) & 255;
    if (exponent < 18 || exponent > 27) fail('Physical flash capacity could not be verified.');
    this.flashBytes = 2 ** exponent;
    this.connectMode=mode;
    return { chip: this.loader.chip.CHIP_NAME, mac: this.mac, flashBytes: this.flashBytes };
  }
  async assertMac() { if (!this.mac || (await this.loader.chip.readMac(this.loader)).toLowerCase() !== this.mac) fail('Physical chip MAC changed. Write stopped.'); }
  recordPlan(plan) {
    if(plan.segments)plan.segments=Object.freeze(plan.segments.map(segment=>Object.freeze({...segment})));
    plan.addresses=Object.freeze([...plan.addresses]); this.plan=plan;
    this.#planProof=this.planProof(plan); this.#written=false; return plan;
  }
  async recordCompatiblePlan(pkg,plan,recovery=null) {
    plan={...plan,...await assessEspCompatibility(this.loader,pkg,plan)};
    if(recovery){
      validateEspWriteRecovery(recovery);
      if(this.connectMode!=='no_reset')fail('Interrupted ESP writes require explicitly reselecting the same chip in already-in-ROM / no-reset mode.');
      if(recovery.stage==='bridge'&&plan.verified&&recovery.mac===plan.mac&&recovery.sha256===pkg.sha256&&recovery.payloadHash===pkg.payloadHash&&recovery.chipId===pkg.chipId&&recovery.flashBytes===this.flashBytes&&recovery.bridgeHash===plan.completed_bridge_sha256&&recovery.partitionHash===plan.completed_source_table_sha256&&JSON.stringify(recovery.segments)===JSON.stringify(plan.completed_bridge_segments)){plan.recoveryResolved=true;}
      else {this.#writeRecovery=bindWriteRecovery(recovery,writeProgram(pkg,plan,this.flashBytes));plan.chunkedRecovery=true;plan.recoveryAttempts=this.#writeRecovery.attempts;}
    }
    return this.recordPlan(plan);
  }
  planProof(plan) { return hash(new TextEncoder().encode(JSON.stringify([plan.sha256,plan.payloadHash,plan.mac,plan.addresses,plan.merged,plan.expert,!!plan.needed,!!plan.verified,plan.bridge_sha256,plan.segments,plan.revisionProof,plan.requiresRevisionOverride,plan.revisionOverrideToken,!!plan.chunkedRecovery]))); }
  async prepare(pkg, {planner,packageBytes,usbSetBytes,resume,expertOffset,recovery} = {}) {
    this.plan=null; this.#planProof=null; this.#written=false;this.#writeRecovery=null;
    if (pkg.architecture !== 'esp32' || pkg.chipId !== this.loader.chip.IMAGE_CHIP_ID || hash(pkg.payload) !== pkg.payloadHash) fail('Firmware chip or immutable payload verification failed.');
    if (pkg.payload.length > this.flashBytes) fail('Image exceeds physical flash.');
    await this.assertMac();
    if(pkg.expert) {
      if(!Number.isInteger(expertOffset) || expertOffset<0 || expertOffset%4096 || expertOffset+Math.ceil(pkg.payload.length/4)*4>this.flashBytes) fail('Expert ESP image requires an explicit 4 KiB-aligned flash offset within physical flash.');
      return this.recordCompatiblePlan(pkg,{sha256:pkg.sha256,payloadHash:pkg.payloadHash,mac:this.mac,addresses:[expertOffset],merged:false,expert:true,parts:[]},recovery);
    }
    const parts = pkg.merged ? partitionTable(pkg.payload.subarray(0x8000,0x9000),this.flashBytes) : partitionTable(await this.loader.readFlash(0x8000,4096),this.flashBytes);
    let addresses;
    if (pkg.merged) {
      const proposed = partitionTable(pkg.payload.subarray(0x8000,0x9000),this.flashBytes);
      const populated=new Set();
      for (const p of proposed.filter(p => p.type === 0 && p.offset < pkg.payload.length)) {
        const image=pkg.payload.subarray(p.offset,Math.min(p.offset+p.size,pkg.payload.length));
        if (image.every(b=>b===255)) continue; // An erased inactive slot is allowed.
        const length = validateEspImage(image);
        if (length > p.size || (image[12]|image[13]<<8)!==pkg.chipId || image.length<36 || new DataView(image.buffer,image.byteOffset,image.byteLength).getUint32(32,true)!==0xabcd5432) fail('Merged application exceeds its partition or has the wrong chip/application identity.');
        populated.add(p.offset);
      }
      const ota=proposed.filter(p=>p.type===1 && p.subtype===0);
      let bootable=proposed.find(p=>p.type===0 && p.subtype===0)?.offset;
      if(proposed.some(part=>part.type===0&&part.subtype>=0x10&&part.subtype<=0x1f)) {
        if(ota.length!==1 || ota[0].size<8192) fail('Merged OTA metadata is ambiguous.');
        const metadata=new Uint8Array(8192).fill(255),source=pkg.payload.subarray(ota[0].offset,Math.min(ota[0].offset+8192,pkg.payload.length)); metadata.set(source);
        bootable=activeOta(proposed,metadata);
      }
      if(bootable===undefined || !populated.has(bootable)) fail('Merged install does not contain a valid application in its boot-selected partition.');
      const mirrors=mergedMirrorSegments(pkg,proposed,populated),segments=[{address:0,sourceOffset:0,length:pkg.payload.length,payloadHash:pkg.payloadHash},...mirrors];
      return this.recordCompatiblePlan(pkg,{sha256:pkg.sha256,payloadHash:pkg.payloadHash,mac:this.mac,addresses:segments.map(segment=>segment.address),merged:true,parts,segments,mirroredSlots:mirrors.length},recovery);
    } else {
      // The shared expansion helper reviews ESP32/C3/S3 only. Other supported
      // chips may update fitting slots, never run an unreviewed migration.
      if (planner && [0,5,9].includes(pkg.chipId)) {
        const nvs=parts.filter(p=>p.type===1 && p.subtype===2),ota=parts.filter(p=>p.type===1 && p.subtype===0);
        if(nvs.length>1 || ota.length>1 || nvs.some(part=>part.size>(1<<20)) || ota.some(part=>part.size<8192)) fail('Ambiguous NVS/OTA layout. Browser migration cannot proceed.');
        if(resume&&(nvs.length!==1||ota.length!==1))fail('Migration completion requires its exact NVS and OTA snapshots.');
        const snapshots={table:await this.loader.readFlash(0x8000,4096),nvs:nvs.length?await this.loader.readFlash(nvs[0].offset,nvs[0].size):null,ota:ota.length?await this.loader.readFlash(ota[0].offset,8192):null,mac:this.mac};
        appWriteOrder(parts,snapshots.ota);
        // The exact native helper decides whether the unchanged source table
        // needs a bridge rewrite or the expanded target needs completion proof.
        // A UI pending marker alone must never force target-table verification.
        let result=await planner.call('plan',{...snapshots,name:pkg.name,image:pkg.payload,chip:this.loader.chip.CHIP_NAME,flashBytes:this.flashBytes,package:packageBytes,usbSet:usbSetBytes});
        if((result.needed&&result.resume===true)||(resume&&!result.needed))result=await planner.call('verify',{...snapshots,image:pkg.payload,sha256:pkg.sha256});
        this.planner=planner;
        return this.recordCompatiblePlan(pkg,{...result,sha256:pkg.sha256,payloadHash:pkg.payloadHash,mac:this.mac,addresses:result.app_offsets,merged:false,parts},recovery);
      }
      const apps = parts.filter(p => p.type === 0);
      if (apps.some(p => pkg.payload.length > p.size)) fail('Partition expansion is required, but no reviewed browser migration plan exists for this chip/layout. No write was performed.');
      const nvs = parts.filter(p => p.type === 1 && p.subtype === 2);
      if (nvs.length > 1 || nvs.some(part=>part.size > (1 << 20))) fail('Ambiguous NVS; migration completion cannot be verified.');
      if(nvs.length) {const state = await this.loader.readFlash(nvs[0].offset,nvs[0].size);if (text(state).includes('mesh-pt-migrate')) fail('NVS has partition migration records, and this chip/layout has no reviewed completion verifier.');}
      const ota = parts.filter(p => p.type === 1 && p.subtype === 0);
      if (ota.length > 1 || ota.some(part=>part.size<8192)) fail('Ambiguous OTA metadata layout.');
      addresses = appWriteOrder(parts,ota.length?await this.loader.readFlash(ota[0].offset,8192):null);
    }
    return this.recordCompatiblePlan(pkg,{ sha256: pkg.sha256, payloadHash: pkg.payloadHash, mac: this.mac, addresses, merged: pkg.merged, parts },recovery);
  }
  async recoverBridge(pkg,{planner}={}) {
    this.plan=null; this.#planProof=null; this.#written=false;
    if(this.connectMode!=='no_reset' || !planner || pkg.architecture!=='esp32' || pkg.merged || pkg.expert || pkg.chipId!==this.loader.chip.IMAGE_CHIP_ID || hash(pkg.payload)!==pkg.payloadHash || pkg.sha256!==pkg.payloadHash) fail('Bridge recovery requires a no-reset ROM connection, the unchanged original final application and its browser validator.');
    await this.assertMac();
    const result=await planner.call('resumeBridge',{mac:this.mac,sha256:pkg.sha256,image:pkg.payload});
    const normalizedMac=this.mac.replace(/:/g,'').toUpperCase();
    const bridge=Uint8Array.from(result.bridge || []),addresses=result.bridge_offsets;
    if(result.format!=='meshcore-usb-partition-expansion-v2' || result.needed!==true || result.started!==true || result.completed!==false || result.verified!==false || result.usb_safe!==true || result.device_mac!==normalizedMac || result.firmware_sha256!==pkg.sha256 || result.chip!==pkg.chipId || result.flash_bytes!==this.flashBytes || !/^[a-f0-9]{64}$/.test(result.source_table_sha256) || bridge.length!==result.bridge_bytes || !bridge.length || hash(bridge)!==result.bridge_sha256 || !Array.isArray(addresses) || !addresses.length || addresses.length>16 || new Set(addresses).size!==addresses.length) fail('Cached bridge plan is not an exact unfinished USB recovery plan for this chip.');
    const table=await this.loader.readFlash(0x8000,4096);
    if(hash(table)!==result.source_table_sha256) fail('Source partition table changed. Do not restart the old bridge; verify migration completion instead.');
    const parts=partitionTable(table,this.flashBytes);
    for(const address of addresses) {
      const slot=parts.find(part=>part.type===0 && part.offset===address);
      if(!Number.isInteger(address) || !slot || bridge.length>slot.size || address+Math.ceil(bridge.length/4)*4>this.flashBytes) fail('Cached bridge offset does not fit its original physical application slot.');
      await this.assertMac();
      if((await this.loader.flashMd5sum(address,bridge.length)).toLowerCase()!==md5hex(bridge)) fail('Not every original bridge slot matches the cached verified bridge. No reset was authorized.');
    }
    await this.assertMac();
    this.planner=planner;
    const plan=await this.recordCompatiblePlan(pkg,{...result,bridge:Array.from(bridge),sha256:pkg.sha256,payloadHash:pkg.payloadHash,mac:this.mac,addresses,merged:false,parts,written:true,recovered:true});
    this.#written=true; // Readback proved the bridge write; allow exactly one start.
    return plan;
  }
  async flash(pkg, progress, {allowRevisionMismatch=false,chunkedRecovery=false} = {}) {
    this.#written=false;
    const plan = this.plan;
    if (!plan || hash(pkg.payload) !== plan.payloadHash || pkg.sha256 !== plan.sha256) fail('Firmware changed after confirmation.');
    await this.assertMac();
    if(!this.#planProof || this.planProof(plan)!==this.#planProof || plan.mac!==this.mac || !plan.addresses.length) fail('Verified flash plan changed after inspection.');
    const compatibility=await assessEspCompatibility(this.loader,pkg,plan);
    if(plan.revisionProof && compatibility.revisionProof!==plan.revisionProof) fail('Silicon revision evidence changed after inspection. Inspect again before authorizing a write.');
    if(compatibility.requiresRevisionOverride && allowRevisionMismatch!==true) fail('ESP image silicon-revision compatibility is not satisfied. An explicit FORCE CHIP REVISION acknowledgement is required before erase or write.');
    if(plan.chunkedRecovery&&chunkedRecovery!==true)fail('Explicit RETRY IN CHUNKS acknowledgement is required for this interrupted write.');
    if(chunkedRecovery&&(!this.#writeRecovery||!plan.chunkedRecovery||this.connectMode!=='no_reset'))fail('Chunk recovery requires the original interrupted-write descriptor and a fresh verified no-reset session.');
    if(chunkedRecovery){await assertSecurity(this.loader);bindWriteRecovery(this.#writeRecovery,writeProgram(pkg,plan,this.flashBytes));}
    const bridge=plan.needed && !plan.verified;
    const payload=bridge?Uint8Array.from(plan.bridge):pkg.payload;
    const segments=plan.segments||plan.addresses.map(address=>({address,payloadHash:hash(payload),length:payload.length}));
    if(segments.some((segment,index)=>segment.address!==plan.addresses[index] || !Number.isInteger(segment.address) || segment.address<0 || segment.address%4096 || segment.address+Math.ceil(segment.length/4)*4>this.flashBytes)) fail('Write exceeds verified physical flash bounds.');
    if(bridge) { if(hash(payload)!==plan.bridge_sha256) fail('Verified bridge bytes changed.'); await this.planner.call('begin',{image:pkg.payload}); }
    let eraseComplete=!plan.merged||!!this.#writeRecovery?.eraseComplete;
    // Update fallback slots first, active slot last. Erase only on explicit merged install.
    try{for (let i = 0; i < plan.addresses.length; i++) {
      await this.assertMac();
      const segment=segments[i],address = plan.addresses[i],data=plan.segments?pkg.payload.subarray(segment.sourceOffset,segment.sourceOffset+segment.length):payload;
      if(data.length!==segment.length||hash(data)!==segment.payloadHash)fail('Write segment changed after inspection.');
      if(chunkedRecovery){
        // Every 16 KiB operation is independently sector-aligned and verified.
        // A disconnect stops here: only another explicit chooser/MAC-bound
        // session can retry; there is no hidden port choice, reset or eraseAll.
        for(let offset=0;offset<data.length;offset+=RECOVERY_CHUNK){
          await this.assertMac();const bytes=data.subarray(offset,Math.min(offset+RECOVERY_CHUNK,data.length)),at=address+offset;
          if((await this.loader.flashMd5sum(at,bytes.length)).toLowerCase()!==md5hex(bytes)){
            await this.loader.writeFlash({fileArray:[{data:bytes,address:at}],flashMode:'keep',flashFreq:'keep',flashSize:'keep',eraseAll:false,compress:true,calculateMD5Hash:md5hex,reportProgress:()=>{}});
            if((await this.loader.flashMd5sum(at,bytes.length)).toLowerCase()!==md5hex(bytes))fail('Chunk target MD5 readback differs. No reset was authorized.');
          }
          progress((i+(offset+bytes.length)/data.length)/plan.addresses.length,`Recovered + verified 0x${at.toString(16)}`);
        }
      }else{
        // In pinned esptool-js 0.7.0 the first progress callback occurs only
        // after eraseAll and flashDeflBegin have returned successfully.
        await this.loader.writeFlash({ fileArray: [{ data, address }], flashMode: 'keep', flashFreq: 'keep', flashSize: 'keep', eraseAll: plan.merged && i === 0, compress: true, calculateMD5Hash: md5hex, reportProgress: (_,written,total) => {if(plan.merged&&i===0)eraseComplete=true;progress((i + written / total) / plan.addresses.length, `Writing + verifying ${bridge?'USB bridge':i&&plan.merged?'fallback application':'application'} 0x${address.toString(16)}`);} });
        if(plan.merged&&i===0)eraseComplete=true;
      }
      if ((await this.loader.flashMd5sum(address,data.length)).toLowerCase() !== md5hex(data)) fail('Target MD5 readback differs from the validated bytes. No automatic reset.');
    }await this.assertMac();}catch(error){
      // Once explicitly in chunk recovery, every failed operation consumes
      // a round, including unfamiliar transport errors or rejected readback.
      if(chunkedRecovery||interruptedTransport(error))error.recovery={...writeProgram(pkg,plan,this.flashBytes),format:RECOVERY_FORMAT,eraseComplete,attempts:chunkedRecovery?this.#writeRecovery.attempts+1:0};
      throw error;
    }
    this.#written=true; progress(1,'Flash verified. Reset pending; application startup remains unverified.');
  }
  async finish(nativeUsb) {
    if(!this.#written || !this.#planProof || !this.plan || this.planProof(this.plan)!==this.#planProof) fail('Reset is permitted only once after a completely verified write.');
    this.#written=false; // An uncertain reset may already have taken effect.
    await this.assertMac();
    if (nativeUsb && [2,9].includes(this.loader.chip.IMAGE_CHIP_ID)) {
      // Native S2/S3 CDC has no external EN pin. Clear only forced download,
      // then arm the hardware RTC watchdog. Never retry an uncertain reset.
      const [force,protect,timeout,config]=this.loader.chip.IMAGE_CHIP_ID===9?[0x6000812c,0x600080b0,0x6000809c,0x60008098]:[0x3f408128,0x3f4080ac,0x3f408098,0x3f408094];
      await this.loader.writeReg(force,0,1);
      await this.loader.writeReg(protect,0x50d83aa1);
      await this.loader.writeReg(timeout,2000);
      await this.loader.writeReg(config,0xd0000102);
      await this.loader.writeReg(protect,0); await sleep(500);
    } else {
      // esptool-js 0.7.0 HardReset only releases RTS; explicitly pulse EN.
      // DTR remains released so the ESP boots its application rather than ROM.
      await this.port.setSignals({dataTerminalReady:false,requestToSend:true});
      await sleep(100);
      await this.port.setSignals({dataTerminalReady:false,requestToSend:false});
    }
  }
  async close({strict=false}={}) {
    if(typeof strict!=='boolean')fail('The strict-close option must be a boolean.');
    try{await this.transport.disconnect();}catch(error){if(strict)throw error;}
  }
}
