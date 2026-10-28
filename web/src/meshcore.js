// MeshCore USB companion protocol. No message-queue consumption or host helper.
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { fail, hash, words, text } from './firmware.js';
import { COMMON_CLI_COMMANDS, commonCliReplyState } from './common-cli.js';
import { captureRegions, validateRegions } from './regions.js';

const encode = value => new TextEncoder().encode(value);
const unhex = value => { if (typeof value !== 'string' || !/^(?:[a-f0-9]{2})*$/i.test(value)) fail('Invalid backup hex data.'); return hexToBytes(value); };
const canonical = value => value === null || typeof value !== 'object' ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonical).join(',')}]` : `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
const record = (value, code, lengths, label) => { const b = unhex(value); if (b[0] !== code || !lengths.includes(b.length)) fail(`Invalid ${label} record.`); return b; };
const integer = (value, min, max, label) => { if (!Number.isInteger(value) || value < min || value > max) fail(`Invalid ${label}.`); return value; };
const fixedText = (value, size, label) => { if (typeof value !== 'string' || /[\x00\r\n]/.test(value) || encode(value).length > size) fail(`Invalid ${label}.`); const b = new Uint8Array(size); b.set(encode(value)); return b; };
const signedByte = value => value < 128 ? value : value - 256;
function wireName(bytes, label) {
  const end=bytes.indexOf(0), value=bytes.subarray(0,end<0?bytes.length:end);
  try {return new TextDecoder('utf-8',{fatal:true}).decode(value);}catch{fail(`Invalid UTF-8 ${label}.`);}
}
function contactRecord(row) {
  const b=record(row,3,[148],'contact'),v=new DataView(b.buffer,b.byteOffset,b.byteLength),packed=b[35];
  // These are the native archive's semantic checks applied to the wire form.
  // Type/flags are uint8 and timestamps uint32 by construction; do not narrow
  // them to an undocumented enum or treat bit 31 as a negative timestamp.
  if(packed!==255&&(packed&63)*((packed>>6)+1)>64)fail('Invalid contact path geometry.');
  if(Math.abs(v.getInt32(136,true))>90000000||Math.abs(v.getInt32(140,true))>180000000)fail('Invalid contact coordinates.');
  // A flood path has no active bytes. Firmware may retain stale unused path
  // and name padding; only the advertised, NUL-terminated name is text.
  wireName(b.subarray(100,132),'contact advertised name');
  return b;
}
export const loggingState = reply => /\busb\.logging\s+(on|off)\b/i.exec(reply || '')?.[1].toLowerCase() ?? null;
export function bluetoothName(reply) {
  if (reply && typeof reply === 'object' && typeof reply.name === 'string' && typeof reply.default === 'boolean') { fixedText(reply.name,32,'Bluetooth name'); return {name:reply.name,default:reply.default}; }
  const m = /^>\s*(.*?)\s+\((default from node name|custom)\)\s*$/i.exec(reply || '');
  if (!m) fail('Unrecognized Bluetooth-name status.'); fixedText(m[1],32,'Bluetooth name'); return {name:m[1],default:m[2].toLowerCase() !== 'custom'};
}
function customVars(row) {
  const b = record(row,21,Array.from({length:513},(_,i)=>i+1),'custom-variable');
  const raw = text(b.subarray(1)), result = new Map();
  for (const pair of raw ? raw.split(',') : []) { const m = /^([^:,\x00\r\n]{1,64}):([^:,\x00\r\n]{0,128})$/.exec(pair); if (!m || result.has(m[1])) fail('Invalid custom-variable inventory.'); result.set(m[1],m[2]); }
  return result;
}
function cadStatus(reply) {
  const m = /\bradio\.cad\s+(on|off),\s*scan=(auto|\d+)(?:\(\d+\))?\s+ms,\s*retry=(auto|\d+)\s+ms,\s*max=(auto|\d+)\s+ms/i.exec(reply || '');
  if (!m) fail('Unrecognized radio CAD status.'); return m.slice(1).map(s=>s.toLowerCase());
}
const unsupportedCliReply = reply => /\b(?:unknown command|unsupported|not supported)\b/i.test(reply || '');
function rejectedCommand(command, frame) {
  const error=new Error(`MeshCore rejected command ${command} (${frame[1] ?? 'disabled'}).`);
  error.meshcoreCommand=command;error.meshcoreResponseCode=frame[0];error.meshcoreErrorCode=frame[1];return error;
}
function validateCompanion(p) {
  const self = unhex(p.self), info = unhex(p.info), key = p.privateKey ? unhex(p.privateKey) : null;
  if (self.length < 59 || self.length > 90 || self[0] !== 5 || self[1] !== 1 || info.length < 80 || info.length > 128 || info[0] !== 13 || info[1] < 3 || p.publicKey !== bytesToHex(self.subarray(4,36))) fail('Invalid companion identity records.');
  if((info[1]>=9 && (info.length<81 || info[80]>1)) || (info[1]>=10 && (info.length<82 || info[81]>3)))fail('Truncated or invalid versioned device settings.');
  let name;try{name=new TextDecoder('utf-8',{fatal:true}).decode(self.subarray(58));}catch{fail('Invalid UTF-8 node name.');}fixedText(name,32,'node name');
  const v = new DataView(self.buffer,self.byteOffset,self.byteLength), lat=v.getInt32(36,true)/1e6,lon=v.getInt32(40,true)/1e6,freq=v.getUint32(48,true)/1000,bw=v.getUint32(52,true)/1000;
  if (Math.abs(lat)>90 || Math.abs(lon)>180 || freq<100 || freq>3000 || bw<1 || bw>1000 || self[56]<5 || self[56]>12 || self[57]<5 || self[57]>8 || self[44]>3 || self[45]>3 || self[46]>63 || self[47]>1) fail('Invalid companion settings.');
  const pin=new DataView(info.buffer,info.byteOffset,info.byteLength).getUint32(4,true); if (pin !== 0 && (pin<100000 || pin>999999)) fail('Invalid BLE PIN.');
  if (key && (key.length !== 65 || key[0] !== 14 || publicFromPrivate(key.subarray(1)) !== p.publicKey)) fail('Private/public identity verification failed.');
  if (!Array.isArray(p.channels) || p.channels.length !== info[3] || !Array.isArray(p.contacts) || p.contacts.length > info[2]*2 || !p.options || typeof p.options !== 'object' || !p.cli || typeof p.cli !== 'object') fail('Incomplete or invalid backup inventories.');
  p.channels.forEach((row,index) => { const b = record(row,18,[50],'channel'); if (b[1] !== index) fail('Channel inventory invalid.');wireName(b.subarray(2,34),'channel name'); });
  const keys=new Set(); p.contacts.forEach(row => { const b=contactRecord(row),id=bytesToHex(b.subarray(1,33));if(keys.has(id))fail('Duplicate contact.');keys.add(id); });
  for (const [name,code,lengths] of [['autoadd',25,[2,3]],['tuning',23,[9]],['scope',28,[1,48]]]) if (typeof p.options[name] === 'string') record(p.options[name],code,lengths,name);
  if(typeof p.options.autoadd==='string'){const b=unhex(p.options.autoadd);if(b.length===3&&b[2]>64)fail('Invalid auto-add maximum hops.');}
  if (typeof p.options.custom === 'string') customVars(p.options.custom);
  if (typeof p.options.scope === 'string') { const b=unhex(p.options.scope); if(b.length===48) { const name=text(b.subarray(1,32)).split('\0')[0]; if(name ? !name.startsWith('#') || encode(name).length>30 || hash(encode(name)).slice(0,32)!==bytesToHex(b.subarray(32)) : b.subarray(32).some(x=>x!==0)) fail('Scope name/key mismatch.'); } }
  for (const [command,value] of Object.entries(p.cli)) if (typeof value !== 'string' && value !== null && !(command==='get bluetooth.name' && typeof value==='object')) fail('Invalid CLI snapshot.'); else if(typeof value==='string' && value.length>8192) fail('Oversize CLI snapshot.');
  if (p.cli['get bluetooth.name']) bluetoothName(p.cli['get bluetooth.name']);
  if (p.cli['get radio.cad'] && /\bradio\.cad\s+(?:on|off),/i.test(p.cli['get radio.cad'])) cadStatus(p.cli['get radio.cad']);
  if(p.batteryAndStorage && !p.batteryAndStorage.unavailable){const b=p.batteryAndStorage;if(!Number.isInteger(b.level)||b.level<0||b.level>65535||('used_kb'in b&&(!Number.isInteger(b.used_kb)||!Number.isInteger(b.total_kb)||b.used_kb<0||b.used_kb>b.total_kb||b.total_kb>0xffffffff)))fail('Invalid battery/storage diagnostic.');}
  return p;
}
export function publicFromPrivate(key) {
  if (key.length !== 64) fail('MeshCore private identity must be 64 bytes.');
  let scalar = 0n; for (let i = 31; i >= 0; i--) scalar = scalar * 256n + BigInt(key[i]);
  scalar %= ed25519.CURVE.n; if (!scalar) fail('Invalid zero identity.');
  return bytesToHex(ed25519.ExtendedPoint.BASE.multiply(scalar).toRawBytes());
}
export function sealBackup(payload) {
  const archive = { schema: 'org.meshfirmware.web-backup/v1', createdUtc: new Date().toISOString(), payload };
  return { ...archive, sha256: hash(encode(canonical(archive))) };
}
export function verifyBackup(archive) {
  if (archive?.schema !== 'org.meshfirmware.web-backup/v1') fail('Import native archives through parseBackup so their exact Python integrity is checked.');
  const {sha256,...covered} = archive;
  if (hash(encode(canonical(covered))) !== sha256) fail('Backup SHA-256 mismatch.');
  const p = archive.payload;
  if (!p || !['companion','common-cli'].includes(p.role) || p.safeForWipe !== false) fail('Invalid backup metadata.');
  if (p.role === 'companion') {
    validateCompanion(p);
  } else {
    if(typeof p.publicKey!=='string'||!/^[a-f0-9]{64}$/i.test(p.publicKey)||!p.replies||typeof p.replies!=='object'||Array.isArray(p.replies))fail('Invalid CommonCLI identity or settings.');
    if(Object.keys(p.replies).length>128||Object.entries(p.replies).some(([command,value])=>command.length>80||/[\x00-\x1f\x7f]/.test(command)||typeof value!=='string'||value.length>8192))fail('Invalid CommonCLI reply snapshot.');
    const privateHex=/(?<![a-f0-9])[a-f0-9]{128}(?![a-f0-9])/i.exec(p.replies['get prv.key']||'')?.[0];
    if(privateHex&&publicFromPrivate(unhex(privateHex))!==p.publicKey.toLowerCase())fail('CommonCLI private/public identity mismatch.');
    if(p.regions!==undefined){
      const regions=p.regions;
      if(!regions||typeof regions!=='object'||Array.isArray(regions)||!['complete','unsupported','error'].includes(regions.state)||regions.reason!==undefined&&(typeof regions.reason!=='string'||regions.reason.length>512))fail('Invalid region capture record.');
      if(regions.state==='complete')validateRegions(regions.data);
      else if(regions.data!==undefined)fail('Incomplete region capture cannot contain a restorable snapshot.');
    }
  }
  return p;
}

// Preserve Python's original numeric spelling for its canonical digest by
// passing the ORIGINAL JSON text to the exact validator running in WebAssembly.
export async function parseBackup(raw, { validatePython } = {}) {
  if (typeof raw !== 'string' || encode(raw).length > (16 << 20)) fail('Backup exceeds the 16 MiB limit.');
  const archive=JSON.parse(raw);
  if (archive?.schema === 'org.meshfirmware.web-backup/v1') { verifyBackup(archive); return archive; }
  if (archive?.schema !== 'org.meshfirmware.meshcore-backup/v1' || typeof validatePython !== 'function') fail('This backup needs the exact MeshCore archive validator.');
  const privateHex=archive.payload?.sections?.identity_private_key?.data?.private_key, expectedPub=archive.payload?.source?.node?.public_key?.toLowerCase();
  if(privateHex && publicFromPrivate(unhex(privateHex))!==expectedPub) fail('Private/public identity verification failed.');
  const result=await validatePython({text:raw,privateHex,expectedPub});
  return convertPythonBackup(result.payload);
}

function convertPythonBackup(payload) {
  if(payload?.source?.capture_api==='meshcore-cli-common-cli') {
    const sections=payload.sections||{},allowed=new Set(['get public.key',...COMMON_CLI_COMMANDS]),replies={};
    const replyText=value=>{
      const raw=typeof value==='string'?value:value&&typeof value==='object'?(typeof value.text==='string'?value.text:typeof value.raw==='string'?value.raw:null):null;
      return value&&typeof value==='object'&&value.ok===false&&raw!==null&&commonCliReplyState(raw).state==='complete'?'Error: native setting query did not succeed':raw;
    };
    const settings=sections.settings?.data;
    if(settings&&typeof settings==='object'&&!Array.isArray(settings))for(const [command,value]of Object.entries(settings)){
      if(!allowed.has(command))continue;const raw=replyText(value),status=sections.settings.query_states?.[command]?.state;
      if(raw!==null)replies[command]=status==='error'?'Error: backup query was not successful':status==='unsupported'?'Unsupported: backup query was not exposed':raw;
    }
    const publicKey=payload.source.node.public_key.toLowerCase();replies['get public.key']=`> ${publicKey}`;
    delete replies['get prv.key'];
    if(sections.identity_private_key?.state==='complete')replies['get prv.key']=`> ${sections.identity_private_key.data.private_key.toLowerCase()}`;
    for(const [name,command]of [['acl','get acl'],['regions','region']])if(sections[name]){
      const raw=replyText(sections[name].data);if(sections[name].state==='complete'&&raw!==null)replies[command]=raw;else replies[command]=sections[name].state==='unsupported'?'Unsupported: backup section was not exposed':'Error: backup section is not complete';
      // A bounded legacy region reply is useful diagnostic text, but cannot
      // imply a complete tree/default snapshot or authorize region setters.
      if(name==='regions'&&raw!==null)replies[command]=raw;
    }
    let regions;
    if(sections.regions?.data&&Object.hasOwn(sections.regions.data,'snapshot')){
      const snapshot=validateRegions(sections.regions.data.snapshot);
      if(sections.regions.state!=='complete')fail('A restorable region snapshot must have a complete capture state.');
      regions={state:'complete',data:snapshot};
    }else if(sections.regions){
      regions={state:sections.regions.state==='error'?'error':'unsupported',reason:typeof sections.regions.reason==='string'?sections.regions.reason:'This archive contains no complete typed region snapshot; create a new backup to capture its tree, flood flags, home and default.'};
    }
    for(const [name,command]of [['bluetooth_name','get bluetooth.name'],['usb_logging','get usb.logging'],['radio_cad','get radio.cad'],['radio_rxps','get radio.rxps.config'],['radio_rxgain','get radio.rxgain'],['radio_fem_rxgain','get radio.fem.rxgain'],['radio_fem_txgain','get radio.fem.txgain'],['display_rotation','get display.rotation'],['power_saving','get powersaving'],['storage_layout','get storage.layout'],['radio2','get radio2'],['radio2_cross','get radio2.cross'],['bluetooth_status','get bluetooth']])if(sections[name]){
      if(sections[name].state!=='complete'){replies[command]=sections[name].state==='unsupported'?'Unsupported: backup section was not exposed':'Error: backup section is not complete';continue;}
      const data=sections[name].data,raw=replyText(data);if(raw!==null)replies[command]=raw;
      else if(name==='bluetooth_name'&&typeof data?.name==='string'&&typeof data?.default==='boolean')replies[command]=`> ${data.name} (${data.default?'default from node name':'custom'})`;
    }
    const result=sealBackup({role:'common-cli',publicKey,safeForWipe:false,replies,...(regions?{regions}:{}),excluded:['CommonCLI captures are partial','Unread messages, logs and unexposed preferences are not exported'],nativeCompleteness:JSON.parse(JSON.stringify(payload.completeness)),nativeSource:{role:payload.source.node.role,deviceHint:payload.source.node.device_hint||payload.source.physical_usb_identity?.device_hint||null}});
    verifyBackup(result);return result;
  }
  if(payload?.source?.node?.role!=='companion') fail('Only companion or partial CommonCLI archives are supported.');
  const sections=payload.sections;
  for(const name of ['self_info','identity_private_key','device_info','channels','contacts']) if(sections?.[name]?.state!=='complete') fail(`Required backup section incomplete: ${name}.`);
  const s=sections.self_info.data,d=sections.device_info.data, self=new Uint8Array(58+encode(s.name).length), v=new DataView(self.buffer),info=new Uint8Array(82),iv=new DataView(info.buffer);
  self.set([5,s.adv_type,s.tx_power,s.max_tx_power]); self.set(unhex(s.public_key),4);v.setInt32(36,Math.round(s.adv_lat*1e6),true);v.setInt32(40,Math.round(s.adv_lon*1e6),true);self.set([s.multi_acks,s.adv_loc_policy,(s.telemetry_mode_env<<4)|(s.telemetry_mode_loc<<2)|s.telemetry_mode_base,+s.manual_add_contacts],44);v.setUint32(48,Math.round(s.radio_freq*1000),true);v.setUint32(52,Math.round(s.radio_bw*1000),true);self.set([s.radio_sf,s.radio_cr],56);self.set(encode(s.name),58);
  info.set([13,d['fw ver'],Math.floor(d.max_contacts/2),d.max_channels]);iv.setUint32(4,d.ble_pin,true);info.set(fixedText(d.fw_build,12,'build'),8);info.set(fixedText(d.model,40,'model'),20);info.set(fixedText(d.ver.slice(0,20),20,'version'),60);info[80]=+d.repeat;info[81]=d.path_hash_mode||0;
  const p={role:'companion',publicKey:payload.source.node.public_key.toLowerCase(),self:bytesToHex(self),info:bytesToHex(info),privateKey:'0e'+sections.identity_private_key.data.private_key.toLowerCase(),safeForWipe:false,channels:[],contacts:[],options:{},cli:{},excluded:['Firmware/bootloader','Unread messages','Optional unsupported settings']};
  for(const row of sections.channels.data) { const b=new Uint8Array(50);b.set([18,integer(row.channel_idx,0,254,'channel index')]);b.set(fixedText(row.channel_name,32,'channel name'),2);b.set(unhex(row.channel_secret),34);p.channels.push(bytesToHex(b)); }
  for(const row of Object.values(sections.contacts.data)) { const b=new Uint8Array(148),cv=new DataView(b.buffer);b[0]=3;b.set(unhex(row.public_key),1);b.set([row.type,row.flags,row.out_path_len===-1?255:(row.out_path_hash_mode<<6)|row.out_path_len],33); const path=unhex(row.out_path);if(path.length>64)fail('Contact path exceeds the wire format.');b.set(path,36);b.set(fixedText(row.adv_name,32,'contact name'),100);cv.setUint32(132,integer(row.last_advert,0,0xffffffff,'contact timestamp'),true);cv.setInt32(136,Math.round(row.adv_lat*1e6),true);cv.setInt32(140,Math.round(row.adv_lon*1e6),true);cv.setUint32(144,integer(row.lastmod,0,0xffffffff,'contact timestamp'),true);p.contacts.push(bytesToHex(b)); }
  const optional=(name)=>sections[name]?.state==='complete'?sections[name].data:null;
  let value=optional('autoadd');if(value)p.options.autoadd=bytesToHex(Uint8Array.from([25,value.config,...(Number.isInteger(value.max_hops)?[integer(value.max_hops,0,64,'auto-add maximum hops')]:[])]));
  value=optional('tuning');if(value)p.options.tuning=bytesToHex(Uint8Array.from([23,...words(value.rx_delay,value.airtime_factor)]));
  value=optional('custom_vars');if(value)p.options.custom=bytesToHex(Uint8Array.from([21,...encode(Object.entries(value).map(([k,v])=>`${k}:${v}`).join(','))]));
  value=optional('default_flood_scope');if(value) { const b=new Uint8Array(value.scope_name?48:1);b[0]=28;if(b.length>1){b.set(fixedText(value.scope_name,31,'scope name'),1);b.set(unhex(value.scope_key),32);}p.options.scope=bytesToHex(b); }
  for(const [name,command] of [['bluetooth_name','get bluetooth.name'],['usb_logging','get usb.logging'],['radio_cad','get radio.cad'],['radio_rxps','get radio.rxps.config'],['radio_rxgain','get radio.rxgain'],['radio_fem_rxgain','get radio.fem.rxgain'],['radio_fem_txgain','get radio.fem.txgain'],['display_rotation','get display.rotation'],['power_saving','get powersaving'],['storage_layout','get storage.layout']]) { value=optional(name);if(value)p.cli[command]=name==='bluetooth_name' && 'name' in value?value:value.text; }
  value=optional('battery_and_storage');if(value)p.batteryAndStorage=value;
  const result=sealBackup(p);verifyBackup(result);return result;
}

export class MeshCore {
  constructor(link, {timeoutMs=7000}={}) { this.link = link; this.bytes = []; this.busy = false; this.timeoutMs=timeoutMs; }
  async frame(ms = 6000) {
    const until = Date.now() + ms;
    while (Date.now() < until) {
      while (this.bytes.length >= 3) {
        if (this.bytes[0] !== 0x3e) { this.bytes.shift(); continue; }
        const n = this.bytes[1] | this.bytes[2] << 8;
        if (!n || n > 8192) fail('Invalid MeshCore frame size.');
        if (this.bytes.length < n + 3) break;
        return Uint8Array.from(this.bytes.splice(0,n + 3).slice(3));
      }
      const chunk=await this.link.read(100);if(this.bytes.length+chunk.length>16384)fail('MeshCore framing limit exceeded. Check USB logging/text mode.');this.bytes.push(...chunk);
    }
    fail('No MeshCore companion response. Device may be in DFU/ROM, text mode, or using another port.');
  }
  async send(command) { if (command.length > 8192) fail('Command limit exceeded.'); await this.link.write(Uint8Array.from([0x3c,command.length & 255,command.length >> 8,...command])); }
  async request(command, code) {
    if (this.busy) fail('Another MeshCore command is active.'); this.busy = true;
    try { await this.send(command); const until = Date.now() + this.timeoutMs; while (Date.now() < until) { const frame = await this.frame(Math.max(1,until - Date.now())); if ([1,15].includes(frame[0])) throw rejectedCommand(command[0],frame); if (frame[0] === code) return frame; } fail('MeshCore command timed out.'); }
    finally { this.busy = false; }
  }
  async self() { const result = await this.request([1,3,32,32,32,32,32,32,...encode('meshfirmware-web')],5); if (result.length < 58) fail('Truncated SELF_INFO.'); return result; }
  async info() { const result = await this.request([22,3],13); if (result.length < 80 || result[1] < 3) fail('Unsupported DEVICE_INFO.'); return result; }
  async cli(command) { if (/[\r\n\x00]/.test(command)) fail('CLI commands must be a single line.'); return text((await this.request([66,...encode(command)],29)).subarray(1)); }
  async contacts() {
    if(this.busy)fail('Another MeshCore command is active.');this.busy=true;
    try {
      await this.send([4]);let first;const startUntil=Date.now()+this.timeoutMs;
      while(Date.now()<startUntil){
        const frame=await this.frame(Math.max(1,startUntil-Date.now()));
        if([1,15].includes(frame[0]))throw rejectedCommand(4,frame);
        if(frame[0]>=0x80)continue; // Asynchronous adverts/message-waiting/etc.
        if(frame[0]!==2||frame.length!==5)fail('Contact inventory did not start.');first=frame;break;
      }
      if(!first)fail('Contact inventory start timed out.');
      const count=new DataView(first.buffer,first.byteOffset,first.byteLength).getUint32(1,true);if(count>510)fail('Contact inventory limit exceeded.');
      const rows=[],keys=new Set(),until=Date.now()+30000;
      while(Date.now()<until){
        const row=await this.frame(Math.min(3000,Math.max(1,until-Date.now())));
        if([1,15].includes(row[0]))throw rejectedCommand(4,row);
        if(row[0]>=0x80)continue;
        if(row[0]===4){if(row.length!==5||rows.length!==count)fail('Incomplete contact inventory.');return rows;}
        if(row[0]!==3||row.length!==148||rows.length>=count)fail('Unexpected contact record.');
        const key=bytesToHex(row.subarray(1,33));if(keys.has(key))fail('Duplicate contact.');keys.add(key);rows.push(row);
      }
      fail('Contact inventory timed out.');
    } finally {this.busy=false;}
  }
  async backup(progress = () => {}) {
    const self = await this.self(); if (self[1] !== 1) fail('This framed API is not a companion. Choose CommonCLI capture.');
    const info = await this.info(), publicKey = bytesToHex(self.subarray(4,36));
    const p = { role: 'companion', publicKey, self: bytesToHex(self), info: bytesToHex(info), channels: [], contacts: [], options: {}, cli: {}, safeForWipe: false, excluded: ['Unread messages (not consumed)', 'Firmware/bootloader', 'Unexposed or unsupported preferences'] };
    try { const key = await this.request([23],14); if (key.length !== 65 || publicFromPrivate(key.subarray(1)) !== publicKey) fail('Exported identity is inconsistent.'); p.privateKey = bytesToHex(key); } catch (error) { p.identityWarning = error.message; }
    p.contacts = (await this.contacts()).map(bytesToHex);
    for (let i = 0; i < info[3]; i++) { const row = await this.request([31,i],18); if (row.length !== 50 || row[1] !== i) fail('Channel response mismatch.'); p.channels.push(bytesToHex(row)); progress(i / info[3],`Reading channel ${i + 1}/${info[3]}`); }
    for (const [name,command,response] of [['autoadd',59,25],['tuning',43,23],['custom',40,21],['scope',64,28]]) {
      try { p.options[name] = bytesToHex(await this.request([command],response)); } catch (error) { p.options[name] = { unavailable: error.message }; }
    }
    try { const battery=await this.request([20],12); if(![3,11].includes(battery.length))fail('Invalid battery/storage response.');const view=new DataView(battery.buffer,battery.byteOffset,battery.byteLength);p.batteryAndStorage={level:view.getUint16(1,true)};if(battery.length===11){p.batteryAndStorage.used_kb=view.getUint32(3,true);p.batteryAndStorage.total_kb=view.getUint32(7,true);if(p.batteryAndStorage.used_kb>p.batteryAndStorage.total_kb)fail('Storage counters are internally inconsistent.');}}catch(error){p.batteryAndStorage={unavailable:error.message};}
    for (const command of ['version','get bluetooth.name','get usb.logging','get bluetooth','get radio.cad','get radio.rxgain','get radio.fem.rxgain','get radio.fem.txgain','get display.rotation','get powersaving','get radio.rxps.config','get radio2','get radio2.cross','get storage.layout']) {
      try { p.cli[command] = await this.cli(command); } catch { p.cli[command] = null; }
    }
    if (bytesToHex((await this.self()).subarray(4,36)) !== publicKey) fail('Identity changed during backup.');
    if(p.cli['get bluetooth.name']) { try { p.cli['get bluetooth.name']=bluetoothName(p.cli['get bluetooth.name']); } catch { p.cli['get bluetooth.name']=null; } }
    progress(1,'Logical backup captured; not a complete flash image.'); const archive=sealBackup(p);verifyBackup(archive);return archive;
  }
  async restore(archive, { newHardware = false, replaceIdentity = false } = {}, progress = () => {}) {
    const p = verifyBackup(archive); if (p.role !== 'companion') fail('CommonCLI captures are partial and cannot be automatically restored.');
    const live = await this.self(), info = await this.info(), source = unhex(p.info), saved = unhex(p.self);
    if (live[1] !== 1 || (!newHardware && text(info.subarray(20,60)) !== text(source.subarray(20,60)))) fail('Different hardware: explicitly enable migration to a new board.');
    if (info[2] * 2 < p.contacts.length || p.channels.slice(info[3]).some(row => unhex(row)[2] !== 0)) fail('Target cannot hold all populated contacts/channels.');
    // SELF_INFO exposes the raw uint8 wire representation, while the firmware
    // interprets CMD_SET_RADIO_TX_POWER as int8 (-9..MAX_LORA_TX_POWER).
    // Preserve that raw byte for the write/readback and native JSON export.
    const desiredTx=signedByte(saved[2]),maximumTx=signedByte(live[3]);
    if(desiredTx < -9 || maximumTx < -9 || desiredTx>maximumTx) fail('Saved TX power is outside this hardware range (-9 dBm to its reported maximum).');
    // Capacity includes contacts already present: do not discover a full table
    // only after writing an identity or some channels.
    const existing=await this.contacts(), union=new Set([...existing.map(row=>bytesToHex(row.subarray(1,33))),...p.contacts.map(row=>row.slice(2,66))]);
    if(union.size>info[2]*2) fail('Existing plus restored contacts exceed target capacity. Nothing was written.');
    const vars=typeof p.options.custom==='string'?customVars(p.options.custom):new Map();
    if(vars.size) { const target=customVars(bytesToHex(await this.request([40],21)));if([...vars.keys()].some(key=>!target.has(key))) fail('This hardware does not expose all saved custom variables. Nothing was written.'); }
    const sameIdentity=bytesToHex(live.subarray(4,36))===p.publicKey;
    if(!sameIdentity&&(!replaceIdentity||!p.privateKey))fail('Identity differs. Explicit replacement and a verified private-key backup are required. Nothing was written.');
    const result={warnings:[],optional:{usbLogging:{state:'not-requested'},bluetooth:{state:'not-requested'},bluetoothName:{state:'not-in-backup'},radioCad:{state:'not-in-backup'}}};
    let cliAvailable=info[1]>=14;
    const optionalCli=async(command,label,key)=>{
      let reason;
      if(!cliAvailable)reason='This companion protocol does not expose the optional CLI API.';
      else try {
        const reply=await this.cli(command);
        if(unsupportedCliReply(reply))reason='The target does not expose this optional command.';
        else return {supported:true,reply};
      }catch(error){
        // Code 1 is UNSUPPORTED_CMD, not a timeout/I/O/bad-state error. Only
        // this explicit protocol result can establish that CLI is absent.
        if(error.meshcoreCommand===66&&error.meshcoreResponseCode===1&&error.meshcoreErrorCode===1){cliAvailable=false;reason='The target explicitly reports that the optional CLI API is unsupported.';}
        else throw error;
      }
      result.optional[key]={state:'unsupported',reason};result.warnings.push(`${label} was not restored: ${reason}`);return {supported:false};
    };
    // Default is off when an older archive has no USB-logging preference.
    // Do not enable logging merely because a Full Companion was in text mode.
    const desiredLogging=loggingState(p.cli['get usb.logging']) || 'off';
    const loggingProbe=await optionalCli('get usb.logging','USB logging','usbLogging'),loggingSupported=loggingProbe.supported;
    if(loggingSupported){
      const priorLogging=loggingState(loggingProbe.reply);
      if(priorLogging===null)fail('USB logging status could not be verified. No restore settings were written.');
      if(priorLogging==='on') { const reply=await this.cli('set usb.logging off');if(!/OK - USB logging off \(saved\)/i.test(reply)||/reboot required/i.test(reply))fail('Cannot safely disable USB logging for restore.'); }
      if(loggingState(await this.cli('get usb.logging'))!=='off')fail('USB logging did not verify off before restore.');
    }
    const bluetoothProbe=await optionalCli('get bluetooth','Bluetooth resync','bluetooth'),bleState=bluetoothProbe.supported?/\bbluetooth\s+(on|off)\b/i.exec(bluetoothProbe.reply)?.[1].toLowerCase():null;
    if(bluetoothProbe.supported&&!bleState)fail('Bluetooth state could not be verified. No restore settings were written.');
    const nameProbe=p.cli['get bluetooth.name']?await optionalCli('get bluetooth.name','Bluetooth name','bluetoothName'):null;
    if(nameProbe?.supported)bluetoothName(nameProbe.reply);
    const cadProbe=p.cli['get radio.cad']&&/\bradio\.cad\s+(?:on|off),/i.test(p.cli['get radio.cad'])?await optionalCli('get radio.cad','Radio CAD','radioCad'):null;
    if(cadProbe?.supported)cadStatus(cadProbe.reply);
    if (!sameIdentity) {
      await this.request([24,...unhex(p.privateKey).subarray(1)],0);
      if (bytesToHex((await this.self()).subarray(4,36)) !== p.publicKey) fail('Restored identity did not verify.');
    }
    for (const [i,row] of p.channels.slice(0,info[3]).entries()) {
      const channel = unhex(row); await this.request([32,...channel.subarray(1)],0);
      if (bytesToHex(await this.request([31,i],18)) !== row) fail(`Channel ${i} verification failed.`);
      progress(i / Math.max(1,p.channels.length) * .4,`Restoring channel ${i + 1}`);
    }
    for (const [i,row] of p.contacts.entries()) { await this.request([9,...unhex(row).subarray(1,144)],0); progress(.4 + i / Math.max(1,p.contacts.length) * .3,'Restoring contacts'); }
    const currentContacts = new Map((await this.contacts()).map(row => [bytesToHex(row.subarray(1,33)),bytesToHex(row.subarray(0,144))]));
    if (p.contacts.some(row => currentContacts.get(row.slice(2,66)) !== row.slice(0,288))) fail('Contact readback failed.');
    await this.request([8,...saved.subarray(58)],0);
    await this.request([14,...saved.subarray(36,44),...words(0)],0);
    await this.request([12,saved[2]],0);
    await this.request([11,...saved.subarray(48,58)],0);
    await this.request([38,saved[47],saved[46],saved[45],saved[44]],0);
    await this.request([37,...source.subarray(4,8)],0);
    if(bytesToHex((await this.info()).subarray(4,8))!==bytesToHex(source.subarray(4,8))) fail('BLE PIN readback failed.');
    for (const [name,command,response] of [['autoadd',58,25],['tuning',21,23]]) if (typeof p.options[name] === 'string') {
      const record = unhex(p.options[name]); if (record[0] !== response || (name === 'tuning' ? record.length !== 9 : ![2,3].includes(record.length))) fail('Invalid optional settings record.');
      await this.request([command,...record.subarray(1)],0);
      if (bytesToHex(await this.request([name === 'tuning' ? 43 : 59],response)) !== p.options[name]) fail(`${name} readback failed.`);
    }
    for(const [key,value] of vars) await this.request([41,...encode(`${key}:${value}`)],0);
    if(vars.size) { const refreshed=customVars(bytesToHex(await this.request([40],21)));if([...vars].some(([key,value])=>refreshed.get(key)!==value))fail('Custom-variable readback failed.'); }
    if(typeof p.options.scope==='string') {
      const scope=unhex(p.options.scope), value=scope.length===1?new Uint8Array(0):scope.subarray(1);
      await this.request([63,...(value.some(x=>x!==0)?value:[])],0);const verified=await this.request([64],28);
      // Empty scope may be represented by the one-byte sentinel or zero fields.
      if(value.some(x=>x!==0)?bytesToHex(verified)!==p.options.scope:verified.subarray(1).some(x=>x!==0))fail('Default scope readback failed.');
    }
    if(nameProbe?.supported) { const desired=bluetoothName(p.cli['get bluetooth.name']), value=desired.default?'default':desired.name;const reply=await this.cli(`set bluetooth.name ${value}`);if(!/OK - Bluetooth name/i.test(reply))fail('Bluetooth name was rejected.');const actual=bluetoothName(await this.cli('get bluetooth.name'));if(actual.default!==desired.default||(!desired.default&&actual.name!==desired.name))fail('Bluetooth name readback failed.');result.optional.bluetoothName={state:'restored'}; }
    if(cadProbe?.supported) {
      const desired=cadStatus(p.cli['get radio.cad']);for(const command of [`set radio.cad timings ${desired.slice(1).join(' ')}`,`set radio.cad ${desired[0]}`]) if(/error|unknown|unsupported/i.test(await this.cli(command)))fail('Radio CAD setting rejected.');
      if(cadStatus(await this.cli('get radio.cad')).join('|')!==desired.join('|'))fail('Radio CAD readback failed.');
      result.optional.radioCad={state:'restored'};
    }
    const verified = await this.self();
    if (verified[2]!==saved[2]) fail('TX power readback failed.');
    if (bytesToHex(verified.subarray(4,58)) !== bytesToHex(saved.subarray(4,58)) || text(verified.subarray(58)) !== text(saved.subarray(58))) fail('Companion settings readback failed.');
    // Preserve off by default; cycle BLE only if it was enabled on this target.
    if (bleState==='on') { try { if(!/OK - Bluetooth off/i.test(await this.cli('set bluetooth off')))fail('Bluetooth off was not confirmed.'); } finally { if(!/OK - Bluetooth on/i.test(await this.cli('set bluetooth on')))fail('Bluetooth could not be re-enabled.'); }if(!/\bbluetooth\s+on\b/i.test(await this.cli('get bluetooth')))fail('Bluetooth did not verify on after resync.'); }
    if(bluetoothProbe.supported)result.optional.bluetooth={state:bleState==='on'?'resynced':'unchanged',value:bleState};
    if(loggingSupported){const current=loggingState(await this.cli('get usb.logging'));if(current===null)fail('USB logging status could not be verified after restore.');if(current!==desiredLogging) { if(!new RegExp(`OK - USB logging ${desiredLogging} \\(saved\\)`,'i').test(await this.cli(`set usb.logging ${desiredLogging}`)))fail('USB logging preference rejected.'); }if(loggingState(await this.cli('get usb.logging'))!==desiredLogging)fail('USB logging readback failed.');result.optional.usbLogging={state:'restored',value:desiredLogging};}
    progress(1,'Restored identity, channels, contacts, core settings, custom variables, scope and supported structured options. Other CLI snapshots remain for manual comparison.');
    return result;
  }
}

// Deliberate handoff for Full Companion text mode; callers must explicitly
// acknowledge the temporary logging change before setting allowLoggingChange.
export async function enterCompanionBinary(link,{allowLoggingChange=false}={}) {
  await link.command('+++MESHCORE-TERM-START',500);
  const state=loggingState(await link.command('get usb.logging',700));
  if(state===null)fail('This terminal did not report its USB logging state.');
  if(state==='on') {
    if(!allowLoggingChange)fail('USB logging is on. Explicit permission is required to disable it for binary access.');
    const reply=await link.command('set usb.logging off',700);
    if(!/OK - USB logging off \(saved\)/i.test(reply)||/reboot required/i.test(reply))fail('Logging could not be disabled without reboot.');
  }
  if(!/OK - Binary mode/i.test(await link.command('+++MESHCORE-TERM-STOP',700))){if(state==='on')await link.command('set usb.logging on',700).catch(()=>{});fail('Binary-mode handoff was not confirmed. Check the current mode and logging state before retrying.');}
  return {originalLogging:state};
}

export async function backupCommonCli(link, progress = () => {}) {
  const commands = COMMON_CLI_COMMANDS;
  const replies = {'get public.key':await link.command('get public.key',600)};
  const key=/(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])/i.exec(replies['get public.key'])?.[0].toLowerCase();
  if(!key)fail('No MeshCore CommonCLI public identity response. A connected DFU/ROM port cannot provide a configuration backup.');
  for (const [i,command] of commands.entries()) { replies[command] = await link.command(command,600); progress(.85*(i+1)/commands.length,command); }
  const regions=await captureRegions(link,{},(value,message)=>progress(.85+.14*value,message));
  const final=/(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])/i.exec(await link.command('get public.key',600))?.[0].toLowerCase();
  if(final!==key)fail('CommonCLI identity changed during backup.');
  const privateHex=/(?<![a-f0-9])[a-f0-9]{128}(?![a-f0-9])/i.exec(replies['get prv.key'])?.[0];
  if(privateHex&&publicFromPrivate(unhex(privateHex))!==key)fail('CommonCLI private/public identity mismatch.');
  progress(1,'CommonCLI exposed settings captured; unsupported settings are reported separately. This is not a wipe-safe image.');
  return sealBackup({role:'common-cli',publicKey:key,safeForWipe:false,replies,regions,excluded:['Private identity may not be exposed','Not an atomic/bulk export','Unread messages, logs and unexposed preferences are not exported']});
}

export function backupSummary(archive) {
  const p=verifyBackup(archive),missing=[];
  if(p.role==='common-cli'){
    const states=Object.entries(p.replies).map(([command,raw])=>({command,...commonCliReplyState(raw,command)})),errors=states.filter(row=>row.state==='error'),unsupported=states.filter(row=>row.state==='unsupported');
    return {role:p.role,complete:false,privateIdentity:!!/(?<![a-f0-9])[a-f0-9]{128}(?![a-f0-9])/i.exec(p.replies?.['get prv.key']||''),reasons:['CommonCLI exports exposed settings, not an atomic or whole-flash backup.',...errors.map(row=>`${row.command}: ${row.reason||'query failed'}`),...unsupported.map(row=>`${row.command}: unsupported by this firmware`),...(p.regions?.state==='complete'?[]:[`Regions: ${p.regions?.reason||'No complete typed region snapshot was captured.'}`])],safeForWipe:false,queryErrors:errors.map(row=>row.command),unsupportedQueries:unsupported.map(row=>row.command)};
  }
  const info=unhex(p.info);if([[8,20],[20,60],[60,80]].some(([from,to])=>!text(info.subarray(from,to)).split('\0')[0]))missing.push('DEVICE_INFO has incomplete build/model/version diagnostics.');
  if(!p.privateKey)missing.push('Private identity was not captured; moving the node identity cannot be completed.');
  for(const name of ['autoadd','tuning','custom','scope'])if(typeof p.options[name]!=='string')missing.push(`${name} settings unavailable.`);
  for(const [command,value] of Object.entries(p.cli))if(value===null||typeof value==='string'&&/^\s*(?:->\s*)?error/i.test(value))missing.push(`${command} unavailable.`);
  if(!p.batteryAndStorage || p.batteryAndStorage.unavailable)missing.push('Battery/storage diagnostics unavailable.');
  return {role:p.role,complete:!missing.length,privateIdentity:!!p.privateKey,reasons:missing,safeForWipe:false};
}

// Probe only the selected port, without consuming unread messages, resetting,
// entering text mode, or changing logging. Native CommonCLI and binary API
// detection share the same public-key evidence; VID/PID alone is not a role.
export function cleanCliReply(reply,command='') {
  if(typeof reply!=='string'||reply.length>8192)return '';
  return reply.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'').split(/[\r\n]+/).map(line=>line.trim().replace(/^(?:(?:->|>)\s*)+/,''))
    .filter(line=>line&&line.toLowerCase()!==command.toLowerCase()).join('\n');
}
function reportedCatalogRole(value){
  const roles=new Map([['repeater','repeater'],['room server','roomServer'],['room-server','roomServer'],['roomserver','roomServer'],['sensor','sensor'],['companionble','companionBle'],['companionusb','companionUsb'],['companionfull','companionFull']]);
  return roles.get(value.trim().toLowerCase())||null;
}
export async function detectMeshCore(link,{timeoutMs=1500}={}) {
  const reply=await link.command('get public.key',Math.min(timeoutMs,450));
  const publicKey=/(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])/i.exec(reply)?.[0].toLowerCase();
  if(publicKey) {
    const name=cleanCliReply(await link.command('get name',350),'get name'),version=cleanCliReply(await link.command('ver',350),'ver'),board=cleanCliReply(await link.command('board',350),'board');
    let catalogRole=null;
    try{catalogRole=reportedCatalogRole(cleanCliReply(await link.command('get role',350),'get role'));}catch{/* Optional role hints never replace the independently read public identity. */}
    return {role:'common-cli',publicKey,name,version,model:!board||board.includes('\n')||/unknown command|unsupported|error/i.test(board)?null:board,catalogRole};
  }
  if(link.buffer)link.buffer.length=0;
  const core=new MeshCore(link,{timeoutMs}),self=await core.self(),info=await core.info();
  if(self[1]!==1)fail('This binary interface is not a companion. Select the primary CommonCLI port.');
  const shortVersion=text(info.subarray(60,80)).split('\0')[0];let version=shortVersion;
  // Protocol 14 exposes read-only role CLI. DEVICE_INFO's version field is only
  // 20 bytes; use its full response for provider/version selection when present.
  // Older companions must not receive unsupported CLI commands during probing.
  if(info[1]>=14){
    try{
      const optional=new MeshCore(link,{timeoutMs:Math.min(timeoutMs,700)}),reply=cleanCliReply(await optional.cli('version'),'version');
      if(/^Companion\s+v?\d+\.\d+\.\d+[^\r\n]*\s+\(protocol\s+\d+,\s*build\s+[^\r\n]+\)$/i.test(reply))version=reply;
    }catch{/* Core companion identity remains usable without the optional full version. */}
  }
  return {role:'companion',publicKey:bytesToHex(self.subarray(4,36)),name:text(self.subarray(58)).split('\0')[0],model:text(info.subarray(20,60)).split('\0')[0],version,shortVersion,protocol:info[1]};
}
