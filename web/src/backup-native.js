// Convert an already verified wire snapshot into the existing native schema.
// Python, inside the worker, owns canonical serialization, sealing and validation.
import { verifyBackup, publicFromPrivate } from './meshcore.js';
import { hash, fail, text } from './firmware.js';
const unhex=s=>Uint8Array.from(s.match(/../g)||[],x=>parseInt(x,16));
const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
const cstr=b=>text(b).split('\0')[0];
const section=(data,required=true,extra={})=>({state:'complete',required,data,...extra});
const absent=(reason,required=true,state='unsupported')=>({state,required,reason});
const cliQueries=[['storage_layout','get storage.layout',null],['radio_cad','get radio.cad','set radio.cad'],['radio_rxgain','get radio.rxgain','set radio.rxgain'],['radio_fem_rxgain','get radio.fem.rxgain','set radio.fem.rxgain'],['radio_fem_txgain','get radio.fem.txgain','set radio.fem.txgain'],['bluetooth_name','get bluetooth.name','set bluetooth.name'],['display_rotation','get display.rotation','set display.rotation'],['power_saving','get powersaving','powersaving on/off'],['usb_logging','get usb.logging','set usb.logging'],['radio_rxps','get radio.rxps.config','set radio.rxps']];

export function nativePayloadFromWeb(archive,{usbIdentity={},deviceHint}={}) {
  const p=verifyBackup(archive),vendor=usbIdentity.usbVendorId??usbIdentity.vendor_id,product=usbIdentity.usbProductId??usbIdentity.product_id;
  if(!Number.isInteger(vendor)||vendor<1||vendor>65535||!Number.isInteger(product)||product<0||product>65535)fail('Native-format export requires the selected USB VID/PID. No physical USB serial will be invented.');
  let sections={};
  if(p.role==='companion') {
    const self=unhex(p.self),info=unhex(p.info),v=new DataView(self.buffer),iv=new DataView(info.buffer);
    const s={adv_type:self[1],tx_power:self[2],max_tx_power:self[3],public_key:p.publicKey,adv_lat:v.getInt32(36,true)/1e6,adv_lon:v.getInt32(40,true)/1e6,multi_acks:self[44],adv_loc_policy:self[45],telemetry_mode_env:(self[46]>>4)&3,telemetry_mode_loc:(self[46]>>2)&3,telemetry_mode_base:self[46]&3,manual_add_contacts:!!self[47],radio_freq:v.getUint32(48,true)/1000,radio_bw:v.getUint32(52,true)/1000,radio_sf:self[56],radio_cr:self[57],name:cstr(self.subarray(58))};
    const d={'fw ver':info[1],max_contacts:info[2]*2,max_channels:info[3],ble_pin:iv.getUint32(4,true),fw_build:cstr(info.subarray(8,20)),model:cstr(info.subarray(20,60)),ver:cstr(info.subarray(60,80)),...(info[1]>=9?{repeat:!!info[80]}:{}),...(info[1]>=10?{path_hash_mode:info[81]}:{})};
    const full=/\bCompanion\s+(\S+)\s+\(protocol\b/i.exec(p.cli.version||'');if(full)d.ver_full=full[1];
    sections.self_info=section(s,true,{restore_method:'set_name/set_coords/set_tx_power/set_radio/set_other_params_from_infos'});
    sections.device_info=[d.fw_build,d.model,d.ver].every(Boolean)?section(d):{...absent('DEVICE_INFO contains empty diagnostic identity fields.',true,'error'),data:d};
    sections.identity_private_key=p.privateKey?section({private_key:p.privateKey.slice(2)},true,{restore_method:'import_private_key'}):absent(p.identityWarning||'Private identity export is unavailable.',true);
    const contacts={};for(const raw of p.contacts){const b=unhex(raw),cv=new DataView(b.buffer),key=hex(b.subarray(1,33)),flood=b[35]===255,len=flood?-1:b[35]&63,mode=flood?-1:b[35]>>6;contacts[key]={public_key:key,type:b[33],flags:b[34],out_path_len:len,out_path_hash_mode:mode,out_path:flood?'':hex(b.subarray(36,36+len*(mode+1))),adv_name:cstr(b.subarray(100,132)),last_advert:cv.getUint32(132,true),adv_lat:cv.getInt32(136,true)/1e6,adv_lon:cv.getInt32(140,true)/1e6,lastmod:cv.getUint32(144,true)};}
    sections.contacts=section(contacts,true,{counts:{declared:p.contacts.length,received:p.contacts.length},restore_method:'add_contact/update_contact'});
    sections.channels=section(p.channels.map(raw=>{const b=unhex(raw),secret=b.subarray(34,50);return {channel_idx:b[1],channel_name:cstr(b.subarray(2,34)),channel_secret:hex(secret),channel_hash:hash(secret).slice(0,2)};}),true,{counts:{declared:info[3],received:p.channels.length},restore_method:'set_channel'});
    for(const [name,key,method] of [['autoadd','autoadd','set_autoadd_config'],['tuning','tuning','set_tuning'],['default_flood_scope','scope','set_default_flood_scope'],['custom_vars','custom','set_custom_var']]) {
      const raw=p.options[key];if(typeof raw!=='string'){sections[name]=absent(raw?.unavailable||'API setting unavailable.');continue;}
      const b=unhex(raw),bv=new DataView(b.buffer);let data;
      if(key==='autoadd')data={config:b[1],...(b.length===3?{max_hops:b[2]}:{})};
      if(key==='tuning')data={rx_delay:bv.getUint32(1,true),airtime_factor:bv.getUint32(5,true)};
      if(key==='scope')data=b.length===1||!cstr(b.subarray(1,32))?{}:{scope_name:cstr(b.subarray(1,32)),scope_key:hex(b.subarray(32,48))};
      if(key==='custom')data=Object.fromEntries(text(b.subarray(1)).split(',').filter(Boolean).map(row=>{const at=row.indexOf(':');return [row.slice(0,at),row.slice(at+1)];}));
      sections[name]=section(data,true,{restore_method:method});
    }
    sections.battery_and_storage=p.batteryAndStorage&&!p.batteryAndStorage.unavailable?section(p.batteryAndStorage,false):absent(p.batteryAndStorage?.unavailable||'Battery/storage API unavailable.',false,'error');
    for(const [name,command,restore_method] of cliQueries){const value=p.cli[command];if(value==null){sections[name]=absent('CLI setting unavailable.',false);continue;}if(typeof value==='string'&&/unknown command|unsupported/i.test(value)){sections[name]=absent('Firmware does not expose this setting.',false);continue;}if(typeof value==='string'&&/^\s*(?:->\s*)?error/i.test(value)){sections[name]=absent('Firmware reported a query error.',false,'error');continue;}sections[name]=section(name==='bluetooth_name'&&typeof value==='object'?value:{text:value},false,{command,...(restore_method?{restore_method}:{}),...(name==='storage_layout'?{diagnostic_scope:'layout_only; this is not a filesystem consistency check'}:{})});}
    for(const [name,command] of [['radio2','get radio2'],['radio2_cross','get radio2.cross'],['bluetooth_status','get bluetooth']])if(typeof p.cli[command]==='string')sections[name]=section({text:p.cli[command]},false,{command,diagnostic_scope:'manual comparison only'});
  } else {
    const replies=p.replies||{},privateHex=/(?<![a-f0-9])[a-f0-9]{128}(?![a-f0-9])/i.exec(replies['get prv.key']||'')?.[0]?.toLowerCase();
    if(privateHex&&publicFromPrivate(unhex(privateHex))!==p.publicKey)fail('CommonCLI private/public identity mismatch.');
    sections={identity_public_key:section({public_key:p.publicKey}),identity_private_key:privateHex?section({private_key:privateHex}):absent('CommonCLI private key unavailable.'),settings:section(replies),contacts:absent('CommonCLI has no versioned contact export.',false),channels:absent('CommonCLI has no versioned channel export.',false),acl:replies['get acl']?section({text:replies['get acl']}):absent('ACL unavailable.'),regions:replies.region?section({text:replies.region}):absent('Regions unavailable.')};
  }
  sections.identity_stability=section({stable:true});
  const missing=Object.entries(sections).filter(([,v])=>v.required&&v.state!=='complete').map(([k])=>k).sort(),errors=Object.entries(sections).filter(([,v])=>!v.required&&v.state==='error').map(([k])=>k).sort();
  return {source:{transport:'usb-serial',port_at_capture:'web-serial',physical_usb_identity:{serial:null,location:null,parent:null,interface:null,device_hint:deviceHint||null,attestation:'browser-port-permission',vendor_id:vendor,product_id:product},node:{public_key:p.publicKey,role:p.role==='companion'?'companion':'common-cli',device_hint:deviceHint||null},capture_api:p.role==='companion'?'companion-api':'meshcore-cli-common-cli'},sections,excluded:{messages:'Not exported: reading consumes unread messages.',logs:'Not exported: runtime logs may contain unrelated private data.',unexposed_preferences:'Not every board-specific setting is exposed.'},completeness:{status:p.role==='companion'&&!missing.length&&!errors.length?'api-snapshot-complete':'partial',safe_for_wipe:false,safe_for_restore:false,missing_required:missing,optional_errors:errors,reasons:[...missing.map(k=>`required section incomplete: ${k}`),...errors.map(k=>`optional query failed: ${k}`),'Web Serial does not expose a physical USB serial or location; native restore requires explicit target selection.','Unread messages and unexposed preferences are not exported.']},restore_plan:{executor_implemented:false,requires_separate_explicit_confirmation:true,requires_target_public_key_or_blank_identity_gate:true,strategy:'role-aware MeshCore APIs and CommonCLI inverse operations',ordered_sections:Object.keys(sections).filter(k=>sections[k].state==='complete'),unavailable_sections:Object.entries(sections).filter(([,v])=>v.state!=='complete').map(([name,v])=>({section:name,state:v.state,reason:v.reason})),post_restore_verification:['re-query public key and role','re-query each restored section','compare canonical nonvolatile values']}};
}

export async function exportNativeBackup(archive,{sealNative,usbIdentity,deviceHint}={}) {
  if(typeof sealNative!=='function')fail('Native archive export requires the exact Python serializer.');
  const payload=nativePayloadFromWeb(archive,{usbIdentity,deviceHint}),privateHex=payload.sections.identity_private_key.state==='complete'?payload.sections.identity_private_key.data.private_key:undefined;
  const result=await sealNative({payload,privateHex,expectedPub:payload.source.node.public_key});
  if(!result?.archive||result.archive.schema!=='org.meshfirmware.meshcore-backup/v1'||result.summary?.public_key!==payload.source.node.public_key)fail('Native archive sealing did not verify.');
  return result.archive;
}
