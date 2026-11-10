import { zipSync } from 'fflate';
import { checkedZip, crc16, crc32, hash, inspectFirmware, partitionTable, text, validateEspImage } from './firmware.js';
import { endfIdentity } from './board-safety.js';

// Versioned firmware ABI, not an arbitrary binary search-and-replace. The
// firmware uses these values only when initializing otherwise unset settings.
const encode=value=>new TextEncoder().encode(value);
const prefix=encode('MCRDEFAULTS'),magic=encode('MCRDEFAULTS0001\0');
const bandwidths=new Set([7800,10400,15600,20800,31250,41700,62500,125000,250000,500000]);
const forbidden=/(?:^|[\\/_.\s-])(?:bootloader|softdevice|erase|wipe|format(?:ter)?|recovery|expert|signed|signature|mota)(?:[\\/_.\s-]|$)|(?:with[-_]bootloader)|(?:^|[\\/])R_/i;
const reject=message=>{throw new Error(message);};
const view=bytes=>new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);
const equal=(a,b)=>a.length===b.length&&a.every((value,index)=>value===b[index]);
const padding=bytes=>bytes.every(value=>value===0||value===255);
const hexBytes=value=>Uint8Array.from(value.match(/../g),pair=>parseInt(pair,16));
function endf(bytes,offset){
  if(offset<0||text(bytes.subarray(offset,offset+4))!=='EndF')return null;
  const identity=endfIdentity(bytes.subarray(0,offset+56));
  if(!identity)reject('The original firmware EndF identity is invalid.');
  return {offset,identity};
}
function repairEndf(bytes,start,footer){if(footer)bytes.set(hexBytes(hash(bytes.subarray(start,start+footer.offset)).slice(0,16)),start+footer.offset+8);}
function markers(bytes){
  const offsets=[];
  for(let at=bytes.indexOf(prefix[0]);at>=0;at=bytes.indexOf(prefix[0],at+1))if(equal(bytes.subarray(at,at+prefix.length),prefix))offsets.push(at);
  return offsets;
}
function oneMarker(bytes){
  const found=markers(bytes);
  if(found.length!==1)reject(found.length?'Duplicate radio-default blocks are not supported.':'This build has no editable defaults block. It can still be flashed unchanged.');
  return found[0];
}
function embeddedMota(bytes){
  // OtaFormat.h framing: magic[4], LE total size, body, "vk496".
  // Refuse even unsigned/unknown framed containers: a radio-default edit must
  // never change a signed or embedded bootloader/application envelope.
  const tag=encode('mOTA'),trailer=encode('vk496'),d=view(bytes);
  for(let at=bytes.indexOf(tag[0]);at>=0;at=bytes.indexOf(tag[0],at+1)){
    if(at+8>bytes.length||!equal(bytes.subarray(at,at+4),tag))continue;
    const size=d.getUint32(at+4,true);
    if(size>=13&&size<=bytes.length-at&&equal(bytes.subarray(at+size-5,at+size),trailer))return true;
  }
  return false;
}
function settingsValue(settings){
  if(!settings||typeof settings!=='object'||Array.isArray(settings)||typeof settings.enabled!=='boolean')reject('Radio defaults need an explicit enabled setting.');
  const allowed=new Set(['enabled','frequencyHz','bandwidthHz','spreadingFactor','codingRate','preambleSymbols','txPowerDbm']);
  if(Object.keys(settings).some(key=>!allowed.has(key)))reject('Unknown radio-default settings field.');
  if(!settings.enabled){
    if(['frequencyHz','bandwidthHz','spreadingFactor','codingRate','preambleSymbols'].some(key=>settings[key]!=null&&settings[key]!==0)||settings.txPowerDbm!=null&&settings.txPowerDbm!==0)reject('Disabled radio defaults must have zero fields.');
    return {enabled:false,frequencyHz:0,bandwidthHz:0,spreadingFactor:0,codingRate:0,preambleSymbols:0,txPowerDbm:null};
  }
  const {frequencyHz,bandwidthHz,spreadingFactor,codingRate,preambleSymbols=0,txPowerDbm=null}=settings;
  if(!Number.isInteger(frequencyHz)||frequencyHz<150000000||frequencyHz>2500000000)reject('Radio-default frequency must be 150–2500 MHz in whole Hz.');
  if(!bandwidths.has(bandwidthHz))reject('Unsupported radio-default bandwidth.');
  if(!Number.isInteger(spreadingFactor)||spreadingFactor<5||spreadingFactor>12)reject('Radio-default spreading factor must be 5–12.');
  if(!Number.isInteger(codingRate)||codingRate<5||codingRate>8)reject('Radio-default coding rate must be 5–8.');
  if(!Number.isInteger(preambleSymbols)||(preambleSymbols!==0&&(preambleSymbols<8||preambleSymbols>65528)))reject('Radio-default preamble must be automatic (0) or 8–65528 symbols.');
  if(txPowerDbm!==null&&(!Number.isInteger(txPowerDbm)||txPowerDbm< -9||txPowerDbm>40))reject('Radio-default TX power must be -9–40 dBm, or omitted.');
  return {enabled:true,frequencyHz,bandwidthHz,spreadingFactor,codingRate,preambleSymbols,txPowerDbm};
}
function decodeBlock(bytes,offset){
  if(offset+64>bytes.length)reject('Radio-default block is truncated.');
  const block=bytes.subarray(offset,offset+64),v=view(block);
  if(!equal(block.subarray(0,16),magic)||v.getUint16(16,true)!==1||v.getUint16(18,true)!==64)reject('Unknown radio-default block version or length.');
  const flags=v.getUint32(20,true);
  if(flags&~3||!(flags&1)&&(flags&2)||block[35]!==0||!block.subarray(38,60).every(value=>value===0))reject('Radio-default flags or reserved fields are invalid.');
  if(v.getUint32(60,true)!==crc32(block.subarray(0,60)))reject('Radio-default block CRC is invalid.');
  if(!(flags&2)&&block[34]!==0)reject('Radio-default TX field has no enabling flag.');
  return settingsValue({enabled:!!(flags&1),frequencyHz:v.getUint32(24,true),bandwidthHz:v.getUint32(28,true),spreadingFactor:block[32],codingRate:block[33],txPowerDbm:flags&2?v.getInt8(34):null,preambleSymbols:v.getUint16(36,true)});
}
function encodeBlock(settings){
  const bytes=new Uint8Array(64),v=view(bytes);bytes.set(magic);v.setUint16(16,1,true);v.setUint16(18,64,true);
  if(settings.enabled){
    v.setUint32(20,1|(settings.txPowerDbm===null?0:2),true);v.setUint32(24,settings.frequencyHz,true);v.setUint32(28,settings.bandwidthHz,true);
    bytes[32]=settings.spreadingFactor;bytes[33]=settings.codingRate;v.setInt8(34,settings.txPowerDbm??0);v.setUint16(36,settings.preambleSymbols,true);
  }
  v.setUint32(60,crc32(bytes.subarray(0,60)),true);return bytes;
}
function signatureMetadata(value){
  if(!value||typeof value!=='object')return false;
  return Object.entries(value).some(([key,nested])=>/sign(?:ature|ed|ing)|(?:^|_)bootloader(?:$|_)/i.test(key)||signatureMetadata(nested));
}
function espImage(bytes,start,end){
  const data=bytes.subarray(start,end),length=validateEspImage(data),v=view(data),segments=[];
  if(data.length<36||v.getUint32(32,true)!==0xabcd5432)reject('Radio defaults require a descriptor-bearing ESP32 application, not a bootloader or expert image.');
  const footer=endf(data,length);
  if(!padding(data.subarray(length+(footer?56:0))))reject('Signed images or nonpadding ESP32 application trailers cannot be customized.');
  let offset=24;
  for(let index=0;index<data[1];index++){const size=v.getUint32(offset+4,true);segments.push({start:start+offset+8,end:start+offset+8+size});offset+=8+size;}
  const checksumOffset=Math.ceil((offset+1)/16)*16-1;
  return {start,end:start+length,segments,checksumOffset:start+checksumOffset,hasHash:data[23]===1,chipId:v.getUint16(12,true),footer};
}
function inspectSource(name,bytes){
  if(typeof name!=='string'||forbidden.test(name))reject('Bootloader, SoftDevice, recovery, erase, signed, and expert images cannot customize radio defaults.');
  const pkg=inspectFirmware(name,bytes);
  let payload,files,manifest,entry,image,footer;
  if(pkg.architecture==='nrf52'){
    if(pkg.kind!=='application'||pkg.erase||pkg.destructive||pkg.expert||pkg.mode!==4||pkg.sdSize!==0||pkg.blSize!==0)reject('Only an ordinary nRF52 application ZIP can customize radio defaults.');
    files=checkedZip(bytes,{maxEntries:3,maxExpanded:2<<20});
    if(Object.keys(files).some(name=>forbidden.test(name)))reject('Component or signed ZIP entries cannot customize radio defaults.');
    manifest=JSON.parse(text(files['manifest.json']));entry=manifest.manifest.application;
    payload=files[entry.bin_file];oneMarker(payload);
    if(signatureMetadata(manifest))reject('Signed or embedded-bootloader ZIPs cannot customize radio defaults.');
    footer=endf(payload,payload.length-56);
  }else if(pkg.architecture==='esp32'){
    if(pkg.expert)reject('Bootloader and expert ESP32 images cannot customize radio defaults.');
    payload=bytes;
    const markerOffset=oneMarker(bytes);
    if(pkg.merged){
      const fileOffset=pkg.flashOffset??0,tableOffset=0x8000-fileOffset;
      const parts=partitionTable(bytes.subarray(tableOffset,tableOffset+4096)),bootStart=([0,2].includes(pkg.chipId)?0x1000:0)-fileOffset;
      const bootLength=validateEspImage(bytes.subarray(bootStart,tableOffset));
      if(!padding(bytes.subarray(bootStart+bootLength,tableOffset)))reject('Signed bootloaders or nonpadding merged bootloader trailers cannot be customized.');
      const candidates=[];let populated=0;
      for(const part of parts.filter(part=>part.type===0)){
        const start=part.offset-fileOffset;
        if(start>=bytes.length||bytes[start]!==0xe9)continue;
        if(++populated>1)reject('Multiple populated ESP32 application partitions cannot be customized as one image.');
        const candidate=espImage(bytes,start,Math.min(start+part.size,bytes.length));
        if(candidate.chipId!==pkg.chipId)reject('Merged application and bootloader chip identities disagree.');
        if(candidate.segments.some(segment=>markerOffset>=segment.start&&markerOffset+64<=segment.end)){
          if(part.flags&1)reject('Encrypted ESP32 application partitions cannot be customized.');
          candidates.push(candidate);
        }
      }
      if(candidates.length!==1)reject('Radio-default block is not inside one validated ESP32 application segment.');
      image=candidates[0];
    }else image=espImage(bytes,0,bytes.length);
    if(!image.segments.some(segment=>markerOffset>=segment.start&&markerOffset+64<=segment.end))reject('Radio-default block is outside the ESP32 application segments.');
  }else reject('This firmware format does not support editable radio defaults.');
  if(embeddedMota(payload))reject('Embedded mOTA containers cannot customize radio defaults, even when renamed as an ordinary application.');
  const offset=oneMarker(payload),settings=decodeBlock(payload,offset);
  return {pkg,payload,files,manifest,entry,image,footer,offset,settings,sourceSha256:hash(bytes)};
}

/** Inspect without affecting ordinary flashing: unsupported/malformed inputs
 * return a reason, not a partially editable firmware image. Settings use whole
 * Hz, SF/CR integers, preamble symbols (0=automatic), and nullable TX dBm. */
export function inspectRadioDefaults(name,bytes){
  let sourceSha256=null;try{if(bytes instanceof Uint8Array)sourceSha256=hash(bytes);const info=inspectSource(name,bytes);return {supported:true,settings:{...info.settings},reason:'',architecture:info.pkg.architecture,sourceSha256:info.sourceSha256};}
  catch(error){return {supported:false,settings:null,reason:error.message||String(error),sourceSha256};}
}

/** Return new full firmware bytes, preserving the original. The optional
 * expectedSourceSha256 binds an editor to its exact original selection.
 * Repackaged DFU ZIP/DAT CRCs and ESP XOR/SHA are independently re-inspected. */
export function customizeRadioDefaults(name,bytes,settings,{expectedSourceSha256}={}){
  const info=inspectSource(name,bytes),normalized=settingsValue(settings);
  if(expectedSourceSha256!==undefined&&(typeof expectedSourceSha256!=='string'||!/^[a-f0-9]{64}$/i.test(expectedSourceSha256)||expectedSourceSha256.toLowerCase()!==info.sourceSha256))reject('The source firmware changed after the radio-default editor was opened.');
  const block=encodeBlock(normalized),changed=!equal(block,info.payload.subarray(info.offset,info.offset+64));
  let output=Uint8Array.from(bytes);
  if(changed&&info.pkg.architecture==='nrf52'){
    const payload=info.payload.slice();payload.set(block,info.offset);repairEndf(payload,0,info.footer);info.files[info.entry.bin_file]=payload;
    const init=info.files[info.entry.dat_file].slice(),v=view(init),at=10+v.getUint16(8,true)*2,crc=crc16(payload);v.setUint16(at,crc,true);info.files[info.entry.dat_file]=init;
    if(info.entry.init_packet_data&&Object.hasOwn(info.entry.init_packet_data,'firmware_crc16'))info.entry.init_packet_data.firmware_crc16=crc;
    info.files['manifest.json']=encode(JSON.stringify(info.manifest));output=zipSync(info.files,{level:6,mtime:new Date(2000,0,1)});
  }else if(changed){
    output.set(block,info.offset);const {image}=info;let checksum=0xef;
    for(const segment of image.segments)for(const byte of output.subarray(segment.start,segment.end))checksum^=byte;
    output[image.checksumOffset]=checksum;
    if(image.hasHash)output.set(hexBytes(hash(output.subarray(image.start,image.checksumOffset+1))),image.checksumOffset+1);
    repairEndf(output,image.start,image.footer);
  }
  const checked=inspectSource(name,output),sha256=hash(output);
  if(JSON.stringify(checked.settings)!==JSON.stringify(normalized)||changed===(sha256===info.sourceSha256))reject('Customized firmware did not pass independent integrity checks.');
  const provenance={operation:'meshfirmware-radio-defaults/v1',sourceSha256:info.sourceSha256,sha256,changed,architecture:info.pkg.architecture};
  return {bytes:output,settings:{...normalized},sourceSha256:info.sourceSha256,sha256,changed,provenance};
}
