// An installed-loader identity is a selection hint, not proof of the physical
// module or permission to write. Only verified normal-release assets are used.
import {validateBootloaderSnapshot} from './bootloader-catalog.js';
import {validateInfo} from './bootloader-info.js';

const xiaoHardware='Seeed Studio Xiao nRF52 WIO';
const ids={
  '28860044':'xiao_nrf52840_ble',
  '28860045':'xiao_nrf52840_ble_sense',
};

export function xiaoInstalledStatus(reply) {
  if(typeof reply!=='string')return null;
  const match=/^BL board=([0-9A-F]{8}) target=([0-9A-F]{8}) name=XIAO_DFU crc=[0-9A-F]{8} abi=\d+ caps=[0-9A-F]{2} \| staged:(?:none|ready) mid=(?:--|[0-9A-F]+) hash=(?:--|[0-9A-F]+)$/i.exec(reply.trim());
  if(!match||match[1].toUpperCase()!==match[2].toUpperCase())return null;
  return ids[match[1].toUpperCase()]||null;
}

export function xiaoInfoProfile(info,usbInfo) {
  try{validateInfo(info);}catch{return null;}
  if(!info||info.model!=='Seeed XIAO nRF52840'||/^(?:R|TEST)_/.test(info.version||''))return null;
  const pairs={
    'nRF52840-SeeedXiao-v1':[0x0044,ids['28860044']],
    'nRF52840-SeeedXiaoSense-v1':[0x0045,ids['28860045']],
  };
  const pair=pairs[info.boardId];
  return pair&&usbInfo?.usbVendorId===0x2886&&usbInfo?.usbProductId===pair[0]?pair[1]:null;
}

export function xiaoBootloaderItem({item,snapshot,profile}) {
  if(item?.hardware!==xiaoHardware||item.architecture!=='nrf52'||!Object.values(ids).includes(profile)||!snapshot)return null;
  let verified;try{verified=validateBootloaderSnapshot(snapshot);}catch{return null;}
  const manifest=verified.manifest,p=manifest.profiles.find(entry=>entry.id===profile);
  if(!p||p.deviceName!=='XIAO_DFU'||p.storage!=='qspi'||!p.files?.zip)return null;
  const file=p.files.zip,info={version:manifest.version,tag:manifest.tag,profile:p.id,hardwareId:profile.endsWith('_sense')?'Xiao_nrf52_Sense':'Xiao_nrf52',label:p.label,deviceName:p.deviceName,storage:p.storage,url:file.url,sha256:file.sha256,size:file.size,releaseUrl:manifest.releaseUrl,checkedAt:verified.checkedAt,cached:verified.cached};
  return {...item,bootloader:[file.url],bootloaderInfo:info};
}
