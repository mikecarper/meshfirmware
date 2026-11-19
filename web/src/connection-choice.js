// Selection only: never opens a port, asserts control lines, resets, or writes.
// Every returned strategy still needs the existing backup/inspection/write gates.
import {isKnownDfu} from './board-safety.js';
import {hash,nrfMetadataHash} from './firmware.js';

const uartIds=new Set([
  '1a86:7523','1a86:5523','1a86:7522','1a86:55d4', // CH340/341/343
  '10c4:ea60','10c4:ea70','10c4:ea71',             // CP210x
  '0403:6001','0403:6010','0403:6011','0403:6015', // FTDI
]);
const usbId=info=>[info?.usbVendorId,info?.usbProductId].every(n=>Number.isInteger(n)&&n>=0&&n<=65535)?[info.usbVendorId,info.usbProductId].map(n=>n.toString(16).padStart(4,'0')).join(':'):'';
const result=(mode,alreadyBootloader,source,reason)=>({mode,alreadyBootloader,source,reason});

// A prior serial DFU ACK is evidence about the selected port during that
// attempt only. Tokens are private to this page, cannot be reconstructed from
// storage, and never authorize a reset or a new transfer by themselves.
const nrfDfuEvidenceBindings=new WeakMap();
const validGeneration=value=>Number.isSafeInteger(value)&&value>=0;
const validHash=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
function validNrfPackage(pkg){
  if(!pkg||pkg.architecture!=='nrf52'||!validHash(pkg.sha256)||!validHash(pkg.payloadHash)||!validHash(pkg.initHash)||!validHash(pkg.metadataHash)||!(pkg.payload instanceof Uint8Array)||!(pkg.init instanceof Uint8Array)||!pkg.payload.length)return false;
  try{return hash(pkg.payload)===pkg.payloadHash&&hash(pkg.init)===pkg.initHash&&nrfMetadataHash(pkg)===pkg.metadataHash;}catch{return false;}
}
function portUsbId(port){try{return port&&typeof port.getInfo==='function'?usbId(port.getInfo()||{}):null;}catch{return null;}}
export function captureNrfDfuEvidence({error,port,generation,pkg}={}){
  const detail=error?.nrfDfu,id=portUsbId(port);
  if(error?.code!=='NRF_DFU_ACK_TIMEOUT'||!detail||!Object.isFrozen(detail)||!['init','data'].includes(detail.stage)||id===null||!validGeneration(generation)||!validNrfPackage(pkg))return null;
  const bytes=detail.acknowledgedBytes;
  if(detail.totalBytes!==pkg.payload.length||detail.kind!==pkg.kind||detail.erase!==(pkg.erase===true)||!Number.isSafeInteger(bytes)||bytes<0||bytes>=detail.totalBytes||!Number.isInteger(detail.sequence)||detail.sequence<0||detail.sequence>7)return null;
  // START is acknowledged before init; init is acknowledged before data.
  // Packet numbers wrap, so use previously acknowledged byte count, not the
  // displayed sequence as a total or a physical-board identifier.
  if(detail.stage==='init'?(bytes!==0||detail.sequence!==2):(bytes%512!==0||detail.sequence!==((3+bytes/512)&7)))return null;
  const token=Object.freeze({});
  nrfDfuEvidenceBindings.set(token,{port,generation,pkg,id,sha256:pkg.sha256,payloadHash:pkg.payloadHash,initHash:pkg.initHash,metadataHash:pkg.metadataHash});
  return token;
}
export function nrfDfuEvidenceCurrent({evidence,port,generation,pkg}={}){
  if(!evidence||typeof evidence!=='object')return false;
  const saved=nrfDfuEvidenceBindings.get(evidence);
  return !!saved&&saved.port===port&&saved.generation===generation&&saved.pkg===pkg&&saved.id===portUsbId(port)&&saved.sha256===pkg?.sha256&&saved.payloadHash===pkg?.payloadHash&&saved.initHash===pkg?.initHash&&saved.metadataHash===pkg?.metadataHash&&validNrfPackage(pkg);
}

export function parseUsbMode(reply){
  if(typeof reply!=='string'||reply.length>128)return null;
  const match=/^usb\.mode (hardware-cdc-jtag|tinyusb|uart|unknown)$/.exec(reply);
  return match?.[0]===reply?match[1]:null;
}

// device.architecture must come from the exact matched running-firmware model,
// not a proposed image filename. usbDescription, when supplied, must describe
// this selected port (e.g. a separately granted matching USB descriptor).
// Web Serial itself does not expose product/interface strings.
export function chooseConnection({usbInfo={},device=null,usbDescription='',alreadyBootloader=false,handoff=false,packageArchitecture=null,nrfDfuEvidence=null,port=null,generation=null,pkg=null}={}) {
  const id=usbId(usbInfo),architecture=device?.architecture||null;
  if(isKnownDfu(usbInfo||{}))return result('nrf52',true,'dfu-usb','Known nRF52 DFU interface; serial DFU needs no 1200-baud touch. USB IDs are a mode hint, not physical-board proof.');
  if(id===portUsbId(port)&&nrfDfuEvidenceCurrent({evidence:nrfDfuEvidence,port,generation,pkg})){
    if(architecture&&architecture!=='nrf52')return result(null,false,'conflict','The earlier DFU acknowledgement conflicts with the running application evidence. Re-select the intended radio; no reset is inferred.');
    return result('nrf52',true,'dfu-ack','This selected port acknowledged a serial DFU packet during the interrupted transfer. It is a connection hint, not physical-board proof or permission to retry.');
  }
  if(alreadyBootloader===true||handoff===true){
    if(architecture==='nrf52'||packageArchitecture==='nrf52')return result('nrf52',true,'explicit-bootloader','Explicit nRF52 bootloader handoff; use the selected serial DFU interface without another reset.');
    return result('no_reset',true,'explicit-bootloader','Explicit ROM/bootloader handoff; inspect this selected interface without another reset.');
  }
  if(device?.firmwareFamily==='bootloader'||device?.role==='bootloader')return result(null,false,'bootloader-file','The selected INFO_UF2.TXT suggests installed bootloader hardware, but does not identify this USB port or prove its mode. Select the same radio’s DFU serial port, or explicitly mark an unlisted port Already in ROM/DFU. No reset is inferred from a file.');
  if(architecture==='nrf52')return result('nrf52',false,'application-model','Running application identifies an nRF52 target; offer its guarded 1200-baud serial-DFU handoff after backup consideration.');
  if(uartIds.has(id))return result('default_reset',false,'uart-usb',`USB ${id} identifies a supported UART bridge; use its qualified DTR/RTS ESP32 bootloader entry after backup.`);
  const description=typeof usbDescription==='string'&&usbDescription.length<=512?usbDescription:'';
  const tiny=/\bTinyUSB\b/i.test(description),jtag=/\b(?:USB[ -]JTAG[/ -](?:serial|debug)|USB\s+Serial[/ -]JTAG)\b/i.test(description);
  if(tiny&&jtag)return result(null,false,'conflict','Conflicting TinyUSB and USB-Serial/JTAG descriptor evidence; choose the connection method manually.');
  const reported=architecture==='esp32'&&device?.model?device.usbMode:null;
  if(['303a:1001','303a:0002','2886:0059'].includes(id)){
    if(reported==='hardware-cdc-jtag'){
      if(tiny||id!=='303a:1001')return result(null,false,'conflict','The running firmware reports hardware USB-Serial/JTAG, but the selected USB interface disagrees; choose the connection method manually.');
      return result('usb_reset',false,'application-report','The selected running firmware reports hardware USB-Serial/JTAG; use its qualified reset after backup.');
    }
    if(reported==='tinyusb'){
      if(jtag)return result(null,false,'conflict','The running firmware reports TinyUSB, but the selected descriptor reports hardware USB-Serial/JTAG; choose the connection method manually.');
      return result('tinyusb',false,'application-report','The selected running firmware reports TinyUSB; use its qualified control-line handoff at 115200 after backup.');
    }
    if(reported==='uart')return result(null,false,'conflict','The running firmware reports a UART primary console on a native USB interface; choose the connection method manually.');
    const fallback=architecture==='esp32'&&device?.model&&['unavailable','unsupported'].includes(device.usbModeStatus)&&device.usbModeFallback?.source==='firmware-map'?device.usbModeFallback:null;
    if(fallback?.usbMode==='hardware-cdc-jtag'){
      if(tiny||id!=='303a:1001')return result(null,false,'conflict','The reviewed running-firmware map and selected USB interface disagree; choose the connection method manually.');
      return result('usb_reset',false,'firmware-map',`${fallback.reason} Hardware USB-Serial/JTAG reset is selected from reviewed historical build data; backup and inspection still apply.`);
    }
    if(fallback?.usbMode==='tinyusb'){
      if(jtag)return result(null,false,'conflict','The reviewed running-firmware map and selected USB descriptor disagree; choose the connection method manually.');
      return result('tinyusb',false,'firmware-map',`${fallback.reason} TinyUSB handoff at 115200 is selected from reviewed historical build data; backup and inspection still apply.`);
    }
    if(fallback?.usbMode==='uart')return result(null,false,'conflict','The reviewed running-firmware map expects a UART console on this native USB interface; choose the connection method manually.');
  }
  if(id.startsWith('303a:')&&jtag)return result('usb_reset',false,'usb-descriptor','The selected port descriptor identifies hardware USB-Serial/JTAG; use its qualified reset after backup.');
  if((id.startsWith('303a:')||id==='2886:0059')&&tiny)return result('tinyusb',false,'usb-descriptor','The selected port descriptor identifies TinyUSB; offer its guarded control-line handoff at 115200 after backup.');
  // 303a:0002 can also be an ESP32-S2 ROM endpoint. Require a successful
  // application-model reply before classifying it as software USB CDC.
  // Hardware USB-Serial/JTAG has its fixed 303a:1001 identity instead.
  if(architecture==='esp32'&&device?.model&&(id==='303a:0002'||id==='2886:0059'))return result('tinyusb',false,'application-usb',`The running ESP32 application answered on USB ${id}; use its software-CDC control-line handoff at 115200 after backup.`);
  if(id==='303a:1001')return result(null,false,'shared-usb','USB 303a:1001 is shared by TinyUSB applications and hardware USB-Serial/JTAG. Web Serial cannot distinguish them from this ID or board model alone; choose manually unless an exact port descriptor is available.');
  return result(null,false,'unknown','No qualified automatic bootloader connection method was found. A missing application reply never proves ROM mode; choose the method manually.');
}
