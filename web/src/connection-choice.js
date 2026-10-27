// Selection only: never opens a port, asserts control lines, resets, or writes.
// Every returned strategy still needs the existing backup/inspection/write gates.
import {isKnownDfu} from './board-safety.js';

const uartIds=new Set([
  '1a86:7523','1a86:5523','1a86:7522','1a86:55d4', // CH340/341/343
  '10c4:ea60','10c4:ea70','10c4:ea71',             // CP210x
  '0403:6001','0403:6010','0403:6011','0403:6015', // FTDI
]);
const usbId=info=>[info?.usbVendorId,info?.usbProductId].every(n=>Number.isInteger(n)&&n>=0&&n<=65535)?[info.usbVendorId,info.usbProductId].map(n=>n.toString(16).padStart(4,'0')).join(':'):'';
const result=(mode,alreadyBootloader,source,reason)=>({mode,alreadyBootloader,source,reason});

// device.architecture must come from the exact matched running-firmware model,
// not a proposed image filename. usbDescription, when supplied, must describe
// this selected port (e.g. a separately granted matching USB descriptor).
// Web Serial itself does not expose product/interface strings.
export function chooseConnection({usbInfo={},device=null,usbDescription='',alreadyBootloader=false,handoff=false,packageArchitecture=null}={}) {
  const id=usbId(usbInfo),architecture=device?.architecture||null;
  if(isKnownDfu(usbInfo||{}))return result('nrf52',true,'dfu-usb','Known nRF52 DFU interface; serial DFU needs no 1200-baud touch. USB IDs are a mode hint, not physical-board proof.');
  if(alreadyBootloader===true||handoff===true){
    if(architecture==='nrf52'||packageArchitecture==='nrf52')return result('nrf52',true,'explicit-bootloader','Explicit nRF52 bootloader handoff; use the selected serial DFU interface without another reset.');
    return result('no_reset',true,'explicit-bootloader','Explicit ROM/bootloader handoff; inspect this selected interface without another reset.');
  }
  if(architecture==='nrf52')return result('nrf52',false,'application-model','Running MeshCore model identifies an nRF52 target; offer its guarded 1200-baud serial-DFU handoff after backup.');
  if(uartIds.has(id))return result('default_reset',false,'uart-usb',`USB ${id} identifies a supported UART bridge; use its qualified DTR/RTS ESP32 bootloader entry after backup.`);
  const description=typeof usbDescription==='string'&&usbDescription.length<=512?usbDescription:'';
  const tiny=/\bTinyUSB\b/i.test(description),jtag=/\b(?:USB[ -]JTAG[/ -](?:serial|debug)|USB\s+Serial[/ -]JTAG)\b/i.test(description);
  if(tiny&&jtag)return result(null,false,'conflict','Conflicting TinyUSB and USB-Serial/JTAG descriptor evidence; choose the connection method manually.');
  if(id.startsWith('303a:')&&jtag)return result('usb_reset',false,'usb-descriptor','The selected port descriptor identifies hardware USB-Serial/JTAG; use its qualified reset after backup.');
  if((id.startsWith('303a:')||id==='2886:0059')&&tiny)return result('tinyusb',false,'usb-descriptor','The selected port descriptor identifies TinyUSB; offer its guarded 1200-baud handoff after backup.');
  // 303a:0002 can also be an ESP32-S2 ROM endpoint. Require a successful
  // application-model reply before classifying it as software USB CDC.
  // Hardware USB-Serial/JTAG has its fixed 303a:1001 identity instead.
  if(architecture==='esp32'&&device?.model&&(id==='303a:0002'||id==='2886:0059'))return result('tinyusb',false,'application-usb',`The running ESP32 application answered on USB ${id}; use its software-CDC 1200-baud handoff after backup.`);
  if(id==='303a:1001')return result(null,false,'shared-usb','USB 303a:1001 is shared by TinyUSB applications and hardware USB-Serial/JTAG. Web Serial cannot distinguish them from this ID or board model alone; choose manually unless an exact port descriptor is available.');
  return result(null,false,'unknown','No qualified automatic bootloader connection method was found. A missing application reply never proves ROM mode; choose the method manually.');
}
