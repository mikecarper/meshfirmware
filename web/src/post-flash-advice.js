// Display-only completion advice, never a write/connection capability.
// Keymind's serviceCompanionUsbBluetoothPriority() in companion_radio/main.cpp
// is guarded by T1000_E && USE_TINYUSB. It inhibits compiled BLE while a USB
// host is mounted; UsbBluetoothPriority releases it 500 ms after disconnect.
// Stock BLE and other boards do not share that policy. USB-only builds cannot
// gain Bluetooth by unplugging, and component/erase writes still need USB.
export function postFlashBleAdvice(pkg,item=null) {
  if(pkg?.architecture!=='nrf52'||pkg.kind!=='application'||pkg.erase||pkg.expert)return '';
  const name=typeof pkg.name==='string'?pkg.name:'';
  // An application may embed its own updater. That is not a component DFU
  // package; allow only the explicit, versioned application-wrapper marker.
  const componentName=name.replace(/-with-bootloader-\d+(?:\.\d+){1,3}(?=-|\.zip$)/ig,'');
  if(/(?:^|[_.\s-])(?:bootloader|softdevice|erase|formatter|format|recovery)(?:[_.\s-]|$)|^R_/i.test(componentName))return '';
  // Only the exact selected artifact may contribute provider/board/role
  // metadata. A previous radio or a board-wide custom-file hint cannot.
  const exact=item?.name===name?item:null;
  const keymind=/^Keymind Cascade(?: Logging)?$/i.test(exact?.provider||'')||/(?:^|[-_])keymind(?:[-_]|$)/i.test(name);
  if(!keymind)return '';
  if(exact?.hardware&&exact.hardware!=='Seeed Studio SenseCAP T1000-E')return '';
  const target=/^t1000e_companion_radio_(?:full|ble)(?:[-_.]|$)/i.test(name);
  const catalog=exact?.hardware==='Seeed Studio SenseCAP T1000-E'&&['companionFull','companionBle'].includes(exact.role);
  if(!target&&!catalog)return '';
  // An explicit USB-only/non-companion role outranks filename hints.
  if(exact?.role&&!['companionFull','companionBle'].includes(exact.role))return '';
  return 'T1000-E: Bluetooth (BLE) stays off while connected to a computer by USB. Finish any USB verification, then unplug USB to use BLE (if enabled in settings).';
}
