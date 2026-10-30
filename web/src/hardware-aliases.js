// Exact provider display-name aliases for the same reviewed physical target.
// Never normalize real radio, display, power, storage or carrier variants.
const aliases=new Map([
  ['Seeed Studio Wio Tracker L1 EINK','Seeed Studio Wio Tracker L1 E-Ink'],
  ['Seeed Studio SenseCAP MeshTracker X1','Seeed SenseCAP MeshTracker X1'],
  ['Seeed Studio SenseCAP Solar Node P1','Seeed Studio SenseCAP Solar'],
  ['Heltec Heltec Wireless Paper','Heltec Wireless Paper'],
]);

export const canonicalHardware=value=>aliases.get(value)||value;
