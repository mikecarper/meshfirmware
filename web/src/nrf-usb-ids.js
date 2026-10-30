// Exact manufacturer/factory nRF52 bootloader USB identities. These identify
// serial-DFU mode only: shared IDs never establish the physical board or grant
// permission to write. Keep the UI and payload-safety checks on one inventory.
// Nano G2 Ultra and Muzi Base retain the factory descriptors reviewed in
// OTAFIX src/boards/{nano_g2_ultra,muzi_base}/board.h (2026-10-30).
export const nrfDfuUsbIds=Object.freeze([
  '2886:0044','2886:0045','2886:0057','2886:1667',
  '239a:0029','239a:002a','239a:0071','239a:0081','239a:00b3','239a:00da',
  '4251:8695',
]);
