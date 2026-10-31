// Exact PUBLIC utilities fetched from the official flasher on 2026-10-31.
// Each ZIP also passed inspectFirmware's canonical erase/formatter payload
// checks. These pins authorize mirror contents only, never device writes.
const base='https://flasher.meshcore.io/firmware/';
export const publicEraseUtilities=Object.freeze([
  ['FLASH_ERASE_nrf52_softdevice_v6.zip',60547,'68cd6f6e5008f06b7de0b60288750f177e9a59c1e799063cdbfa47ea70ee835c','f17500b598ce53d4d4183f6bd20e06e9bf2bd3468d9a22ff3af7f148bb0dfc0c'],
  ['FLASH_ERASE_nrf52_softdevice_v7.zip',60547,'8c541e7b7296d6f4bd353266e125bdd6f61e19aaeb99c50792f5ae3ea005994e','01f8d553e5ce865312fcfe3ddf1eb06f10ed7ca6bd4f34dd81e58b6f8400be8e'],
  ['ThinkNode_M1_QSPIFlash_Format-v1.2.zip',66835,'a8d1da641c3291e4f1846016c3bf0d659ddb571e3454d87c550fbee326f0ecf1','5f704a28b9abe49998cad9a63565c855ae27d3af4bc8dd1870a468618025ceb2'],
  ['LilyGo_T-Echo_QSPIFlash_Format-v1.2.zip',66867,'4cb44c0b77ecfd53c44b5cc2be7a43b4ffc0c71b6639551ebdcf7c76c82d88e3','dc6f52a8c7c6734be1cc1d3ce9ee01db657acac1383bbd48f4be017408cb20b9'],
  ['WioTrackerL1_QSPIFlash_Format-v1.2.zip',66723,'b3e49b697921a0d739a928015822afb84639b8a9478d74ada5a92c71cc1c5b72','bfd6d72de724c4b84395a963c0428c89de245038a44f02241907838e6caf9e09'],
  ['Xiao_nrf52_QSPIFlash_Format-v1.2.zip',73251,'aace65588da8f71850f661d7e2026a9ae9d4030c68b0742a232e23bcbbd0cabf','400008ca61ead5d5ccd6a22278aef7555e0377e9982a676f17a030642384bd82'],
  ['Nano_G2_Ultra_QSPIFlash_Format-v1.2.zip',71323,'d04ebf1aa630efc71a1ada01f9a7c97f437102530eeba4bebdfcdb6501d9f4e0','c3580dcd94d4f9983a9bf1d5e40ff678b38c6e9074f5e287360f27e992f29174'],
].map(([name,size,sha256,payloadHash])=>Object.freeze({name,url:base+name,size,sha256,payloadHash})));

export const publicEraseUtility=url=>publicEraseUtilities.find(utility=>utility.url===url)||null;
