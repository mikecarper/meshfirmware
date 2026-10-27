import test from 'node:test';
import assert from 'node:assert/strict';
import {zipSync} from 'fflate';
import {nrfEraseIntent,nrfPackage,crc16} from '../src/firmware.js';
// Read-only reference fetches from official /firmware/ URLs on 2026-10-27.
// The BIN hash is stable across archive renaming/repacking, unlike ZIP hashes.
const published=[
  ['WioTrackerL1','bfd6d72de724c4b84395a963c0428c89de245038a44f02241907838e6caf9e09'],
  ['LilyGo_T-Echo','dc6f52a8c7c6734be1cc1d3ce9ee01db657acac1383bbd48f4be017408cb20b9'],
  ['Xiao_nrf52','400008ca61ead5d5ccd6a22278aef7555e0377e9982a676f17a030642384bd82'],
  ['ThinkNode_M1','5f704a28b9abe49998cad9a63565c855ae27d3af4bc8dd1870a468618025ceb2'],
  ['Nano_G2_Ultra','c3580dcd94d4f9983a9bf1d5e40ff678b38c6e9074f5e287360f27e992f29174']
];
const encode=s=>new TextEncoder().encode(s);
function archive(binName='firmware.bin'){
  const payload=new Uint8Array(256),init=new Uint8Array(12),v=new DataView(init.buffer);v.setUint16(0,0x52,true);v.setUint16(10,crc16(payload),true);
  return zipSync({'manifest.json':encode(JSON.stringify({manifest:{dfu_version:.5,application:{bin_file:binName,dat_file:'firmware.dat'}}})),[binName]:payload,'firmware.dat':init});
}
test('all five official QSPI utilities retain destructive proof when renamed',()=>{
  for(const [board,digest]of published){const evidence=nrfEraseIntent('renamed.zip',digest);assert.equal(evidence,`official QSPI formatter payload (${board} v1.2)`);}
});
test('published formatter names and inner format names conservatively require destructive acknowledgement',()=>{
  for(const [board]of published){const pkg=nrfPackage(`${board}_QSPIFlash_Format-v1.2.zip`,archive());assert.equal(pkg.kind,'application');assert.equal(pkg.erase,true);assert.equal(pkg.destructive,true);}
  const inside=nrfPackage('renamed.zip',archive('qspi_flash_format.bin'));assert.equal(inside.destructive,true);assert.equal(inside.erase,true);
  assert.equal(nrfPackage('ordinary.zip',archive()).destructive,false);
});
