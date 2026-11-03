import {BOOTLOADER_REPOSITORY,validateBootloaderSnapshot} from '../../src/bootloader-catalog.js';

// Synthetic public metadata for unit tests, not a downloadable release or a
// cached build output. Every call returns an independent, schema-checked copy.
export function xiaoBootloaderSnapshot(){
  const tag='v0.11.0-OTAFIX2.4.12',root=`https://github.com/${BOOTLOADER_REPOSITORY}`;
  const releaseUrl=`${root}/releases/tag/${tag}`,download=`${root}/releases/download/${tag}/`;
  const profiles=[
    ['xiao_nrf52840_ble','Xiao_nrf52','XIAO nRF52840','1'],
    ['xiao_nrf52840_ble_sense','Xiao_nrf52_Sense','XIAO nRF52840 Sense','2'],
  ].map(([id,hardware,label,digest])=>{
    const name=`${id}_bootloader-${tag}_s140_7.3.0.zip`;
    return {id,label,meshcoreHardware:[hardware],deviceName:'XIAO_DFU',storage:'qspi',files:{zip:{name,url:download+name,size:192834,sha256:digest.repeat(64)}}};
  });
  const manifest={schemaVersion:1,repository:BOOTLOADER_REPOSITORY,tag,version:'2.4.12',releaseUrl,prerelease:false,profiles,unavailableProfiles:[]};
  const release={tag_name:tag,html_url:releaseUrl,draft:false,prerelease:false,assets:[
    {name:'bootloader-manifest.json',browser_download_url:download+'bootloader-manifest.json',size:12345,digest:'sha256:'+'a'.repeat(64)},
    ...profiles.map(({files:{zip}})=>({name:zip.name,browser_download_url:zip.url,size:zip.size,digest:'sha256:'+zip.sha256})),
  ]};
  return validateBootloaderSnapshot({schemaVersion:1,checkedAt:'2026-10-27T05:00:00.000Z',release,manifest});
}
