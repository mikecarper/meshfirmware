import {zipSync} from 'fflate';
import {crc16,hash} from '../../src/firmware.js';
const encode=value=>new TextEncoder().encode(typeof value==='string'?value:JSON.stringify(value));
export function recoveryFixture({mutateManifest,mutateFiles,kind='softdevice_bootloader'}={}){
  const tag='v0.11.0-OTAFIX2.4.12',version='2.4.12',releaseUrl=`https://github.com/mikecarper/Adafruit_nRF52_Bootloader_OTAFIX/releases/tag/${tag}`,files={},inner={};
  const boards=['xiao_nrf52840_ble','xiao_nrf52840_ble_sense'].map((id,index)=>{
    const payload=new Uint8Array(192).fill(index+7),init=new Uint8Array(12),view=new DataView(init.buffer);view.setUint16(0,0x52,true);view.setUint16(10,crc16(payload),true);
    const item={bin_file:'sd_bl.bin',dat_file:'sd_bl.dat',...(kind==='softdevice_bootloader'?{sd_size:64,bl_size:128}:{})},name=`R_${id}_bootloader-${tag}_s140_7.3.0.zip`;
    const bytes=zipSync({'manifest.json':encode({manifest:{dfu_version:.5,[kind]:item}}),'sd_bl.dat':init,'sd_bl.bin':payload});inner[id]=bytes;
    const hex=name.replace(/\.zip$/,'.hex'),uf2=`update-R_${id}_bootloader-${tag}_mbr.uf2`,hexBytes=encode('fixture hex'),uf2Bytes=encode('fixture UF2');files[`boards/${id}/${name}`]=bytes;files[`boards/${id}/${hex}`]=hexBytes;files[`boards/${id}/${uf2}`]=uf2Bytes;
    return {board:id,device_name:'XIAO_DFU',bootloader_manifest_crc32:'0x1234ABCD',bootloader_sha256:hash(payload.subarray(64)),files:{[name]:hash(bytes),[hex]:hash(hexBytes),[uf2]:hash(uf2Bytes)}};
  });
  const manifest={tag,recovery_only:true,packed_bootloader_version:'0x02040CFF',board_count:boards.length,boards,excluded_boards:{unsupported_board:'No reviewed recovery profile.'}};
  mutateManifest?.(manifest);files['manifest.json']=encode(manifest);files['RECOVERY-README.md']=encode('Synthetic recovery test only.');mutateFiles?.(files);
  const bundle=zipSync(files),name=`OTAFIX-${version}-R_recovery.zip`,asset={name,size:bundle.length,browser_download_url:`https://github.com/mikecarper/Adafruit_nRF52_Bootloader_OTAFIX/releases/download/${tag}/${name}`,digest:`sha256:${hash(bundle)}`},release={tag_name:tag,html_url:releaseUrl,draft:false,prerelease:false,assets:[asset]};
  return {release,bundle,manifest,inner,files,asset,tag,version,releaseUrl};
}
