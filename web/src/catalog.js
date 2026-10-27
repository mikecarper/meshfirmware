import {gzipSync,gunzipSync,strToU8,strFromU8} from 'fflate';

export function httpsUrl(value, base) {
  const url = new URL(value, base);
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error('Firmware URLs must use HTTPS without credentials.');
  return url.href;
}
export function compareVersions(a,b) {
  const parts=value=>{const match=String(value).match(/(?:^|\bv?)(\d+(?:\.\d+){0,3})(.*)$/i);return match?{numbers:match[1].split('.').map(Number),suffix:match[2]}:null;};
  const x=parts(a),y=parts(b);
  if(x&&y) {for(let i=0;i<Math.max(x.numbers.length,y.numbers.length);i++){const delta=(y.numbers[i]||0)-(x.numbers[i]||0);if(delta)return delta;}if(!x.suffix&&y.suffix)return -1;if(x.suffix&&!y.suffix)return 1;}
  return String(b).localeCompare(String(a),undefined,{numeric:true,sensitivity:'base'});
}
function assets(value,config) {return (Array.isArray(value)?value:value?[value]:[]).map(name=>httpsUrl(/^[a-z][a-z0-9+.-]*:|^\//i.test(name)?name:`${config.staticPath||'/firmware'}/${name}`,'https://flasher.meshcore.io'));}
function metadata(config,device,firmware,release={}) {
  const role=config.role?.[firmware.role]||{},bootloader=assets(device.bootloader,config).filter(url=>device.type!=='nrf52'||/\.zip(?:[?#]|$)/i.test(url));
  let notice=config.notice?.[firmware.notice]||firmware.notice||'';
  notice=String(notice).replace(/\$\{(\w+)\}/g,(_,field)=>field==='bootloader'?bootloader[0]||'':String(Array.isArray(device[field])?device[field][0]||'':device[field]||''));
  return {title:firmware.title||role.title||firmware.role,subtitle:firmware.subTitle||firmware.subtitle||role.subTitle||role.subtitle||'',notice:notice.replace(/<[^>]*>/g,' ').replace(/\s+/g,' ').trim(),bootloader,erase:assets(device.erase,config),releaseNotes:release.notes||release.description||'',maker:device.maker||'',hardwareVersion:device.version||device.hardwareVersion||''};
}
const publishedHash=file=>{const value=file.sha256||String(file.digest||'').replace(/^sha256:/,'');return /^[a-f0-9]{64}$/i.test(value||'')?value.toLowerCase():undefined;};
export function catalogItems(config, releases = [], provider = 'MeshCore') {
  const items = [];
  for (const device of config.device || []) for (const firmware of device.firmware || []) {
    if (firmware.github?.files) for (const [action, pattern] of Object.entries(firmware.github.files)) {
      if (String(pattern).length > 512) continue;
      let re; try { re = new RegExp(`^(?:${pattern})$`,'i'); } catch { continue; }
      for (const release of releases.filter(r => r.type === firmware.github.type)) for (const file of release.files || []) {
        if (!re.test(file.name)) continue;
        items.push({ project: 'MeshCore', provider, hardware: device.name, architecture: device.type, role: firmware.role, version: release.version, action, name: file.name, url: httpsUrl(file.url,'https://github.com/meshcore-dev/MeshCore'),sha256:publishedHash(file),...metadata(config,device,firmware,release) });
      }
    }
    for (const [version, release] of Object.entries(firmware.version || {})) for (const file of release.files || []) {
      const raw = file.url || (typeof file.name === 'string' && /^https:/.test(file.name) ? file.name : `${config.staticPath || '/firmware'}/${file.name}`);
      items.push({ project: 'MeshCore', provider, hardware: device.name, architecture: device.type, role: firmware.role, version, action: file.type, name: String(file.name).split('/').pop(), url: httpsUrl(raw,'https://flasher.meshcore.io'),sha256:publishedHash(file),...metadata(config,device,firmware,release),artifactTitle:file.title||'' });
    }
  }
  // nRF52 is always the CLI-style serial DFU path, never a UF2 drive action.
  return items.filter(item => item.architecture !== 'nrf52' || /\.zip$/i.test(item.name));
}
export function validateCatalog(value) {
  if(!value||!Array.isArray(value.items)||value.items.length>50000||!Array.isArray(value.warnings)||!Number.isFinite(Date.parse(value.generatedAt)))throw new Error('Invalid catalog snapshot.');
  for(const item of value.items) {if(item.project!=='MeshCore'||typeof item.name!=='string'||typeof item.hardware!=='string')throw new Error('Invalid catalog entry.');httpsUrl(item.url);for(const url of [...(item.erase||[]),...(item.bootloader||[])])httpsUrl(url);}
  return value;
}
function encodeCache(value) {
  const bytes=gzipSync(strToU8(JSON.stringify(value)),{level:6});let binary='';
  for(let i=0;i<bytes.length;i+=8192)binary+=String.fromCharCode(...bytes.subarray(i,i+8192));
  return JSON.stringify({encoding:'gzip-base64',data:btoa(binary)});
}
function decodeCache(raw) {
  if(typeof raw!=='string'||raw.length>(4<<20))throw new Error('Invalid cached catalog size.');
  const value=JSON.parse(raw);if(value?.encoding!=='gzip-base64')return value;
  const binary=atob(value.data),bytes=Uint8Array.from(binary,c=>c.charCodeAt(0));
  if(bytes.length<18||bytes.length>(2<<20)||bytes[0]!==31||bytes[1]!==139)throw new Error('Invalid compressed catalog.');
  const length=new DataView(bytes.buffer).getUint32(bytes.length-4,true);if(!length||length>(32<<20))throw new Error('Cached catalog expansion exceeds limit.');
  const expanded=gunzipSync(bytes);if(expanded.length!==length)throw new Error('Cached catalog length mismatch.');return JSON.parse(strFromU8(expanded));
}
export async function getCatalog({fetchImpl=fetch,storage}={}) {
  const key='meshfirmware.publicCatalog.v1';
  if(storage===undefined)try{storage=globalThis.localStorage;}catch{}
  try {
    const response = await fetchImpl(new URL('../catalog.json', import.meta.url),{cache:'no-cache'});
    if (!response.ok) throw new Error('Catalog snapshot unavailable.');
    const value=validateCatalog(await response.json());try{storage?.setItem(key,encodeCache(value));}catch{}return value;
  } catch(error) {
    try {const value=validateCatalog(decodeCache(storage?.getItem(key)));return {...value,cached:true,warnings:[...value.warnings,`Using cached public catalog from ${value.generatedAt}; refresh unavailable.`]};}catch{}
    throw new Error(`${error.message} Choose a local firmware file or an HTTPS URL.`);
  }
}
