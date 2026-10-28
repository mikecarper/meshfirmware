const pickerBase='https://mikecarper.github.io/MeshCore/firmware_picker/';
const pickerResults='firmware-picker-1-results';
const stockReleases='https://github.com/meshcore-dev/MeshCore/releases';
const canonicalProvider=value=>value==='Keymind Cascade Logging'?'Keymind Cascade':value;
const roles=Object.freeze({companionBle:'companion',companionUsb:'companion',companionFull:'companion',companion:'companion',repeater:'repeater',roomServer:'room',room:'room',sensor:'sensor',kissRadio:'kiss',kiss:'kiss'});
const hardwareId=value=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$/.test(value)?value:null;

function safeHttps(value){
  if(typeof value!=='string'||value.length>4096||/[\u0000-\u0020\u007f]/.test(value))return null;
  try{const url=new URL(value);return url.protocol==='https:'&&!url.username&&!url.password?url:null;}catch{return null;}
}

function hardwareEvidence(item){
  const ids=new Set(),declared=hardwareId(item?.bootloaderInfo?.hardwareId);
  if(declared)ids.add(declared);
  const notes=typeof item?.releaseNotes==='string'?item.releaseNotes.slice(0,100000):'';
  for(const match of notes.matchAll(/\bSETUP\s*-\s*(https:\/\/[^\s<>"']+)/gi)){
    // Do not forward metadata URLs or their queries. Read only the public
    // hardware identifier from our exact picker endpoint, then rebuild a URL.
    const raw=match[1],url=safeHttps(raw);
    if(!url||!/^https:\/\/mikecarper\.github\.io\//i.test(raw)||url.origin!=='https://mikecarper.github.io'||!['/MeshCore/firmware_picker/','/MeshCore/firmware_picker'].includes(url.pathname))continue;
    const values=url.searchParams.getAll('hardware');
    if(values.length!==1)continue;
    const id=hardwareId(values[0]);if(id)ids.add(id);
  }
  return ids;
}

/** Public browse/download links only; never infer a board from its filename. */
export function firmwareFilesLinks({items=[],item=null,provider='Keymind Cascade',hardware='',role=''}={}){
  const selected=item&&typeof item==='object'?item:null;
  const chosenProvider=canonicalProvider(selected?.provider||provider)||'Keymind Cascade';
  const chosenRole=selected?(typeof selected.role==='string'?selected.role:''):role;
  const download=safeHttps(selected?.url),downloadUrl=download?.href||null;
  if(chosenProvider==='MeshCore'){
    let browseUrl=stockReleases;
    const match=download?.origin==='https://github.com'&&/^\/meshcore-dev\/MeshCore\/releases\/download\/([^/]+)\/[^/]+$/i.exec(download.pathname);
    if(match)browseUrl=stockReleases+'/tag/'+match[1];
    return {browseUrl,downloadUrl,detail:'Browse stock MeshCore firmware releases. Download selected build keeps the exact selected file and version.'};
  }

  const candidates=selected?[selected]:hardware&&Array.isArray(items)?items.filter(candidate=>candidate&&canonicalProvider(candidate.provider)===chosenProvider&&candidate.hardware===hardware&&(!role||candidate.role===role)):[];
  const evidence=new Set();
  if(chosenProvider==='Keymind Cascade')for(const candidate of candidates)for(const id of hardwareEvidence(candidate))evidence.add(id);
  const id=evidence.size===1?[...evidence][0]:null;
  const url=new URL(pickerBase),parts=['1'];
  const encode=value=>encodeURIComponent(value).replace(/\./g,'%2E');
  if(id)parts.push('h'+encode(id));
  const roleId=typeof chosenRole==='string'&&Object.hasOwn(roles,chosenRole)?roles[chosenRole]:null;
  if(roleId)parts.push('r'+encode(roleId));
  if(parts.length>1)url.searchParams.set('s',parts.join('.'));
  url.hash=pickerResults;
  return {browseUrl:url.href,downloadUrl,detail:'Browse current Keymind Cascade firmware files'+(id?' for this hardware':'; choose hardware in the picker')+'. Download selected build keeps the exact selected file and version.'};
}
