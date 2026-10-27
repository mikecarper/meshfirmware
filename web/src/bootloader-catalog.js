// Public download metadata only. Never infer a bootloader from shared USB IDs,
// a similar board name, an R_ recovery archive, or an unqualified source port.
export const BOOTLOADER_REPOSITORY='mikecarper/Adafruit_nRF52_Bootloader_OTAFIX';
export const BOOTLOADER_LATEST_URL=`https://api.github.com/repos/${BOOTLOADER_REPOSITORY}/releases/latest`;
const github=`https://github.com/${BOOTLOADER_REPOSITORY}`;
const fail=message=>{throw new Error(message);};
const sha=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const text=(value,max=256)=>typeof value==='string'&&value.trim()&&value.length<=max;
const assetFields=asset=>({name:asset.name,browser_download_url:asset.browser_download_url,size:asset.size,digest:asset.digest});

function releaseInfo(release) {
  if(!release||release.draft!==false||release.prerelease!==false||typeof release.tag_name!=='string'||!/^(?:v?[0-9]+\.[0-9]+\.[0-9]+-)?OTAFIX[0-9]+\.[0-9]+\.[0-9]+$/.test(release.tag_name)||release.html_url!==`${github}/releases/tag/${release.tag_name}`||!Array.isArray(release.assets)||release.assets.length>4096)fail('Expected the published stable OTAFIX release, never a recovery or prerelease tag.');
  return {tag:release.tag_name,version:release.tag_name.split('OTAFIX')[1],releaseUrl:release.html_url};
}
function checkedAsset(asset,tag,maxSize) {
  if(!asset||typeof asset.name!=='string'||!/^[A-Za-z0-9_.-]{1,256}$/.test(asset.name)||asset.browser_download_url!==`${github}/releases/download/${tag}/${asset.name}`||!Number.isInteger(asset.size)||asset.size<=0||asset.size>maxSize||typeof asset.digest!=='string'||!/^sha256:[a-f0-9]{64}$/.test(asset.digest))fail('OTAFIX release asset has an invalid URL, size or SHA-256.');
  return asset;
}
export function bootloaderManifestAsset(release) {
  const {tag}=releaseInfo(release),matches=release.assets.filter(asset=>asset.name==='bootloader-manifest.json');
  if(matches.length!==1)fail('Latest stable OTAFIX release has no unique bootloader download manifest.');
  return checkedAsset(matches[0],tag,1<<20);
}

export function validateBootloaderSnapshot(snapshot) {
  if(!snapshot||snapshot.schemaVersion!==1||typeof snapshot.checkedAt!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(snapshot.checkedAt)||!Number.isFinite(Date.parse(snapshot.checkedAt)))fail('Invalid verified OTAFIX snapshot or checkedAt timestamp.');
  const release=snapshot.release,{tag,version,releaseUrl}=releaseInfo(release),manifestAsset=bootloaderManifestAsset(release),manifest=snapshot.manifest;
  if(!manifest||manifest.schemaVersion!==1||manifest.repository!==BOOTLOADER_REPOSITORY||manifest.tag!==tag||manifest.version!==version||manifest.releaseUrl!==releaseUrl||manifest.prerelease!==false||!Array.isArray(manifest.profiles)||!manifest.profiles.length||manifest.profiles.length>128||!Array.isArray(manifest.unavailableProfiles||[])||(manifest.unavailableProfiles||[]).length>128)fail('OTAFIX download manifest does not match the verified stable release.');
  const ids=new Set(),aliases=new Set(),assets=[assetFields(manifestAsset)];
  const profileIdentity=profile=>{
    if(!profile||typeof profile.id!=='string'||!/^[a-z0-9_]{1,80}$/.test(profile.id)||ids.has(profile.id)||!text(profile.label)||!Array.isArray(profile.meshcoreHardware)||!profile.meshcoreHardware.length||profile.meshcoreHardware.length>256)fail('Invalid or duplicate OTAFIX board profile.');
    ids.add(profile.id);
    for(const name of profile.meshcoreHardware){if(typeof name!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(name)||aliases.has(name))fail('Ambiguous OTAFIX hardware mapping.');aliases.add(name);}
    return {id:profile.id,label:profile.label,meshcoreHardware:[...profile.meshcoreHardware]};
  };
  const profiles=manifest.profiles.map(profile=>{
    const identity=profileIdentity(profile),file=profile.files?.zip,prefix=`${profile.id}_bootloader-${tag}_s140_`;
    if(!text(profile.deviceName,32)||!/^[A-Za-z0-9_-]+$/.test(profile.deviceName)||!['internal','qspi','sd','adaptive'].includes(profile.storage)||!file||typeof file.name!=='string'||!file.name.startsWith(prefix)||!/^[0-9]+\.[0-9]+\.[0-9]+\.zip$/.test(file.name.slice(prefix.length))||!sha(file.sha256))fail('Invalid normal OTAFIX serial DFU ZIP metadata.');
    const matches=release.assets.filter(asset=>asset.name===file.name);
    if(matches.length!==1)fail('OTAFIX normal DFU ZIP is missing or ambiguous in the release.');
    const asset=checkedAsset(matches[0],tag,4<<20);
    if(file.url!==asset.browser_download_url||file.size!==asset.size||`sha256:${file.sha256}`!==asset.digest)fail('OTAFIX DFU ZIP differs from the uploaded release asset.');
    assets.push(assetFields(asset));
    return {...identity,deviceName:profile.deviceName,storage:profile.storage,files:{zip:{name:file.name,url:file.url,size:file.size,sha256:file.sha256}}};
  });
  const unavailableProfiles=(manifest.unavailableProfiles||[]).map(profile=>{
    const identity=profileIdentity(profile);if(!text(profile.reason,4000)||profile.files)fail('Unavailable OTAFIX profiles cannot offer a download.');
    return {...identity,reason:profile.reason};
  });
  return {schemaVersion:1,checkedAt:snapshot.checkedAt,cached:snapshot.cached===true,release:{tag_name:tag,html_url:releaseUrl,draft:false,prerelease:false,assets},manifest:{schemaVersion:1,repository:BOOTLOADER_REPOSITORY,tag,version,releaseUrl,prerelease:false,profiles,unavailableProfiles}};
}

function hardwareEvidence(item,aliases) {
  const setup=new Set();
  if(['Keymind Cascade','Keymind Cascade Logging'].includes(item.provider))for(const match of String(item.releaseNotes||'').matchAll(/\bSETUP\s*-\s*(https:\/\/[^\s<>"']+)/g)){
    try{const url=new URL(match[1]);if(url.origin==='https://mikecarper.github.io'&&['/MeshCore/firmware_picker/','/MeshCore/firmware_picker'].includes(url.pathname)&&url.searchParams.getAll('hardware').length===1)setup.add(url.searchParams.get('hardware'));}catch{}
  }
  const name=String(item.name||'').split(/[\\/]/).pop(),matches=[...aliases.keys()].filter(id=>name.startsWith(id+'_')&&/^(?:companion|repeater|room_server|sensor|kiss_modem|kiss_radio)(?:[_-]|$)/i.test(name.slice(id.length+1))),longest=Math.max(0,...matches.map(id=>id.length)),filename=matches.filter(id=>id.length===longest);
  const evidence=new Set([...setup,...filename]);
  if(evidence.size!==1)return {reason:evidence.size?'Conflicting exact hardware evidence; select the physical board’s bootloader manually.':'No exact released OTAFIX hardware mapping was found; select a verified board-specific ZIP manually.'};
  const hardwareId=[...evidence][0],profile=aliases.get(hardwareId);
  if(!profile)return {hardwareId,reason:`OTAFIX does not publish an exact verified bootloader mapping for ${hardwareId}.`};
  return {hardwareId,profile};
}
const unavailableNotice='No verified automatic OTAFIX bootloader recommendation is available.';
function updatedNotice(item,replacement=null){
  if(typeof item.notice!=='string')return {};
  let notice=item.notice;
  for(const previous of item.bootloader||[])if(typeof previous==='string'&&previous)notice=notice.split(previous).join(replacement||unavailableNotice);
  if(replacement)notice=notice.split(unavailableNotice).join(replacement);
  return notice===item.notice?{}:{notice};
}

export function applyBootloaderCatalog(items,snapshot=null,{unavailableReason}={}) {
  const verified=snapshot?validateBootloaderSnapshot(snapshot):null,manifest=verified?.manifest,aliases=new Map();
  if(manifest)for(const profile of [...manifest.profiles,...manifest.unavailableProfiles])for(const id of profile.meshcoreHardware)aliases.set(id,profile);
  return items.map(item=>{
    if(item.architecture!=='nrf52')return item;
    const {bootloaderInfo:oldInfo,bootloaderUnavailable:oldUnavailable,...base}=item;
    if(!manifest)return {...base,...updatedNotice(item),bootloader:[],bootloaderUnavailable:unavailableReason||'The latest OTAFIX release could not be verified and no verified cached release is available. Automatic bootloader recommendations are disabled; application firmware remains available.'};
    const evidence=hardwareEvidence(item,aliases),profile=evidence.profile;
    if(!profile?.files?.zip)return {...base,...updatedNotice(item),bootloader:[],bootloaderUnavailable:evidence.reason||profile.reason};
    const file=profile.files.zip;
    return {...base,...updatedNotice(item,file.url),bootloader:[file.url],bootloaderInfo:{version:manifest.version,tag:manifest.tag,profile:profile.id,hardwareId:evidence.hardwareId,label:profile.label,deviceName:profile.deviceName,storage:profile.storage,url:file.url,sha256:file.sha256,size:file.size,releaseUrl:manifest.releaseUrl,checkedAt:verified.checkedAt,cached:verified.cached}};
  });
}
