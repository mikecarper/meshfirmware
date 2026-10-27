// Recovery is an explicit installed-bootloader profile choice, never a normal
// recommendation and never a guess from a shared USB/BLE advertised identity.
import {BOOTLOADER_REPOSITORY} from './bootloader-catalog.js';
import {checkedZip,hash,nrfPackage} from './firmware.js';

const origin=`https://github.com/${BOOTLOADER_REPOSITORY}`;
const fail=message=>{throw new Error(message);};
const sha=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const id=value=>typeof value==='string'&&/^[a-z0-9_]{1,80}$/.test(value)&&!['__proto__','constructor','prototype'].includes(value);
const identity=value=>typeof value==='string'&&/^[A-Za-z0-9_-]{1,32}$/.test(value);
const crc=value=>typeof value==='string'&&/^0x[0-9a-f]{8}$/i.test(value);
const normalizedCrc=value=>'0x'+value.slice(2).toUpperCase();
const assetFields=asset=>({name:asset.name,browser_download_url:asset.browser_download_url,size:asset.size,digest:asset.digest});

function releaseInfo(release){
  const match=typeof release?.tag_name==='string'&&/^(?:v?[0-9]+\.[0-9]+\.[0-9]+-)?OTAFIX([0-9]+)\.([0-9]+)\.([0-9]+)$/.exec(release.tag_name);
  if(!match||release.draft!==false||release.prerelease!==false||release.html_url!==`${origin}/releases/tag/${release.tag_name}`||!Array.isArray(release.assets)||release.assets.length>4096)fail('Recovery metadata requires the published stable OTAFIX release, never an R_ or prerelease tag.');
  const numbers=match.slice(1).map(Number);if(numbers.some(n=>!Number.isInteger(n)||n<0||n>255))fail('Unsupported packed OTAFIX recovery version.');
  return {tag:release.tag_name,version:match.slice(1).join('.'),releaseUrl:release.html_url,packed:(numbers[0]*2**24+numbers[1]*2**16+numbers[2]*256+255)>>>0};
}
export function recoveryBundleAsset(release){
  const {tag,version}=releaseInfo(release),name=`OTAFIX-${version}-R_recovery.zip`,matches=release.assets.filter(asset=>asset?.name===name);
  if(matches.length!==1)fail('Stable OTAFIX release has no unique R_ recovery bundle.');
  const asset=matches[0];
  if(asset.browser_download_url!==`${origin}/releases/download/${tag}/${name}`||!Number.isInteger(asset.size)||asset.size<22||asset.size>(32<<20)||typeof asset.digest!=='string'||!/^sha256:[a-f0-9]{64}$/.test(asset.digest))fail('Recovery bundle has an invalid release URL, size or SHA-256.');
  return assetFields(asset);
}
function checkedAt(value){if(typeof value!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)||!Number.isFinite(Date.parse(value)))fail('Invalid recovery catalog checkedAt timestamp.');return value;}
function profile(value,tag){
  if(!value||!id(value.id)||!identity(value.installedIdentity)||typeof value.name!=='string'||!value.name.startsWith(`R_${value.id}_bootloader-${tag}_s140_`)||!/^[0-9]+\.[0-9]+\.[0-9]+\.zip$/.test(value.name.slice(`R_${value.id}_bootloader-${tag}_s140_`.length))||value.entry!==`boards/${value.id}/${value.name}`||!Number.isInteger(value.size)||value.size<22||value.size>(4<<20)||!sha(value.sha256)||!sha(value.bootloaderSha256)||!crc(value.manifestCrc32))fail('Invalid exact installed-bootloader recovery profile or nested DFU ZIP.');
  return {id:value.id,installedIdentity:value.installedIdentity,entry:value.entry,name:value.name,size:value.size,sha256:value.sha256,bootloaderSha256:value.bootloaderSha256,manifestCrc32:normalizedCrc(value.manifestCrc32)};
}
export function validateRecoveryCatalog(snapshot){
  if(!snapshot||snapshot.schemaVersion!==1)fail('Invalid recovery catalog schema.');
  checkedAt(snapshot.checkedAt);const {tag,version,releaseUrl}=releaseInfo(snapshot.release),asset=recoveryBundleAsset(snapshot.release),bundle=snapshot.bundle;
  if(snapshot.tag!==tag||snapshot.version!==version||snapshot.releaseUrl!==releaseUrl||!bundle||bundle.name!==asset.name||bundle.url!==asset.browser_download_url||bundle.size!==asset.size||bundle.sha256!==asset.digest.slice(7)||!Array.isArray(snapshot.profiles)||!snapshot.profiles.length||snapshot.profiles.length>128)fail('Recovery snapshot differs from its stable release bundle metadata.');
  const profiles=snapshot.profiles.map(value=>profile(value,tag)).sort((a,b)=>a.id.localeCompare(b.id));
  if(new Set(profiles.map(p=>p.id)).size!==profiles.length||new Set(profiles.map(p=>p.entry)).size!==profiles.length)fail('Duplicate recovery profile or ZIP entry.');
  return {schemaVersion:1,checkedAt:snapshot.checkedAt,cached:snapshot.cached===true,release:{tag_name:tag,html_url:releaseUrl,draft:false,prerelease:false,assets:[asset]},tag,version,releaseUrl,bundle:{name:asset.name,url:asset.browser_download_url,size:asset.size,sha256:asset.digest.slice(7)},profiles};
}
function parsedBundle(release,bundleBytes,when){
  const info=releaseInfo(release),asset=recoveryBundleAsset(release);checkedAt(when);
  // The trusted release digest is checked before any ZIP directory parsing or
  // decompression. No inferred URL or unverified archive becomes selectable.
  if(!(bundleBytes instanceof Uint8Array)||bundleBytes.length!==asset.size||hash(bundleBytes)!==asset.digest.slice(7))fail('Recovery bundle size or SHA-256 differs from the release asset.');
  const options={maxEntries:1024,maxExpanded:64<<20},records=checkedZip(bundleBytes,{...options,directoryOnly:true}),inventory=new Map(records.map(record=>[record.name,record]));
  if(!inventory.has('manifest.json')||inventory.get('manifest.json').length>(1<<20))fail('Recovery root manifest is missing or oversized.');
  const rootBytes=checkedZip(bundleBytes,{...options,select:name=>name==='manifest.json'})['manifest.json'];let manifest;
  try{manifest=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(rootBytes));}catch{fail('Recovery root manifest is not valid UTF-8 JSON.');}
  if(!manifest||manifest.tag!==info.tag||manifest.recovery_only!==true||!crc(manifest.packed_bootloader_version)||parseInt(manifest.packed_bootloader_version.slice(2),16)!==info.packed||!Number.isInteger(manifest.board_count)||manifest.board_count<1||manifest.board_count>128||!Array.isArray(manifest.boards)||manifest.boards.length!==manifest.board_count)fail('Recovery root manifest tag, recovery-only marker, packed version or board count is invalid.');
  const ids=new Set(),selected=new Set();
  const profiles=manifest.boards.map(board=>{
    if(!board||!id(board.board)||ids.has(board.board)||!identity(board.device_name)||!sha(board.bootloader_sha256)||!crc(board.bootloader_manifest_crc32)||!board.files||typeof board.files!=='object'||Array.isArray(board.files)||Object.keys(board.files).length>16||Object.values(board.files).some(value=>!sha(value)))fail('Invalid or duplicate recovery board metadata.');
    ids.add(board.board);const names=Object.keys(board.files).filter(name=>/\.zip$/i.test(name));if(names.length!==1)fail('Each recovery profile must declare exactly one serial DFU ZIP.');
    const name=names[0],entry=`boards/${board.board}/${name}`,record=inventory.get(entry);if(!record)fail('Declared recovery DFU ZIP is missing from its exact board directory.');
    const result=profile({id:board.board,installedIdentity:board.device_name,name,entry,size:record.length,sha256:board.files[name],bootloaderSha256:board.bootloader_sha256,manifestCrc32:board.bootloader_manifest_crc32},info.tag);selected.add(entry);return result;
  });
  if(records.filter(record=>/\.zip$/i.test(record.name)).some(record=>!selected.has(record.name)))fail('Recovery bundle contains an undeclared or ambiguous nested ZIP.');
  const packages=checkedZip(bundleBytes,{...options,select:name=>selected.has(name)});
  for(const value of profiles){
    const bytes=packages[value.entry];if(bytes.length!==value.size||hash(bytes)!==value.sha256)fail(`Recovery ZIP hash or size differs for ${value.id}.`);
    const pkg=nrfPackage(value.name,bytes);
    if(pkg.kind!=='softdevice_bootloader'||pkg.erase||!pkg.destructive||!pkg.sdSize||!pkg.blSize||hash(pkg.payload.subarray(pkg.sdSize))!==value.bootloaderSha256)fail(`Recovery ZIP is not the declared combined SoftDevice/bootloader for ${value.id}.`);
  }
  const snapshot=validateRecoveryCatalog({schemaVersion:1,checkedAt:when,cached:false,release,tag:info.tag,version:info.version,releaseUrl:info.releaseUrl,bundle:{name:asset.name,url:asset.browser_download_url,size:asset.size,sha256:asset.digest.slice(7)},profiles});
  return {snapshot,packages};
}
export function createRecoveryCatalog(release,bundleBytes,when){return parsedBundle(release,bundleBytes,when).snapshot;}
export function recoveryPackage(snapshot,profileId,bundleBytes){
  const expected=validateRecoveryCatalog(snapshot);
  if(!id(profileId))fail('Select the exact installed bootloader profile manually, not its advertised identity.');
  const {snapshot:actual,packages}=parsedBundle(expected.release,bundleBytes,expected.checkedAt);
  if(JSON.stringify(actual.profiles)!==JSON.stringify(expected.profiles))fail('Cached recovery profiles differ from the verified raw bundle manifest.');
  const selected=actual.profiles.find(value=>value.id===profileId);if(!selected)fail('The selected installed bootloader profile is not in this verified recovery bundle.');
  return {name:selected.name,bytes:packages[selected.entry],profile:selected};
}
