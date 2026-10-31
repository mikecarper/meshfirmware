// The mirror may publish only exact, public MeshCore migration release
// metadata and archives. This allowlist never authorizes a device operation.
const owner='mikecarper',repository='MeshCore';
const metadataBase=`https://api.github.com/repos/${owner}/${repository}/releases/tags/`;
const archiveBase=`https://github.com/${owner}/${repository}/releases/download/`;
const utilityTag=/^utility-v\d+(?:\.\d+){2,3}(?:-[A-Za-z0-9._-]+)?$/;
const sharedTag='utility-usb-partition-v1-3d3d5827';
const sharedName='meshcore-usb-partition-bridges.zip';

function canonicalUrl(value){
  if(typeof value!=='string'||value.length>2048)return null;
  let url;try{url=new URL(value);}catch{return null;}
  // Reject normalization aliases too (including :443, whitespace, dot paths,
  // and encoded tag characters). Allowed tags already contain URL-safe ASCII.
  if(url.protocol!=='https:'||url.port||url.username||url.password||url.search||url.hash||url.href!==value)return null;
  return url;
}

export function migrationMetadataSource(value){
  const url=canonicalUrl(value);if(!url||!value.startsWith(metadataBase))return null;
  const tag=value.slice(metadataBase.length);
  // The basename stays within common 255-byte filesystem component limits.
  if(tag.length>250||!utilityTag.test(tag))return null;
  return {url:value,owner,repository,tag,name:tag+'.json'};
}

export function isMigrationArchive(value){
  const url=canonicalUrl(value);if(!url||!value.startsWith(archiveBase))return false;
  const match=/^([^/]+)\/([A-Za-z0-9_.-]{1,256})$/.exec(value.slice(archiveBase.length));
  if(!match)return false;
  const [,tag,name]=match;
  if(tag===sharedTag)return name===sharedName;
  return tag.length<=250&&utilityTag.test(tag)&&(name===sharedName||/^.+-migration\.zip$/.test(name));
}
