import {hash} from './firmware.js';
import {endfIdentity} from './board-safety.js';
import {findFirmwareSources} from './downloads.js';

const sha=value=>typeof value==='string'&&/^[a-f0-9]{64}$/i.test(value);
const roles={repeater:'repeater',repeatr:'repeater',room_server:'roomServer',room_svr:'roomServer',sensor:'sensor'};

function sourceIdentity(value,version){
  let url;try{url=new URL(value);}catch{return null;}
  if(url.origin!=='https://github.com'||url.username||url.password||url.search||url.hash||url.href!==value)return null;
  const route=/^\/mikecarper\/MeshCore\/releases\/download\/[^/]+\/([^/]+)$/.exec(url.pathname);
  if(!route)return null;
  let name;try{name=decodeURIComponent(route[1]);}catch{return null;}
  if(name.length>240||!/^[A-Za-z0-9_.-]+\.bin$/.test(name)||/-(?:merged|factory)(?:[.-]|$)|bootloader|full.?install/i.test(name))return null;
  // Same release-identity grammar as the unchanged shared expansion helper.
  const release=/(?:^|[-_])(v\d+(?:\.\d+){2,3}-[A-Za-z0-9][A-Za-z0-9._-]*?)-([0-9a-f]{8,40})\.bin$/.exec(name);
  if(!release)return null;
  const numbers=/^v(\d+(?:\.\d+){2,3})(?:-|$)/.exec(release[1])?.[1].split('.').map(Number);
  if(!numbers||numbers.some(number=>number>255))return null;
  while(numbers.length<4)numbers.push(0);
  if(numbers.reduce((result,number)=>result*256+number,0)!==version)return null;
  const profile=name.slice(0,release.index),target=/^(.+?)[_-](repeater|repeatr|room_server|room_svr|sensor)(?=[_-]|$)/i.exec(profile);
  if(!target)return null;
  return {name,url:value,firmwareVersion:release[1],sourceCommit:release[2],
    family:target[1].toLowerCase(),role:roles[target[2].toLowerCase()]};
}

// Recover only publication provenance for a byte-identical application. This
// never changes the bytes, display filename or board choice and cannot approve
// expansion: the shared Python helper still validates its exact ZIP and bridge.
export async function resolveCustomFirmwareName(pkg,items=[],options={}){
  if(!pkg||pkg.architecture!=='esp32'||pkg.merged||pkg.expert)return null;
  if(!(pkg.payload instanceof Uint8Array)||!pkg.payload.length||!sha(pkg.sha256)||!sha(pkg.payloadHash)||
      pkg.sha256.toLowerCase()!==pkg.payloadHash.toLowerCase()||hash(pkg.payload)!==pkg.payloadHash.toLowerCase())
    throw new Error('Custom firmware bytes or their immutable SHA-256 changed. Load the file again.');
  const identity=endfIdentity(pkg.payload);if(!identity)return null;
  if(!Array.isArray(items)||items.length>50000)throw new Error('Invalid custom firmware source catalog.');
  const expected=pkg.payloadHash.toLowerCase(),byteLength=pkg.payload.length,candidates=[];
  for(const item of items){
    if(!item||item.project!=='MeshCore'||item.provider!=='Keymind Cascade'||item.architecture!=='esp32'||item.action!=='flash-update'||
        !sha(item.sha256)||item.sha256.toLowerCase()!==expected||(item.size!==undefined&&item.size!==byteLength))continue;
    const candidate=sourceIdentity(item.url,identity.version);
    if(candidate&&item.name===candidate.name&&item.role===candidate.role)candidates.push({...candidate,source:'catalog-sha256'});
  }
  if(!candidates.length){
    const finder=options.findSources||findFirmwareSources;
    const sources=await finder({sha256:expected,size:byteLength},options);
    if(!Array.isArray(sources)||sources.length>10000)throw new Error('Invalid custom firmware source index.');
    for(const entry of sources){
      if(!entry||entry.sha256!==expected||entry.size!==byteLength)continue;
      const candidate=sourceIdentity(entry.url,identity.version);
      if(candidate)candidates.push({...candidate,source:'same-origin-mirror-sha256'});
    }
  }
  if(!candidates.length)return null;
  const identities=new Set(candidates.map(candidate=>JSON.stringify([candidate.firmwareVersion,candidate.sourceCommit,candidate.family,candidate.role])));
  if(identities.size!==1)throw new Error('Exact custom firmware has ambiguous published release or hardware-role names. Supply its matching migration ZIP instead.');
  const selected=candidates.sort((a,b)=>a.name.localeCompare(b.name)||a.url.localeCompare(b.url))[0];
  return Object.freeze({name:selected.name,url:selected.url,sha256:expected,size:byteLength,source:selected.source,
    firmwareVersion:selected.firmwareVersion,sourceCommit:selected.sourceCommit});
}
