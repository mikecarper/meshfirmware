import {catalogItems,compareVersions,validateCatalog,inheritOfficialUtilities} from '../src/catalog.js';
import {BOOTLOADER_LATEST_URL,bootloaderManifestAsset,validateBootloaderSnapshot,applyBootloaderCatalog} from '../src/bootloader-catalog.js';
import {recoveryBundleAsset,createRecoveryCatalog,validateRecoveryCatalog} from '../src/bootloader-recovery.js';

const raw='https://raw.githubusercontent.com/mikecarper/MeshCore/keymindCascade/';
const treeURL='https://api.github.com/repos/mikecarper/MeshCore/git/trees/keymindCascade?recursive=1';
export function keymindProviderPaths(tree,variant) {
  const logging=variant==='logging',pattern=logging?/^mesh-america\/keymind-cascade-logging-v([0-9]+(?:\.[0-9]+){1,3})[^/]*-provider\.json$/:/^mesh-america\/keymind-cascade-v([0-9]+(?:\.[0-9]+){1,3})[^/]*-provider\.json$/;
  const fallback=`mesh-america/keymind-cascade-${logging?'logging-':''}v1.16.0-provider.json`;
  return [...new Set([...(tree?.tree||[]).filter(entry=>entry.type==='blob'&&pattern.test(entry.path)).map(entry=>entry.path),fallback])].sort((a,b)=>compareVersions(pattern.exec(a)?.[1]||'',pattern.exec(b)?.[1]||''));
}
export async function buildCatalog({readJson,readBytes,previous=async()=>null,now=()=>new Date().toISOString()}) {
  const warnings=[],items=[];let cached,bootloaderCatalog=null,recoveryCatalog=null;
  const latestRelease=Promise.resolve().then(()=>readJson(BOOTLOADER_LATEST_URL));
  const prior=async()=>{if(cached===undefined){try{cached=validateCatalog(await previous());}catch{cached=null;}}return cached;};
  async function source(urls,validate,label) {
    const failures=[];
    for(const url of urls)try{const value=await readJson(url);if(!validate(value))throw new Error('invalid metadata');if(failures.length)warnings.push(`${label}: primary source unavailable; using fallback.`);return value;}catch(error){failures.push(error.message);}
    throw new Error(`${label}: ${failures.join('; ')}`);
  }
  async function reuse(provider,error) {warnings.push(`${provider}: ${error.message}`);const old=(await prior())?.items.filter(item=>item.provider===provider)||[];if(old.length){items.push(...old);warnings.push(`${provider}: retained last known public entries.`);}}
  await Promise.all([
    (async()=>{try{const [config,releases]=await Promise.all([
      source(['https://flasher.meshcore.io/config.json','https://apps.meshamerica.com/proxy/flasher/config.json'],v=>Array.isArray(v?.device)&&v.device.length>0,'MeshCore config'),
      source(['https://flasher.meshcore.io/releases','https://apps.meshamerica.com/proxy/flasher/releases'],v=>Array.isArray(v)&&v.length>0,'MeshCore releases')
    ]);items.push(...catalogItems(config,releases));}catch(error){await reuse('MeshCore',error);}})(),
    (async()=>{let tree;try{tree=await readJson(treeURL);if(!Array.isArray(tree?.tree)||tree.truncated)throw new Error('incomplete tree');}catch(error){warnings.push(`Keymind provider discovery: ${error.message}; trying published fallback paths.`);}
      await Promise.all([['Keymind Cascade','cascade'],['Keymind Cascade Logging','logging']].map(async([provider,variant])=>{try{const paths=keymindProviderPaths(tree,variant),config=await source(paths.map(path=>raw+path),v=>Array.isArray(v?.device)&&v.device.length>0,provider);items.push(...catalogItems(config,[],provider));}catch(error){await reuse(provider,error);}}));
    })(),
    (async()=>{try{
      const release=await latestRelease,asset=bootloaderManifestAsset(release);
      const manifest=await readJson(asset.browser_download_url,{sha256:asset.digest.slice(7),size:asset.size});
      bootloaderCatalog=validateBootloaderSnapshot({schemaVersion:1,checkedAt:now(),release,manifest});
    }catch(error){
      warnings.push(`OTAFIX latest stable release: ${error.message}`);
      try{const old=(await prior())?.bootloaderCatalog;if(old)bootloaderCatalog={...validateBootloaderSnapshot(old),cached:true};}catch{}
      warnings.push(bootloaderCatalog?`OTAFIX ${bootloaderCatalog.manifest.version}: using the last verified public release; the latest release could not be checked.`:'OTAFIX: automatic bootloader recommendations disabled because no verified latest or cached release is available. Application firmware remains available.');
    }})(),
    (async()=>{try{
      if(typeof readBytes!=='function')throw new Error('No verified recovery-bundle byte loader is configured.');
      const release=await latestRelease,asset=recoveryBundleAsset(release);
      const bundle=await readBytes(asset.browser_download_url,{sha256:asset.digest.slice(7),size:asset.size});
      recoveryCatalog=createRecoveryCatalog(release,bundle,now());
    }catch(error){
      warnings.push(`OTAFIX recovery catalog: ${error.message}`);
      try{const old=(await prior())?.recoveryCatalog;if(old)recoveryCatalog={...validateRecoveryCatalog(old),cached:true};}catch{}
      warnings.push(recoveryCatalog?`OTAFIX recovery ${recoveryCatalog.version}: using the last verified public recovery catalog; the latest recovery bundle could not be checked.`:'OTAFIX recovery: built-in recovery selection is unavailable; normal bootloader and application firmware selection are independent.');
    }})()
  ]);
  if(!items.length)throw new Error('No fresh or validated cached MeshCore catalog entries are available. Existing deployed site was not replaced.');
  const seen=new Set();return {generatedAt:now(),bootloaderCatalog,recoveryCatalog,items:applyBootloaderCatalog(inheritOfficialUtilities(items.filter(item=>{const key=JSON.stringify([item.provider,item.hardware,item.role,item.version,item.action,item.url]);if(seen.has(key))return false;seen.add(key);return true;})),bootloaderCatalog).sort((a,b)=>a.provider.localeCompare(b.provider)||a.hardware.localeCompare(b.hardware)||a.role.localeCompare(b.role)||compareVersions(a.version,b.version)||a.name.localeCompare(b.name)),warnings};
}
