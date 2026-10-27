// Deterministic publication check: every generated route, not a few fixtures.
// Network availability/CORS is separate; this never issues thousands of HEADs.
import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { combineProviderItems, inheritOfficialUtilities, validateCatalog, validateFirmwareUrl } from '../src/catalog.js';
import { applyBootloaderCatalog } from '../src/bootloader-catalog.js';
export function checkCatalogRoutes(catalog) {
  assert.ok(Array.isArray(catalog?.items),'Invalid raw catalog item inventory.');
  let artifacts=0,utilities=0,officialReleases=0;
  // Publication is stricter than browser legacy-cache recovery: check the raw
  // bytes' URLs FIRST. Never accept repaired copies while publishing bad JSON.
  for(const item of catalog.items){
    validateFirmwareUrl(item?.url);artifacts++;
    if(new URL(item.url).hostname==='github.com'&&new URL(item.url).pathname.includes('/releases/download/'))officialReleases++;
    for(const url of [...(item.erase||[]),...(item.bootloader||[])]){validateFirmwareUrl(url);utilities++;}
    if(item.architecture==='nrf52')assert.ok(/\.zip$/i.test(item.name),'nRF52 must offer serial DFU ZIPs, never drive-copy images.');
  }
  assert.ok(artifacts>0,'Empty catalog cannot replace a published catalog.');
  const checked=validateCatalog(catalog);
  if(catalog.recoveryCatalog)assert.deepEqual(catalog.recoveryCatalog,checked.recoveryCatalog,'Published recovery metadata must match its verified stable-release bundle.');
  // Compare every distinct raw entry with its own expected recommendations,
  // before final browser deduplication can change inventory indexes.
  const inventory=combineProviderItems(catalog.items);
  const expected=applyBootloaderCatalog(inheritOfficialUtilities(inventory),checked.bootloaderCatalog);
  for(let i=0;i<inventory.length;i++)if(inventory[i].architecture==='nrf52'){
    assert.deepEqual(inventory[i].bootloader||[],expected[i].bootloader||[],'Published nRF52 bootloader recommendations must match the verified fork manifest.');
    assert.deepEqual(inventory[i].bootloaderInfo,expected[i].bootloaderInfo,'Published nRF52 bootloader hashes and profiles must match the verified fork manifest.');
  }
  return {artifacts,utilities,officialReleases};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  const catalog=JSON.parse(await readFile(new URL('../public/catalog.json',import.meta.url),'utf8'));
  const {artifacts,utilities,officialReleases}=checkCatalogRoutes(catalog);
  console.log(`Catalog routes verified: ${artifacts} artifacts, ${officialReleases} complete GitHub release routes, ${utilities} utility references; no repository-less GitHub release URLs.`);
  if(catalog.recoveryCatalog)console.log(`Recovery catalog verified: ${catalog.recoveryCatalog.profiles.length} installed-bootloader profiles, OTAFIX ${catalog.recoveryCatalog.version}; metadata only, no recovery binaries.`);
}
