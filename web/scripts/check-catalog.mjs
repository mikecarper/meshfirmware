// Deterministic publication check: every generated route, not a few fixtures.
// Network availability/CORS is separate; this never issues thousands of HEADs.
import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { validateCatalog, validateFirmwareUrl } from '../src/catalog.js';
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
  validateCatalog(catalog);
  return {artifacts,utilities,officialReleases};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  const catalog=JSON.parse(await readFile(new URL('../public/catalog.json',import.meta.url),'utf8'));
  const {artifacts,utilities,officialReleases}=checkCatalogRoutes(catalog);
  console.log(`Catalog routes verified: ${artifacts} artifacts, ${officialReleases} complete GitHub release routes, ${utilities} utility references; no repository-less GitHub release URLs.`);
}
