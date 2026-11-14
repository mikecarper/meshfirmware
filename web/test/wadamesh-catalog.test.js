import test from 'node:test';
import assert from 'node:assert/strict';
import {validateCatalog} from '../src/catalog.js';
import {WADAMESH_PROVIDER,WADAMESH_REPOSITORY,WADAMESH_LATEST_URL,wadameshBoardsUrl,wadameshCatalog} from '../scripts/wadamesh-catalog.mjs';

const definitions=[
  ['tdeck','tdeck','LilyGo_TDeck_companion_radio_touch'],
  ['m9','thinknode-m9','ThinkNode_M9_companion_radio_touch'],
  ['pager','tlora-pager-sx1262','tlora_pager_sx1262_companion_radio_touch'],
  ['pager','tlora-pager-lr1121','tlora_pager_lr1121_companion_radio_touch'],
  ['heltec-v4','heltec-v4','heltec_v4_tft_companion_radio_usb_tcp_touch'],
  ['heltec-v4','heltec-v4-r8','heltec_v4_r8_tft_companion_radio_usb_tcp_touch'],
  ['wio-l2','wio-tracker-l2','wio_tracker_l2_companion_radio_touch'],
  ['crowpanel','crowpanel-35','crowpanel_35_companion_radio_touch'],
  ['crowpanel','crowpanel-50','crowpanel_50_companion_radio_touch'],
];
function fixture(tag='tak-beta_103.1'){
  const boards=[];
  for(const [id,build,env] of definitions){let board=boards.find(board=>board.id===id);if(!board)boards.push(board={id,chip:'ESP32-S3',builds:{}});board.builds[build]={env};}
  const assets=definitions.flatMap(([,build],index)=>['.bin','-merged.bin'].map((suffix,merged)=>({name:`wadamesh-${build}${suffix}`,size:4000000+index*4096+merged*65536,digest:'sha256:'+((index+merged)%16).toString(16).repeat(64),browser_download_url:`${WADAMESH_REPOSITORY}/releases/download/${tag}/wadamesh-${build}${suffix}`})));
  assets.push({name:'wadamesh-tdeck.bin.sig',size:64,digest:'sha256:'+'f'.repeat(64),browser_download_url:'https://example.test/signature'}, {name:'mem-report-tdisplay-p4.txt',size:200});
  return {release:{draft:false,prerelease:false,tag_name:tag,published_at:'2026-11-13T03:24:05Z',html_url:`${WADAMESH_REPOSITORY}/releases/tag/${tag}`,body:'Standalone release notes.',assets},manifest:{boards}};
}
test('Wadamesh discovery reads its own latest release and release-tag-pinned board JSON',()=>{
  const {release}=fixture();assert.equal(WADAMESH_LATEST_URL,'https://api.github.com/repos/jade-on-mesh/wadamesh-tak/releases/latest');
  assert.equal(wadameshBoardsUrl(release),'https://raw.githubusercontent.com/jade-on-mesh/wadamesh-tak/tak-beta_103.1/boards.json');
});
test('nine reviewed S3 variants expose only exact application/merged pairs with release hashes and provenance',()=>{
  const {release,manifest}=fixture(),before=structuredClone({release,manifest}),result=wadameshCatalog(release,manifest);
  assert.equal(result.items.length,18);assert.deepEqual(result.warnings,[]);
  for(const item of result.items){
    const asset=release.assets.find(asset=>asset.name===item.name);
    assert.equal(item.provider,WADAMESH_PROVIDER);assert.equal(item.project,'MeshCore');assert.equal(item.role,'gui');assert.equal(item.architecture,'esp32');assert.equal(item.chipFamily,'ESP32-S3');
    assert.equal(item.sha256,asset.digest.slice(7));assert.equal(item.size,asset.size);assert.equal(item.url,asset.browser_download_url);
    assert.equal(item.version,release.tag_name);assert.equal(item.releasePage,release.html_url);assert.equal(item.sourceRepository,WADAMESH_REPOSITORY);assert.match(item.sourceManifest,/tak-beta_103\.1\/boards\.json$/);
    assert.match(item.notice,/erases identity, contacts, channels and settings/);assert.match(item.releaseNotes,new RegExp('EXACT TARGET - '+item.exactTarget.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
    assert.equal(item.action,item.name.endsWith('-merged.bin')?'flash-wipe':'flash-update');
    assert.equal(item.requiresExistingProvider,item.action==='flash-update'?WADAMESH_PROVIDER:undefined);
  }
  assert.ok(!result.items.some(item=>/\.sig|mem-report/.test(item.name)));assert.deepEqual({release,manifest},before);
});
test('display, radio and board revisions stay explicit instead of collapsing physically different builds',()=>{
  const {release,manifest}=fixture(),{items}=wadameshCatalog(release,manifest);
  for(const hardware of ['Heltec v4','Heltec v4 R8']){const target=items.filter(item=>item.hardware===hardware);assert.equal(target.length,2);assert.ok(target.every(item=>item.requiredDisplay==='tft'&&/not compatible with the OLED/.test(item.notice)));}
  const pagers=items.filter(item=>item.hardware.startsWith('LilyGo T-Lora Pager'));assert.deepEqual([...new Set(pagers.map(item=>item.radioVariant))],['SX1262','LR1121']);assert.equal(new Set(pagers.map(item=>item.hardware)).size,2);
  assert.ok(items.some(item=>item.hardware==='LilyGo T-Deck'));assert.ok(items.some(item=>item.hardware==='Elecrow ThinkNode M9'));assert.ok(items.some(item=>item.hardware==='Seeed Wio Tracker L2'));
  assert.equal(new Set(items.filter(item=>item.hardware.includes('CrowPanel')).map(item=>item.hardware)).size,2);
});
test('all P4 processor/display/radio/coproc variants are excluded with an actionable warning',()=>{
  const {release,manifest}=fixture();manifest.boards.push({id:'p4',chip:'ESP32-P4',builds:Object.fromEntries(['tdisplay-p4','tdisplay-p4-lr2021','tdisplay-p4-at','tdisplay-p4-lr2021-at','tdisplay-p4-lcd','tdisplay-p4-lcd-lr2021','tdisplay-p4-lcd-at','tdisplay-p4-lcd-lr2021-at'].map(build=>[build,{idf:''}]))});
  const result=wadameshCatalog(release,manifest);assert.equal(result.items.length,18);assert.ok(result.items.every(item=>!item.name.includes('tdisplay-p4')));assert.match(result.warnings.join(' '),/8 ESP32-P4 variants.*does not support.*MediaMesh Flasher/);
});
test('draft, foreign repository, unsafe tags and missing publication metadata cannot become a provider',()=>{
  for(const mutate of [r=>r.draft=true,r=>delete r.draft,r=>r.html_url='https://github.com/other/repo/releases/tag/'+r.tag_name,r=>r.tag_name='../main',r=>r.tag_name='main',r=>r.published_at='not a date',r=>r.assets=[]]){
    const {release,manifest}=fixture();mutate(release);assert.throws(()=>wadameshCatalog(release,manifest),/release|tag|publication|asset inventory/i);
  }
});
test('missing, weak or invalid digests and invalid sizes fail the whole fresh provider snapshot',()=>{
  for(const mutate of [a=>delete a.digest,a=>a.digest='sha1:'+'a'.repeat(40),a=>a.digest='sha256:'+'g'.repeat(64),a=>a.size=0,a=>a.size=-1,a=>a.size=33<<20,a=>a.size=1.1]){
    const {release,manifest}=fixture();mutate(release.assets[0]);assert.throws(()=>wadameshCatalog(release,manifest),/SHA-256|size/);
  }
});
test('only exact immutable asset URLs for this repository and release are accepted',()=>{
  for(const url of ['http://github.com/jade-on-mesh/wadamesh-tak/releases/download/tak-beta_103.1/wadamesh-tdeck.bin','https://github.com/other/repo/releases/download/tak-beta_103.1/wadamesh-tdeck.bin','https://github.com/jade-on-mesh/wadamesh-tak/releases/latest/download/wadamesh-tdeck.bin',`${WADAMESH_REPOSITORY}/releases/download/tak-beta_103.1/wadamesh-tdeck.bin?token=private`,`${WADAMESH_REPOSITORY}/releases/download/tak-beta_102.1/wadamesh-tdeck.bin`]){
    const {release,manifest}=fixture();release.assets[0].browser_download_url=url;assert.throws(()=>wadameshCatalog(release,manifest),/download URL/);
  }
});
test('ambiguous asset names, board IDs and build IDs fail rather than choosing the first',()=>{
  for(const mutate of [(r,m)=>r.assets.push({...r.assets[0]}),(r,m)=>m.boards.push({...m.boards[0]}),(r,m)=>m.boards.push({id:'other',chip:'ESP32-S3',builds:{tdeck:{env:'LilyGo_TDeck_companion_radio_touch'}}})]){
    const {release,manifest}=fixture();mutate(release,manifest);assert.throws(()=>wadameshCatalog(release,manifest),/duplicate/);
  }
});
test('changed build environments, chip families or board ownership require review',()=>{
  for(const mutate of [b=>b.chip='ESP32-P4',b=>b.id='other-board',b=>b.builds.tdeck.env='wrong_environment',b=>b.builds.tdeck.idf='WADA_P4=1']){
    const {release,manifest}=fixture();mutate(manifest.boards[0]);assert.throws(()=>wadameshCatalog(release,manifest),/mapping changed/);
  }
});
test('a partially uploaded application/merged pair is not published as a complete provider',()=>{
  const {release,manifest}=fixture();release.assets.splice(1,1);assert.throws(()=>wadameshCatalog(release,manifest),/missing its merged install asset/);
});
test('future unknown boards are omitted with a warning instead of inferred from similar filenames',()=>{
  const {release,manifest}=fixture();manifest.boards.push({id:'future',chip:'ESP32-S3',builds:{'tdeck-lookalike':{env:'future_env'}}});release.assets.push({name:'wadamesh-tdeck-lookalike-merged.bin'});
  const result=wadameshCatalog(release,manifest);assert.equal(result.items.length,18);assert.match(result.warnings.join(' '),/unreviewed board\/build future\/tdeck-lookalike/);assert.ok(!result.items.some(item=>item.name.includes('lookalike')));
});
test('a release containing only unsupported or unknown boards cannot replace a working snapshot',()=>{
  const {release}=fixture();assert.throws(()=>wadameshCatalog(release,{boards:[{id:'future',chip:'ESP32-S3',builds:{future:{env:'future'}}}]}),/No reviewed, supported/);
});
test('future version tags remain pinned consistently without parsing a version from filenames',()=>{
  const {release,manifest}=fixture('tak-beta_104.12'),result=wadameshCatalog(release,manifest);assert.ok(result.items.every(item=>item.version==='tak-beta_104.12'&&item.url.includes('/tak-beta_104.12/')&&item.sourceManifest.includes('/tak-beta_104.12/')));
});
test('provider safety metadata survives the normal browser catalog validation and cache boundary',()=>{
  const {release,manifest}=fixture(),{items}=wadameshCatalog(release,manifest),checked=validateCatalog({generatedAt:release.published_at,warnings:[],items});
  assert.deepEqual(checked.items,items);assert.ok(checked.items.some(item=>item.requiredDisplay==='tft'));assert.ok(checked.items.some(item=>item.requiresExistingProvider===WADAMESH_PROVIDER));
});
