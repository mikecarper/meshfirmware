// Reviewed standalone targets only. The release JSON supplies immutable asset
// URLs, sizes and digests; its tagged boards.json must agree with this map.
export const WADAMESH_PROVIDER='Wadamesh TAK';
export const WADAMESH_REPOSITORY='https://github.com/jade-on-mesh/wadamesh-tak';
export const WADAMESH_LATEST_URL='https://api.github.com/repos/jade-on-mesh/wadamesh-tak/releases/latest';
const raw='https://raw.githubusercontent.com/jade-on-mesh/wadamesh-tak/';
const reviewed=new Map([
  ['tdeck',{board:'tdeck',hardware:'LilyGo T-Deck',env:'LilyGo_TDeck_companion_radio_touch',variant:'T-Deck / T-Deck Plus'}],
  ['thinknode-m9',{board:'m9',hardware:'Elecrow ThinkNode M9',env:'ThinkNode_M9_companion_radio_touch',variant:'ThinkNode M9',radioVariant:'LR1110'}],
  ['tlora-pager-sx1262',{board:'pager',hardware:'LilyGo T-Lora Pager (SX1262)',env:'tlora_pager_sx1262_companion_radio_touch',variant:'T-LoRa Pager · SX1262',radioVariant:'SX1262'}],
  ['tlora-pager-lr1121',{board:'pager',hardware:'LilyGo T-Lora Pager (LR1121)',env:'tlora_pager_lr1121_companion_radio_touch',variant:'T-LoRa Pager · LR1121',radioVariant:'LR1121'}],
  ['heltec-v4',{board:'heltec-v4',hardware:'Heltec v4',env:'heltec_v4_tft_companion_radio_usb_tcp_touch',variant:'V4 · 2.4-inch TFT touch screen',requiredDisplay:'tft'}],
  ['heltec-v4-r8',{board:'heltec-v4',hardware:'Heltec v4 R8',env:'heltec_v4_r8_tft_companion_radio_usb_tcp_touch',variant:'V4-R8 · TFT / Expansion Kit V2',requiredDisplay:'tft'}],
  ['wio-tracker-l2',{board:'wio-l2',hardware:'Seeed Wio Tracker L2',env:'wio_tracker_l2_companion_radio_touch',variant:'Wio Tracker L2 · touch screen'}],
  ['crowpanel-35',{board:'crowpanel',hardware:'Elecrow CrowPanel Advance 3.5',env:'crowpanel_35_companion_radio_touch',variant:'CrowPanel Advance · 3.5-inch',radioVariant:'SX1262'}],
  ['crowpanel-50',{board:'crowpanel',hardware:'Elecrow CrowPanel Advance 5.0',env:'crowpanel_50_companion_radio_touch',variant:'CrowPanel Advance · 5-inch',radioVariant:'SX1262'}],
]);
const object=value=>!!value&&typeof value==='object'&&!Array.isArray(value);
const id=value=>typeof value==='string'&&/^[a-z0-9][a-z0-9-]{0,100}$/.test(value);
const invariant=(condition,message)=>{if(!condition)throw new Error(message);};
function releaseIdentity(release){
  invariant(object(release)&&release.draft===false,'Wadamesh release must be a published, non-draft release.');
  const tag=release.tag_name;
  invariant(typeof tag==='string'&&tag.length<=100&&/^tak-beta_\d+(?:\.\d+){0,3}(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?$/.test(tag),'Invalid Wadamesh release tag.');
  const releasePage=`${WADAMESH_REPOSITORY}/releases/tag/${tag}`;
  invariant(release.html_url===releasePage,'Wadamesh release page does not match its repository and tag.');
  invariant(typeof release.published_at==='string'&&Number.isFinite(Date.parse(release.published_at)),'Wadamesh release has no valid publication date.');
  invariant(Array.isArray(release.assets)&&release.assets.length>0&&release.assets.length<=512,'Invalid Wadamesh release asset inventory.');
  return {tag,releasePage};
}
export function wadameshBoardsUrl(release){return `${raw}${releaseIdentity(release).tag}/boards.json`;}

export function wadameshCatalog(release,manifest){
  const {tag,releasePage}=releaseIdentity(release),manifestUrl=wadameshBoardsUrl(release),items=[],warnings=[];
  invariant(object(manifest)&&Array.isArray(manifest.boards)&&manifest.boards.length>0&&manifest.boards.length<=128,'Invalid release-pinned Wadamesh board matrix.');
  const assets=new Map();
  for(const asset of release.assets){
    invariant(object(asset)&&typeof asset.name==='string'&&asset.name.length>0&&asset.name.length<=240,'Invalid Wadamesh asset name.');
    invariant(!assets.has(asset.name),'Ambiguous duplicate Wadamesh release asset name.');assets.set(asset.name,asset);
  }
  const boardIds=new Set(),buildIds=new Set(),seenAssets=new Set(),unsupportedAssets=new Set();let unsupportedP4=0;
  for(const board of manifest.boards){
    invariant(object(board)&&id(board.id)&&object(board.builds),'Invalid Wadamesh board definition.');
    invariant(!boardIds.has(board.id),'Ambiguous duplicate Wadamesh board ID.');boardIds.add(board.id);
    const builds=Object.entries(board.builds);invariant(builds.length>0&&builds.length<=128,'Invalid Wadamesh board build inventory.');
    for(const [build,configuration] of builds){
      invariant(id(build)&&object(configuration),'Invalid Wadamesh build definition.');
      invariant(!buildIds.has(build),'Ambiguous duplicate Wadamesh build ID.');buildIds.add(build);
      const target=reviewed.get(build);
      if(!target&&board.chip==='ESP32-P4'){unsupportedP4++;for(const suffix of ['.bin','-merged.bin'])unsupportedAssets.add(`wadamesh-${build}${suffix}`);continue;}
      if(!target){warnings.push(`Wadamesh TAK: unreviewed board/build ${board.id}/${build} was not added automatically.`);continue;}
      invariant(board.chip==='ESP32-S3'&&target.board===board.id&&configuration.env===target.env&&!Object.hasOwn(configuration,'idf'),`Wadamesh board/build mapping changed for ${build}; review its exact hardware before enabling it.`);
      for(const merged of [false,true]){
        const name=`wadamesh-${build}${merged?'-merged':''}.bin`,asset=assets.get(name);
        invariant(asset,`Wadamesh ${build} is missing its ${merged?'merged install':'application update'} asset.`);
        const url=`${WADAMESH_REPOSITORY}/releases/download/${tag}/${name}`;
        invariant(asset.browser_download_url===url,`Wadamesh ${name} has an invalid or mutable download URL.`);
        invariant(typeof asset.digest==='string'&&/^sha256:[a-f0-9]{64}$/.test(asset.digest),`Wadamesh ${name} has no valid published SHA-256.`);
        invariant(Number.isSafeInteger(asset.size)&&asset.size>0&&asset.size<=(32<<20),`Wadamesh ${name} has an invalid asset size.`);
        seenAssets.add(name);
        const display=target.requiredDisplay?' TFT only; not compatible with the OLED display.':'';
        const common='First install or changing firmware family requires the matching merged image. This flasher’s Erase & new install erases identity, contacts, channels and settings; the upstream installer’s preservation promise does not apply here.';
        items.push({project:'MeshCore',provider:WADAMESH_PROVIDER,hardware:target.hardware,architecture:'esp32',role:'gui',version:tag,action:merged?'flash-wipe':'flash-update',name,url,sha256:asset.digest.slice(7),size:asset.size,
          title:'Wadamesh TAK · standalone',subtitle:target.variant,notice:common+display+(merged?'':' App-only updates require an existing Wadamesh TAK installation and matching partition layout.'),
          releaseNotes:`EXACT TARGET - ${target.env}.\n${typeof release.body==='string'?release.body.slice(0,100000):''}`,releasePage,sourceRepository:WADAMESH_REPOSITORY,sourceManifest:manifestUrl,chipFamily:'ESP32-S3',exactTarget:target.env,wadameshBuild:build,
          ...(target.requiredDisplay?{requiredDisplay:target.requiredDisplay}:{}),...(target.radioVariant?{radioVariant:target.radioVariant}:{}),...(!merged?{requiresExistingProvider:WADAMESH_PROVIDER}:{})});
      }
    }
  }
  if(unsupportedP4)warnings.push(`Wadamesh TAK: ${unsupportedP4} ESP32-P4 variants were omitted because this flasher does not support that processor. Use the MediaMesh Flasher for those boards.`);
  const unknownAssets=[...assets.keys()].filter(name=>/^wadamesh-.+\.bin$/.test(name)&&!seenAssets.has(name)&&!unsupportedAssets.has(name));
  if(unknownAssets.length)warnings.push(`Wadamesh TAK: ${unknownAssets.length} binary assets did not match a reviewed released board/build and were omitted.`);
  invariant(items.length>0,'No reviewed, supported Wadamesh TAK board images are available in this release.');
  return {items,warnings};
}
