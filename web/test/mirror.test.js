import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,readFile,writeFile,readdir,rm,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve,join,basename} from 'node:path';
import {createHash} from 'node:crypto';
import {gzipSync,gunzipSync} from 'node:zlib';
import {buildMirror,selectMirrorSources,githubAsset,MIRROR_MAX_ASSET_BYTES,MIRROR_MAX_BYTES} from '../scripts/mirror.mjs';

const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const bytes=value=>new TextEncoder().encode(value);
const releaseUrl=(tag,name,owner='meshcore-dev',repository='MeshCore')=>`https://github.com/${owner}/${repository}/releases/download/${tag}/${name}`;
function application({name='board_repeater-v1.18.0.bin',version='v1.18.0',...patch}={}){
  return {project:'MeshCore',provider:'MeshCore',hardware:'Board',architecture:'esp32',role:'repeater',action:'flash-update',name,version,url:releaseUrl(version,name),bootloader:[],erase:[],...patch};
}
function inventory(items,contents=new Map()){
  const releases=new Map(),repositories=new Map(),assetRequests=[],apiRequests=[];
  for(const item of items){
    const route=githubAsset(item.url);if(!route)continue;
    const data=contents.get(item.url)||bytes(item.name||route.name),api=`https://api.github.com/repos/${route.owner}/${route.repository}/releases/tags/${encodeURIComponent(route.tag)}`;
    repositories.set(`https://api.github.com/repos/${route.owner}/${route.repository}`,{full_name:`${route.owner}/${route.repository}`,private:false,visibility:'public'});
    if(!releases.has(api))releases.set(api,{tag_name:route.tag,draft:false,assets:[]});
    releases.get(api).assets.push({name:route.name,browser_download_url:route.url,size:data.length,digest:'sha256:'+hash(data)});contents.set(item.url,data);
  }
  const fetchImpl=async(url,options)=>{
    if(url.startsWith('https://api.github.com/')){apiRequests.push({url,options});return releases.has(url)?Response.json(releases.get(url)):repositories.has(url)?Response.json(repositories.get(url)):new Response('missing',{status:404});}
    assetRequests.push({url,options});return contents.has(url)?new Response(contents.get(url)):new Response('missing',{status:404});
  };
  return {releases,repositories,contents,fetchImpl,assetRequests,apiRequests};
}
async function output(t){
  const root=await mkdtemp(join(tmpdir(),'meshfirmware-mirror-'));
  t.after(async()=>{const absolute=resolve(root),base=resolve(tmpdir());assert.ok(absolute.startsWith(base+'\\')||absolute.startsWith(base+'/'));assert.ok(basename(absolute).startsWith('meshfirmware-mirror-'));await rm(absolute,{recursive:true,force:true});});
  return join(root,'firmware');
}
const build=(catalog,outputDir,fixture,options={})=>buildMirror({catalog:{items:catalog},outputDir,fetchImpl:fixture.fetchImpl,now:()=> '2026-10-27T00:00:00Z',...options});

test('only complete public HTTPS GitHub release assets qualify as mirror sources',()=>{
  const url=releaseUrl('v1.2.3','board.zip');assert.deepEqual(githubAsset(url),{url,owner:'meshcore-dev',repository:'MeshCore',tag:'v1.2.3',name:'board.zip'});
  for(const value of ['http://github.com/a/b/releases/download/t/x.zip','https://u:p@github.com/a/b/releases/download/t/x.zip','https://github.com:444/a/b/releases/download/t/x.zip','https://github.com/a/b/releases/download/t/x.zip?q=secret','https://github.com/a/b/releases/download/t/x.zip#hash','https://raw.githubusercontent.com/a/b/main/x.zip','https://api.github.com/repos/a/b/releases/1','https://github.com/a/b/releases/download/t/subtag/file.zip','https://github.com/a/b/releases/download/t/a%2fb.zip','https://github.com/a/b/releases/download/t/a%5cb.zip','C:\\backups\\node.json'])assert.equal(githubAsset(value),null,value);
});

test('selection keeps newest exact profiles and both modes while excluding embedded bootloader apps',()=>{
  const old=application({name:'board_repeater-full-v1.17.0-abcdef0.bin',version:'v1.17.0'}),current=application({name:'board_repeater-full-v1.18.0-abcdef1.bin'}),reduced=application({name:'board_repeater-reduced-v1.18.0-abcdef1.bin'}),merged=application({name:'board_repeater-full-v1.18.0-abcdef1-merged.bin',action:'flash-wipe'}),other=application({hardware:'Other',name:'other_repeater-full-v1.18.0-abcdef1.bin'}),nrf=application({architecture:'nrf52',action:'flash',name:'nrf_repeater-v1.18.0.zip'}),embedded={...nrf,name:'nrf_repeater-with-bootloader-2.4.12-v1.18.0.zip'};
  const result=selectMirrorSources({items:[old,current,reduced,merged,other,nrf,embedded]});
  assert.equal(result.selectedApplications,5);assert.deepEqual(new Set(result.sources.map(source=>source.url)),new Set([current,reduced,merged,other,nrf].map(item=>item.url)));
  assert.ok(result.sources.every(source=>source.priority===1));
});

test('explicit separate utility references survive without guessing a board or profile',()=>{
  const boot=releaseUrl('v0.11.0-OTAFIX2.4.12','board_bootloader.zip','mikecarper','Adafruit_nRF52_Bootloader_OTAFIX'),erase=releaseUrl('utility-v1','FLASH_ERASE.zip'),recovery=releaseUrl('v0.11.0-OTAFIX2.4.12','R_recovery.zip','mikecarper','Adafruit_nRF52_Bootloader_OTAFIX');
  const app=application({bootloader:[boot],erase:[erase],bootloaderInfo:{url:boot,sha256:'a'.repeat(64),size:100}}),result=selectMirrorSources({items:[app],recoveryCatalog:{bundle:{url:recovery,sha256:'b'.repeat(64),size:120}}});
  assert.deepEqual(result.sources.filter(source=>source.priority===0).map(source=>source.kind).sort(),['bootloader','erase','recovery']);
  assert.equal(result.sources.find(source=>source.url===boot).sha256,'a'.repeat(64));assert.equal(result.sources.find(source=>source.url===recovery).size,120);
  assert.throws(()=>selectMirrorSources({items:[app,{...app,bootloaderInfo:{...app.bootloaderInfo,sha256:'c'.repeat(64)}}]}),/Conflicting catalog SHA/);
});

test('mirror verifies GitHub bytes then writes deterministic content-addressed gzip and a public index',async t=>{
  const app=application(),raw=bytes('a public signed-release application payload'),fixture=inventory([app],new Map([[app.url,raw]])),directory=await output(t),result=await build([app],directory,fixture,{token:'test-only-token'});
  assert.equal(result.index.schemaVersion,1);assert.equal(result.index.generatedAt,'2026-10-27T00:00:00Z');assert.equal(result.index.entries.length,1);
  const entry=result.index.entries[0],compressed=await readFile(join(directory,entry.path));
  assert.deepEqual(entry,{url:app.url,sha256:hash(raw),size:raw.length,gzipSha256:hash(compressed),gzipSize:compressed.length,path:hash(raw)+'.gz'});
  assert.deepEqual(gunzipSync(compressed),Buffer.from(raw));assert.deepEqual([...compressed.subarray(0,4)],[31,139,8,0]);assert.equal(compressed.readUInt32LE(compressed.length-4),raw.length);
  assert.deepEqual(JSON.parse(await readFile(join(directory,'index.json'),'utf8')),result.index);assert.equal(result.bytes,compressed.length);
  assert.equal(fixture.apiRequests.length,2);assert.ok(fixture.apiRequests.every(request=>request.options.headers.Authorization==='Bearer test-only-token'));assert.equal(fixture.assetRequests[0].options.headers.Authorization,undefined);assert.equal(fixture.assetRequests[0].options.credentials,'omit');
  assert.equal(fixture.apiRequests[0].options.redirect,'error');
  assert.ok(!JSON.stringify(result.index).includes('test-only-token'));assert.deepEqual((await readdir(directory)).sort(),['index.json',hash(raw)+'.gz'].sort());
});

test('same content aliases share one file and one budget charge; metadata is cached per release',async t=>{
  const a=application({name:'board_repeater-full-v1.18.0.bin'}),b=application({name:'board_repeater-reduced-v1.18.0.bin'}),raw=bytes('same immutable release bytes'),fixture=inventory([a,b],new Map([[a.url,raw],[b.url,raw]])),directory=await output(t),compressed=gzipSync(raw,{level:9,mtime:0});
  const result=await build([a,b],directory,fixture,{maxBytes:compressed.length});
  assert.equal(result.index.entries.length,2);assert.equal(result.files,1);assert.equal(result.bytes,compressed.length);assert.equal(fixture.apiRequests.length,2);assert.equal(result.skipped,0);
});

test('an existing generated mirror is rechecked against current authoritative hashes without redownloading bytes',async t=>{
  const app=application(),fixture=inventory([app]),directory=await output(t),first=await build([app],directory,fixture);fixture.assetRequests.length=0;
  const second=await build([app],directory,fixture);assert.deepEqual(second.index,first.index);assert.equal(fixture.assetRequests.length,0);
  await writeFile(join(directory,first.index.entries[0].path),bytes('corrupt cache'));
  await assert.rejects(build([app],directory,fixture),/Cached public mirror/);assert.equal(fixture.assetRequests.length,0);
});

test('catalog SHA, size, exact asset URL and downloaded bytes fail closed on inconsistency',async t=>{
  for(const failure of ['catalog hash','catalog size','asset URL','bytes','declared limit','stream limit']){
    const app=application(),fixture=inventory([app]),directory=await output(t),asset=[...fixture.releases.values()][0].assets[0];
    if(failure==='catalog hash')app.sha256='f'.repeat(64);
    if(failure==='catalog size'){const boot=app.url;app.bootloader=[boot];app.bootloaderInfo={url:boot,size:asset.size+1};}
    if(failure==='asset URL')asset.browser_download_url=releaseUrl('v1.18.0','different.bin');
    if(failure==='bytes')fixture.contents.set(app.url,bytes('x'.repeat(asset.size)));
    if(failure==='declared limit'){const original=fixture.fetchImpl;fixture.fetchImpl=async(url,options)=>url===app.url?new Response(bytes('x'),{headers:{'content-length':String(asset.size+1)}}):original(url,options);}
    if(failure==='stream limit')fixture.contents.set(app.url,bytes('x'.repeat(asset.size+1)));
    await assert.rejects(build([app],directory,fixture),/differs|exceeds|invalid/,failure);
    assert.ok(!(await readdir(directory)).includes('index.json'),failure);
  }
});

test('missing assets or missing authoritative digests are honest omissions, not trusted fallbacks',async t=>{
  for(const failure of ['missing','digest','network']){
    const app=application(),fixture=inventory([app]),directory=await output(t),release=[...fixture.releases.values()][0];
    if(failure==='missing')release.assets=[];if(failure==='digest')release.assets[0].digest=null;
    if(failure==='network')fixture.fetchImpl=async()=>{throw new Error('Do not expose this private transport detail');};
    const result=await build([app],directory,fixture);assert.deepEqual(result.index.entries,[]);assert.equal(result.index.warnings.length,1);assert.ok(!JSON.stringify(result.index).includes('private transport detail'));assert.equal(fixture.assetRequests.length,0);
  }
});

test('budget selection is deterministic even when higher-priority asset fetches resolve later',async t=>{
  const a=application({name:'a_repeater-v1.18.0.bin'}),b=application({name:'b_repeater-v1.18.0.bin'}),fixture=inventory([a,b]),directory=await output(t),firstSize=gzipSync(fixture.contents.get(a.url),{level:9,mtime:0}).length,original=fixture.fetchImpl;
  fixture.fetchImpl=async(url,options)=>{if(url===a.url)await new Promise(resolve=>setTimeout(resolve,10));return original(url,options);};
  const result=await build([b,a],directory,fixture,{maxBytes:firstSize,concurrency:2});
  assert.deepEqual(result.index.entries.map(entry=>entry.url),[a.url]);assert.equal(result.skipped,1);assert.match(result.index.warnings.at(-1),/did not fit.*budget/);
});

test('Keymind utility discovery uses its exact tag and migration asset inventory only',async t=>{
  const app=application({provider:'Keymind Cascade',version:'v1.18.0.1-halo-keymind-cascade-dev-abcdef12',name:'board_repeater-v1.18.0.1-halo-keymind-cascade-dev-abcdef12.bin',url:releaseUrl('full-profiles-v1.18.0.1-halo-keymind-cascade-dev-abcdef12','board_repeater-v1.18.0.1-halo-keymind-cascade-dev-abcdef12.bin','mikecarper')}),migration={url:releaseUrl('utility-'+ 'v1.18.0.1-halo-keymind-cascade-dev-abcdef12','board-v1.18.0.1-halo-keymind-cascade-dev-abcdef12-migration.zip','mikecarper'),name:'board-v1.18.0.1-halo-keymind-cascade-dev-abcdef12-migration.zip'},fixture=inventory([app,migration]),directory=await output(t);
  const result=await build([app],directory,fixture);
  assert.equal(result.index.entries.length,2);assert.ok(result.index.entries.some(entry=>entry.url===migration.url));assert.ok(fixture.apiRequests.some(request=>request.url.includes('/tags/utility-v1.18.0.1-halo-keymind-cascade-dev-abcdef12')));assert.ok(result.index.warnings.some(warning=>warning.includes('meshcore-usb-partition-bridges.zip')));
  assert.equal(result.index.entries[0].url,app.url,'Applications are prioritized before optional migration archives');
});

test('output refuses arbitrary folders, unowned hashes, pending files and symlinks; only a valid previous index proves cleanup ownership',async t=>{
  const app=application(),fixture=inventory([app]),directory=await output(t);
  await assert.rejects(build([app],resolve(directory,'..'),fixture),/dedicated firmware/);
  await mkdir(directory);await writeFile(join(directory,'private-backup.json'),'not public');await assert.rejects(build([app],directory,fixture),/Unexpected file/);assert.equal(await readFile(join(directory,'private-backup.json'),'utf8'),'not public');
  await rm(join(directory,'private-backup.json'));const unknown='f'.repeat(64)+'.gz';await writeFile(join(directory,unknown),'unknown user file');await assert.rejects(build([app],directory,fixture),/Unowned hash/);assert.equal(await readFile(join(directory,unknown),'utf8'),'unknown user file');await rm(join(directory,unknown));
  await writeFile(join(directory,'index.json.pending'),'incomplete index');await assert.rejects(build([app],directory,fixture),/Unexpected file/);assert.equal(await readFile(join(directory,'index.json.pending'),'utf8'),'incomplete index');await rm(join(directory,'index.json.pending'));
  const previous=await build([app],directory,fixture),stale=previous.index.entries[0].path,next=application({name:'new_repeater-v1.19.0.bin',version:'v1.19.0'}),nextFixture=inventory([next]);
  await build([next],directory,nextFixture);assert.ok(!(await readdir(directory)).includes(stale));
  const linked=await output(t);try{await symlink(directory,linked,'junction');}catch(error){if(error.code==='EPERM'){t.diagnostic('Symlink creation is unavailable on this host');return;}throw error;}
  await assert.rejects(build([app],linked,fixture),/symlink/);
});

test('cache files and owned index sizes are checked before loading them into memory',async t=>{
  const app=application(),fixture=inventory([app]),directory=await output(t),result=await build([app],directory,fixture),entry=result.index.entries[0];
  const {open}=await import('node:fs/promises');let handle=await open(join(directory,entry.path),'r+');await handle.truncate(MIRROR_MAX_ASSET_BYTES+1);await handle.close();
  await assert.rejects(build([app],directory,fixture),/bounded regular file/);
  await writeFile(join(directory,entry.path),gzipSync(fixture.contents.get(app.url),{level:9,mtime:0}));
  handle=await open(join(directory,'index.json'),'r+');await handle.truncate((4<<20)+1);await handle.close();await assert.rejects(build([app],directory,fixture),/index exceeds its safe size/);
});

test('CI coverage policy rejects an empty or under-covered application mirror without inventing fallback entries',async t=>{
  const app=application(),fixture=inventory([app]),directory=await output(t);[...fixture.releases.values()][0].assets[0].digest=null;
  await assert.rejects(build([app],directory,fixture,{requireApplications:true,minimumApplicationRatio:0.9}),/No verified public application assets/);
  const a=application({name:'a_repeater-v1.18.0.bin'}),b=application({name:'b_repeater-v1.18.0.bin'}),partial=inventory([a,b]);[...partial.releases.values()][0].assets[1].digest=null;
  await assert.rejects(build([a,b],await output(t),partial,{requireApplications:true,minimumApplicationRatio:0.9}),/metadata coverage/);
  const good=inventory([a]),complete=await build([a],await output(t),good,{requireApplications:true,minimumApplicationRatio:0.9});assert.equal(complete.appRequested,1);assert.equal(complete.appResolved,1);assert.equal(complete.appMirrored,1);
  const tiny=inventory([a]);await assert.rejects(build([a],await output(t),tiny,{requireApplications:true,minimumApplicationRatio:0.9,maxBytes:1}),/No verified public application payloads/);
});

test('authoritative metadata never follows redirects or accepts a redirected API response',async t=>{
  const app=application(),fixture=inventory([app]),original=fixture.fetchImpl;
  fixture.fetchImpl=async(url,options)=>{const response=await original(url,options);if(url.startsWith('https://api.github.com/')){assert.equal(options.redirect,'error');Object.defineProperty(response,'url',{value:'https://untrusted.test/fake-release.json'});}return response;};
  await assert.rejects(build([app],await output(t),fixture,{token:'do-not-forward'}),/Authoritative GitHub API metadata redirected/);assert.equal(fixture.assetRequests.length,0);
});

test('only an explicitly public exact repository can supply authenticated release metadata or cached payloads',async t=>{
  for(const change of [{private:true,visibility:'private'},{private:false,visibility:'internal'},{private:false},{private:false,visibility:'public',full_name:'someone/another-repository'}]){
    const app=application(),fixture=inventory([app]),directory=await output(t);
    fixture.repositories.set([...fixture.repositories.keys()][0],change);
    await assert.rejects(build([app],directory,fixture,{token:'public-only-token'}),/repository is private|public identity/);assert.equal(fixture.assetRequests.length,0);assert.equal(fixture.apiRequests.length,1,'A non-public repository never reaches authenticated release metadata');
  }
  const app=application(),fixture=inventory([app]),directory=await output(t),first=await build([app],directory,fixture,{token:'public-only-token'}),snapshot=await readFile(join(directory,'index.json'),'utf8');fixture.assetRequests.length=0;fixture.apiRequests.length=0;
  Object.assign([...fixture.repositories.values()][0],{private:true,visibility:'private'});
  await assert.rejects(build([app],directory,fixture,{token:'public-only-token'}),/repository is private|public identity/);assert.equal(fixture.assetRequests.length,0);assert.equal(fixture.apiRequests.length,1);assert.equal(await readFile(join(directory,'index.json'),'utf8'),snapshot);assert.deepEqual((await readdir(directory)).sort(),[first.index.entries[0].path,'index.json'].sort());
});

test('hard asset/site bounds and redirect restrictions cannot be overridden by caller input',async t=>{
  const app=application(),fixture=inventory([app]),directory=await output(t);
  await assert.rejects(build([app],directory,fixture,{maxBytes:MIRROR_MAX_BYTES+1}),/850 MiB/);await assert.rejects(build([app],directory,fixture,{concurrency:0}),/concurrency/);
  [...fixture.releases.values()][0].assets[0].size=MIRROR_MAX_ASSET_BYTES+1;await assert.rejects(build([app],directory,fixture),/size.*64 MiB/);
  [...fixture.releases.values()][0].assets[0].size=fixture.contents.get(app.url).length;const original=fixture.fetchImpl;
  for(const target of ['http://127.0.0.1/private','https://release-assets.githubusercontent.com:444/file']){
    fixture.fetchImpl=async(url,options)=>{const response=await original(url,options);if(url===app.url)Object.defineProperty(response,'url',{value:target});return response;};
    await assert.rejects(build([app],directory,fixture),/unapproved origin/);
  }
});
