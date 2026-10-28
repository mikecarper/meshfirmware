// Public, source-bound USB fallback inventory. No PlatformIO, firmware build,
// device access, source checkout changes, shell interpolation or git fetch.
import {execFileSync} from 'node:child_process';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {dirname,resolve} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';

const revisionPattern=/^[a-f0-9]{40}$/;
const repositories=new Set(['https://github.com/mikecarper/MeshCore','https://github.com/meshcore-dev/MeshCore']);
const safeName=/^[A-Za-z0-9][A-Za-z0-9_.+:-]{0,199}$/;
const architectures=new Set(['esp32','nrf52']);
const unique=values=>[...new Set(values)].sort();

export function readGitSource(checkout,revision) {
  if(!revisionPattern.test(revision))throw new Error('Source revision must be a full pinned Git commit.');
  const git=(args,options={})=>execFileSync('git',['-C',checkout,...args],{maxBuffer:96<<20,...options});
  if(git(['rev-parse','--verify',`${revision}^{commit}`],{encoding:'utf8'}).trim()!==revision)throw new Error('Pinned source commit is unavailable.');
  const names=git(['ls-tree','-r','--name-only',revision],{encoding:'utf8'}).trim().split('\n').filter(name=>
    name==='platformio.ini'||/^(?:variants\/.*\/platformio\.ini|boards\/[^/]+\.json|variants\/.*\.(?:h|cpp)|build(?:_legacy)?\.sh|src\/helpers\/(?:UsbLogging\.h|ESP32Board\.h))$/.test(name));
  if(names.length>6000)throw new Error('Pinned source file limit exceeded.');
  const bytes=git(['cat-file','--batch'],{input:names.map(name=>`${revision}:${name}\n`).join('')});
  const files=new Map();let offset=0;
  for(const name of names){
    const end=bytes.indexOf(10,offset);if(end<0)throw new Error('Incomplete Git object header.');
    const header=/^[a-f0-9]{40} blob ([0-9]+)$/.exec(bytes.subarray(offset,end).toString());
    if(!header)throw new Error('Pinned source is not an ordinary Git blob.');
    const size=Number(header[1]);if(size>(8<<20)||end+1+size>=bytes.length)throw new Error('Pinned source object bound exceeded.');
    files.set(name,bytes.subarray(end+1,end+1+size).toString('utf8'));offset=end+size+2;
  }
  if(offset!==bytes.length)throw new Error('Unexpected trailing Git object bytes.');
  return files;
}

// Match ConfigParser's whitespace-delimited #/; comments, multiline options,
// case-sensitive section names and lowercase option names. Imported files are
// merged in source order; no local/untracked settings or host env are read.
export function parseIni(text,path='platformio.ini',sections=new Map()) {
  let section,last,lastIndent=0;
  for(const raw of String(text).replace(/^\uFEFF/,'').split(/\r?\n/)){
    const line=raw.replace(/(^|\s)[#;].*$/,'$1').trimEnd();if(!line.trim())continue;
    const head=/^\s*\[([^\]]+)\]\s*$/.exec(line);
    if(head){section=head[1];if(!sections.has(section))sections.set(section,new Map());last=null;continue;}
    if(!section)throw new Error(`Option outside an INI section: ${path}`);
    const indent=raw.match(/^\s*/)[0].length;
    if(last&&indent>lastIndent){sections.get(section).get(last).value+='\n'+line.trim();continue;}
    const option=/^\s*([A-Za-z0-9_.-]+)\s*=\s*(.*)$/.exec(line);
    if(option){last=option[1].toLowerCase();lastIndent=indent;sections.get(section).set(last,{value:option[2],path});continue;}
    throw new Error(`Unsupported INI syntax in ${path}`);
  }
  return sections;
}

function words(value) {
  const result=[];let token='',quote=null,escaped=false;
  for(const char of String(value)){
    if(escaped){token+=char;escaped=false;continue;}
    if(char==='\\'&&quote!=="'"){escaped=true;continue;}
    if(quote){if(char===quote)quote=null;else token+=char;continue;}
    if(char==='"'||char==="'"){quote=char;continue;}
    if(/\s/.test(char)){if(token){result.push(token);token='';}}else token+=char;
  }
  if(quote||escaped)throw new Error('Unresolved build flag quoting.');
  if(token)result.push(token);return result;
}
export function flagOperations(value) {
  const tokens=words(value),operations=[];
  for(let index=0;index<tokens.length;index++){
    let token=tokens[index];if(token==='-D'||token==='-U')token+=tokens[++index]||'';
    const match=/^-([DU])([A-Za-z_]\w*)(?:=(.*))?$/.exec(token);
    if(match)operations.push({kind:match[1],name:match[2],value:match[3]??null});
  }
  return operations;
}

export function createSourceResolver(files) {
  if(!(files instanceof Map)||!files.has('platformio.ini'))throw new Error('Pinned PlatformIO source is missing.');
  const sections=new Map(),loaded=new Set(),imports=[];
  function load(path){
    if(loaded.has(path))return;loaded.add(path);
    if(!files.has(path))return;
    parseIni(files.get(path),path,sections);
    const value=sections.get('platformio')?.get('extra_configs')?.value||'';
    for(const pattern of value.split(/[\n,]+/).map(v=>v.trim()).filter(Boolean)){
      if(pattern==='platformio.local.ini'&&!files.has(pattern))continue;
      if(!/^[A-Za-z0-9_./*+-]+$/.test(pattern)||pattern.split('/').includes('..'))throw new Error('Unreviewed PlatformIO configuration import.');
      if(imports.includes(pattern))continue;imports.push(pattern);
      const regex=new RegExp('^'+pattern.replace(/[.+^${}()|[\]\\]/g,'\\$&').replace(/\*/g,'[^/]*')+'$');
      for(const name of [...files.keys()].filter(name=>regex.test(name)).sort())load(name);
    }
  }
  load('platformio.ini');
  const cache=new Map();
  function get(section,key,stack=[],evidence=new Set()){
    key=key.toLowerCase();const at=section+'.'+key;
    if(stack.includes(at)||stack.length>60)throw new Error('Cyclic/unbounded PlatformIO inheritance.');
    const next=[...stack,at],queue=(section.startsWith('env:')?['env',section]:[section]).map(selected=>({selected,ancestors:[]})),visited=new Set();
    let found;
    while(queue.length){
      const {selected,ancestors}=queue.pop();if(ancestors.includes(selected))throw new Error('Cyclic PlatformIO extends.');if(visited.has(selected))continue;visited.add(selected);
      const row=sections.get(selected);if(!row)continue;
      if(row.has(key)){found=row.get(key);break;}
      if(row.has('extends')){
        const parents=row.get('extends');evidence.add(parents.path);
        // PlatformIO walk_options visits the LAST extends parent first.
        queue.push(...parents.value.split(/[\n,]+/).map(v=>v.trim()).filter(Boolean).map(parent=>({selected:parent,ancestors:[...ancestors,selected]})));
      }
    }
    if(!found)return '';
    evidence.add(found.path);
    return found.value.replace(/\$\{([^}]+)\}/g,(_,reference)=>{
      const point=reference.indexOf('.');if(point<1)throw new Error('Unresolved SCons/environment interpolation.');
      let from=reference.slice(0,point),option=reference.slice(point+1);if(from==='sysenv')throw new Error('Host environment interpolation is not release evidence.');
      if(from==='this'){if(option==='__env__')return section.replace(/^env:/,'');from=section;}
      return get(from,option,next,evidence);
    });
  }
  function environment(name){
    if(!safeName.test(name)||!sections.has('env:'+name))throw new Error('Exact published build environment is absent from pinned source.');
    if(cache.has(name))return cache.get(name);
    const evidence=new Set(),values={};
    for(const key of ['board','board_build.mcu','board_build.variant','board_build.extra_flags','build_flags','build_unflags','platform','platform_packages','build_src_filter'])values[key]=get('env:'+name,key,[],evidence);
    const result={values,evidence:[...evidence]};cache.set(name,result);return result;
  }
  return {files,environment};
}

function number(value){
  if(typeof value!=='string')return null;const match=/^(0x[0-9a-f]+|[0-9]+)[uUlL]*$/i.exec(value.trim());
  return match?Number(match[1]):null;
}
function stableDefinitions(flags,unflags){
  const removed=flagOperations(unflags),operations=flagOperations(flags).filter(op=>!removed.some(drop=>drop.kind===op.kind&&drop.name===op.name&&(drop.value===null||drop.value===op.value)));
  const definitions=new Map();
  for(const op of operations){
    if(op.kind==='U')continue;
    const value=op.value??'1';
    if(definitions.has(op.name)&&definitions.get(op.name)!==value)definitions.set(op.name,null);
    else if(!definitions.has(op.name))definitions.set(op.name,value);
  }
  for(const op of operations)if(op.kind==='U')definitions.delete(op.name);
  return definitions;
}

export function resolveUsbProfile(item,resolver) {
  const evidence=new Set(),unknown=reason=>({usbMode:'unknown',usbIds:[],evidence:unique([...evidence]),reason});
  try{
    if(!item.runtimeVersion)return unknown('The exact embedded runtime version is not proven by the release inventory.');
    const {values,evidence:paths}=resolver.environment(item.environment);paths.forEach(path=>evidence.add(path));
    const board=values.board;if(!safeName.test(board)||board.includes(':'))return unknown('Board identity is not a literal source-bound name.');
    const boardPath=`boards/${board}.json`;
    if(!resolver.files.has(boardPath))return unknown('Board build metadata belongs to an external SDK package and is not present in this pinned source tree.');
    evidence.add(boardPath);const metadata=JSON.parse(resolver.files.get(boardPath)),build=metadata.build;
    if(!build||typeof build!=='object')return unknown('Board metadata has no reviewed build definitions.');
    const mcu=(values['board_build.mcu']||build.mcu||'').toLowerCase();
    const extra=Array.isArray(build.extra_flags)?build.extra_flags.join('\n'):build.extra_flags||'';
    const flags=[extra,values['board_build.extra_flags'],values.build_flags].join('\n');
    const definitions=stableDefinitions(flags,values.build_unflags);
    if(definitions.has('Serial')||definitions.has('SERIAL_PORT'))return unknown('The primary Serial port is explicitly overridden.');
    const variants=new Set([...flags.matchAll(/(?:^|\s)-I\s*(variants\/[A-Za-z0-9_.-]+)/g)].map(match=>match[1]));
    const variant=values['board_build.variant']||build.variant;if(variant&&/^[A-Za-z0-9_.-]+$/.test(variant))variants.add('variants/'+variant);
    for(const [path,text] of resolver.files){
      if(![...variants].some(directory=>path.startsWith(directory+'/'))||!/[.](?:h|cpp)$/.test(path))continue;
      if(/^\s*#\s*(?:define|undef)\s+Serial(?:\s|$)/m.test(text)){evidence.add(path);return unknown('Selected board source redirects the primary Serial object.');}
    }
    if(item.architecture==='nrf52'){
      if(!definitions.has('USE_TINYUSB'))return unknown('nRF52 TinyUSB selection is supplied outside this pinned board recipe.');
      const ids=applicationUsbIds(definitions,variants,resolver.files,evidence);return {usbMode:'tinyusb',usbIds:ids,evidence:unique([...evidence]),...(ids.length?{}:{reason:'The primary TinyUSB backend is proven, but its application VID/PID is not source-bound.'})};
    }
    if(item.architecture!=='esp32')return unknown('Architecture is not supported by this fallback inventory.');
    if(!['esp32','esp32s2','esp32s3','esp32c3'].includes(mcu))return unknown('The chip/framework USB implementation has not been reviewed for this inventory.');
    if(!/^platformio\/espressif32@6\.[0-9]+\.[0-9]+$/.test(values.platform.trim()))return unknown('The source does not pin the reviewed Arduino-ESP32 2.x platform family.');
    const frameworkOverrides=[...values.platform_packages.matchAll(/framework-arduinoespressif32\s*@\s*([^\s]+)/g)].map(match=>match[1]);
    if(frameworkOverrides.some(value=>value!=='https://github.com/IoTThinks/powersaving-arduino-lib/releases/download/2.0.17/esp32-2.0.17.zip'))return unknown('The application overrides Arduino-ESP32 with an unreviewed framework package.');
    const cdc=definitions.has('ARDUINO_USB_CDC_ON_BOOT')?number(definitions.get('ARDUINO_USB_CDC_ON_BOOT')):0;
    if(cdc===null)return unknown('CDC-on-boot has conflicting or nonliteral effective definitions.');
    if(cdc===0)return {usbMode:'uart',usbIds:boardUsbIds(metadata),evidence:unique([...evidence]),reason:'Primary Serial is UART; a USB adapter identity must be independently established.'};
    const mode=definitions.has('ARDUINO_USB_MODE')?number(definitions.get('ARDUINO_USB_MODE')):null;
    if(mode===1&&['esp32s3','esp32c3'].includes(mcu))return {usbMode:'hardware-cdc-jtag',usbIds:['303a:1001'],evidence:unique([...evidence])};
    if(mode===0&&['esp32s2','esp32s3'].includes(mcu)){
      // A board's upload hwids may contain bootloader PIDs, so only explicit
      // application descriptor definitions qualify a TinyUSB runtime port.
      const usbIds=applicationUsbIds(definitions,variants,resolver.files,evidence);return {usbMode:'tinyusb',usbIds,evidence:unique([...evidence]),...(usbIds.length?{}:{reason:'The TinyUSB backend is known, but the application descriptor is absent or ambiguous; automatic matching remains disabled.'})};
    }
    return unknown('Native USB mode is missing, conflicting, nonliteral, or incompatible with the proven MCU.');
  }catch(error){return unknown(String(error.message).slice(0,240));}
}

function applicationUsbIds(definitions,variants,files,evidence){
  const candidates=[];
  function add(vid,pid){if(Number.isInteger(vid)&&Number.isInteger(pid)&&vid>0&&pid>0&&vid<=65535&&pid<=65535)candidates.push([vid,pid].map(value=>value.toString(16).padStart(4,'0')).join(':'));}
  add(number(definitions.get('USB_VID')),number(definitions.get('USB_PID')));
  for(const [path,text] of files)if([...variants].some(directory=>path===directory+'/pins_arduino.h')){
    const vid=/^\s*#define\s+USB_VID\s+(0x[0-9a-f]+|[0-9]+)\b/im.exec(text),pid=/^\s*#define\s+USB_PID\s+(0x[0-9a-f]+|[0-9]+)\b/im.exec(text);
    if(vid&&pid){evidence.add(path);add(Number(vid[1]),Number(pid[1]));}
  }
  const ids=unique(candidates);return ids.length===1?ids:[];
}

function boardUsbIds(metadata){
  // Upload IDs are not sufficient to prove a runtime native-USB descriptor.
  // UART rows can retain them only as public evidence for an independent
  // adapter match. Native USB runtime IDs use applicationUsbIds instead.
  return unique((metadata.build?.hwids||[]).flatMap(pair=>{
    if(!Array.isArray(pair)||pair.length!==2)return [];
    const numbers=pair.map(value=>number(String(value)));return numbers.every(value=>Number.isInteger(value)&&value>0&&value<=65535)?[numbers.map(value=>value.toString(16).padStart(4,'0')).join(':')]:[];
  }));
}

export function buildUsbConnectionMap(inventory,{sourceFor}={}) {
  if(inventory?.schemaVersion!==1||!Array.isArray(inventory.items)||inventory.items.length>10000)throw new Error('Invalid reviewed release inventory.');
  if(typeof sourceFor!=='function')throw new Error('A pinned source reader is required.');
  const builds=new Map(),resolvers=new Map();
  for(const item of inventory.items){
    if(!architectures.has(item.architecture))continue;
    const source=item.source;
    if(!source||!repositories.has(source.repository)||!revisionPattern.test(source.revision))throw new Error('Inventory source provenance is invalid.');
    if(typeof item.hardware!=='string'||!item.hardware||item.hardware.length>200||!safeName.test(item.role||''))throw new Error('Inventory public hardware/role is invalid.');
    const version=item.runtimeVersion||item.version;if(typeof version!=='string'||!version||version.length>200||/[\x00-\x20\x7f]/.test(version))throw new Error('Inventory version is invalid.');
    const key=JSON.stringify([version,source.repository,source.revision]);
    if(!builds.has(key))builds.set(key,{version,source:{repository:source.repository,revision:source.revision},profiles:[]});
    const build=builds.get(key),resolverKey=source.revision;
    let result;
    try{if(!resolvers.has(resolverKey))resolvers.set(resolverKey,createSourceResolver(sourceFor(source)));result=resolveUsbProfile(item,resolvers.get(resolverKey));}
    catch(error){result={usbMode:'unknown',usbIds:[],evidence:[],reason:String(error.message).slice(0,240)};}
    const profile={hardware:item.hardware,architecture:item.architecture,role:item.role,
      usbMode:result.usbMode,usbIds:result.usbIds,
      targets:unique([item.environment,item.target].filter(value=>typeof value==='string'&&safeName.test(value))),
      evidence:result.evidence.length?result.evidence:['platformio.ini']};
    const same=build.profiles.find(row=>JSON.stringify({...row,targets:[]})===JSON.stringify({...profile,targets:[]}));
    if(same)same.targets=unique([...same.targets,...profile.targets]);else build.profiles.push(profile);
  }
  return {schemaVersion:1,builds:[...builds.values()].sort((a,b)=>a.version.localeCompare(b.version)||a.source.repository.localeCompare(b.source.repository)).map(build=>({...build,profiles:build.profiles.sort((a,b)=>a.hardware.localeCompare(b.hardware)||a.role.localeCompare(b.role)||a.usbMode.localeCompare(b.usbMode)||a.targets.join().localeCompare(b.targets.join()))}))};
}

async function main(args){
  const options=new Map();for(let index=0;index<args.length;index+=2){if(!/^--(?:source-checkout|inventory|output)$/.test(args[index])||!args[index+1])throw new Error('Use --source-checkout PATH --inventory FILE --output FILE.');options.set(args[index],args[index+1]);}
  const checkout=resolve(options.get('--source-checkout')||fileURLToPath(new URL('../../../MeshCore/',import.meta.url)));
  const inventoryPath=resolve(options.get('--inventory')||fileURLToPath(new URL('./usb-connection-inventory.json',import.meta.url)));
  const output=resolve(options.get('--output')||fileURLToPath(new URL('../src/data/usb-connection-map.json',import.meta.url)));
  const bytes=await readFile(inventoryPath);if(bytes.length>(16<<20))throw new Error('Reviewed inventory exceeds its size bound.');
  const result=buildUsbConnectionMap(JSON.parse(bytes),{sourceFor:source=>readGitSource(checkout,source.revision)});
  await mkdir(dirname(output),{recursive:true});await writeFile(output,JSON.stringify(result,null,2)+'\n');
  const profiles=result.builds.flatMap(build=>build.profiles),counts=Object.fromEntries(['hardware-cdc-jtag','tinyusb','uart','unknown'].map(mode=>[mode,profiles.filter(row=>row.usbMode===mode).length]));
  console.log(JSON.stringify({builds:result.builds.length,profiles:profiles.length,counts,matchingUsbIds:profiles.filter(row=>row.usbIds.length>0).length,output}));
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)main(process.argv.slice(2)).catch(error=>{console.error(error.message);process.exitCode=1;});
