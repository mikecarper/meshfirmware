import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chooseBootloaderInfoFile} from '../src/bootloader-info-file.js';

const text='UF2 Bootloader 0.9.2\r\nModel: Heltec T114\r\nBoard-ID: HT-n5262\r\n';
const failure=(name,message='private filename or path')=>Object.assign(new Error(message),{name});
function file({name='INFO_UF2.TXT',size=new TextEncoder().encode(text).length,value=text,readError=null}={}){
  return {name,size,reads:0,async text(){this.reads++;if(readError)throw readError;return value;}};
}
class Target{
  listeners=new Map();
  addEventListener(type,handler){if(!this.listeners.has(type))this.listeners.set(type,new Set());this.listeners.get(type).add(handler);}
  removeEventListener(type,handler){this.listeners.get(type)?.delete(handler);}
  dispatch(type){for(const handler of [...(this.listeners.get(type)||[])])handler({type,target:this});}
  get listenerCount(){return [...this.listeners.values()].reduce((sum,value)=>sum+value.size,0);}
}
function legacy(onClick=()=>{}){
  const window=new Target(),input=new Target(),children=[],timers=new Map();let nextTimer=0,created=0,clicks=0;
  input.files=[];input.remove=()=>{const index=children.indexOf(input);if(index>=0)children.splice(index,1);};input.click=()=>{clicks++;onClick(input,window);};
  window.setTimeout=(callback,delay)=>{assert.equal(delay,300);timers.set(++nextTimer,callback);return nextTimer;};window.clearTimeout=id=>timers.delete(id);
  const document={body:{append:element=>children.push(element)},createElement:tag=>{assert.equal(tag,'input');created++;return input;}};
  return {window,document,input,children,timers,get created(){return created;},get clicks(){return clicks;},flushFocus(){for(const [id,callback] of [...timers]){timers.delete(id);callback();}}};
}
const assertClean=fixture=>{assert.equal(fixture.children.length,0);assert.equal(fixture.input.listenerCount,0);assert.equal(fixture.window.listenerCount,0);assert.equal(fixture.timers.size,0);};

test('native picker requests only one text file and reads the selected INFO_UF2 without directory or write permission',async()=>{
  const chosen=file(),calls=[],window={async showOpenFilePicker(options){calls.push(options);return [{getFile:async()=>chosen}];}},document={createElement(){throw Error('No input fallback');}};
  assert.deepEqual(await chooseBootloaderInfoFile({window,document}),{name:'INFO_UF2.TXT',text});assert.equal(chosen.reads,1);
  assert.deepEqual(calls,[{id:'meshfirmware-bootloader-info',multiple:false,excludeAcceptAllOption:true,types:[{description:'INFO_UF2.TXT from the radio',accept:{'text/plain':['.TXT']}}]}]);
  assert.ok(!Object.hasOwn(calls[0],'startIn'));assert.ok(!Object.hasOwn(calls[0],'mode'));
});

test('native cancellation returns null and never invokes the legacy picker',async()=>{
  for(const response of ['abort','empty']){
    const fallback=legacy(),window={showOpenFilePicker:async()=>{if(response==='abort')throw failure('AbortError');return [];}};
    assert.equal(await chooseBootloaderInfoFile({window,document:fallback.document}),null);assert.equal(fallback.created,0);
  }
});

test('permission and security failures are safe errors, not a second permission attempt through the input fallback',async()=>{
  for(const name of ['NotAllowedError','SecurityError','NotFoundError','TypeError','UnknownError']){
    const fallback=legacy(),window={showOpenFilePicker:async()=>{throw failure(name);}};
    await assert.rejects(chooseBootloaderInfoFile({window,document:fallback.document}),error=>/could not be selected/.test(error.message)&&!error.message.includes('private'));assert.equal(fallback.created,0);
  }
});

test('native getFile and content-read errors reveal no paths and never trigger another picker',async()=>{
  const fallback=legacy();
  await assert.rejects(chooseBootloaderInfoFile({window:{showOpenFilePicker:async()=>[{getFile:async()=>{throw failure('NotAllowedError');}}]},document:fallback.document}),error=>/could not be read/.test(error.message)&&!error.message.includes('private'));
  const unreadable=file({readError:failure('AbortError')});
  await assert.rejects(chooseBootloaderInfoFile({window:{showOpenFilePicker:async()=>[{getFile:async()=>unreadable}]},document:fallback.document}),/could not be read/);assert.equal(fallback.created,0);
});

test('unsupported native picker and browsers without it use the single-file HTML fallback',async()=>{
  for(const native of [false,true]){
    const chosen=file({name:'info_uf2.txt'}),f=legacy(input=>{input.files=[chosen];input.dispatch('change');});
    if(native)f.window.showOpenFilePicker=async()=>{throw failure('NotSupportedError');};
    assert.deepEqual(await chooseBootloaderInfoFile(f),{name:'INFO_UF2.TXT',text});assert.equal(f.clicks,1);assert.equal(f.created,1);assert.equal(f.input.type,'file');assert.equal(f.input.multiple,false);assert.equal(f.input.hidden,true);assert.match(f.input.accept,/\.txt/);assertClean(f);
  }
});

test('legacy cancel and empty selection return null with listeners, timer and hidden input removed',async()=>{
  for(const event of ['cancel','change']){
    const f=legacy(input=>input.dispatch(event));assert.equal(await chooseBootloaderInfoFile(f),null);assertClean(f);
  }
});

test('older mobile picker cancellation settles after focus returns when no cancel event exists',async()=>{
  const f=legacy(),pending=chooseBootloaderInfoFile(f);assert.equal(f.children.length,1);f.window.dispatch('focus');assert.equal(f.timers.size,1);f.flushFocus();assert.equal(await pending,null);assertClean(f);
});

test('focus fallback waits for the change event and does not prematurely discard a selected file',async()=>{
  const chosen=file(),f=legacy(),pending=chooseBootloaderInfoFile(f);f.window.dispatch('focus');assert.equal(f.timers.size,1);f.input.files=[chosen];f.input.dispatch('change');assert.deepEqual(await pending,{name:'INFO_UF2.TXT',text});assertClean(f);f.flushFocus();assert.equal(chosen.reads,1);
  const selected=legacy(),later=chooseBootloaderInfoFile(selected);selected.input.files=[file()];selected.window.dispatch('focus');selected.flushFocus();assert.deepEqual(await later,{name:'INFO_UF2.TXT',text});assertClean(selected);
});

test('legacy picker exceptions are sanitized and its created input is removed',async()=>{
  const f=legacy(()=>{throw failure('SecurityError');});await assert.rejects(chooseBootloaderInfoFile(f),error=>/could not be selected/.test(error.message)&&!error.message.includes('private'));assertClean(f);
  await assert.rejects(chooseBootloaderInfoFile({window:{},document:{body:{},createElement(){throw failure('Error');}}}),/could not be selected/);
  await assert.rejects(chooseBootloaderInfoFile({window:{},document:null}),/could not be selected/);
});

test('only an exact case-insensitive INFO_UF2.TXT basename is accepted before reading contents',async()=>{
  for(const name of ['firmware.bin','INFO_UF2.TXT.bin','../INFO_UF2.TXT','C:\\private\\INFO_UF2.TXT','INFO_UF2.TXT\0',' INFO_UF2.TXT','ınfo_uf2.txt']){
    const chosen=file({name}),window={showOpenFilePicker:async()=>[{getFile:async()=>chosen}]};
    await assert.rejects(chooseBootloaderInfoFile({window}),error=>error.message==='Choose INFO_UF2.TXT from the radio’s bootloader drive.');assert.equal(chosen.reads,0);
  }
  for(const name of ['INFO_UF2.TXT','info_uf2.txt','Info_Uf2.TxT'])assert.equal((await chooseBootloaderInfoFile({window:{showOpenFilePicker:async()=>[{getFile:async()=>file({name})}]}})).name,'INFO_UF2.TXT');
});

test('oversized or invalid file sizes fail before text is read',async()=>{
  for(const size of [8193,-1,NaN,Infinity,1.5,undefined]){
    const chosen=file();chosen.size=size;await assert.rejects(chooseBootloaderInfoFile({window:{showOpenFilePicker:async()=>[{getFile:async()=>chosen}]}}),/allowed size/);assert.equal(chosen.reads,0);
  }
  const chosen=file({size:20}),f=legacy(input=>{input.files=[chosen];input.dispatch('change');});await assert.rejects(chooseBootloaderInfoFile({...f,maxBytes:10}),/No file content was read/);assert.equal(chosen.reads,0);assertClean(f);
});

test('returned text is bounded by UTF-8 bytes even if a file-like object lies about its size',async()=>{
  for(const value of ['a'.repeat(10),'🦷🦷',null]){
    const chosen=file({size:1,value});await assert.rejects(chooseBootloaderInfoFile({window:{showOpenFilePicker:async()=>[{getFile:async()=>chosen}]},maxBytes:4}),/allowed size/);assert.equal(chosen.reads,1);
  }
});

test('malformed picker results, multi-file legacy selection and invalid size options fail closed',async()=>{
  for(const result of [null,{},[{}],[{getFile:async()=>file()},{getFile:async()=>file()}]])await assert.rejects(chooseBootloaderInfoFile({window:{showOpenFilePicker:async()=>result}}),/could not be selected/);
  const f=legacy(input=>{input.files=[file(),file()];input.dispatch('change');});await assert.rejects(chooseBootloaderInfoFile(f),/Choose only/);assertClean(f);
  let calls=0;for(const maxBytes of [0,-1,NaN,Infinity,1.5,2**30])await assert.rejects(chooseBootloaderInfoFile({window:{showOpenFilePicker:async()=>{calls++;return [];}},maxBytes}),/size limit/);assert.equal(calls,0);
});
