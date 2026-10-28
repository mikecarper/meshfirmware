import test from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {build} from 'vite';

const root=fileURLToPath(new URL('../',import.meta.url));
const entry='virtual:esp-minified-regression';
let compiled;
function productionModule(){
  // Build the real modules and dependency together, not an imitation error
  // class. Public assets/mirrors and all filesystem output are disabled.
  return compiled ||= (async()=>{
    const result=await build({
      root,configFile:false,publicDir:false,logLevel:'silent',
      plugins:[{
        name:'esp-minified-regression',
        resolveId(id){
          if(id===entry)return '\0'+entry;
          if(id==='esp-under-test')return fileURLToPath(new URL('../src/esp.js',import.meta.url));
          if(id==='fallback-under-test')return fileURLToPath(new URL('../src/connection-fallback.js',import.meta.url));
        },
        load(id){
          if(id==='\0'+entry)return "export {ESPError} from 'esptool-js';export {EspSession} from 'esp-under-test';export {tryNativeUsbFallback} from 'fallback-under-test';";
        },
      }],
      build:{
        write:false,minify:true,target:'es2022',emptyOutDir:false,
        rolldownOptions:{input:entry,preserveEntrySignatures:'strict',output:{format:'es',codeSplitting:false}},
      },
    });
    const outputs=(Array.isArray(result)?result:[result]).flatMap(bundle=>bundle.output||[]);
    const chunks=outputs.filter(output=>output.type==='chunk');
    assert.equal(chunks.length,1,'The regression must run the one actual minified module, with no external chunks');
    assert.equal(outputs.filter(output=>output.type==='asset').length,0,'The test must not require copied public assets');
    const url='data:text/javascript;base64,'+Buffer.from(chunks[0].code+'\n//# sourceURL=esp-minified-regression.js\n').toString('base64');
    return import(url);
  })();
}

function serialFixture({readerFailure=null}={}){
  const calls=[];
  let controller,failed=false;
  const port={
    readable:null,writable:null,
    getInfo:()=>({usbVendorId:0x303a,usbProductId:0x1001}),
    async open(){
      calls.push('open');
      this.readable=new ReadableStream({start(value){controller=value;}});
      this.writable=new WritableStream({write(){
        calls.push('write');
        if(readerFailure&&!failed){failed=true;controller.error(readerFailure);}
      }});
    },
    async close(){
      assert.ok(!this.readable?.locked&&!this.writable?.locked,'Strict cleanup must release both streams');
      calls.push('close');this.readable=null;this.writable=null;
    },
    async setSignals(){calls.push('signal');},
  };
  return {port,calls};
}

test('production-minified ESPError retains class identity and silent pre-sync advances to the next bounded method',async()=>{
  const {ESPError,EspSession,tryNativeUsbFallback}=await productionModule();
  const fixture=serialFixture(),messages=[],session=new EspSession(fixture.port,message=>messages.push(message));
  session.transport.trace=()=>{};
  let nativeError,firstFailure;
  try{await session.transport.read(1);}catch(error){nativeError=error;}
  assert.ok(nativeError instanceof ESPError,'The real minified Transport must throw this bundle\'s ESPError');
  assert.notEqual(nativeError.name,'ESPError','The production minifier must rename the error constructor, reproducing the browser-only failure');
  assert.equal(nativeError.message,'Serial data stream stopped: Possible serial noise or corruption.');
  const attempts=[],winningSession={verified:true},info={chip:'ESP32-S3',mac:'aa:bb:cc:dd:ee:ff',flashBytes:16<<20};
  const result=await tryNativeUsbFallback({
    connect:async(mode,options)=>{
      attempts.push(mode);assert.equal(options.singleReset,true);
      if(mode==='no_reset'){
        try{return {session,info:await session.connect(mode,options)};}catch(error){firstFailure=error;throw error;}
      }
      assert.equal(mode,'usb_reset');return {session:winningSession,info};
    },
    close:()=>session.close({strict:true}),
    touch:()=>{throw Error('A successful second method must never touch TinyUSB');},
    isCurrent:()=>true,portAvailable:()=>true,
  });
  assert.deepEqual(attempts,['no_reset','usb_reset']);
  assert.equal(firstFailure.romHandshakeFailed,true);
  assert.ok(firstFailure.cause instanceof ESPError,'The collapsed failure must still originate in the minified dependency');
  assert.notEqual(firstFailure.cause.name,'ESPError');
  assert.equal(result.session,winningSession);assert.equal(result.info,info);assert.equal(result.mode,'usb_reset');
  assert.equal(fixture.calls.filter(call=>call==='close').length,1);assert.ok(!fixture.calls.includes('signal'));
  assert.ok(messages.some(message=>String(message).includes('Serial data stream stopped')),'Diagnostics must preserve the real underlying error');
});

test('production-minified reader loss or denied reads cannot become permission for another reset',async()=>{
  const {EspSession,tryNativeUsbFallback}=await productionModule();
  for(const name of ['NetworkError','NotAllowedError']){
    const failure=new DOMException(name==='NetworkError'?'The device has been lost.':'Access denied.',name);
    const fixture=serialFixture({readerFailure:failure}),session=new EspSession(fixture.port,()=>{}),attempts=[];
    session.transport.trace=()=>{};
    await assert.rejects(tryNativeUsbFallback({
      connect:async(mode,options)=>{attempts.push(mode);return {session,info:await session.connect(mode,options)};},
      close:()=>session.close({strict:true}),
      touch:()=>{throw Error('A failed reader must not trigger a handoff');},
      isCurrent:()=>true,portAvailable:()=>true,
    }),error=>!error.romHandshakeFailed&&/reader stopped|device has been lost|denied/i.test(error.message),name);
    assert.deepEqual(attempts,['no_reset'],name);assert.equal(fixture.calls.filter(call=>call==='close').length,1);assert.ok(!fixture.calls.includes('signal'));
  }
});
