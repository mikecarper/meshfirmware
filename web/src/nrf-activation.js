// A positive, fresh application reply can end a conservative activation wait.
// Neither a DFU ACK, a USB disconnect, nor the bootloader version attests to
// bank-copy completion. Unknown/component updates retain the normal wait.
const READ_MS=3000, CLOSE_MS=1000, RETRY_MS=250, MAX_ATTEMPTS=16, MAX_WAIT_MS=120000;
const key=value=>typeof value==='string'&&/^[a-f0-9]{64}$/i.test(value)?value.toLowerCase():null;
const models=new Set(['Seeed Tracker T1000-E','Seeed Studio SenseCAP T1000-E','T1000-E']);
const hardwareName='Seeed Studio SenseCAP T1000-E';
const bootloader=/^(?:v?0\.11\.0-)?OTAFIX2\.4\.12(?:-preview\.142)?$/i;
const versionToken='v?\\d+\\.\\d+\\.\\d+(?:\\.\\d+)?(?:[-+][A-Za-z0-9]+(?:[._+-][A-Za-z0-9]+)*)?';
const rawVersion=new RegExp(`^(${versionToken})$`);
const companionVersion=new RegExp(`^Companion (${versionToken}) \\(protocol \\d+, build [A-Za-z0-9: _-]{1,64}\\)$`);
const filenameVersion=new RegExp(`-(${versionToken})\\.zip$`);
const componentName=/(?:^|[_.\s-])(?:bootloader|softdevice|erase|wipe|formatter|format|recovery)(?:[_.\s-]|$)|^R_/i;
const normalizeVersion=value=>value.replace(/^v/,'');
function version(value){
  if(typeof value!=='string'||value.length>256||/[\x00-\x1f\x7f\u2026]/.test(value))return null;
  const text=value.trim(),match=rawVersion.exec(text)||companionVersion.exec(text);
  return match?normalizeVersion(match[1]):null;
}
function expectedVersion(pkg){
  const fromName=filenameVersion.exec(pkg.name)?.[1],fromIdentity=version(pkg.firmwareIdentity?.versionText);
  if(fromName){
    const parsed=version(fromName);
    if(!parsed)return null;
    // A content-bound footer must agree with the filename's numeric version.
    if(fromIdentity&&parsed.split(/[-+]/)[0]!==fromIdentity.split(/[-+]/)[0])return null;
    return parsed;
  }
  return fromIdentity;
}
function usb(port,vendor,product){
  try{const info=port?.getInfo?.();return info?.usbVendorId===vendor&&info?.usbProductId===product;}catch{return false;}
}
function retryable(error){
  const name=String(error?.name||''),message=String(error?.message||'');
  if(/permission|access.?denied|not.?allowed|security|unauthori[sz]ed/i.test(name+' '+message))return false;
  return ['NetworkError','NotFoundError','TimeoutError'].includes(name)||/\b(?:timed?\s*out|timeout)\b/i.test(message);
}
function defaultDelay(ms,{signal}={}){
  return new Promise((resolve,reject)=>{
    const abort=()=>{clearTimeout(timer);reject(Object.assign(new Error('Cancelled activation timer.'),{name:'AbortError'}));};
    const timer=setTimeout(()=>{signal?.removeEventListener('abort',abort);resolve();},ms);
    if(signal?.aborted)abort();else signal?.addEventListener('abort',abort,{once:true});
  });
}

export function createNrfActivationCheck({pkg,device,knownApplicationPort,hardware,expectedRole,readApplication,isCurrent,delay=defaultDelay,now=Date.now,log=()=>{}}={}){
  if(!pkg||pkg.architecture!=='nrf52'||pkg.kind!=='application'||pkg.mode!==4||pkg.sdSize!==0||pkg.blSize!==0||pkg.erase||pkg.expert||pkg.destructive||
    !Number.isInteger(pkg.appSize)||pkg.appSize<=0||pkg.appSize>(1<<20)||typeof pkg.name!=='string'||componentName.test(pkg.name)||
    ['includesBootloader','containsBootloader','embeddedBootloader','includesSoftdevice','containsSoftdevice','embeddedSoftdevice'].some(name=>pkg[name]===true))return null;
  if(device?.firmwareFamily==='meshtastic'||device?.role!=='companion'||expectedRole!=='companion'||!models.has(device.model)||
    (hardware!=null&&hardware!==hardwareName)||!bootloader.test(device.bootloaderVersion||''))return null;
  const publicKey=key(device.publicKey),appPort=knownApplicationPort?.port,wantedVersion=expectedVersion(pkg);
  if(!publicKey||key(knownApplicationPort?.publicKey)!==publicKey||!usb(appPort,0x239a,0x8029)||!wantedVersion||
    !key(pkg.sha256)||typeof readApplication!=='function'||typeof isCurrent!=='function'||typeof delay!=='function'||typeof now!=='function'||typeof log!=='function')return null;
  const bound={name:pkg.name,sha256:pkg.sha256,metadataHash:pkg.metadataHash,payloadHash:pkg.payloadHash,appSize:pkg.appSize};
  let used=false;
  return async({link,pkg:actual,maxWaitMs,onProgress=()=>{}}={})=>{
    if(used)return false;used=true;
    if(actual!==pkg||!Number.isFinite(maxWaitMs)||maxWaitMs<READ_MS||maxWaitMs>MAX_WAIT_MS||typeof link?.close!=='function'||!usb(link.port,0x2886,0x0057)||typeof onProgress!=='function')return false;
    let start;try{start=now();}catch{return false;}
    if(!Number.isFinite(start))return false;
    const dfuPort=link.port,deadline=start+maxWaitMs;let last=start;
    const current=()=>{
      const tick=now();
      if(!Number.isFinite(tick)||tick<last||tick>=deadline)return false;
      last=tick;
      try{return isCurrent()===true&&actual===pkg&&Object.entries(bound).every(([name,value])=>pkg[name]===value)&&
        pkg.architecture==='nrf52'&&pkg.kind==='application'&&pkg.mode===4&&pkg.sdSize===0&&pkg.blSize===0&&!pkg.erase&&!pkg.expert&&!pkg.destructive&&
        link.port===dfuPort&&knownApplicationPort.port===appPort&&key(knownApplicationPort.publicKey)===publicKey&&usb(appPort,0x239a,0x8029);}catch{return false;}
    };
    // Abort the adapter's read on its own deadline. Never start another probe
    // after racing an adapter which has not returned; it may still be closing.
    async function bounded(action,timeoutMs){
      const readAbort=new AbortController(),timerAbort=new AbortController();
      const work=Promise.resolve().then(()=>action(readAbort.signal)).then(value=>({type:'value',value}),error=>({type:'error',error}));
      const timer=Promise.resolve().then(()=>delay(timeoutMs,{signal:timerAbort.signal})).then(()=>({type:'timeout'}),error=>({type:'timer-error',error}));
      const result=await Promise.race([work,timer]);timerAbort.abort();
      if(result.type!=='value'&&result.type!=='error')readAbort.abort();
      // A delay implementation may ignore AbortSignal, but its later result
      // cannot abort an already completed read or change caller state.
      return result;
    }
    try{
      if(!current())return false;
      const closed=await bounded(()=>link.close(),Math.min(CLOSE_MS,deadline-now()));
      if(closed.type!=='value'||!current())return false;
      for(let attempt=0;attempt<MAX_ATTEMPTS;attempt++){
        if(!current()||deadline-now()<READ_MS)return false;
        onProgress(.96,'Waiting for the same radio’s application USB connection…');
        if(!current())return false;
        const result=await bounded(signal=>readApplication(appPort,{timeoutMs:READ_MS,signal}),READ_MS);
        if(!current())return false;
        if(result.type==='value'){
          const fresh=result.value;
          if(fresh?.firmwareFamily==='meshtastic'||fresh?.role!==expectedRole||!models.has(fresh?.model)||key(fresh?.publicKey)!==publicKey||version(fresh?.version)!==wantedVersion)return false;
          if(!current())return false;
          log('The same radio’s application answered with the expected identity and complete firmware version. Ending the activation wait early.');
          return current();
        }
        if(result.type!=='error'||!retryable(result.error))return false;
        if(attempt+1===MAX_ATTEMPTS||deadline-now()<READ_MS+RETRY_MS)return false;
        await delay(RETRY_MS);
        if(!current())return false;
      }
    }catch{/* Readiness is optional. Keep the original conservative wait on every failure. */}
    return false;
  };
}
