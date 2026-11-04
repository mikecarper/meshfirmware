// Read-only application identification. Failed MeshCore probing may fall back
// to the Meshtastic PhoneAPI; neither path resets a port or authorizes a write.
import {detectMeshCore} from './meshcore.js';
import {detectMeshtastic} from './meshtastic.js';
import {sleep} from './firmware.js';

export async function detectApplication(link,{assertCurrent=()=>{},meshCoreTimeoutMs=1500,meshtasticTimeoutMs=25000,onProgress=()=>{},now=Date.now,delay=sleep,meshCoreOnly=false}={}){
  if(typeof onProgress!=='function')throw Error('Invalid application detection progress callback.');
  if(typeof assertCurrent!=='function'||typeof now!=='function'||typeof delay!=='function'||typeof meshCoreOnly!=='boolean')throw Error('Invalid application detection timing or scope options.');
  const startupEvidence=link.startupEvidence,startup=startupEvidence?.observedRomBoot===true;
  let ioFailure=null,contextFailure=null,progressFailure=null,timingFailure=null,lastTime=null;
  let protocol=null,phaseDeadline=null,lastProgress=-1;
  const windowExpired=Error('Application startup readiness deadline reached.'),probeExpired=Error('Application readiness probe timed out.');
  function current(){try{assertCurrent();}catch(error){contextFailure=error;throw error;}}
  function clock(){
    let value;try{value=now();}catch(error){timingFailure=error;throw error;}
    if(!Number.isFinite(value)||(lastTime!==null&&value<lastTime)){timingFailure=Error('Application detection clock is invalid or moved backwards.');throw timingFailure;}
    lastTime=value;return value;
  }
  current();const started=startup?clock():null,deadline=startup?started+25000:null;
  function emit(event){current();try{onProgress(event);}catch(error){progressFailure=error;throw error;}current();}
  function tick(){
    if(!startup)return;
    const seconds=Math.min(25,Math.floor((clock()-started)/1000));
    while(lastProgress<seconds){lastProgress++;emit({stage:'startup',elapsedSeconds:lastProgress,timeoutSeconds:25});}
  }
  function checkpoint({phase=true}={}){
    if(contextFailure||progressFailure||timingFailure||ioFailure)throw contextFailure||progressFailure||timingFailure||ioFailure;
    current();if(!startup)return;tick();
    const time=clock();if(time>=deadline)throw windowExpired;
    if(phase&&phaseDeadline!==null&&time>=phaseDeadline)throw probeExpired;
  }
  function nonRetryable(error){
    if(contextFailure||progressFailure||timingFailure||ioFailure)throw contextFailure||progressFailure||timingFailure||ioFailure;
    current();if(error?.meshcoreApplicationIdentified)throw error;
  }
  const guarded={get buffer(){return link.buffer;},get startupEvidence(){return startupEvidence;}};
  for(const method of ['command','read','write'])guarded[method]=async(...args)=>{
    // A new request may follow an expired unknown probe, but never the total
    // startup deadline. No asynchronous loser is left running in the background.
    checkpoint({phase:method==='read'});
    if(startup){
      if(method==='command'){phaseDeadline=null;args[1]=Math.max(1,Math.min(args[1]??800,deadline-clock()));}
      if(method==='write'&&protocol==='meshcore')phaseDeadline=Math.min(deadline,clock()+(args[0]?.[0]===0x3c?Math.min(1500,meshCoreTimeoutMs):700));
      if(method==='read')args[0]=Math.max(1,Math.min(args[0]??500,deadline-clock(),phaseDeadline===null?Infinity:phaseDeadline-clock()));
    }
    let result;
    try{result=await link[method](...args);}catch(error){current();ioFailure=error;throw error;}
    checkpoint();return result;
  };
  async function wait(milliseconds){
    checkpoint();const duration=startup?Math.min(milliseconds,deadline-clock(),phaseDeadline===null?Infinity:phaseDeadline-clock()):milliseconds;
    await delay(Math.max(0,duration));checkpoint();
  }
  async function meshCoreProbe(){
    protocol='meshcore';phaseDeadline=null;
    try{
      const timeoutMs=startup?Math.max(1,Math.min(1500,meshCoreTimeoutMs,deadline-clock())):meshCoreTimeoutMs;
      const device=await detectMeshCore(guarded,{timeoutMs});checkpoint();return {device:{...device,firmwareFamily:'meshcore'}};
    }catch(error){nonRetryable(error);if(error===windowExpired)throw error;return {error};}
  }
  async function meshtasticProbe(){
    protocol='meshtastic';
    const timeoutMs=startup?Math.max(1,Math.min(1000,meshtasticTimeoutMs,deadline-clock())):meshtasticTimeoutMs;
    phaseDeadline=startup?Math.min(deadline,clock()+timeoutMs):null;
    try{
      const device=await detectMeshtastic(guarded,{timeoutMs,assertCurrent:checkpoint,delay:wait,now:clock,onProgress:startup?()=>checkpoint():emit});
      checkpoint();return device;
    }catch(error){nonRetryable(error);if(startup&&error===probeExpired)return null;throw error;}
  }
  if(!startup){
    emit({stage:'meshcore'});const result=await meshCoreProbe();if(result.device)return result.device;
    if(meshCoreOnly)throw result.error;
    const device=await meshtasticProbe();if(device)return device;
  }else{
    // Only an observed UART ROM banner permits readiness retries. Alternate
    // short read-only protocols on this same open link; never reopen or reset.
    try{
      checkpoint();
      while(clock()<deadline){
        const result=await meshCoreProbe();if(result.device)return result.device;
        checkpoint({phase:false});
        if(!meshCoreOnly){const device=await meshtasticProbe();if(device)return device;}
        protocol=null;phaseDeadline=null;await wait(100);
      }
    }catch(error){nonRetryable(error);if(error!==windowExpired)throw error;}
  }
  const error=Error((startup?'The radio reported a ROM boot, but no supported application became ready within 25 seconds. ':'')+'No supported MeshCore or Meshtastic application answered. If this USB port opens, its serial driver is available. The installed firmware may not provide a USB API, for example a BLE-only Companion build. Check the selected application port; a ROM/DFU port cannot identify the running application. Choose the exact hardware manually and matching USB-enabled firmware. No reset or firmware write was sent.');
  error.code='APPLICATION_UNIDENTIFIED';throw error;
}
