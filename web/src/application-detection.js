// Read-only application identification. Failed MeshCore probing may fall back
// to the Meshtastic PhoneAPI; neither path resets a port or authorizes a write.
import {detectMeshCore} from './meshcore.js';
import {detectMeshtastic} from './meshtastic.js';

export async function detectApplication(link,{assertCurrent=()=>{},meshCoreTimeoutMs=1500,meshtasticTimeoutMs=25000,onProgress=()=>{}}={}){
  if(typeof onProgress!=='function')throw Error('Invalid application detection progress callback.');
  assertCurrent();let ioFailure=null;
  const guarded={get buffer(){return link.buffer;}};
  for(const method of ['command','read','write'])guarded[method]=async(...args)=>{
    assertCurrent();let result;
    try{result=await link[method](...args);}catch(error){assertCurrent();ioFailure=error;throw error;}
    assertCurrent();return result;
  };
  // A progress callback failure is not a failed protocol probe and must never
  // trigger a second protocol or retry on the selected radio.
  assertCurrent();onProgress({stage:'meshcore'});assertCurrent();
  try{
    const device=await detectMeshCore(guarded,{timeoutMs:meshCoreTimeoutMs});assertCurrent();
    return {...device,firmwareFamily:'meshcore'};
  }catch{
    assertCurrent();if(ioFailure)throw ioFailure;
  }
  const device=await detectMeshtastic(guarded,{timeoutMs:meshtasticTimeoutMs,assertCurrent,onProgress});assertCurrent();
  if(device)return device;
  const error=Error('No supported MeshCore or Meshtastic application answered. Check the selected port; a ROM/DFU port cannot identify the running application. Read INFO_UF2.TXT from the same radio’s bootloader drive, or choose hardware manually.');
  error.code='APPLICATION_UNIDENTIFIED';throw error;
}
