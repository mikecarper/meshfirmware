// Read-only application identification. Failed MeshCore probing may fall back
// to the Meshtastic PhoneAPI; neither path resets a port or authorizes a write.
import {detectMeshCore} from './meshcore.js';
import {detectMeshtastic} from './meshtastic.js';

export async function detectApplication(link,{assertCurrent=()=>{},meshCoreTimeoutMs=1500,meshtasticTimeoutMs=1800}={}){
  assertCurrent();let ioFailure=null;
  const guarded={get buffer(){return link.buffer;}};
  for(const method of ['command','read','write'])guarded[method]=async(...args)=>{
    assertCurrent();let result;
    try{result=await link[method](...args);}catch(error){assertCurrent();ioFailure=error;throw error;}
    assertCurrent();return result;
  };
  try{
    const device=await detectMeshCore(guarded,{timeoutMs:meshCoreTimeoutMs});assertCurrent();
    return {...device,firmwareFamily:'meshcore'};
  }catch{
    assertCurrent();if(ioFailure)throw ioFailure;
  }
  const device=await detectMeshtastic(guarded,{timeoutMs:meshtasticTimeoutMs,assertCurrent});assertCurrent();
  if(device)return device;
  const error=Error('No supported MeshCore or Meshtastic application answered. Check the selected port; a ROM/DFU port cannot identify the running application. Read INFO_UF2.TXT from the same radio’s bootloader drive, or choose hardware manually.');
  error.code='APPLICATION_UNIDENTIFIED';throw error;
}
