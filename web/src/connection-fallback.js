// Call only from an explicitly approved, backup-considered Prepare operation
// on a qualified native ESP32 interface. Eligibility and the selected-device
// snapshot belong to the caller; this helper never chooses another USB port.
const fatalNames=new Set(['NotAllowedError','SecurityError','NotFoundError','NetworkError','InvalidStateError','AbortError']);
function mayTryAnotherMethod(error){
  return error?.romHandshakeFailed===true&&!fatalNames.has(error.name)&&!/permission|access.?denied|not.?allowed|security|secure boot|encrypt|disconnect|device (?:lost|removed)|mac.*(?:changed|mismatch)|unsupported.*chip|stub|flash/i.test(error.message||'');
}
function stale(){return new Error('The selected radio or firmware changed during connection testing. No further reset was sent.');}

export async function tryNativeUsbFallback({connect,close,touch,isCurrent,portAvailable,log=()=>{}}={}){
  if([connect,close,touch,isCurrent,portAvailable,log].some(callback=>typeof callback!=='function'))throw new TypeError('Native USB connection testing requires bounded connection and selected-port callbacks.');
  const current=()=>{if(isCurrent()!==true)throw stale();};
  const available=()=>portAvailable()===true;
  async function attempt(mode){
    current();
    if(!available())return {handoff:true};
    let closeStarted=false;
    try{
      log(mode==='no_reset'?'Testing the selected port for an already waiting ESP32 ROM; no reset is sent.':'Testing one guarded hardware USB-Serial/JTAG reset, then ESP32 ROM synchronization.');
      const result=await connect(mode,{singleReset:true});
      current();
      if(!result?.session||!result.info||typeof result.info!=='object')throw new Error('The ESP connection test returned no verified chip session.');
      if(!available()){closeStarted=true;await close();return {handoff:true};}
      log(`ESP32 ROM connection verified using ${mode}; retaining this session without another reset.`);
      return {session:result.session,info:result.info,mode};
    }catch(error){
      // Even a failed handshake can leave an open transport. An uncertain
      // close stops testing instead of opening/resetting it a second time.
      if(!closeStarted)try{await close();}catch(closeError){log(`Connection-test cleanup stopped: ${closeError.message||closeError}`);throw error;}
      current();
      if(!mayTryAnotherMethod(error))throw error;
      if(!available())return {handoff:true};
      log(`No ROM synchronization using ${mode}; that connection attempt was closed.`);
      return null;
    }
  }
  for(const mode of ['no_reset','usb_reset']){
    const result=await attempt(mode);
    if(result)return result;
  }
  current();
  if(!available())return {handoff:true};
  log('Trying one TinyUSB control-line handoff at 115200 baud. No UART reset or nRF52 baud touch is used.');
  // Delivery is uncertain if this rejects: never repeat the touch or move on
  // to another reset sequence. The existing handoff helper owns its port close.
  await touch();
  current();
  if(!available())return {handoff:true};
  // Some CDC endpoints retain their already granted object. Only a no-reset
  // synchronization may follow the touch; a new endpoint remains manual.
  const result=await attempt('no_reset');
  if(result)return result;
  const error=new Error('Automatic native USB connection tests did not reach the ROM bootloader. Choose the bootloader connection manually. No erase or firmware write was sent.');
  error.connectionFallbackExhausted=true;
  throw error;
}
