// This chooser is invoked only by an explicit user action. It grants access to
// one selected file, never a directory, drive, writable handle or firmware.
const fileName='INFO_UF2.TXT';
const error=message=>new Error(message);
const pickError=()=>error('The bootloader information file could not be selected. Check browser access and try again.');
const readError=()=>error('The selected bootloader information file could not be read. Keep the radio connected and try again.');

async function readInfo(file,maxBytes){
  if(!file||typeof file.name!=='string'||file.name.toLowerCase()!=='info_uf2.txt')throw error('Choose INFO_UF2.TXT from the radio’s bootloader drive.');
  if(!Number.isSafeInteger(file.size)||file.size<0||file.size>maxBytes)throw error('INFO_UF2.TXT exceeds the allowed size. No file content was read.');
  if(typeof file.text!=='function')throw readError();
  let text;try{text=await file.text();}catch{throw readError();}
  if(typeof text!=='string'||new TextEncoder().encode(text).length>maxBytes)throw error('INFO_UF2.TXT exceeds the allowed size.');
  return {name:fileName,text};
}

function inputFile(window,document){
  if(!document||typeof document.createElement!=='function'||!document.body)throw pickError();
  return new Promise((resolve,reject)=>{
    let input,settled=false,focusTimer=null;
    const timers=typeof window?.setTimeout==='function'&&typeof window?.clearTimeout==='function'?window:globalThis;
    const cleanup=()=>{
      input?.removeEventListener?.('change',changed);input?.removeEventListener?.('cancel',cancelled);
      window?.removeEventListener?.('focus',focused);
      if(focusTimer!==null)timers.clearTimeout(focusTimer);
      input?.remove?.();
    };
    const finish=(value,failure=null)=>{if(settled)return;settled=true;cleanup();if(failure)reject(failure);else resolve(value);};
    const changed=()=>{
      if(!input.files?.length){finish(null);return;}
      if(input.files.length!==1){finish(null,error('Choose only INFO_UF2.TXT from the intended radio.'));return;}
      finish(input.files[0]);
    };
    const cancelled=()=>finish(null);
    // Older mobile browsers do not emit the input's cancel event. Wait until
    // focus returns, giving their change event time to update the FileList.
    const focused=()=>{
      if(settled||focusTimer!==null)return;
      focusTimer=timers.setTimeout(()=>{focusTimer=null;if(!settled)changed();},300);
    };
    try{
      input=document.createElement('input');input.type='file';input.accept='.txt,.TXT';input.multiple=false;input.hidden=true;
      input.addEventListener('change',changed);input.addEventListener('cancel',cancelled);
      window?.addEventListener?.('focus',focused);document.body.append(input);input.click();
    }catch{finish(null,pickError());}
  });
}

export async function chooseBootloaderInfoFile({window=globalThis,document=globalThis.document,maxBytes=8192}={}){
  if(!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>(1<<20))throw error('Invalid bootloader information file size limit.');
  let file;
  if(typeof window?.showOpenFilePicker==='function'){
    let handles;
    try{
      handles=await window.showOpenFilePicker({id:'meshfirmware-bootloader-info',multiple:false,excludeAcceptAllOption:true,types:[{description:'INFO_UF2.TXT from the radio',accept:{'text/plain':['.TXT']}}]});
    }catch(failure){
      if(failure?.name==='AbortError')return null;
      // Unsupported API is the only fallback. A denied permission or security
      // restriction must not be retried through a different permission path.
      if(failure?.name!=='NotSupportedError')throw pickError();
      file=await inputFile(window,document);return file===null?null:readInfo(file,maxBytes);
    }
    if(Array.isArray(handles)&&handles.length===0)return null;
    if(!Array.isArray(handles)||handles.length!==1||typeof handles[0]?.getFile!=='function')throw pickError();
    try{file=await handles[0].getFile();}catch{throw readError();}
  }else file=await inputFile(window,document);
  return file===null?null:readInfo(file,maxBytes);
}
