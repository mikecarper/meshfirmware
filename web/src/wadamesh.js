export const WADAMESH_PROVIDER='Wadamesh TAK';
export const WADAMESH_RELEASES_URL='https://github.com/jade-on-mesh/wadamesh-tak/releases/latest';
export const WADAMESH_FLASHER_URL='https://cascadiamesh.org/mediamesh-flasher/';

// Provider identity is explicit catalog/user metadata, never inferred from a
// filename, node name, download host or similarly named firmware fork.
export function isWadamesh(value){
  return (typeof value==='string'?value:value?.provider||value?.item?.provider)===WADAMESH_PROVIDER;
}

const displayModel=value=>typeof value==='string'&&value.length<=256?value.trim():'';
const result=(status,reason,extra={})=>Object.freeze({status,requiresOverride:status==='mismatch',reason,warning:status==='mismatch'||status==='unknown'?reason:'',requiredDisplay:null,reportedDisplay:null,...extra});

// The runtime board string is a firmware-reported configuration, not physical
// panel detection. A known OLED report must not silently become permission to
// install Wadamesh's TFT-only V4 image; unknown evidence remains only a warning.
export function wadameshDisplayAssessment({item,device}={}){
  if(!isWadamesh(item)||item?.requiredDisplay!=='tft')return result('not-applicable','No Wadamesh display-specific requirement applies.');
  const model=device?.firmwareFamily==='bootloader'||device?.role==='bootloader'?'':displayModel(device?.model);
  const match=/^Heltec[ _-]+V4(?:\.[23])?(?:[ _-]+R8)?[ _-]+(OLED|TFT)$/i.exec(model);
  const reportedDisplay=match?.[1].toLowerCase()||null,extra={requiredDisplay:'tft',reportedDisplay};
  if(reportedDisplay==='oled')return result('mismatch','This Wadamesh TAK build requires a TFT display, but the running firmware reports a Heltec V4 OLED configuration. It will not add OLED support. Choose a compatible build, or explicitly acknowledge this display mismatch.',extra);
  if(reportedDisplay==='tft')return result('match','The running firmware reports a TFT configuration matching this build. This does not independently prove the physical display.',extra);
  return result('unknown','This Wadamesh TAK build requires the TFT display. The connected display has not been identified; confirm the physical screen and exact hardware variant before flashing.',extra);
}

export const WADAMESH_INSTALL_NOTICE='First USB installation needs the matching merged image and its partition layout. This flasher’s Erase & new install performs a whole-chip erase; existing identity and settings are not promised to survive. Plain application images are only for an already matching Wadamesh layout. Select the exact display and radio variant.';
export const WADAMESH_STARTUP_NOTICE='The firmware transfer was verified. Wadamesh TAK is a standalone application; its screen and application startup are not verified through the MeshCore USB checks. Check the radio’s screen after restart.';
