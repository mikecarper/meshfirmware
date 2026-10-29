// Share public catalog choices only. Rebuild from a clean production URL so
// page query strings, local preview paths and device/private state never leak.
const base='https://mikecarper.github.io/meshfirmware/';
const valid=value=>typeof value==='string'&&value.length<=512&&value===value.trim()&&!/[\x00-\x1f\x7f\u2028\u2029]/.test(value)&&new URLSearchParams({v:value}).get('v')===value;

export function selectionLink({provider='',hardware='',role='',version='',mode='update',build=''}={}){
  if(![provider,hardware,role,version,build].every(valid)||!hardware||!['update','install'].includes(mode))return null;
  if(build&&(/[\\/]/.test(build)||build==='.'||build==='..'))return null;
  const url=new URL(base),selections={provider:provider==='Keymind Cascade Logging'?'Keymind Cascade':provider||'Keymind Cascade',hardware,role,version,mode,build};
  for(const [key,value]of Object.entries(selections))if(value)url.searchParams.set(key,value);
  url.hash='firmware-choices';return url.href;
}
