// Read-only version assessment. The caller supplies get bootloader.ver's
// response and the already verified catalog's stable OTAFIX version. Neither
// an application version nor a shared USB ID is bootloader-version evidence.
const component='(?:0|[1-9][0-9]{0,2})';
const stablePattern=new RegExp(`^(${component})\\.(${component})\\.(${component})$`);
const installedPattern=new RegExp(`^(?:v?${component}\\.${component}\\.${component}-)?OTAFIX(${component})\\.(${component})(?:\\.(${component}))?(?:\\.(0))?([-+_][A-Za-z0-9][A-Za-z0-9._+-]*)?$`,'i');
const withinByte=values=>values.every(value=>Number.isInteger(value)&&value>=0&&value<=255);
const compare=(a,b)=>{
  for(let i=0;i<3;i++)if(a[i]!==b[i])return a[i]<b[i]?-1:1;
  return 0;
};

function stable(value){
  if(typeof value!=='string')return null;
  const match=stablePattern.exec(value);
  if(!match)return null;
  const parts=match.slice(1).map(Number);
  return withinByte(parts)?{parts,version:parts.join('.')}:null;
}

function report(value){
  if(typeof value!=='string'||value.length>256||/[\x00-\x1f\x7f]/.test(value))return '';
  // A single CLI prompt is permitted; echoes, multiple lines and repeated
  // prompts must be cleaned by the caller rather than guessed here.
  return value.trim().replace(/^>\s*/,'');
}

export function assessBootloaderVersion(reported,latestVersion){
  const text=report(reported),latest=stable(latestVersion);
  const result={status:'unknown',reported:text,installedVersion:null,latestVersion:latest?.version||null,offerUpdate:false};
  if(!text||(text.match(/OTAFIX/gi)||[]).length!==1)return result;
  const match=installedPattern.exec(text);
  if(!match)return result;
  const parts=[Number(match[1]),Number(match[2]),Number(match[3]??0)];
  if(!withinByte(parts))return result;
  result.installedVersion=parts.join('.');
  if(!latest)return result;
  const order=compare(parts,latest.parts),suffix=match[5]||'';
  if(order<0){result.status='older';result.offerUpdate=true;}
  else if(order>0)result.status='newer';
  else if(!suffix)result.status='current';
  else if(/^-preview\.(?:[1-9][0-9]{0,2})$/i.test(suffix)&&Number(suffix.slice(suffix.lastIndexOf('.')+1))<255){result.status='preview';result.offerUpdate=true;}
  else result.status='custom';
  return result;
}
