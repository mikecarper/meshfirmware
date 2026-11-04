import { commonCliReplyState } from './common-cli.js';

// Only fixed, reviewed local CLI commands are generated here. The caller owns
// connection/identity verification, user approval and the lifetime of request.
const schema='meshfirmware-post-flash-settings/v1';
const bandwidths=new Set([7800,10400,15600,20800,31250,41700,62500,125000,250000,500000]);
const tupleKeys=['frequencyHz','bandwidthHz','spreadingFactor','codingRate','preambleSymbols'];
const reject=message=>{throw new Error(message);};
const ownKeys=(value,keys,label)=>{if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(key=>!keys.includes(key)))reject(`Invalid ${label} settings.`);};
function tuple(value,{nullablePreamble=false}={}){
  const {frequencyHz,bandwidthHz,spreadingFactor,codingRate,preambleSymbols=nullablePreamble?null:0}=value;
  if(!Number.isInteger(frequencyHz)||frequencyHz<150000000||frequencyHz>2500000000||frequencyHz%1000)reject('Post-flash frequency must be 150–2500 MHz in whole kHz so the serial getter can verify it.');
  if(!bandwidths.has(bandwidthHz)||!Number.isInteger(spreadingFactor)||spreadingFactor<5||spreadingFactor>12||!Number.isInteger(codingRate)||codingRate<5||codingRate>8)reject('Invalid post-flash radio bandwidth, spreading factor or coding rate.');
  if(!(nullablePreamble&&preambleSymbols===null)&&(!Number.isInteger(preambleSymbols)||preambleSymbols!==0&&(preambleSymbols<8||preambleSymbols>65528)))reject('Post-flash preamble must be automatic (0) or 8–65528 symbols.');
  return {frequencyHz,bandwidthHz,spreadingFactor,codingRate,preambleSymbols};
}
function primarySettings(value){
  if(value==null)return null;
  ownKeys(value,['enabled',...tupleKeys,'txPowerDbm'],'primary radio');
  if(typeof value.enabled!=='boolean')reject('Primary radio needs an explicit enabled choice.');
  if(!value.enabled){if(tupleKeys.some(key=>value[key]!=null&&value[key]!==0)||value.txPowerDbm!=null&&value.txPowerDbm!==0)reject('Disabled primary radio settings must be empty.');return null;}
  const txPowerDbm=value.txPowerDbm??null;
  if(txPowerDbm!==null&&(!Number.isInteger(txPowerDbm)||txPowerDbm< -9||txPowerDbm>40))reject('Post-flash TX power must be -9–40 dBm or omitted.');
  return Object.freeze({enabled:true,...tuple(value,{nullablePreamble:true}),txPowerDbm});
}
function mediaSettings(value){
  if(value==null)return Object.freeze({preset:'unchanged',cross:'unchanged'});
  ownKeys(value,['preset','mode','cross',...tupleKeys],'MediaMesh');
  const {preset='unchanged',cross='unchanged'}=value;
  if(!['unchanged','off','mediamesh','mediamesh-range','custom'].includes(preset)||!['unchanged','on','off','auto'].includes(cross))reject('Invalid MediaMesh preset or crossing choice.');
  if(['unchanged','off'].includes(preset)){
    if([...tupleKeys,'mode'].some(key=>Object.hasOwn(value,key)))reject('Unchanged/off MediaMesh settings must not include ignored radio fields.');
    return Object.freeze({preset,cross});
  }
  const base={frequencyHz:911150000,bandwidthHz:preset==='mediamesh-range'?125000:250000,spreadingFactor:7,codingRate:5,preambleSymbols:0,mode:'rxtx'};
  if(preset==='custom'&&['frequencyHz','bandwidthHz','spreadingFactor','codingRate'].some(key=>!Object.hasOwn(value,key)))reject('Custom MediaMesh needs the complete radio tuple.');
  const desired={...base,...value};if(!['rx','rxtx'].includes(desired.mode))reject('MediaMesh mode must be rx or rxtx.');
  return Object.freeze({preset,...tuple(desired),mode:desired.mode,cross});
}
const number=(value,scale)=>String(Number((value/scale).toFixed(6)));
const tupleCommand=desired=>[number(desired.frequencyHz,1e6),number(desired.bandwidthHz,1000),desired.spreadingFactor,desired.codingRate].join(',');
const preambleCommand=value=>value===0?'auto':String(value);
export function createPostFlashSettingsPlan(input={}){
  ownKeys(input,['primary','mediaMesh'],'post-flash');const {primary=null,mediaMesh=null}=input;
  const p=primarySettings(primary),m=mediaSettings(mediaMesh),summary=[];
  if(p)summary.push(`Primary radio: ${number(p.frequencyHz,1e6)} MHz / ${number(p.bandwidthHz,1000)} kHz / SF${p.spreadingFactor} / CR4/${p.codingRate}${p.preambleSymbols===null?'':`; preamble ${p.preambleSymbols||'auto'}`}${p.txPowerDbm===null?'':`; TX ${p.txPowerDbm} dBm`}`);
  if(m.preset!=='unchanged')summary.push(m.preset==='off'?'MediaMesh radio2: off':`MediaMesh radio2: ${number(m.frequencyHz,1e6)} MHz / ${number(m.bandwidthHz,1000)} kHz / SF${m.spreadingFactor} / CR4/${m.codingRate} / ${m.mode}; preamble ${m.preambleSymbols||'auto'}`);
  if(m.cross!=='unchanged')summary.push(`Radio crossing: ${m.cross}`);
  return Object.freeze({schema,primary:p,mediaMesh:m,summary:summary.join('. ')});
}
const decimal=value=>{if(!/^(?:\d+(?:\.\d*)?|\.\d+)$/.test(value))throw Error('Unrecognized numeric radio reply.');const n=Number(value);if(!Number.isFinite(n))throw Error('Unrecognized numeric radio reply.');return n;};
function parsedTuple(fields){
  if(fields.length!==4)throw Error('Unrecognized radio tuple reply.');
  const [frequencyMHz,bandwidthKHz,spreadingFactor,codingRate]=fields.map(decimal);
  if(frequencyMHz<100||frequencyMHz>3000||bandwidthKHz<1||bandwidthKHz>1000||!Number.isInteger(spreadingFactor)||spreadingFactor<5||spreadingFactor>12||!Number.isInteger(codingRate)||codingRate<5||codingRate>8)throw Error('Radio tuple reply is out of range.');
  return {frequencyMHz,bandwidthKHz,spreadingFactor,codingRate,frequencyPlaces:(fields[0].split('.')[1]||'').length,bandwidthPlaces:(fields[1].split('.')[1]||'').length};
}
function parsePreamble(value){
  const text=value.replace(/^radio\.preamble\s+/i,'');if(text==='auto'||text==='0')return 0;
  if(!/^\d+$/.test(text)||Number(text)<8||Number(text)>65528)throw Error('Unrecognized primary preamble reply.');return Number(text);
}
function parseRadio2(value){
  if(/auto-owned|;\s*@|change pending|MediaMesh scope save pending/i.test(value))throw Error('Radio2 is automatically owned, scheduled, or still pending; it was not changed.');
  if(/^off(?: \((?:manual|automatic allowed)\))?(?:;[^\r\n]*)?$/.test(value))return {mode:'off'};
  const match=/^([^;,]+),([^;,]+),(\d+),(\d+),(rx|rxtx),(\d+)( \(auto\))?(?:;[^\r\n]*)?$/.exec(value);
  if(!match)throw Error('Unrecognized radio2 reply.');
  const effective=Number(match[6]);if(!Number.isInteger(effective)||effective<4||effective>65535)throw Error('Unrecognized radio2 preamble reply.');
  return {...parsedTuple(match.slice(1,5)),mode:match[5],preambleSymbols:match[7]?0:effective};
}
const parseCross=value=>{if(!['auto','on','off'].includes(value))throw Error('Unrecognized radio2 crossing reply.');return value;};
const parseTx=value=>{if(!/^-?\d+$/.test(value)||Number(value)< -20||Number(value)>40)throw Error('Unrecognized TX power reply.');return Number(value);};
const near=(actual,desired,places)=>Math.abs(actual-Math.fround(desired))<=Math.min(.0005,.5*10**-Math.min(9,places))+1e-7;
const sameTuple=(actual,desired)=>near(actual.frequencyMHz,desired.frequencyHz/1e6,actual.frequencyPlaces)&&near(actual.bandwidthKHz,desired.bandwidthHz/1000,actual.bandwidthPlaces)&&actual.spreadingFactor===desired.spreadingFactor&&actual.codingRate===desired.codingRate;
const sameRadio2=(actual,desired)=>desired.mode==='off'?actual.mode==='off':sameTuple(actual,desired)&&actual.mode===desired.mode&&actual.preambleSymbols===desired.preambleSymbols;
const warningLine=value=>/^(?:WARN recommended preamble: (?:radio|radio2)=\d+(?:,radio2=\d+)?(?:; short override: (?:radio|radio2|radio,radio2))?(?:; switch=\d+us)?|WARN need >\d+: (?:radio|radio2|radio,radio2)|WARN radio2 overlaps radio1 \(6kHz guard\)(?:; try \d+(?:\.\d{1,6})?MHz)?|timing self-test pending(?:; wait=\d+s)?|short override: (?:radio|radio2|radio,radio2)|switch=\d+us)$/.test(value);

/** The request adapter must already own a freshly verified local application.
 * This module never opens a port, resets/reboots/flashes, queries secrets, or
 * retries a mutation. Every requested getter is preflighted before any setter.
 * Unsupported sections are explicit skips; errors stop all remaining writes. */
export async function applyPostFlashSettings(plan,{request,isCurrent,log=()=>{}}={}){
  ownKeys(plan,['schema','primary','mediaMesh','summary'],'post-flash plan');
  if(plan?.schema!==schema)reject('Invalid post-flash settings plan.');
  const canonical=createPostFlashSettingsPlan({primary:plan.primary,mediaMesh:plan.mediaMesh});
  if(typeof request!=='function'||typeof isCurrent!=='function'||typeof log!=='function')reject('Verified request and current-context adapters are required.');
  const result={complete:false,applied:[],skipped:[],errors:[],readbacks:{},writes:[],warnings:[]};let section='preflight',stage='preflight';
  const current=()=>{if(isCurrent()!==true)throw Error('The verified application or approved settings changed. No further settings were sent.');};
  const ask=async(command,parse,{optional=false,warningLines=false}={})=>{
    current();let raw;try{raw=await request(command);}catch{current();throw Error('The verified application did not answer the settings request.');}current();
    const status=commonCliReplyState(raw,command);
    if(status.state==='unsupported'){if(optional)return {unsupported:true};throw Error('A required setting is unsupported by this firmware.');}
    if(status.state!=='complete')throw Error('The firmware settings reply was invalid or ambiguous.');
    const lines=status.text.split('\n');if(lines.length>1&&(!warningLines||!lines.slice(1).every(warningLine)))throw Error('The firmware settings reply was invalid or ambiguous.');
    const value=parse(lines.join('; '));result.readbacks[command]=value;return {value};
  };
  const set=async command=>{
    current();const write={section,command,accepted:false};result.writes.push(write);
    const status=await ask(command,value=>{if(!/^OK\b/.test(value)||/after reply|reboot|restart/i.test(value))throw Error('The settings write was rejected or requires manual completion.');return value;},{warningLines:true});
    write.accepted=true;return status;
  };
  const skip=(id,reason)=>result.skipped.push({section:id,reason});
  try{
    current();let primary=null,media=null;
    if(canonical.primary){
      section='primary';const desired=canonical.primary,radio=await ask('get radio',value=>parsedTuple(value.split(',')),{optional:true});
      const preamble=await ask('get radio.preamble',parsePreamble,{optional:true});
      const power=desired.txPowerDbm===null?null:await ask('get tx',parseTx,{optional:true});
      if(radio.unsupported||desired.preambleSymbols!==null&&preamble.unsupported||power?.unsupported)skip('primary','The target cannot read and verify every explicitly selected primary-radio value; primary settings were not changed.');
      else{
        const desiredPreamble=desired.preambleSymbols===null?(preamble.unsupported?null:preamble.value):desired.preambleSymbols;
        primary={desired,actual:radio.value,preamble:preamble.unsupported?null:preamble.value,desiredPreamble,power:power?.value};
        if(desiredPreamble===null)result.warnings.push('Primary preamble is unsupported: the legacy four-field radio command uses firmware-default behavior; no preamble change or verification is claimed.');
      }
    }
    if(canonical.mediaMesh.preset!=='unchanged'||canonical.mediaMesh.cross!=='unchanged'){
      section='mediaMesh';const radio=await ask('get radio2',parseRadio2,{optional:true,warningLines:true}),cross=await ask('get radio2.cross',parseCross,{optional:true});
      if(radio.unsupported||cross.unsupported)skip('mediaMesh','This firmware cannot read and verify radio2 and its crossing policy; MediaMesh settings were not changed.');
      else media={desired:canonical.mediaMesh,actual:radio.value,cross:cross.value};
    }
    current();stage='write';
    if(primary){
      section='primary';const p=primary.desired,changed=!sameTuple(primary.actual,p)||primary.desiredPreamble!==null&&primary.preamble!==primary.desiredPreamble;log('Applying approved primary-radio settings.');current();
      if(changed){
        await set(`set radio ${tupleCommand(p)}${primary.desiredPreamble===null?'':','+preambleCommand(primary.desiredPreamble)}`);stage='readback';
        const actual=await ask('get radio',value=>parsedTuple(value.split(',')));if(!sameTuple(actual.value,p))throw Error('Primary-radio readback did not match. Earlier settings may already have changed.');
        if(primary.desiredPreamble!==null){const saved=await ask('get radio.preamble',parsePreamble);if(saved.value!==primary.desiredPreamble)throw Error('Primary preamble readback did not match. Earlier settings may already have changed.');}
      }
      let powerChanged=false;
      if(p.txPowerDbm!==null&&primary.power!==p.txPowerDbm){stage='write';await set(`set tx ${p.txPowerDbm}`);stage='readback';const actual=await ask('get tx',parseTx);if(actual.value!==p.txPowerDbm)throw Error('TX power readback did not match. Earlier settings may already have changed.');powerChanged=true;}
      result.applied.push({section:'primary',unchanged:!changed&&!powerChanged,preambleVerified:primary.desiredPreamble!==null,txPowerVerified:p.txPowerDbm!==null});
    }
    if(media){
      section='mediaMesh';stage='write';const m=media.desired;let changed=false;
      log('Applying approved MediaMesh settings.');current();
      const writeRadio2=async(command,desired)=>{stage='write';await set(command);changed=true;stage='readback';const actual=await ask('get radio2',parseRadio2,{warningLines:true});if(!sameRadio2(actual.value,desired))throw Error('Radio2 readback did not match. Earlier settings may already have changed.');media.actual=actual.value;};
      if(m.preset==='off')await writeRadio2('set radio2 off',{mode:'off'});
      else if(m.preset!=='unchanged'){
        // Establish the firmware-managed public MediaMesh permission first,
        // including when a custom tuple is requested or already appears saved.
        const base={frequencyHz:911150000,bandwidthHz:m.preset==='mediamesh-range'?125000:250000,spreadingFactor:7,codingRate:5,preambleSymbols:0,mode:'rxtx'};
        await writeRadio2(`set radio2 ${m.preset==='mediamesh-range'?'mediamesh-range':'mediamesh'}`,base);
        if(!sameRadio2(media.actual,m))await writeRadio2(`set radio2 ${tupleCommand(m)},${m.mode},${preambleCommand(m.preambleSymbols)}`,m);
      }
      stage='readback';const cross=await ask('get radio2.cross',parseCross);
      if(m.cross==='unchanged'){if(cross.value!==media.cross)throw Error('Radio2 crossing changed unexpectedly; no crossing write was sent.');}
      else if(cross.value!==m.cross){stage='write';await set(`set radio2.cross ${m.cross}`);changed=true;stage='readback';const actual=await ask('get radio2.cross',parseCross);if(actual.value!==m.cross)throw Error('Radio2 crossing readback did not match. Earlier settings may already have changed.');}
      result.applied.push({section:'mediaMesh',unchanged:!changed,preset:m.preset,cross:m.cross});
    }
    current();result.complete=result.skipped.length===0;
  }catch(error){result.errors.push({section,stage,reason:error.message||'Settings could not be applied; no further commands were sent.'});}
  return result;
}
