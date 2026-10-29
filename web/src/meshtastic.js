// Read-only USB identity lookup, not a Meshtastic settings backup or physical
// board attestation. Wire fields are the official meshtastic/mesh.proto schema:
// https://github.com/meshtastic/protobufs/blob/master/meshtastic/mesh.proto
// Framing: https://meshtastic.org/docs/development/device/client-api/
// 69420 is PhoneAPI's SPECIAL_NONCE_ONLY_CONFIG (also used by the native probe).
// Stop at local MyNodeInfo + DeviceMetadata; do not request node DB, admin/RF
// operations, or deliberately drain packets. Firmware may stream additional
// configuration or queued packets after this request: only identity is decoded
// or retained here. The caller closes the serial connection immediately after
// probing; this protocol cannot promise that no other bytes were delivered.
// The official Python StreamInterface also sends START2 32 times and waits
// 100 ms before asking for configuration, to wake/resynchronize its receiver:
// https://github.com/meshtastic/python/blob/master/meshtastic/stream_interface.py
const wakeBytes=new Uint8Array(32).fill(0xc3);
const configRequest=Uint8Array.of(0x94,0xc3,0,4,0x18,0xac,0x9e,4);
const maxFrame=512,maxBuffered=8192,maxReceived=128*1024,maxFrames=512;
const decoder=new TextDecoder('utf-8',{fatal:true});
const wait=ms=>new Promise(resolve=>setTimeout(resolve,ms));

function fields(bytes){
  const result=[];let offset=0;
  const varint=()=>{
    let value=0n;
    for(let count=0;count<10;count++){
      if(offset>=bytes.length)throw Error('Truncated Meshtastic protobuf.');
      const byte=bytes[offset++];
      if(count===9&&byte>1)throw Error('Invalid Meshtastic varint.');
      value|=BigInt(byte&127)<<BigInt(7*count);
      if(!(byte&128))return value;
    }
    throw Error('Invalid Meshtastic varint.');
  };
  while(offset<bytes.length){
    if(result.length>=256)throw Error('Meshtastic protobuf field limit exceeded.');
    const tag=varint(),id=Number(tag>>3n),wire=Number(tag&7n);
    if(!id||id>0x1fffffff)throw Error('Invalid Meshtastic field.');
    let value;
    if(wire===0)value=varint();
    else if(wire===1||wire===5){
      const count=wire===1?8:4;if(count>bytes.length-offset)throw Error('Truncated Meshtastic field.');
      value=bytes.subarray(offset,offset+count);offset+=count;
    }else if(wire===2){
      const count=varint();if(count>BigInt(bytes.length-offset))throw Error('Truncated Meshtastic field.');
      value=bytes.subarray(offset,offset+Number(count));offset+=Number(count);
    }else throw Error('Unsupported Meshtastic protobuf wire type.');
    result.push({id,wire,value});
  }
  return result;
}
function field(rows,id,wire){
  const values=rows.filter(row=>row.id===id);
  if(values.length>1||values.length&&values[0].wire!==wire)throw Error('Ambiguous Meshtastic identity field.');
  return values[0]?.value??null;
}
function uint32(value){
  if(typeof value!=='bigint'||value<0n||value>0xffffffffn)throw Error('Invalid Meshtastic identity number.');
  return Number(value);
}
function string(value,limit){
  if(!(value instanceof Uint8Array)||!value.length||value.length>limit)throw Error('Invalid Meshtastic identity text.');
  const decoded=decoder.decode(value);
  if(/[\x00-\x1f\x7f\u2028\u2029]/.test(decoded)||decoded!==decoded.trim())throw Error('Invalid Meshtastic identity text.');
  return decoded;
}
function message(bytes,localNode){
  const rows=fields(bytes),payloads=rows.filter(row=>row.id>=2&&row.id<=17);
  if(payloads.length>1)throw Error('Ambiguous Meshtastic identity payload.');
  if(!payloads.length)return null;
  const payload=payloads[0];
  if(![3,4,13].includes(payload.id))return null;
  if(payload.wire!==2)throw Error('Invalid Meshtastic identity payload.');
  if(payload.id===4){
    // User-selected display names are optional and never hardware evidence.
    // A bad or legacy NodeInfo must not obscure valid local metadata.
    try{
      const data=fields(payload.value),nodeNum=uint32(field(data,1,0));
      if(nodeNum!==localNode)return null;
      const user=field(data,2,2);if(!user)return null;
      const userFields=fields(user),longName=field(userFields,2,2),shortName=field(userFields,3,2);
      return {kind:'name',nodeNum,name:longName?.length?string(longName,120):shortName?.length?string(shortName,32):''};
    }catch{return null;}
  }
  const data=fields(payload.value);
  if(payload.id===3){
    const nodeNum=uint32(field(data,1,0));
    if(!nodeNum||nodeNum===0xffffffff)throw Error('Meshtastic local identity is unavailable.');
    return {kind:'local',nodeNum};
  }
  if(payload.id===13){
    const hardware=uint32(field(data,9,0)),version=string(field(data,1,2),120);
    if(!hardware||hardware>0x7fffffff)throw Error('Meshtastic hardware model is unavailable.');
    return {kind:'metadata',hardware,version};
  }
  return null;
}

export async function detectMeshtastic(link,{timeoutMs=25000,assertCurrent=()=>{},delay=wait,now=Date.now,onProgress=()=>{}}={}){
  if(!link||typeof link.write!=='function'||typeof link.read!=='function')throw Error('Meshtastic detection needs a serial connection.');
  if(!Number.isFinite(timeoutMs)||timeoutMs<1||timeoutMs>30000)throw Error('Invalid Meshtastic detection timeout.');
  if(typeof delay!=='function'||typeof now!=='function')throw Error('Invalid Meshtastic detection clock.');
  if(typeof onProgress!=='function')throw Error('Invalid Meshtastic detection progress callback.');
  const clock=()=>{const value=now();if(!Number.isFinite(value)||Math.abs(value)>Number.MAX_SAFE_INTEGER)throw Error('Invalid Meshtastic detection clock.');return value;};
  clock();
  assertCurrent();if(Array.isArray(link.buffer))link.buffer.length=0;
  await link.write(wakeBytes.slice());assertCurrent();
  await delay(100);assertCurrent();
  if(Array.isArray(link.buffer))link.buffer.length=0;
  await link.write(configRequest.slice());assertCurrent();
  // Meshtastic 2.7.15's ESP32 native-USB console may poll only once per 20 s
  // while HWCDC::isPlugged() is false. A short probe misses a healthy TinyUSB
  // application; allow one bounded poll interval and return early on identity.
  const started=clock(),until=started+timeoutMs,timeoutSeconds=Math.ceil(timeoutMs/1000);
  let elapsedSeconds=-1,buffer=[],received=0,processed=0,local=null,metadata=null,name='';
  const report=value=>{
    const seconds=Math.min(timeoutSeconds,Math.max(elapsedSeconds,0,Math.floor((value-started)/1000)));
    if(seconds===elapsedSeconds)return;
    assertCurrent();onProgress({stage:'meshtastic',elapsedSeconds:seconds,timeoutSeconds});assertCurrent();elapsedSeconds=seconds;
  };
  // Reporting is tied to this bounded read loop, never a background interval.
  report(started);
  while(clock()<until){
    assertCurrent();const chunk=await link.read(Math.max(1,Math.min(100,until-clock())));assertCurrent();
    report(clock());
    if(!(chunk instanceof Uint8Array))throw Error('Invalid Meshtastic serial data.');
    received+=chunk.length;
    if(received>maxReceived)return null;
    const accepted=chunk.subarray(0,maxBuffered-buffer.length),overflow=accepted.length!==chunk.length;
    for(const byte of accepted)buffer.push(byte);
    while(buffer.length>=4){
      if(buffer[0]!==0x94||buffer[1]!==0xc3){buffer.shift();continue;}
      const length=buffer[2]*256+buffer[3];
      if(!length||length>maxFrame){buffer.shift();continue;}
      if(buffer.length<length+4)break;
      const payload=Uint8Array.from(buffer.splice(0,length+4).slice(4));
      if(++processed>maxFrames)return null;
      let decoded;try{decoded=message(payload,local);}catch{return null;}
      if(!decoded)continue;
      if(decoded.kind==='local'){
        if(local!==null&&local!==decoded.nodeNum)return null;
        local=decoded.nodeNum;
      }else if(decoded.kind==='metadata'){
        if(metadata&&(metadata.hardware!==decoded.hardware||metadata.version!==decoded.version))return null;
        metadata=decoded;
      }else if(decoded.kind==='name'&&decoded.nodeNum===local)name=decoded.name;
      if(local!==null&&metadata){
        return {firmwareFamily:'meshtastic',role:'meshtastic',meshtasticHardware:metadata.hardware,
          model:'Meshtastic hardware '+metadata.hardware,nodeNum:local,name,version:metadata.version,
          catalogRole:null,publicKey:null};
      }
    }
    if(overflow)return null;
  }
  report(clock());
  return null;
}
