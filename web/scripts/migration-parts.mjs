// Build-only exact-byte deduplication. Never decompress or rebuild the ZIP.
// The browser still verifies the SHA-256 of the complete original release ZIP.
const MAX_ARCHIVE_BYTES=32<<20,MAX_ENTRIES=32,MAX_PARTS=128;
const safeName=name=>/^[A-Za-z0-9_.-]{1,255}$/.test(name)&&!['.','..'].includes(name);

function storedMembers(raw){
  const view=new DataView(raw.buffer,raw.byteOffset,raw.byteLength),members=[],names=new Set();let at=0;
  const u16=offset=>view.getUint16(offset,true),u32=offset=>view.getUint32(offset,true);
  while(at+30<=raw.length&&u32(at)===0x04034b50){
    if(members.length>=MAX_ENTRIES)return null;
    const flags=u16(at+6),method=u16(at+8),compressed=u32(at+18),size=u32(at+22),nameSize=u16(at+26),extra=u16(at+28),start=at+30+nameSize+extra,end=start+size;
    if(flags!==0||method!==0||compressed!==size||size===0||nameSize<1||nameSize>255||start>raw.length||end>raw.length)return null;
    const name=Buffer.from(raw.subarray(at+30,at+30+nameSize)).toString('ascii');
    if(!safeName(name)||names.has(name)||Buffer.from(name,'ascii').compare(raw.subarray(at+30,at+30+nameSize))!==0)return null;
    names.add(name);members.push({name,start,end,offset:at,crc:u32(at+14)});at=end;
  }
  if(!members.length)return null;
  const centralStart=at,seen=new Set();
  for(let count=0;count<members.length;count++){
    if(at+46>raw.length||u32(at)!==0x02014b50)return null;
    const nameSize=u16(at+28),extra=u16(at+30),comment=u16(at+32),end=at+46+nameSize+extra+comment;
    if(end>raw.length||nameSize<1||nameSize>255||u16(at+8)!==0||u16(at+10)!==0||u16(at+34)!==0)return null;
    const name=Buffer.from(raw.subarray(at+46,at+46+nameSize)).toString('ascii'),member=members.find(entry=>entry.offset===u32(at+42));
    if(!member||seen.has(member.offset)||name!==member.name||Buffer.from(name,'ascii').compare(raw.subarray(at+46,at+46+nameSize))!==0||u32(at+16)!==member.crc||u32(at+20)!==member.end-member.start||u32(at+24)!==member.end-member.start)return null;
    seen.add(member.offset);at=end;
  }
  if(at+22>raw.length||u32(at)!==0x06054b50||u16(at+4)!==0||u16(at+6)!==0||u16(at+8)!==members.length||u16(at+10)!==members.length||u32(at+12)!==at-centralStart||u32(at+16)!==centralStart||at+22+u16(at+20)!==raw.length)return null;
  return members;
}

export function splitMigrationArchive(raw){
  if(!(raw instanceof Uint8Array)||raw.length===0||raw.length>MAX_ARCHIVE_BYTES)throw new Error('Migration archive must be bounded public bytes (1–32 MiB).');
  const fallback=()=>[raw],members=storedMembers(raw);if(!members)return fallback();
  // A stored .bin is byte-identical to its ordinary application mirror. MOTA
  // files often enclose that same complete binary with a small metadata header.
  // Reuse only exact whole matches; never infer a target or alter either file.
  const binaries=members.filter(member=>member.name.endsWith('.bin')).sort((a,b)=>(b.end-b.start)-(a.end-a.start)),payloads=binaries.map(({start,end})=>({start,end}));
  for(const member of members.filter(entry=>entry.name.endsWith('.mota'))){
    const body=Buffer.from(raw.buffer,raw.byteOffset+member.start,member.end-member.start),matches=[];
    for(const binary of binaries){
      const candidate=raw.subarray(binary.start,binary.end);if(candidate.length<1024||candidate.length>body.length)continue;
      let from=0;
      while(from+candidate.length<=body.length){
        const found=body.indexOf(candidate,from);if(found<0)break;
        const start=member.start+found,end=start+candidate.length;
        if(!matches.some(match=>start<match.end&&end>match.start))matches.push({start,end});
        if((payloads.length+matches.length)*2+1>MAX_PARTS)return fallback();
        from=found+candidate.length;
      }
    }
    payloads.push(...matches);
  }
  payloads.sort((a,b)=>a.start-b.start);const parts=[];let at=0;
  for(const payload of payloads){if(payload.start>at)parts.push(raw.subarray(at,payload.start));parts.push(raw.subarray(payload.start,payload.end));at=payload.end;}
  if(at<raw.length)parts.push(raw.subarray(at));
  return parts.length&&parts.length<=MAX_PARTS?parts:fallback();
}
