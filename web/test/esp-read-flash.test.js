import test from 'node:test';
import assert from 'node:assert/strict';
import {ESPLoader,ESPError} from 'esptool-js';
import {EspSession} from '../src/esp.js';
import {hash,md5hex,words} from '../src/firmware.js';

// Real ESPLoader command/status parsing and EspSession's owned read wrapper;
// only the decoded serial transport is simulated. No port is ever opened.
const vendorReadFlash=ESPLoader.prototype.readFlash;
const block=(length,seed=1)=>Uint8Array.from({length},(_,index)=>(index*17+seed)&255);
const bytesOf=hex=>Uint8Array.from(hex.match(/../g),part=>parseInt(part,16));
function response(op,value=0,data=Uint8Array.of(0,0)){
  const packet=new Uint8Array(8+data.length),view=new DataView(packet.buffer);
  packet[0]=1;packet[1]=op;view.setUint16(2,data.length,true);view.setUint32(4,value,true);packet.set(data,8);return packet;
}
function fixture(reads=[],{registerValue=0x12345678}={}){
  const packets=[],commands=[],acks=[],dropped=[],timeouts=[],signals=[];
  const missingPacket=new ESPError('Serial data stream stopped: Possible serial noise or corruption.');
  const port={getInfo:()=>({usbVendorId:0x10c4,usbProductId:0xea60}),setSignals:async value=>signals.push(value)};
  const session=new EspSession(port,()=>{}),loader=session.loader;
  let nextRead=0,active=null;
  const transport={
    tracing:false,getInfo:()=> 'synthetic transport without hardware',
    flushInput(){dropped.push(...packets.splice(0));},
    async write(bytes){
      const view=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);
      if(bytes.length===4){
        const received=view.getUint32(0,true);acks.push(received);
        assert.ok(active,'an ACK must belong to a read command');
        if(received===active.size){
          if(active.digest!==null)packets.push(active.digest);
          active=null;
        }
        return;
      }
      assert.equal(bytes[0],0,'expected a loader request, not a control-line operation');
      const op=bytes[1],payload=bytes.subarray(8);assert.equal(view.getUint16(2,true),payload.length);
      commands.push({op,payload:payload.slice()});
      if(op===loader.ESP_READ_FLASH){
        assert.equal(active,null,'reads cannot overlap');
        const request=reads[nextRead++];assert.ok(request,'unexpected read command');
        assert.deepEqual(payload,words(request.address,request.size,4096,64));
        const data=Uint8Array.from(request.frames.flatMap(frame=>[...frame]));
        active={size:request.size,digest:Object.hasOwn(request,'digest')?request.digest:bytesOf(md5hex(data))};
        packets.push(response(op),...request.frames);
      }else if(op===loader.ESP_READ_REG){
        assert.deepEqual(payload,words(0x60000000));packets.push(response(op,registerValue));
      }else assert.fail(`unexpected loader operation 0x${op.toString(16)}`);
    },
    async read(timeout){
      timeouts.push(timeout);const packet=packets.shift();
      if(packet instanceof Error)throw packet;
      if(packet===undefined)throw missingPacket;
      return packet;
    },
  };
  loader.transport=transport;loader.IS_STUB=true;
  return {session,loader,packets,commands,acks,dropped,timeouts,signals,missingPacket};
}

test('the owned flash-read wrapper consumes and verifies the complete stub digest before returning',async()=>{
  const first=block(4096),last=block(17,2),expected=Uint8Array.from([...first,...last]);
  const f=fixture([{address:0x8000,size:expected.length,frames:[first,last]}]),progress=[];
  const result=await f.loader.readFlash(0x8000,expected.length,(packet,received,total)=>progress.push([packet.length,received,total]));
  assert.deepEqual(result,expected);
  assert.deepEqual(f.acks,[4096,4113]);
  assert.deepEqual(progress,[[4096,4096,4113],[17,4113,4113]]);
  assert.equal(f.packets.length,0,'the trailing digest must not remain for the next command');
  assert.deepEqual(f.dropped,[]);
  assert.ok(f.timeouts.slice(1).every(timeout=>timeout===f.loader.FLASH_READ_TIMEOUT));
  assert.deepEqual(f.signals,[]);
});

test('corrupt MD5 and truncated digest frames reject rather than returning unverified flash bytes',async()=>{
  for(const digest of [new Uint8Array(16),new Uint8Array(15),new Uint8Array(17)]){
    const f=fixture([{address:0x8000,size:4,frames:[block(4)],digest}]);
    await assert.rejects(f.loader.readFlash(0x8000,4),/digest|md5|checksum/i);
    assert.deepEqual(f.acks,[4]);assert.equal(f.commands.length,1);assert.deepEqual(f.signals,[]);
  }
});

test('missing digest and transport failures propagate the original error without retries or resets',async()=>{
  const failure=Object.assign(new Error('Synthetic transport disconnected'),{name:'NetworkError'});
  for(const digest of [null,failure]){
    const f=fixture([{address:0x8000,size:4,frames:[block(4)],digest}]);
    await assert.rejects(f.loader.readFlash(0x8000,4),error=>error===(digest===null?f.missingPacket:failure));
    assert.deepEqual(f.acks,[4]);assert.equal(f.commands.length,1);assert.deepEqual(f.signals,[]);
  }
});

test('short non-final data and overlong data frames fail before acknowledging malformed bytes',async()=>{
  for(const request of [
    {address:0x8000,size:8192,frames:[block(4095)]},
    {address:0x8000,size:4,frames:[block(5)]},
  ]){
    const f=fixture([request]);
    await assert.rejects(f.loader.readFlash(request.address,request.size),/truncated data block|more data than requested/i);
    assert.deepEqual(f.acks,[]);assert.equal(f.commands.length,1);assert.deepEqual(f.signals,[]);
  }
});

test('consecutive verified flash reads leave no digest to be discarded or parsed by a real register command',async()=>{
  const a=block(4096),b=block(32,2),f=fixture([
    {address:0x8000,size:a.length,frames:[a]},
    {address:0xe000,size:b.length,frames:[b]},
  ]);
  assert.deepEqual(await f.loader.readFlash(0x8000,a.length),a);
  assert.deepEqual(await f.loader.readFlash(0xe000,b.length),b);
  assert.equal(await f.loader.readReg(0x60000000),0x12345678);
  assert.deepEqual(f.commands.map(command=>command.op),[f.loader.ESP_READ_FLASH,f.loader.ESP_READ_FLASH,f.loader.ESP_READ_REG]);
  assert.deepEqual(f.dropped,[]);assert.equal(f.packets.length,0);assert.deepEqual(f.signals,[]);
});

test('flash-read verification is instance-owned and cannot send stub commands from an unverified ROM session',async()=>{
  const f=fixture();
  assert.equal(ESPLoader.prototype.readFlash,vendorReadFlash);
  assert.equal(Object.hasOwn(f.loader,'readFlash'),true);
  assert.notEqual(f.loader.readFlash,vendorReadFlash);
  const plain=new ESPLoader({transport:{getInfo:()=> 'unconnected synthetic loader'},baudrate:115200,terminal:{clean(){},writeLine(){},write(){}}});
  assert.equal(plain.readFlash,vendorReadFlash);
  f.loader.IS_STUB=false;
  await assert.rejects(f.loader.readFlash(0x8000,4096),/stub/i);
  assert.deepEqual(f.commands,[]);assert.deepEqual(f.acks,[]);assert.deepEqual(f.signals,[]);
});

test('a corrupt or timed-out partition digest cannot create a plan, authorize a write or permit a finish reset',async()=>{
  for(const digest of [new Uint8Array(16),null]){
    const f=fixture([{address:0x8000,size:4096,frames:[block(4096)],digest}]);
    f.session.mac='aa:bb:cc:dd:ee:ff';f.session.flashBytes=4<<20;
    f.loader.chip={IMAGE_CHIP_ID:9,CHIP_NAME:'ESP32-S3',readMac:async()=>f.session.mac};
    const payload=block(64),pkg={architecture:'esp32',chipId:9,payload,payloadHash:hash(payload),sha256:hash(payload)};
    await assert.rejects(f.session.prepare(pkg),error=>digest===null?error===f.missingPacket:/digest|md5|checksum/i.test(error.message));
    assert.equal(f.session.plan,null);
    await assert.rejects(f.session.flash(pkg,()=>{}),/Firmware changed|plan|verified/i);
    await assert.rejects(f.session.finish(false),/verified/i);
    assert.deepEqual(f.commands.map(command=>command.op),[f.loader.ESP_READ_FLASH]);
    assert.deepEqual(f.signals,[]);
  }
});
