import test from 'node:test';
import assert from 'node:assert/strict';
import {SerialLink} from '../src/serial.js';
import {detectMeshCore,cleanCliReply} from '../src/meshcore.js';

const encode=value=>new TextEncoder().encode(value);
function serialPort(usbVendorId,usbProductId){
  const calls=[];let finish;
  return {calls,getInfo:()=>({usbVendorId,usbProductId}),open:async options=>calls.push(['open',options]),setSignals:async signals=>calls.push(['signals',signals]),close:async()=>calls.push(['close']),
    readable:{getReader:()=>({read:()=>new Promise(resolve=>{finish=resolve;}),cancel:async()=>finish?.({done:true}),releaseLock(){}})}};
}

test('reviewed native application opens assert DTR at 115200 without toggling RTS or baud',async()=>{
  for(const [vid,pid] of [[0x303a,0x0002],[0x303a,0x1001],[0x2886,0x0059],[0x2886,0x8044],[0x2886,0x8045]]){
    const port=serialPort(vid,pid),link=new SerialLink(port);await link.open(115200,{application:true});
    assert.deepEqual(port.calls,[['open',{baudRate:115200,flowControl:'none',bufferSize:65536}],['signals',{dataTerminalReady:true,requestToSend:false}]]);await link.close();
  }
});
test('default and DFU opens retain deasserted DTR, including native interfaces',async()=>{
  for(const [vid,pid] of [[0x303a,0x0002],[0x2886,0x0057],[0x239a,0x0029]]){
    const port=serialPort(vid,pid),link=new SerialLink(port);await link.open();assert.equal(port.calls[1][1].dataTerminalReady,false);await link.close();
  }
});
test('application probing never asserts DTR on UART bridges, unknown IDs, neighbors or 1200 baud',async()=>{
  for(const [vid,pid,baud] of [[0x10c4,0xea60,115200],[0x1a86,0x7523,115200],[0x0403,0x6001,115200],[0x303a,0x0003,115200],[0x303a,0x0002,1200],[undefined,undefined,115200]]){
    const port=serialPort(vid,pid),link=new SerialLink(port);await link.open(baud,{application:true});assert.equal(port.calls[1][1].dataTerminalReady,false);assert.equal(port.calls[1][1].requestToSend,false);await link.close();
  }
});

test('old CommonCLI prompt and command echoes are removed without altering the reported model',()=>{
  assert.equal(cleanCliReply('board\r\r\n  -> Heltec V4 OLED\r\r\n','board'),'Heltec V4 OLED');
  assert.equal(cleanCliReply('get role\r\r\n  -> > repeater\r\r\n','get role'),'repeater');
  assert.equal(cleanCliReply('> board\n\x1b[32m-> Heltec V4 OLED\x1b[0m\n>','board'),'Heltec V4 OLED');
  assert.equal(cleanCliReply('x'.repeat(8193),'board'),'');
});
function commonPort(role='repeater',board='Heltec V4 OLED'){
  const commands=[];
  return {commands,command:async command=>{commands.push(command);return `${command}\r\r\n  -> ${command==='get public.key'?'11'.repeat(32):command==='get name'?'> Test V4':command==='ver'?'v1.14.1-467959c (Build: 20-Mar-2026)':command==='get role'?'> '+role:board}\r\r\n`;}};
}
test('old V4 CommonCLI detection selects exact model and repeater catalog role with read-only commands',async()=>{
  const port=commonPort(),device=await detectMeshCore(port);assert.equal(device.model,'Heltec V4 OLED');assert.equal(device.role,'common-cli');assert.equal(device.catalogRole,'repeater');assert.equal(device.name,'Test V4');assert.equal(device.version,'v1.14.1-467959c (Build: 20-Mar-2026)');
  assert.deepEqual(port.commands,['get public.key','get name','ver','board','get role']);
});
test('unknown, compound and unsupported role replies never choose repeater implicitly',async()=>{
  for(const role of ['Unknown command','repeater extra','repeater\nroom-server','companion','on','off',''])assert.equal((await detectMeshCore(commonPort(role))).catalogRole,null);
  assert.equal((await detectMeshCore(commonPort('room-server'))).catalogRole,'roomServer');
  assert.equal((await detectMeshCore(commonPort('sensor'))).catalogRole,'sensor');
  assert.equal((await detectMeshCore(commonPort('repeater','unrelated log\nHeltec V4 OLED'))).model,null);
});

function binaryPort(protocol,versionReply){
  const commands=[],queue=[],self=new Uint8Array(62),info=new Uint8Array(80);
  self.set([5,1]);self.set(new Uint8Array(32).fill(0x11),4);self.set(encode('test'),58);
  info.set([13,protocol]);info.set(encode('Heltec V4'),20);info.set(encode('v1.18.0.1-halo-keymi'),60);
  return {commands,buffer:[],command:async()=>'',write:async bytes=>{
    const command=Array.from(bytes.subarray(3));commands.push(command);
    const reply=command[0]===1?self:command[0]===22?info:versionReply instanceof Uint8Array?versionReply:Uint8Array.from([29,...encode(versionReply)]);
    queue.push(Uint8Array.from([62,reply.length&255,reply.length>>8,...reply]));
  },read:async()=>queue.shift()||new Uint8Array()};
}
test('protocol 13 companions use DEVICE_INFO without sending unsupported optional CLI',async()=>{
  const port=binaryPort(13,'must not be queried'),device=await detectMeshCore(port);assert.equal(device.protocol,13);assert.equal(device.version,'v1.18.0.1-halo-keymi');assert.deepEqual(port.commands.map(c=>c[0]),[1,22]);
});
test('protocol 14 companion detection retains full version rather than its 20-byte diagnostic field',async()=>{
  const full='Companion v1.18.0.1-halo-keymind-cascade-dev-03214a16 (protocol 14, build 27-Oct-2026)',port=binaryPort(14,full),device=await detectMeshCore(port);assert.equal(device.version,full);assert.equal(device.shortVersion,'v1.18.0.1-halo-keymi');assert.deepEqual(port.commands.map(c=>c[0]),[1,22,66]);assert.equal(new TextDecoder().decode(Uint8Array.from(port.commands[2].slice(1))),'version');
});
test('unsupported or malformed optional companion version does not replace core identity or short version',async()=>{
  for(const reply of [Uint8Array.of(1,1),'Unknown command','repeater v1.18.0','Companion v1.18.0\nother']){
    const device=await detectMeshCore(binaryPort(14,reply));assert.equal(device.version,'v1.18.0.1-halo-keymi');assert.equal(device.model,'Heltec V4');assert.equal(device.publicKey,'11'.repeat(32));
  }
});
