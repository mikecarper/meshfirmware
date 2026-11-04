import test from 'node:test';
import assert from 'node:assert/strict';
import {detectMeshCore} from '../src/meshcore.js';
import {detectApplication} from '../src/application-detection.js';

const encode=value=>new TextEncoder().encode(value);
const publicKey='52'.repeat(32);
const version='Companion v1.18.0.1-halo-keymind-cascade-dev-03214a16 (protocol 14, build 24-Oct-2026)';
const frame=payload=>Uint8Array.from([0x3e,payload.length&255,payload.length>>8,...payload]);

function terminalRadio({firstReply,role='companion',reportedVersion=version,logging='usb.logging off; port: USB primary',handoff='OK - Binary mode',binaryKey=publicKey,latePrompt=false,binaryTimeout=false,startInBinary=false,fragmentControl=false,opaqueTraffic=false,omitFreshNonce=false,omitFullBanner=false}={}){
  const commands=[],writes=[],rawWrites=[],events=[],queue=[],buffer=[];let recovered=false;
  const self=new Uint8Array(66),info=new Uint8Array(82);
  self.set([5,1,22,22]);self.set(Buffer.from(binaryKey,'hex'),4);self.set(encode('52525252'),58);
  info.set([13,14,50,40]);info.set(encode('24-Oct-2026'),8);info.set(encode('Heltec V3'),20);info.set(encode('v1.18.0.1-halo-keymi'),60);
  const replies={
    'get public.key':firstReply??`\r\n===== MeshCore Full Companion Terminal =====\r\nWELCOME  52525252\r\n${publicKey.toUpperCase()}\r\nCompanion v1.18.0.1-halo-keymind-cascade-dev-03214a16\r\n> get public.key\r\n  -> > ${publicKey}\r\n> `,
    'get name':'> 52525252',ver:reportedVersion,board:'Heltec V3','get role':`> ${role}`,'get usb.logging':logging,
  };
  const fakeSelf=Uint8Array.from(self);fakeSelf.set(new Uint8Array(32).fill(0x11),4);
  const opaque=frame([0x88,...encode('OK - Binary mode\r\n'),...frame(fakeSelf)]);
  const enqueueControl=bytes=>{if(fragmentControl)for(const byte of bytes)queue.push(Uint8Array.of(byte));else queue.push(bytes);};
  return {commands,writes,rawWrites,events,buffer,
    command:async command=>{
      commands.push(command);events.push(command);
      assert.ok(Object.hasOwn(replies,command),`Unexpected text command: ${command}`);
      if(command==='get public.key'&&startInBinary&&!recovered)return '\u0088opaque binary packet log';
      return replies[command];
    },
    write:async bytes=>{
      if(bytes[0]!==0x3c){
        const request=new TextDecoder().decode(bytes);rawWrites.push(request);
        const challenge=/get __meshfirmware_probe_[a-f0-9]{32}/.exec(request)?.[0];assert.ok(challenge,'A raw transition must use a fresh read-only challenge');
        const error=`${challenge}\r\n  ERROR: unknown command: ${challenge}\r\n> `;
        if(request.startsWith('+++MESHCORE-TERM-START\r\n')){
          assert.equal(recovered,false,'The recovery start token must not be retried');recovered=true;events.push('terminal-start');
          enqueueControl(Uint8Array.from([...(opaqueTraffic?opaque.subarray(4):[]),...encode(`${omitFullBanner?'':'===== MeshCore Full Companion Terminal =====\r\n'}> ${error}`)]));
        }else{
          assert.equal(request,`${challenge}\r\n+++MESHCORE-TERM-STOP\r\n`);events.push('terminal-stop');
          if(latePrompt)buffer.push(...encode('> \r\n'));
          const prefix=opaqueTraffic?opaque.subarray(4):[];
          const response=encode(`> ${omitFreshNonce?'get __meshfirmware_probe_00000000000000000000000000000000\r\n':error}+++MESHCORE-TERM-STOP\r\n${handoff}\r\n`);
          enqueueControl(Uint8Array.from([...prefix,...response,...(opaqueTraffic?opaque.subarray(0,2):[])]));
          if(opaqueTraffic)queue.push(opaque.subarray(2));
        }
        return;
      }
      assert.equal(bytes[0],0x3c);const payload=Array.from(bytes.subarray(3));writes.push(payload);events.push(`binary:${payload[0]}`);
      assert.ok([1,22].includes(payload[0]),`Unexpected binary command: ${payload[0]}`);
      if(startInBinary&&!recovered){queue.push(Uint8Array.of(0x3e,0xff,0xff));return;}
      if(!binaryTimeout)queue.push(frame(payload[0]===1?self:info));
    },
    read:async()=>{events.push('read');return buffer.length?Uint8Array.from(buffer.splice(0)):queue.shift()||new Uint8Array();},
  };
}

function assertReadOnly(radio){
  assert.ok(!radio.commands.some(command=>/^(?:set |reboot|reset|erase)|prv\.key/i.test(command)));
  assert.ok(radio.writes.every(payload=>[1,22].includes(payload[0])));
  assert.ok(radio.rawWrites.every(request=>request.split('\r\n').filter(Boolean).every(command=>/^get __meshfirmware_probe_[a-f0-9]{32}$|^\+\+\+MESHCORE-TERM-(?:START|STOP)$/.test(command))));
}

test('a stock Companion SELF_INFO followed by an INFO timeout never launches terminal recovery or Meshtastic',async()=>{
  for(const observedRomBoot of [false,true]){
    const queue=[],writes=[],self=new Uint8Array(66);self.set([5,1,22,22]);self.set(Buffer.from(publicKey,'hex'),4);self.set(encode('TestV3'),58);
    const link={buffer:[],startupEvidence:Object.freeze({observedRomBoot}),
      command:async command=>{assert.equal(command,'get public.key');return '';},
      write:async bytes=>{writes.push([...bytes]);assert.equal(bytes[0],0x3c,'Only the two Companion identity queries may be sent');if(bytes[3]===1)queue.push(frame(self));},
      read:async()=>queue.shift()||new Uint8Array(),
    };
    await assert.rejects(detectApplication(link,{meshCoreTimeoutMs:100,meshtasticTimeoutMs:100}),error=>error.meshcoreApplicationIdentified===true);
    assert.deepEqual(writes.map(bytes=>bytes[3]),[1,22]);
  }
});

test('first Full Companion banner and getter may repeat the same normalized public identity',async()=>{
  for(const role of ['companion','companionFull','COMPANIONFULL']){
    const radio=terminalRadio({role}),device=await detectMeshCore(radio,{timeoutMs:50});
    assert.equal(device.role,'companion');assert.equal(device.catalogRole,'companionFull');assert.equal(device.publicKey,publicKey);assert.equal(device.model,'Heltec V3');assert.equal(device.version,version);assert.equal(device.protocol,14);
    assert.deepEqual(radio.commands,['get public.key','get name','ver','board','get role','get usb.logging']);assert.equal(radio.rawWrites.length,1);
    assert.deepEqual(radio.writes.map(payload=>payload[0]),[1,22]);assertReadOnly(radio);
  }
});

test('case-folded duplicate getter lines remain valid for ordinary CommonCLI without mode commands',async()=>{
  const radio=terminalRadio({firstReply:`> ${publicKey.toUpperCase()}\r\n -> ${publicKey}`,role:'repeater',reportedVersion:'v1.18.0.1'});
  const device=await detectMeshCore(radio,{timeoutMs:50});assert.equal(device.role,'common-cli');assert.equal(device.publicKey,publicKey);assert.equal(device.catalogRole,'repeater');
  assert.deepEqual(radio.commands,['get public.key','get name','ver','board','get role']);assert.equal(radio.writes.length,0);assertReadOnly(radio);
});

test('conflicting complete public identities never become CommonCLI evidence or trigger another protocol',async()=>{
  const radio=terminalRadio({firstReply:`> ${publicKey}\r\n> ${'11'.repeat(32)}`});
  await assert.rejects(detectMeshCore(radio,{timeoutMs:10}),error=>error.code==='MESHCORE_IDENTITY_CONFLICT'&&error.meshcoreApplicationIdentified===true);
  assert.deepEqual(radio.commands,['get public.key']);assert.equal(radio.writes.length,0);assertReadOnly(radio);
});

test('logging on or stream remains an explicitly identified ASCII Companion with no settings or mode changes',async()=>{
  for(const logging of ['on','stream']){
    const radio=terminalRadio({logging:`usb.logging ${logging}; port: USB primary`}),device=await detectMeshCore(radio,{timeoutMs:50});
    assert.equal(device.role,'common-cli');assert.equal(device.companionTerminal,true);assert.equal(device.catalogRole,'companionFull');assert.equal(device.usbLogging,logging);assert.equal(device.publicKey,publicKey);assert.match(device.companionModeReason,/detection did not change it/);
    assert.deepEqual(radio.commands,['get public.key','get name','ver','board','get role','get usb.logging']);assert.equal(radio.writes.length,0);assertReadOnly(radio);
  }
});

test('unsupported, ambiguous, or error logging replies cannot authorize a binary handoff',async()=>{
  for(const logging of ['Unknown command','','ERROR: use usb.logging off first','usb.logging off\nusb.logging on','unrelated usb.logging off','usb.logging off trailing']){
    const radio=terminalRadio({logging}),device=await detectMeshCore(radio,{timeoutMs:50});
    assert.equal(device.companionTerminal,true);assert.equal(device.usbLogging,null);assert.match(device.companionModeReason,/did not confirm/);assert.equal(radio.commands.at(-1),'get usb.logging');assert.equal(radio.writes.length,0);assertReadOnly(radio);
  }
});

test('role and complete Companion version must agree before detection requests any mode transition',async()=>{
  for(const options of [{role:'companion extra'},{role:'companion',reportedVersion:'v1.18.0.1'},{role:'repeater'},{role:'companion',reportedVersion:version+'\nother'}]){
    const radio=terminalRadio(options),device=await detectMeshCore(radio,{timeoutMs:50});assert.equal(device.role,'common-cli');assert.equal(device.companionTerminal,undefined);
    assert.equal(radio.commands.at(-1),'get role');assert.equal(radio.writes.length,0);assertReadOnly(radio);
  }
});

test('confirmed handoff waits through a late ASCII prompt before sending SELF_INFO',async()=>{
  const radio=terminalRadio({latePrompt:true}),device=await detectMeshCore(radio,{timeoutMs:50});
  assert.equal(device.publicKey,publicKey);const transition=radio.events.indexOf('terminal-stop');
  assert.deepEqual(radio.events.slice(transition,transition+4),['terminal-stop','read','read','binary:1']);assertReadOnly(radio);
});

test('a missing handoff acknowledgment is typed and sends the stop token only once, without binary queries',async()=>{
  for(const handoff of ['', 'ERROR: set usb.logging off before Binary mode','not OK - Binary mode']){
    const radio=terminalRadio({handoff});
    await assert.rejects(detectMeshCore(radio,{timeoutMs:10}),error=>error.code==='MESHCORE_COMPANION_MODE'&&error.meshcoreApplicationIdentified===true&&/not confirmed/.test(error.message));
    assert.equal(radio.rawWrites.filter(request=>request.includes('+++MESHCORE-TERM-STOP')).length,1);assert.equal(radio.commands.at(-1),'get usb.logging');assert.equal(radio.writes.length,0);assertReadOnly(radio);
  }
});

test('binary identity must match text identity before any further binary query',async()=>{
  const radio=terminalRadio({binaryKey:'11'.repeat(32)});
  await assert.rejects(detectMeshCore(radio,{timeoutMs:10}),error=>error.code==='MESHCORE_IDENTITY_MISMATCH'&&error.meshcoreApplicationIdentified===true);
  assert.deepEqual(radio.writes.map(payload=>payload[0]),[1]);assertReadOnly(radio);
});

test('binary timeout after a confirmed handoff stays an identified Companion failure without retries',async()=>{
  const radio=terminalRadio({binaryTimeout:true});
  await assert.rejects(detectMeshCore(radio,{timeoutMs:2}),error=>error.code==='MESHCORE_COMPANION_MODE'&&error.meshcoreApplicationIdentified===true);
  assert.deepEqual(radio.writes.map(payload=>payload[0]),[1]);assert.equal(radio.rawWrites.filter(request=>request.includes('+++MESHCORE-TERM-STOP')).length,1);assertReadOnly(radio);
});

test('application detection never falls back to Meshtastic after Companion mode or identity evidence',async()=>{
  for(const [options,code] of [[{handoff:''},'MESHCORE_COMPANION_MODE'],[{binaryKey:'11'.repeat(32)},'MESHCORE_IDENTITY_MISMATCH'],[{firstReply:`> ${publicKey}\n> ${'11'.repeat(32)}`},'MESHCORE_IDENTITY_CONFLICT']]){
    const radio=terminalRadio(options);
    await assert.rejects(detectApplication(radio,{meshCoreTimeoutMs:10,meshtasticTimeoutMs:1}),error=>error.code===code);
    assertReadOnly(radio);
  }
  const radio=terminalRadio({logging:'usb.logging on; port: USB primary'}),device=await detectApplication(radio,{meshCoreTimeoutMs:10,meshtasticTimeoutMs:1});
  assert.equal(device.firmwareFamily,'meshcore');assert.equal(device.companionTerminal,true);assert.equal(radio.writes.length,0);assertReadOnly(radio);
});

test('a transport failure during the acknowledged handoff retains its original error and sends no binary query',async()=>{
  const radio=terminalRadio(),failure=new Error('The selected serial port disconnected.');radio.read=async()=>{throw failure;};
  await assert.rejects(detectApplication(radio,{meshCoreTimeoutMs:10,meshtasticTimeoutMs:1}),error=>error===failure);
  assert.equal(radio.commands.at(-1),'get usb.logging');assert.equal(radio.writes.length,0);assertReadOnly(radio);
});

test('nonce-bound ACK survives byte fragmentation and preserves an immediate partial opaque push containing a fake SELF_INFO',async()=>{
  const radio=terminalRadio({fragmentControl:true,opaqueTraffic:true}),device=await detectMeshCore(radio,{timeoutMs:100});
  assert.equal(device.publicKey,publicKey);assert.deepEqual(radio.writes.map(payload=>payload[0]),[1,22]);assertReadOnly(radio);
});

test('unidentified binary failure gets one proven Full terminal recovery before a clean nonce-bound binary handoff',async()=>{
  const radio=terminalRadio({startInBinary:true,fragmentControl:true,opaqueTraffic:true}),device=await detectMeshCore(radio,{timeoutMs:100});
  assert.equal(device.publicKey,publicKey);assert.equal(device.role,'companion');assert.deepEqual(radio.writes.map(payload=>payload[0]),[1,1,22]);
  assert.equal(radio.rawWrites.filter(request=>request.includes('+++MESHCORE-TERM-START')).length,1);assert.equal(radio.rawWrites.filter(request=>request.includes('+++MESHCORE-TERM-STOP')).length,1);assertReadOnly(radio);
});

test('opaque fake ACK and SELF_INFO without this request\'s fresh nonce cannot authorize binary queries',async()=>{
  const radio=terminalRadio({opaqueTraffic:true,omitFreshNonce:true});
  await assert.rejects(detectApplication(radio,{meshCoreTimeoutMs:10,meshtasticTimeoutMs:1}),error=>error.code==='MESHCORE_COMPANION_MODE');
  assert.equal(radio.writes.length,0);assert.equal(radio.rawWrites.length,1);assertReadOnly(radio);
});

test('a nonce response without the Full terminal banner cannot promote unknown binary firmware to Full',async()=>{
  const radio=terminalRadio({startInBinary:true,omitFullBanner:true});
  await assert.rejects(detectMeshCore(radio,{timeoutMs:10}),/Invalid MeshCore frame size/);
  assert.equal(radio.rawWrites.length,1);assert.deepEqual(radio.writes.map(payload=>payload[0]),[1]);assertReadOnly(radio);
});
