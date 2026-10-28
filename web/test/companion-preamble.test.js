import {test} from 'node:test';
import assert from 'node:assert/strict';
import {MeshCore,sealBackup} from '../src/meshcore.js';

const hex=bytes=>Buffer.from(bytes).toString('hex');
function fixture(value='64'){
  const self=new Uint8Array(62),view=new DataView(self.buffer),info=new Uint8Array(82),channel=new Uint8Array(50);
  self.set([5,1,20,22]);self.fill(0x11,4,36);view.setUint32(48,910525,true);view.setUint32(52,125000,true);self[56]=10;self[57]=5;self.set(new TextEncoder().encode('test'),58);
  info.set([13,14,2,1]);info.set(new TextEncoder().encode('test-model'),20);channel[0]=18;
  const payload={role:'companion',publicKey:'11'.repeat(32),self:hex(self),info:hex(info),channels:[hex(channel)],contacts:[],options:{},cli:value===null?{}:{'get radio.preamble':'> '+value},safeForWipe:false};
  const core=new MeshCore({}),commands=[],binary=[];let actual='32',ignore=false,report='Unknown command',response=null;
  core.self=async()=>self;core.info=async()=>info;core.contacts=async()=>[];
  core.request=async command=>{binary.push(command);return command[0]===31?channel:Uint8Array.of(0);};
  core.cli=async command=>{
    commands.push(command);
    if(command==='get config.cap')return report;
    if(command==='get radio.preamble')return response??'> '+actual;
    if(command==='get usb.logging')return '> usb.logging off';
    if(command==='get bluetooth')return '> bluetooth off';
    if(command.startsWith('set radio ')){if(!ignore)actual=command.split(',').at(-1);return 'OK';}
    throw Error('Unexpected test command');
  };
  return {payload,core,commands,binary,setActual:value=>{actual=value;},ignore:()=>{ignore=true;},report:value=>{report=value;},response:value=>{response=value;}};
}

test('companion saved custom and automatic preambles use the reviewed composite setter and exact readback',async()=>{
  for(const desired of ['8','64','65528','auto','0']){
    const f=fixture(desired),result=await f.core.restore(sealBackup(f.payload));
    assert.ok(f.commands.includes(`set radio 910.525,125,10,5,${desired==='0'?'auto':desired}`));
    assert.ok(f.commands.filter(command=>command==='get radio.preamble').length>=2);
    assert.equal(result.optional.radioPreamble.state,'restored');
    assert.ok(!f.commands.includes('set radio.preamble '+desired));
  }
});

test('companion legacy archives never invent or reset a saved primary preamble',async()=>{
  const f=fixture(null),result=await f.core.restore(sealBackup(f.payload));
  assert.equal(result.optional.radioPreamble.state,'not-in-backup');assert.ok(!f.commands.some(command=>command.includes('preamble')||command==='get config.cap'||command.startsWith('set radio ')));
});

test('unsupported or read-only target preambles are explicit skips without a preamble write',async()=>{
  for(const mode of ['unsupported','fixed','na','readonly']){
    const f=fixture();
    if(mode==='unsupported')f.response('Unknown command');
    else f.report(`config.cap v1 get=${mode==='na'?'00000000':'00000800'} set=00000000 fixed=${mode==='fixed'?'00000800':'00000000'} na=${mode==='na'?'00000800':'00000000'}`);
    const result=await f.core.restore(sealBackup(f.payload));
    assert.equal(result.optional.radioPreamble.state,'unsupported');assert.ok(result.warnings.some(text=>/preamble/.test(text)));assert.ok(!f.commands.some(command=>command.startsWith('set radio ')));
    if(mode!=='unsupported')assert.ok(!f.commands.includes('get radio.preamble'));
  }
  const old=fixture(),info=Buffer.from(old.payload.info,'hex');info[1]=13;old.core.info=async()=>info;
  const result=await old.core.restore(sealBackup(old.payload));assert.equal(result.optional.radioPreamble.state,'unsupported');assert.equal(old.commands.length,0);
});

test('malformed saved preambles fail before device access and target failures precede all writes',async()=>{
  for(const value of ['7','65529','65535','64\0','32\nreboot','32\nError: read failed']){
    const f=fixture(value);let accessed=false;f.core.self=async()=>{accessed=true;throw Error('Must validate before USB');};
    await assert.rejects(f.core.restore(sealBackup(f.payload)),/Invalid saved primary-radio preamble/);assert.equal(accessed,false);
  }
  for(const value of ['> 7','> unavailable','Error: read failed']){
    const f=fixture();f.response(value);await assert.rejects(f.core.restore(sealBackup(f.payload)),/preamble/);assert.equal(f.binary.length,0);assert.ok(!f.commands.some(command=>command.startsWith('set ')));
  }
});

test('a genuine failed saved preamble query stays visible instead of being treated as absent',async()=>{
  for(const value of [null,'Error: query failed']){
    const f=fixture();f.payload.cli['get radio.preamble']=value;const result=await f.core.restore(sealBackup(f.payload));assert.equal(result.optional.radioPreamble.state,'not-restored');assert.ok(result.warnings.some(text=>/backup query failed/.test(text)));assert.ok(!f.commands.some(command=>command.startsWith('set radio ')));
  }
});

test('companion restore cannot report success from a preamble setter acknowledgement alone',async()=>{
  const f=fixture();f.ignore();await assert.rejects(f.core.restore(sealBackup(f.payload)),/preamble readback failed/);assert.equal(f.commands.filter(command=>command.startsWith('set radio ')).length,1);
});
