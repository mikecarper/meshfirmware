import test from 'node:test';
import assert from 'node:assert/strict';
import { readManagedContacts, renameManagedContact, addManagedContact, removeManagedContact } from '../src/managed-contacts.js';

const key='aa'.repeat(32), other='bb'.repeat(32);
function fixture(){
  const row=new Uint8Array(148);row[0]=3;row.fill(7,1,33);row[33]=2;row[34]=3;row[35]=255;row.set([10,11,12],36);row.set(new TextEncoder().encode('Old name'),100);new DataView(row.buffer).setUint32(144,42,true);
  const self=new Uint8Array(58);self[0]=5;self.fill(0xaa,4,36);
  const state={row,self,requests:[],checks:0,current:true};
  const core={
    async self(){return state.self.slice();},
    async contacts(){return [state.row.slice()];},
    async request(command,code){state.requests.push({command,code});state.row.set(command.slice(1),1);new DataView(state.row.buffer).setUint32(144,43,true);return Uint8Array.of(0);},
  };
  const options={publicKey:key,maxContacts:2000,assertCurrent(){state.checks++;if(!state.current)throw Error('Device changed.');}};
  return {state,core,options};
}
function listFixture(){
  const f=fixture();f.state.rows=[f.state.row.slice()];
  f.core.contacts=async()=>f.state.rows.map(row=>row.slice());
  f.core.request=async(command,code)=>{
    f.state.requests.push({command,code});
    if(command[0]===9){const row=new Uint8Array(148);row[0]=3;row.set(command.slice(1),1);new DataView(row.buffer).setUint32(144,10,true);const i=f.state.rows.findIndex(r=>r.subarray(1,33).every((v,j)=>v===row[j+1]));if(i<0)f.state.rows.push(row);else f.state.rows[i]=row;}
    if(command[0]===15)f.state.rows=f.state.rows.filter(row=>!row.subarray(1,33).every((v,i)=>v===command[i+1]));
    return Uint8Array.of(0);
  };
  return f;
}

test('contact inventory reads only public identity and summaries',async()=>{
  const f=fixture(), rows=await readManagedContacts(f.core,f.options);
  assert.equal(rows.length,1);assert.equal(rows[0].name,'Old name');assert.equal(rows[0].publicKey,'07'.repeat(32));assert.equal(rows[0].type,2);assert.equal(rows[0].flags,3);assert.deepEqual(f.state.requests,[]);assert.ok(f.state.checks>=4);
});
test('untrusted contact names cannot inject misleading review lines',async()=>{
  for(const name of ['Other\nNew: Trusted','Else\u202e123']){
    const f=fixture();f.state.row.fill(0,100,132);f.state.row.set(new TextEncoder().encode(name),100);
    await assert.rejects(readManagedContacts(f.core,f.options),/control characters/);assert.deepEqual(f.state.requests,[]);
  }
});
test('rename preserves writable contact fields and verifies readback',async()=>{
  const f=fixture(), [contact]=await readManagedContacts(f.core,f.options),before=f.state.row.slice();
  const updated=await renameManagedContact(f.core,{...f.options,contact,name:'New name'});
  assert.equal(updated.name,'New name');assert.equal(f.state.requests.length,1);assert.equal(f.state.requests[0].command[0],9);assert.equal(f.state.requests[0].code,0);
  assert.deepEqual(f.state.row.slice(1,100),before.slice(1,100));assert.deepEqual(f.state.row.slice(132,144),before.slice(132,144));assert.equal(new DataView(f.state.row.buffer).getUint32(144,true),43);
});
test('stale contact, invalid name or different device fail before writes',async()=>{
  const f=fixture(), [contact]=await readManagedContacts(f.core,f.options);
  for(const name of ['', ' '.repeat(2), 'x'.repeat(32), 'a\ncommand', '📻'.repeat(8)])await assert.rejects(renameManagedContact(f.core,{...f.options,contact,name}),/Contact name/);
  f.state.row[34]++;await assert.rejects(renameManagedContact(f.core,{...f.options,contact,name:'Other'}),/changed since/);f.state.row[34]--;
  await assert.rejects(renameManagedContact(f.core,{...f.options,publicKey:other,contact,name:'Other'}),/identity changed/);
  f.state.current=false;await assert.rejects(renameManagedContact(f.core,{...f.options,contact,name:'Other'}),/Device changed/);
  assert.deepEqual(f.state.requests,[]);
});
test('lost acknowledgement and mismatched readback report uncertainty without retry',async()=>{
  for(const issue of ['ack','readback','timeout','changed']){
    const f=fixture(),[contact]=await readManagedContacts(f.core,f.options),request=f.core.request;
    f.core.request=async(...args)=>{const reply=await request(...args);if(issue==='readback')f.state.row[34]^=1;if(issue==='timeout')throw Error('Reply lost');if(issue==='changed')f.state.current=false;return issue==='ack'?Uint8Array.of(0,1):reply;};
    await assert.rejects(renameManagedContact(f.core,{...f.options,contact,name:'Other'}),/may have been saved/);assert.equal(f.state.requests.length,1);
  }
});

test('add uses the exact reviewed contact frame with unknown route and verifies inventory',async()=>{
  for(const type of [1,2,3,4]){
    const f=listFixture(),added=await addManagedContact(f.core,{...f.options,contactPublicKey:other,name:'Test node',type});
    assert.equal(added.publicKey,other);assert.equal(added.name,'Test node');assert.equal(added.type,type);assert.equal(added.flags,0);
    assert.equal(f.state.requests.length,1);const cmd=f.state.requests[0].command;
    assert.equal(cmd[0],9);assert.equal(cmd.length,144);assert.equal(cmd[35],255);assert.ok(cmd.slice(36,100).every(v=>v===0));assert.ok(cmd.slice(132,144).every(v=>v===0));
  }
});
test('add rejects duplicates, full list, invalid identity and types before any write',async()=>{
  const f=listFixture();
  for(const input of [
    {contactPublicKey:'07'.repeat(32),name:'Exists',type:1},
    {contactPublicKey:key,name:'Own identity',type:1},
    {contactPublicKey:'00'.repeat(32),name:'Zeros',type:1},
    {contactPublicKey:'12',name:'Invalid',type:1},
    {contactPublicKey:other,name:'Invalid',type:0},
    {contactPublicKey:other,name:'Invalid',type:5},
    {contactPublicKey:other,name:'Invalid\nname',type:1},
  ])await assert.rejects(addManagedContact(f.core,{...f.options,...input}));
  await assert.rejects(addManagedContact(f.core,{...f.options,maxContacts:1,contactPublicKey:other,name:'Full',type:1}),/full/);
  assert.deepEqual(f.state.requests,[]);
});
test('remove checks the exact selected snapshot and verifies contact absence',async()=>{
  const f=listFixture(),[contact]=await readManagedContacts(f.core,f.options);
  assert.equal(await removeManagedContact(f.core,{...f.options,contact}),true);assert.equal(f.state.requests.length,1);
  assert.deepEqual(f.state.requests[0].command,[15,...Array(32).fill(7)]);assert.equal(f.state.rows.length,0);
});
test('remove rejects changed or replaced devices before deletion',async()=>{
  const f=listFixture(),[contact]=await readManagedContacts(f.core,f.options);
  f.state.rows[0][34]++;await assert.rejects(removeManagedContact(f.core,{...f.options,contact}),/changed since/);f.state.rows[0][34]--;
  await assert.rejects(removeManagedContact(f.core,{...f.options,publicKey:other,contact}),/identity changed/);assert.deepEqual(f.state.requests,[]);
});
test('lost replies and failed verification for addition or removal are reported without retry',async()=>{
  for(const action of ['add','remove'])for(const failure of ['ack','readback','timeout']){
    const f=listFixture(),[contact]=await readManagedContacts(f.core,f.options),request=f.core.request;
    f.core.request=async(...args)=>{const before=f.state.rows.map(row=>row.slice()),reply=await request(...args);if(failure==='readback')f.state.rows=before;if(failure==='timeout')throw Error('Reply lost');return failure==='ack'?Uint8Array.of(0,1):reply;};
    const promise=action==='add'?addManagedContact(f.core,{...f.options,contactPublicKey:other,name:'New',type:1}):removeManagedContact(f.core,{...f.options,contact});
    await assert.rejects(promise,/may have (?:been saved|occurred)/);assert.equal(f.state.requests.length,1);
  }
});
