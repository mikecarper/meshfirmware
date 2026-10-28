import test from 'node:test';
import assert from 'node:assert/strict';
import {createNextStepScroller} from '../src/next-step-scroll.js';

function fixture({reduced=false}={}){
  let next=0,dialog=null,hit=null;const frames=new Map(),calls=[];
  const document={querySelector:()=>dialog,elementFromPoint:()=>hit};
  const window={innerWidth:600,innerHeight:500,requestAnimationFrame:callback=>{frames.set(++next,callback);return next;},cancelAnimationFrame:id=>frames.delete(id),matchMedia:query=>{assert.equal(query,'(prefers-reduced-motion: reduce)');return {matches:reduced};}};
  const target=(rect={top:600,bottom:642,left:20,right:220})=>({isConnected:true,disabled:false,hidden:false,value:'unchanged',getBoundingClientRect:()=>rect,getClientRects:()=>[rect],getAttribute:()=>null,closest:()=>null,contains:node=>node?.owner===node,scrollIntoView:options=>calls.push(options),focus:()=>assert.fail('Must not focus a control'),click:()=>assert.fail('Must not click a control')});
  const scroller=createNextStepScroller({window,document});
  return {window,document,scroller,calls,frames,target,flush(){const ready=[...frames.values()];frames.clear();for(const frame of ready)frame();},setDialog(value){dialog=value;},setHit(value){hit=value;}};
}

test('initial load and repeated same-action updates never pull the page',()=>{
  const f=fixture(),target=f.target();assert.equal(f.scroller.update(target),false);f.flush();assert.deepEqual(f.calls,[]);assert.equal(f.scroller.update(target),false);f.flush();assert.deepEqual(f.calls,[]);assert.equal(target.value,'unchanged');
});
test('a transition waits one frame for panels to reveal, then scrolls an out-of-view action once',()=>{
  const f=fixture(),first=f.target(),next=f.target();f.scroller.update(first);assert.equal(f.scroller.update(next),true);assert.deepEqual(f.calls,[]);f.scroller.update(next);assert.equal(f.frames.size,1);f.flush();assert.deepEqual(f.calls,[{block:'center',behavior:'smooth'}]);f.scroller.update(next);f.flush();assert.equal(f.calls.length,1);
});
test('busy null cancels old work and permits the same action once when an operation finishes',()=>{
  const f=fixture(),first=f.target(),next=f.target();f.scroller.update(first);f.scroller.update(next);f.scroller.update(null);f.flush();assert.deepEqual(f.calls,[]);f.scroller.update(next);f.flush();assert.equal(f.calls.length,1);f.scroller.update(next);f.flush();assert.equal(f.calls.length,1);
});
test('fully visible controls do not scroll, but a fixed overlay can trigger guidance',()=>{
  const f=fixture(),visible=f.target({top:100,bottom:142,left:20,right:220});f.scroller.update(null);f.scroller.update(visible);f.flush();assert.deepEqual(f.calls,[]);f.scroller.update(null);f.setHit({id:'fixed-header'});f.scroller.update(visible);f.flush();assert.equal(f.calls.length,1);
});
test('hit testing treats button children as part of the visible target',()=>{
  const f=fixture(),visible=f.target({top:100,bottom:142,left:20,right:220}),child={id:'label'};visible.contains=value=>value===child;f.setHit(child);f.scroller.update(null);f.scroller.update(visible);f.flush();assert.deepEqual(f.calls,[]);
});
test('safe viewport includes visual viewport offset and leaves space around the target',()=>{
  const f=fixture(),edge=f.target({top:200,bottom:242,left:20,right:220});f.window.visualViewport={offsetTop:210,offsetLeft:0,width:600,height:250};f.scroller.update(null);f.scroller.update(edge);f.flush();assert.equal(f.calls.length,1);
});
test('reduced-motion preference uses an immediate centered scroll',()=>{
  const f=fixture({reduced:true});f.scroller.update(null);f.scroller.update(f.target());f.flush();assert.deepEqual(f.calls,[{block:'center',behavior:'auto'}]);
});
test('an open dialog blocks scrolling underlying page controls, including a dialog opened after scheduling',()=>{
  const f=fixture(),outside=f.target(),inside=f.target();f.scroller.update(null);f.setDialog({contains:target=>target===inside});assert.equal(f.scroller.update(outside),false);f.flush();assert.deepEqual(f.calls,[]);f.scroller.update(inside);f.flush();assert.equal(f.calls.length,1);
  f.setDialog(null);f.scroller.update(outside);f.setDialog({contains:()=>false});f.flush();assert.equal(f.calls.length,1);
});
test('hidden, detached, disabled or inert controls and invalid geometry never scroll',()=>{
  for(const changes of [{hidden:true},{disabled:true},{isConnected:false},{getAttribute:()=> 'true'},{closest:()=>({})},{getClientRects:()=>[]},{getBoundingClientRect:()=>({top:NaN,bottom:2,left:1,right:2})}]){
    const f=fixture(),target=Object.assign(f.target(),changes);f.scroller.update(null);f.scroller.update(target);f.flush();assert.deepEqual(f.calls,[]);
  }
});
test('changing or destroying guidance invalidates earlier frames and never mutates a target',()=>{
  const f=fixture(),one=f.target(),two=f.target();f.scroller.update(null);f.scroller.update(one);f.scroller.update(two);f.flush();assert.equal(f.calls.length,1);assert.equal(one.value,'unchanged');assert.equal(two.value,'unchanged');f.scroller.update(one);f.scroller.destroy();f.flush();assert.equal(f.calls.length,1);assert.equal(f.scroller.update(two),false);
});
test('layout and scrolling failures remain nonfatal and a fresh initial marker stays quiet',()=>{
  const f=fixture(),target=f.target();target.scrollIntoView=()=>{throw Error('unsupported')};f.scroller.update(null);f.scroller.update(target);assert.doesNotThrow(()=>f.flush());assert.equal(f.scroller.update(f.target(),{initial:true}),false);f.flush();assert.deepEqual(f.calls,[]);
});
