// SPDX-License-Identifier: GPL-3.0-only
import {test} from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {assertTabBinding,figmaProbeExpression} from './probe-policy.mjs';
const binding={thread:'thread',tab:'tab',profile:'profile'};
const status={available:true,tabId:'tab',url:'https://www.figma.com/login',control:{owner:'agent',ownedByCaller:true,generation:0}};
const list={sessions:[{threadId:'thread',tabId:'tab',profileId:'profile'}]};
test('exact app/thread/tab/profile/control are required',()=>{
  assert.deepEqual(assertTabBinding(binding,status,list),{url:status.url,generation:0});
  for(const s of [{...status,url:'https://www.figma.com.evil.invalid/login'},{...status,tabId:'other'},{...status,control:{...status.control,owner:'human'}},{...status,dialog:{}},])assert.throws(()=>assertTabBinding(binding,s,list));
  for(const prop of ['threadId','profileId'])assert.throws(()=>assertTabBinding(binding,status,{sessions:[{...list.sessions[0],[prop]:'other'}]}));
  assert.throws(()=>assertTabBinding(binding,{...status,control:{...status.control,generation:1}},list,{url:status.url,generation:0}));
});
const nonce='12345678-1234-1234-1234-123456789abc';
function fixture(){
  let reads=0;const form={};
  class Input{
    constructor(type){Object.assign(this,{type,form,isConnected:true,disabled:false,readOnly:false,_value:''});}
    get value(){return this._value;} set value(v){this._value=v;}
    getClientRects(){return [1];}getBoundingClientRect(){return {left:0,top:0,width:100,height:30};}
    focus(){document.activeElement=this;}contains(x){return x===this;}dispatchEvent(){}
  }
  const email=new Input('email'),password=new Input('password');
  const document={readyState:'complete',body:{innerText:''},hasFocus:()=>true,querySelectorAll:s=>s==='input#email'?[email]:s==='input#current-password'?[password]:[],elementFromPoint:()=>email};
  const navigator={permissions:{query:async()=>({state:'granted'})},clipboard:{readText:async()=>{reads++;return 'vault2-input-check+'+nonce+'@example.invalid';}}};
  const context=vm.createContext({document,navigator,location:{href:status.url,origin:'https://www.figma.com'},performance,Date,setTimeout,HTMLInputElement:Input,getComputedStyle:()=>({visibility:'visible'}),Event:class{}});
  const run=action=>vm.runInContext(figmaProbeExpression({action,nonce,url:status.url}),context);
  return {run,document,navigator,email,password,context,get reads(){return reads;}};
}
test('already granted clipboard path fills then clears; no submission path',async()=>{
  const f=fixture();assert.equal((await f.run('arm')).state,'armed');
  const r=await f.run('fill-clear');assert.equal(r.state,'benign_input_verified');assert.equal(f.email.value,'');assert.equal(f.password.value,'');assert.equal(f.reads,1);
  assert.equal((await f.run('fill-clear')).state,'binding_changed');assert.equal(f.reads,1);
});
test('permission prompt and human input deny before clipboard reading',async()=>{
  const f=fixture();f.navigator.permissions.query=async()=>({state:'prompt'});
  assert.equal((await f.run('arm')).state,'clipboard_permission_required');assert.equal(f.reads,0);
  f.email.value='human input';assert.equal((await f.run('arm')).state,'nonempty_form');assert.equal(f.email.value,'human input');
});
test('navigation during asynchronous clipboard read prevents insertion',async()=>{
  const f=fixture();await f.run('arm');f.navigator.clipboard.readText=async()=>{f.context.location.href='https://www.figma.com/other';return 'vault2-input-check+'+nonce+'@example.invalid';};
  assert.equal((await f.run('fill-clear')).state,'clipboard_mismatch');assert.equal(f.email.value,'');
});
test('human input during clipboard read is preserved',async()=>{
  const f=fixture();await f.run('arm');f.navigator.clipboard.readText=async()=>{f.email.value='human input';return 'vault2-input-check+'+nonce+'@example.invalid';};
  assert.equal((await f.run('fill-clear')).state,'clipboard_mismatch');assert.equal(f.email.value,'human input');
});
test('same-URL document/form replacement invalidates the armed transaction',async()=>{
  const f=fixture();await f.run('arm');f.email.form={};
  assert.equal((await f.run('fill-clear')).state,'form_unavailable');assert.equal(f.reads,0);
});
