#!/usr/bin/env bun
// SPDX-License-Identifier: GPL-3.0-only
// API-free Figma input experiment. Never imports or reads a vault credential.
import {createInterface} from 'node:readline';
import {parseArgs} from 'node:util';
import {randomUUID} from 'node:crypto';
import {spawn} from 'node:child_process';
import {mkdir,rmdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {assertTabBinding,figmaProbeExpression} from './probe-policy.mjs';

const {values:binding}=parseArgs({options:{thread:{type:'string'},tab:{type:'string'},profile:{type:'string'}}});
if(!['thread','tab','profile'].every(k=>typeof binding[k]==='string'&&binding[k].length>0&&binding[k].length<257))process.exit(2);
const out=value=>process.stdout.write(JSON.stringify(value)+'\n');
const pending=new Map();let busy=false,held,lockHeld=false,lockState='not_acquired',clipboard='not_used';
const lock=join(tmpdir(),`osiris-agent-vault-browser-${process.getuid()}.lock`);
function call(name,args){return new Promise((resolve,reject)=>{
  const id=randomUUID(),timer=setTimeout(()=>{pending.delete(id);reject(new Error('host_transport_unavailable'));},20000);
  pending.set(id,{resolve,reject,timer});out({type:'tool_request',id,name,args});
});}
async function guard(expected){
  const [status,list]=await Promise.all([call('preview_status',{tabId:binding.tab}),call('t3_preview_list',{limit:50})]);
  return assertTabBinding(binding,status,list,expected);
}
async function evaluate(expression){return (await call('preview_evaluate',{tabId:binding.tab,expression,awaitPromise:true,returnByValue:true})).value;}
function native(command,input=''){return new Promise((resolve,reject)=>{
  const p=spawn(command,[],{stdio:['pipe','pipe','ignore']});let data='',failed=false;
  const fail=()=>{failed=true;p.kill();reject(new Error('clipboard_unavailable'));};
  const timer=setTimeout(fail,3000);p.on('error',()=>{clearTimeout(timer);fail();});p.stdin.on('error',()=>{});
  p.stdout.on('data',c=>{data+=c;if(data.length>100000)fail();});
  p.on('close',code=>{clearTimeout(timer);if(!failed)code===0?resolve(data):reject(new Error('clipboard_unavailable'));});p.stdin.end(input);
});}
async function cleanup(){
  if(held!==undefined){
    if(await native('/usr/bin/pbpaste')===held){await native('/usr/bin/pbcopy');if(await native('/usr/bin/pbpaste')!=='')throw new Error('clipboard_unavailable');clipboard='cleared';}
    else clipboard='replaced_externally';
    held=undefined;
  }
  if(lockHeld){await rmdir(lock);lockHeld=false;lockState='released';}
  return {session:'not_created',clipboard,lock:lockState};
}
async function probe(){
  const start=performance.now(),expected=await guard(),nonce=randomUUID();
  const armed=await evaluate(figmaProbeExpression({action:'arm',nonce,url:expected.url}));
  if(armed?.state!=='armed')return {...armed,credentialsRead:false,submitted:false};
  await guard(expected);
  await mkdir(lock,{mode:0o700});lockHeld=true;lockState='held';
  try{
    held=`vault2-input-check+${nonce}@example.invalid`;clipboard='cleanup_unverified';
    await native('/usr/bin/pbcopy',held);
    if(await native('/usr/bin/pbpaste')!==held)throw new Error('clipboard_unavailable');
    await guard(expected);
    const fillStart=performance.now();
    const result=await evaluate(figmaProbeExpression({action:'fill-clear',nonce,url:expected.url}));
    const guardedInputMs=performance.now()-fillStart;
    await guard(expected);
    return {...result,credentialsRead:false,submitted:false,timings:{guardedInputMs,commandMs:performance.now()-start}};
  }finally{await cleanup();}
}
const input=createInterface({input:process.stdin,terminal:false});
if(process.stdin.isTTY)process.stdin.setRawMode(true);
input.on('line',async line=>{
  let m;try{if(line.length>262144)return;m=JSON.parse(line);}catch{return;}
  if(m.type==='tool_response'){const p=pending.get(m.id);if(p){pending.delete(m.id);clearTimeout(p.timer);m.error?p.reject(new Error('host_operation_failed')):p.resolve(m.result);}return;}
  if(m.type!=='command'||busy)return;busy=true;
  try{
    if(m.action==='close'){const receipt=await cleanup();out({type:'result',result:{state:'closed',cleanup:receipt}});input.close();process.exit(0);}
    out({type:'result',result:m.action==='probe-input'?await probe():{state:'denied',reasonCode:'invalid_request'}});
  }catch(e){const reasons=['host_transport_unavailable','host_operation_failed','origin_mismatch','binding_changed','host_control_unavailable','clipboard_unavailable'];out({type:'result',result:{state:'needs_attention',reasonCode:reasons.includes(e.message)?e.message:'host_operation_failed',credentialsRead:false,submitted:false}});}
  finally{busy=false;}
});
input.on('close',()=>{cleanup().finally(()=>process.exit(0));});
for(const s of ['SIGINT','SIGTERM'])process.on(s,()=>{cleanup().finally(()=>process.exit(0));});
setTimeout(()=>{cleanup().finally(()=>process.exit(0));},120000).unref();
out({type:'session_ready',transport:'chat-tool-relay',purpose:'nonsecret-figma-input-probe',expiresInSeconds:120});
