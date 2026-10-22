#!/usr/bin/env bun
// SPDX-License-Identifier: GPL-3.0-only
// Owner-assisted local GHL login. Tool requests contain no credential values.
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdir, rmdir } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { readPrivateFile } from './private-file.mjs';
import { cleanupResources } from './cleanup.mjs';

const ORIGIN = 'https://app.gohighlevel.com';
const ROOT = join(homedir(), '.local/share/agent-vault-upstream-raven');
// Owner-selected identity remains private configuration, never public source.
let configured;
try { configured=JSON.parse(await readPrivateFile(join(ROOT,'ghl-selection.json'))); }
catch { process.stdout.write(JSON.stringify({type:'result',result:{state:'denied',reasonCode:'selection_not_configured'}})+'\n');process.exit(2); }
if(configured.version!==1||configured.origin!==ORIGIN||!/^[0-9a-f-]{36}$/i.test(configured.accountId)||typeof configured.username!=='string'||! /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(configured.username)){process.exit(2);}
const ACCOUNT=configured.accountId, USERNAME=configured.username;
const allowed = new Set(['preview_status', 't3_preview_list', 'preview_click', 'preview_evaluate', 'preview_press']);
const output = value => process.stdout.write(JSON.stringify(value) + '\n');
const pending = new Map();
let token, busy = false, selection, held, lockHeld = false, closing;
let clipboardState = 'not_used';
let lockState = 'not_acquired';
const timings = {ownerSessionMs:0, credentialLookupMs:0, benignInputMs:0, privateFillMs:0, submitMs:0};
async function timed(key, action) { const start=performance.now();try{return await action();}finally{timings[key]+=performance.now()-start;} }
const lock = join(tmpdir(), `osiris-agent-vault-browser-${process.getuid()}.lock`);
const { values: binding } = parseArgs({options:{thread:{type:'string'},tab:{type:'string'},profile:{type:'string'},account:{type:'string'}}});
if (!['thread','tab','profile','account'].every(k => typeof binding[k] === 'string' && binding[k].length > 0 && binding[k].length < 257)) {
  output({type:'result',result:{state:'denied',reasonCode:'invalid_binding'}}); process.exit(2);
}
if(binding.account!==ACCOUNT){output({type:'result',result:{state:'denied',reasonCode:'selection_invalid'}});process.exit(2);}
function call(name,args) {
  if (!allowed.has(name)) throw new Error('unsupported_tool');
  return new Promise((resolve,reject) => {
    const id=randomUUID();
    const timer=setTimeout(()=>{pending.delete(id);reject(new Error('host_transport_unavailable'));},30000);
    pending.set(id,{resolve,reject,timer}); output({type:'tool_request',id,name,args});
  });
}
async function api(path,body) {
  const response=await fetch('http://127.0.0.1:14321'+path,{method:body?'POST':'GET',redirect:'error',
    headers:{...(body?{'Content-Type':'application/json'}:{}),...(token?{Authorization:'Bearer '+token}:{})},
    body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(10000)});
  if (!response.ok) throw new Error(response.status===429?'engine_rate_limited':'engine_unavailable');
  const raw=await response.text(); if(raw.length>262144)throw new Error('engine_unavailable');
  return JSON.parse(raw);
}
async function loginOwner() {
  if(token)return;
  return timed('ownerSessionMs',async()=>{
  const owner=JSON.parse(await readPrivateFile(join(ROOT,'demo-owner.json')));
  const session=await api('/v1/auth/login',{email:owner.email,password:owner.password,device_label:'Vault2 owner-assisted GHL chat'});
  if(typeof session.token!=='string'||!session.token)throw new Error('engine_unavailable');
  token=session.token;
  const me=await api('/v1/auth/me');
  if(me.email!==owner.email||me.role!=='owner')throw new Error('engine_unavailable');
  });
}
async function reveal(key) {
  if(typeof key!=='string'||!/^BW_[A-Z0-9_]{1,200}$/.test(key))throw new Error('credential_unavailable');
  const r=await timed('credentialLookupMs',()=>api('/v1/credentials?'+new URLSearchParams({vault:'bitwarden-import',reveal:'true',key})));
  if(r.keys?.length!==1||r.keys[0]!==key||r.credentials?.length!==1||r.credentials[0].key!==key||typeof r.credentials[0].value!=='string')throw new Error('credential_unavailable');
  return r.credentials[0].value;
}
async function account() {
  await loginOwner();
  const manifest=JSON.parse(await readPrivateFile(join(ROOT,'bitwarden-import-manifest.json'),200000));
  if(manifest.vault!=='bitwarden-import')throw new Error('credential_unavailable');
  const rows=manifest.records.filter(r=>r.sourceID===binding.account);
  if(rows.length!==1||!rows[0].usernameKey||!rows[0].passwordKey)throw new Error('credential_unavailable');
  const row=rows[0], metadata=JSON.parse(await reveal(row.metadataKey));
  if(metadata.id!==binding.account||!(metadata.login?.uris||[]).some(u=>{try{return new URL(u.uri).origin===ORIGIN;}catch{return false;}}))throw new Error('origin_mismatch');
  const username=await reveal(row.usernameKey);
  if(username!==USERNAME)throw new Error('selection_invalid');
  return {row,username};
}
async function guard(expected) {
  const s=await call('preview_status',{tabId:binding.tab});
  if(!s.available||s.tabId!==binding.tab||s.control?.owner!=='agent'||!s.control.ownedByCaller||s.dialog||s.fileChooser)throw new Error('host_control_unavailable');
  if(new URL(s.url).origin!==ORIGIN)throw new Error('origin_mismatch');
  if(expected&&(s.url!==expected.url||s.control.generation!==expected.generation))throw new Error('binding_changed');
  const list=await call('t3_preview_list',{limit:50});
  const tab=list.sessions?.find(t=>t.tabId===binding.tab);
  if(!tab||tab.threadId!==binding.thread||tab.profileId!==binding.profile)throw new Error('host_control_unavailable');
  return {url:s.url,generation:s.control.generation};
}
async function evaluate(expression){return (await call('preview_evaluate',{tabId:binding.tab,expression,returnByValue:true})).value;}
const visible="e=>e.getClientRects().length>0&&!e.disabled&&getComputedStyle(e).visibility!=='hidden'";
async function pageState() {
  return evaluate(`(()=>{if(location.origin!==${JSON.stringify(ORIGIN)})return 'denied';if(!document.body||document.readyState==='loading')return 'page_loading';const t=document.body.innerText;if(/incorrect (email|password)|invalid (email|password|credentials)|wrong password|authentication failed/i.test(t))return 'credentials_rejected';if(/verification code|verify your identity|two.factor|security code|verify your device|check your email|captcha|account recovery/i.test(t)||[...document.querySelectorAll('input[autocomplete="one-time-code"],iframe[src*="bframe"],iframe[title*="challenge"]')].some(${visible}))return 'verification_required';return 'ready';})()`);
}
async function formOkay(){return evaluate(`(()=>{if(location.origin!==${JSON.stringify(ORIGIN)})return false;const us=[...document.querySelectorAll('input#email')].filter(${visible}),ps=[...document.querySelectorAll('input#password')].filter(${visible}),bs=[...document.querySelectorAll('button[type="submit"]')].filter(${visible}).filter(e=>e.textContent.trim()==='Sign in');return us.length===1&&ps.length===1&&bs.length===1&&us[0].type==='text'&&ps[0].type==='password'&&!!ps[0].form&&us[0].form===ps[0].form&&bs[0].form===ps[0].form&&!us[0].readOnly&&!ps[0].readOnly;})()`);}
function native(command,input='') {
  return new Promise((resolve,reject)=>{
    const p=spawn(command,[],{stdio:['pipe','pipe','ignore']}); let data='';
    const timer=setTimeout(()=>{p.kill();reject(new Error('clipboard_unavailable'));},4000);
    p.on('error',()=>{clearTimeout(timer);reject(new Error('clipboard_unavailable'));});p.stdin.on('error',()=>{});
    p.stdout.on('data',c=>{data+=c;if(data.length>100000){p.kill();reject(new Error('clipboard_unavailable'));}});
    p.on('close',code=>{clearTimeout(timer);code===0?resolve(data):reject(new Error('clipboard_unavailable'));});p.stdin.end(input);
  });
}
async function clearHeld(){
  if(held!==undefined){
    if(await native('/usr/bin/pbpaste')===held){await native('/usr/bin/pbcopy');if(await native('/usr/bin/pbpaste')!=='')throw new Error('clipboard_unavailable');clipboardState='cleared';}
    else clipboardState='replaced_externally';
    held=undefined;
  }
  return clipboardState;
}
async function paste(selector,type,value,expected) {
  await guard(expected);
  await call('preview_click',{tabId:binding.tab,locator:selector,timeoutMs:3000});
  const focused=()=>evaluate(`(()=>{const es=[...document.querySelectorAll(${JSON.stringify(selector)})].filter(${visible});const e=es[0];return location.origin===${JSON.stringify(ORIGIN)}&&document.hasFocus()&&es.length===1&&document.activeElement===e&&e.type===${JSON.stringify(type)}&&!e.readOnly;})()`);
  if(!await focused())throw new Error('form_unavailable');
  await call('preview_press',{tabId:binding.tab,key:'A',modifiers:['Meta']});
  await call('preview_press',{tabId:binding.tab,key:'Backspace'});
  held=value; clipboardState='cleanup_unverified'; await native('/usr/bin/pbcopy',value);
  try {
    await guard(expected);if(!await focused()||await native('/usr/bin/pbpaste')!==value)throw new Error('clipboard_unavailable');
    await call('preview_press',{tabId:binding.tab,key:'V',modifiers:['Meta']});
    await guard(expected);if(!await focused())throw new Error('form_unavailable');
    const length=await evaluate('document.activeElement.value.length');if(length!==value.length)throw new Error('form_unavailable');
  }finally{await clearHeld();}
}
async function discover() {
  const expected=await guard();
  const state=await pageState();if(state!=='ready')return {state};
  if(!await formOkay())return {state:'form_unavailable'};
  const a=await account();
  selection={id:randomUUID(),expires:Date.now()+300000,expected,username:a.username,row:a.row};
  return {state:'account_selected',selectionId:selection.id,username:a.username,origin:ORIGIN};
}
async function probeInput() {
  const expected=await guard();const state=await pageState();if(state!=='ready')return {state};
  if(!await formOkay())return {state:'form_unavailable'};
  await mkdir(lock,{mode:0o700});lockHeld=true;lockState='held';
  try{
    await timed('benignInputMs',()=>paste('input#email','text','vault2-input-check@example.invalid',expected));
    if(!await evaluate("document.querySelector('input#email').value==='vault2-input-check@example.invalid'"))throw new Error('form_unavailable');
    await guard(expected);
    await call('preview_press',{tabId:binding.tab,key:'A',modifiers:['Meta']});
    await call('preview_press',{tabId:binding.tab,key:'Backspace'});
    if(!await evaluate("location.origin==='https://app.gohighlevel.com'&&document.activeElement===document.querySelector('input#email')&&document.activeElement.value===''"))throw new Error('form_unavailable');
    return {state:'benign_input_verified',credentialsRead:false};
  }finally{await clearHeld();await rmdir(lock);lockHeld=false;lockState='released';}
}
async function signIn(args) {
  const s=selection;selection=undefined;
  if(!s||args?.selectionId!==s.id||Date.now()>s.expires)throw new Error('selection_invalid');
  await guard(s.expected);if(await pageState()!=='ready')return {state:'verification_required'};
  if(!await formOkay())throw new Error('form_unavailable');
  await mkdir(lock,{mode:0o700});lockHeld=true;lockState='held';
  try {
    // Prove the native input path using harmless text before retrieving a password.
    await timed('benignInputMs',()=>paste('input#email','text','vault2-input-check@example.invalid',s.expected));
    if(!await evaluate("document.querySelector('input#email').value==='vault2-input-check@example.invalid'"))throw new Error('form_unavailable');
    await timed('privateFillMs',()=>paste('input#email','text',s.username,s.expected));
    if(await pageState()!=='ready'||!await formOkay())return {state:'verification_required'};
    let password=await reveal(s.row.passwordKey);
    try{if(!password||password.length>65536)throw new Error('credential_unavailable');await timed('privateFillMs',()=>paste('input#password','password',password,s.expected));}finally{password=undefined;}
    await guard(s.expected);if(await pageState()!=='ready'||!await formOkay())return {state:'verification_required'};
    await timed('submitMs',()=>call('preview_click',{tabId:binding.tab,locator:'button[type="submit"]:text-is("Sign in")',timeoutMs:3000}));
    return {state:'submitted',identityVerified:false,username:s.username,clipboard:clipboardState};
  }finally{await clearHeld();if(lockHeld){await rmdir(lock);lockHeld=false;lockState='released';}}
}
async function shutdown(){
  if(closing)return closing;
  selection=undefined;
  closing=cleanupResources({hasSession:!!token,clearClipboard:clearHeld,
    releaseLock:async()=>{if(!lockHeld)return lockState;await rmdir(lock);lockHeld=false;lockState='released';return lockState;},
    logout:()=>api('/v1/auth/logout',{}),
    sessionRejected:async()=>{const r=await fetch('http://127.0.0.1:14321/v1/auth/me',{headers:{Authorization:'Bearer '+token},redirect:'error',signal:AbortSignal.timeout(10000)});await r.body?.cancel();return r.status===401;},
  }).finally(()=>{token=undefined;});
  return closing;
}
const input=createInterface({input:process.stdin,terminal:false});
if(process.stdin.isTTY)process.stdin.setRawMode(true);
input.on('line',async line=>{
  let m;try{if(line.length>262144)return;m=JSON.parse(line);}catch{return;}
  if(m.type==='tool_response'){const p=pending.get(m.id);if(p){pending.delete(m.id);clearTimeout(p.timer);m.error?p.reject(new Error('host_operation_failed')):p.resolve(m.result);}return;}
  if(m.type!=='command'||busy)return;busy=true;
  try {
    if(m.action==='close'){const cleanup=await shutdown();output({type:'result',result:{state:'closed',cleanup,timings}});input.close();process.exit(0);}
    const start=performance.now();
    const result=m.action==='probe-input'?await probeInput():m.action==='discover'?await discover():m.action==='sign-in'?await signIn(m.args):{state:'denied',reasonCode:'invalid_request'};
    output({type:'result',result:{...result,timings:{...timings,commandMs:performance.now()-start}}});
  }catch(e){const reasons=new Set(['engine_rate_limited','engine_unavailable','credential_unavailable','origin_mismatch','host_control_unavailable','binding_changed','clipboard_unavailable','form_unavailable','selection_invalid','host_transport_unavailable']);output({type:'result',result:{state:'needs_attention',reasonCode:reasons.has(e.message)?e.message:'host_operation_failed',timings}});}
  finally{busy=false;}
});
input.on('close',()=>{shutdown().finally(()=>process.exit(0));});
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>{shutdown().finally(()=>process.exit(0));});
setTimeout(()=>{shutdown().finally(()=>process.exit(0));},600000).unref();
output({type:'session_ready',transport:'chat-tool-relay',origin:ORIGIN,expiresInSeconds:600});
