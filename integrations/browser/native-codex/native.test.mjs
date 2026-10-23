// SPDX-License-Identifier: GPL-3.0-only
import {test} from 'bun:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,access,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {SavedAccount} from './vault.mjs';
import {NativeSession} from './session.mjs';
import {validateSelection,reason,ORIGIN} from './policy.mjs';

const selected={version:1,origin:ORIGIN,accountId:'11111111-1111-4111-8111-111111111111',username:'fixture@example.invalid'};
const identity={accountId:selected.accountId,username:selected.username,origin:ORIGIN};
function fixture({config=selected,wrongUsername=false,wrongMetadata=false,logoutFails=false,revocationStatus=401}={}) {
  let revoked=false;const calls=[];
  const values={BW_META:JSON.stringify({id:wrongMetadata?'other':selected.accountId,login:{uris:[{uri:ORIGIN}]}}),
    BW_USER:wrongUsername?'other@example.invalid':selected.username,BW_PASS:'synthetic-password-never-returned'};
  const vault=new SavedAccount({root:'/synthetic',read:async path=>JSON.stringify(path.endsWith('ghl-selection.json')?config:
    path.endsWith('demo-owner.json')?{email:'owner@example.invalid',password:'synthetic-owner-password'}:
    {vault:'bitwarden-import',records:[{sourceID:selected.accountId,metadataKey:'BW_META',usernameKey:'BW_USER',passwordKey:'BW_PASS'}]}),
    request:async(url,options)=>{
      const u=new URL(url);calls.push({path:u.pathname,key:u.searchParams.get('key')});
      if(u.pathname==='/v1/auth/login')return Response.json({token:'synthetic-session-token'});
      if(u.pathname==='/v1/auth/logout'){if(logoutFails)throw new Error('private upstream error');revoked=true;return Response.json({});}
      if(u.pathname==='/v1/auth/me')return revoked?new Response('',{status:revocationStatus}):Response.json({role:'owner',email:'owner@example.invalid'});
      const key=u.searchParams.get('key');assert.ok(key in values);assert.equal(u.searchParams.get('vault'),'bitwarden-import');
      return Response.json({keys:[key],credentials:[{key,value:values[key]}]});
    }});
  return {vault,calls};
}
test('native: configured account, metadata origin and exact username are required before password read',async()=>{
  for(const options of [{wrongUsername:true},{wrongMetadata:true},{config:{...selected,origin:ORIGIN+'.evil.invalid'}}]){
    const {vault,calls}=fixture(options);
    await assert.rejects(vault.select());
    assert.ok(!calls.some(c=>c.key==='BW_PASS'));
    await vault.close();
  }
  assert.throws(()=>validateSelection({...selected,accountId:'arbitrary'}));
});
test('native: single-key password stays inside callback; logout requires rejected follow-up auth',async()=>{
  const {vault,calls}=fixture();assert.deepEqual(await vault.select(),identity);
  const returned=await vault.usePassword(async value=>{assert.ok(value.length>0);return value;});
  assert.equal(returned,undefined);
  assert.ok(!JSON.stringify(vault).includes('synthetic-password-never-returned'));
  assert.deepEqual(calls.filter(c=>c.key).map(c=>c.key),['BW_META','BW_USER','BW_PASS']);
  assert.equal(await vault.close(),'revoked');
  const failure=fixture({revocationStatus:200});await failure.vault.select();assert.equal(await failure.vault.close(),'revocation_unverified');
  const logout=fixture({logoutFails:true});await logout.vault.select();assert.equal(await logout.vault.close(),'revocation_unverified');
});
test('native: changed owner selection invalidates the password action',async()=>{
  const mutable={...selected};const {vault,calls}=fixture({config:mutable});await vault.select();mutable.username='changed@example.invalid';
  await assert.rejects(vault.usePassword(()=>assert.fail('must not fill')));
  assert.ok(!calls.some(c=>c.key==='BW_PASS'));await vault.close();
});
function browserStub(overrides={}) {
  return {open:async()=>{},waitForPage:async()=> 'login_form',inspect:async()=> 'login_form',arm:async()=>{},guard:async()=>{},
    fill:async()=>{},submit:async()=>{},waitForProvider:async()=> 'verification_required',clearOwnedFields:async()=> 'cleared',
    screenshot:async()=>{throw new Error('no fixture image');},verify:async()=>true,close:async()=>({browser:'closed',profile:'removed'}),...overrides};
}
async function sessionFixture(overrides={}){
  const root=await mkdtemp(join(tmpdir(),'vault2-native-tests-'));let fills=0,submits=0,closes=0;
  const session=new NativeSession({browser:browserStub({fill:async()=>{fills++;},submit:async()=>{submits++;},...overrides}),
    vault:{select:async()=>identity,usePassword:async action=>action('synthetic'),close:async()=>{closes++;return 'revoked';}},
    evidenceRoot:root,lockPath:join(root,'lock')});
  const opened=await session.run('open');
  const close=async()=>{await session.closeWhenIdle();await rm(root,{recursive:true,force:true});};
  return {session,id:opened.sessionId,root,close,counts:()=>({fills,submits,closes})};
}
test('native: session ownership, one-use selection, one submission and cleanup',async()=>{
  const f=await sessionFixture();try{
    assert.equal((await f.session.run('select',{sessionId:'wrong'})).reasonCode,'session_invalid');
    const s=await f.session.run('select',{sessionId:f.id});
    const submitted=await f.session.run('sign-in',{sessionId:f.id,selectionId:s.selectionId});
    assert.equal(submitted.state,'verification_required');assert.equal(submitted.identityVerified,false);
    assert.deepEqual(submitted.cleanup,{fields:'cleared',clipboard:'not_used',session:'revoked',lock:'released'});
    assert.equal((await f.session.run('sign-in',{sessionId:f.id,selectionId:s.selectionId})).reasonCode,'already_attempted');
    assert.equal(f.counts().submits,1);assert.equal(f.counts().fills,1);
    await assert.rejects(access(join(f.root,'lock')));
    assert.equal((await f.session.run('verify',{sessionId:f.id})).verifiedAfterReload,true);
  }finally{await f.close();}
});
test('native: uncertain submission is redacted, never retried and cannot verify success',async()=>{
  let calls=0;const f=await sessionFixture({submit:async()=>{calls++;throw new Error('synthetic-password-never-returned');}});
  try{
    const s=await f.session.run('select',{sessionId:f.id});
    const result=await f.session.run('sign-in',{sessionId:f.id,selectionId:s.selectionId});
    assert.equal(result.attemptConsumed,true);assert.ok(!JSON.stringify(result).includes('synthetic-password-never-returned'));
    assert.equal((await f.session.run('sign-in',{sessionId:f.id,selectionId:s.selectionId})).reasonCode,'already_attempted');
    assert.equal((await f.session.run('verify',{sessionId:f.id})).reasonCode,'identity_unverified');
    assert.equal(calls,1);
  }finally{await f.close();}
});
test('native: concurrent commands fail closed; close waits for an active operation',async()=>{
  let unblock;const waiting=new Promise(r=>{unblock=r;});const f=await sessionFixture({fill:()=>waiting});
  try{
    const s=await f.session.run('select',{sessionId:f.id});
    const pending=f.session.run('sign-in',{sessionId:f.id,selectionId:s.selectionId});
    await new Promise(r=>setTimeout(r,20));
    assert.equal((await f.session.run('inspect',{sessionId:f.id})).reasonCode,'operation_busy');
    const close=f.session.closeWhenIdle();unblock();await pending;const closed=await close;
    assert.equal(closed.state,'closed');assert.equal(closed.cleanup.profile,'removed');
  }finally{unblock();await f.close();}
});
test('native: exception diagnostics cannot become secret-bearing tool output',()=>{
  assert.equal(reason(new Error('private secret')),'operation_failed');
});
test('native: an existing browser lock is neither taken over nor removed',async()=>{
  const f=await sessionFixture();try{
    await mkdir(join(f.root,'lock'),{mode:0o700});
    const s=await f.session.run('select',{sessionId:f.id});
    const r=await f.session.run('sign-in',{sessionId:f.id,selectionId:s.selectionId});
    assert.equal(r.reasonCode,'lock_unavailable');assert.equal(f.counts().fills,0);assert.equal(f.counts().submits,0);
    await f.session.closeWhenIdle();await access(join(f.root,'lock'));
  }finally{await f.close();}
});
test('native: cleanup failure prevents a successful identity result',async()=>{
  const f=await sessionFixture({clearOwnedFields:async()=> 'cleanup_unverified'});try{
    const s=await f.session.run('select',{sessionId:f.id});
    const r=await f.session.run('sign-in',{sessionId:f.id,selectionId:s.selectionId});
    assert.equal(r.cleanupVerified,false);
    const v=await f.session.run('verify',{sessionId:f.id});
    assert.equal(v.reasonCode,'cleanup_unverified');assert.equal(v.identityVerified,false);
  }finally{await f.close();}
});
