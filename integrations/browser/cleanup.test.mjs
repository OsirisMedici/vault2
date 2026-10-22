// SPDX-License-Identifier: GPL-3.0-only
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {cleanupResources} from './cleanup.mjs';

const base = {hasSession:true, logout:async()=>{}, sessionRejected:async()=>true,
  clearClipboard:async()=>'cleared',releaseLock:async()=>'released'};
test('logout requires a rejected follow-up session check',async()=>{
  assert.equal((await cleanupResources(base)).session,'revoked');
  assert.equal((await cleanupResources({...base,sessionRejected:async()=>false})).session,'revocation_unverified');
});
test('logout failure remains unverified and still runs independent cleanup',async()=>{
  const r=await cleanupResources({...base,logout:async()=>{throw new Error('private failure');}});
  assert.deepEqual(r,{session:'revocation_unverified',clipboard:'cleared',lock:'released'});
  assert.ok(!JSON.stringify(r).includes('private failure'));
});
test('clipboard and lock failures remain visible while session is revoked',async()=>{
  const fail=async()=>{throw new Error('unavailable');};
  assert.deepEqual(await cleanupResources({...base,clearClipboard:fail,releaseLock:fail}),
    {session:'revoked',clipboard:'cleanup_unverified',lock:'release_unverified'});
});
test('no session causes no auth API calls',async()=>{
  let calls=0;
  const r=await cleanupResources({...base,hasSession:false,logout:async()=>{calls++;},sessionRejected:async()=>{calls++;return true;},clearClipboard:async()=>'not_used',releaseLock:async()=>'not_acquired'});
  assert.equal(calls,0);assert.equal(r.session,'not_created');
});
