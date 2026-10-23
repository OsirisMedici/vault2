// SPDX-License-Identifier: GPL-3.0-only
import {test} from 'bun:test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {IsolatedBrowser} from './browser.mjs';
import {ORIGIN} from './policy.mjs';

// Fully intercepted synthetic app. No provider requests or real Vault reads.
const username='fixture@example.invalid';
const fixture=`<!doctype html><html><head><meta charset="utf-8"><style>body{font:20px system-ui;margin:60px;background:#f7f6ef}form{display:grid;gap:20px;width:400px;padding:30px;background:white}input,button{font:inherit;padding:12px}aside{color:#8b2600} [role=menu]{padding:20px;background:white}</style></head><body><aside>SYNTHETIC FIXTURE - NOT GHL LOGIN ACCEPTANCE</aside><main></main><script>
const main=document.querySelector('main');
function app(){if(localStorage.getItem('synthetic-auth')){
main.innerHTML='<h1>Fixture dashboard</h1><button aria-label="Open Profile Menu">Profile</button><div role="menu" hidden><span>${username}</span></div>';
document.querySelector('button').onclick=()=>document.querySelector('[role=menu]').hidden=false;
}else{main.innerHTML='<h1>Fixture sign in</h1><form><label>Email<input id="email" type="text"></label><label>Password<input id="password" type="password"></label><button type="submit">Sign in</button></form>';
document.querySelector('form').onsubmit=e=>{e.preventDefault();localStorage.setItem('synthetic-auth','1');app();};}}
app();</script></body></html>`;
async function makeBrowser() {
  let page;
  const browser=new IsolatedBrowser({headless:true,preparePage:async p=>{
    page=p;await p.route('**/*',route=>route.request().url().startsWith(ORIGIN+'/')?
      route.fulfill({status:200,contentType:'text/html',body:fixture}):
      route.fulfill({status:200,contentType:'text/html',body:'Synthetic foreign origin'}));
  }});
  await browser.open();return {browser,get page(){return page;}};
}
test('native browser: private fill, exact identity after reload and independent profiles',async()=>{
  const a=await makeBrowser();let b;
  try{
    assert.equal(await a.browser.waitForPage(),'login_form');await a.browser.arm();
    if(process.env.VAULT2_TEST_EVIDENCE_DIR){await mkdir(process.env.VAULT2_TEST_EVIDENCE_DIR,{recursive:true});await a.browser.screenshot(join(process.env.VAULT2_TEST_EVIDENCE_DIR,'fixture-before.png'));}
    await a.browser.fill(username,'synthetic-fixture-only');await a.browser.submit(username);
    assert.equal(await a.browser.waitForProvider(),'identity_unverified');
    assert.equal(await a.browser.verify('different@example.invalid'),false);
    assert.equal(await a.browser.verify(username),true);
    if(process.env.VAULT2_TEST_EVIDENCE_DIR)await a.browser.screenshot(join(process.env.VAULT2_TEST_EVIDENCE_DIR,'fixture-result.png'));
    b=await makeBrowser();assert.equal(await b.browser.waitForPage(),'login_form');
    const closed=await b.browser.close();assert.deepEqual(closed,{browser:'closed',profile:'removed'});b=undefined;
    assert.deepEqual(await a.browser.close(),{browser:'closed',profile:'removed'});
  }finally{await b?.browser.close();await a.browser.close();}
},30000);
test('native browser: changed URL, replaced form, changed input type and human input invalidate binding',async()=>{
  const f=await makeBrowser();try{
    await f.browser.arm();await f.page.evaluate(()=>document.querySelector('form').outerHTML=document.querySelector('form').outerHTML);
    await assert.rejects(f.browser.guard());
    await f.browser.arm();await f.page.goto(ORIGIN+'/changed');await assert.rejects(f.browser.guard());
    await f.browser.arm();await f.page.locator('#email').fill('human@example.invalid');await assert.rejects(f.browser.guard());
    await f.page.reload();await f.browser.arm();
    await f.page.evaluate(()=>document.querySelector('#email').addEventListener('input',()=>document.querySelector('#password').type='text'));
    await assert.rejects(f.browser.fill(username,'synthetic-fixture-only'));
    assert.equal(await f.page.locator('#password').evaluate(e=>e.value.length===0),true);
    await f.page.goto('https://example.invalid/');await assert.rejects(f.browser.inspect());
  }finally{await f.browser.close();}
},30000);
