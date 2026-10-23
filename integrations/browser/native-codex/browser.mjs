// SPDX-License-Identifier: GPL-3.0-only
import {mkdtemp, chmod, rm, access} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {ORIGIN, LOGIN_URL, fail} from './policy.mjs';

// Disable library debug output before loading the browser driver, not only in
// Chrome's child environment. Diagnostics must not print private call data.
for(const key of ['DEBUG','PWDEBUG','DEBUG_FILE'])delete process.env[key];
const {chromium}=await import('playwright-core');

// This adapter launches its own Chrome, never attaches to IAB/T3/personal CDP.
// No arbitrary URL, selector, evaluation, storage export or secret-input tool.
export class IsolatedBrowser {
  #context; #page; #profile; #witness; #generation=0; #armedGeneration; #hazard=false;
  constructor({headless=false, preparePage}={}) { this.headless=headless; this.preparePage=preparePage; }
  async open() {
    this.#profile=await mkdtemp(join(tmpdir(),'vault2-native-'));
    await chmod(this.#profile,0o700);
    try {
      const env={...process.env};
      for(const key of ['DEBUG','PWDEBUG','DEBUG_FILE','NODE_OPTIONS']) delete env[key];
      this.#context=await chromium.launchPersistentContext(this.#profile,{
        channel:'chrome',headless:this.headless,env,acceptDownloads:false,chromiumSandbox:true,
        viewport:{width:1280,height:900},serviceWorkers:'block',
        // No storageState, user profile, extension, trace, video or HAR input.
      });
      this.#page=this.#context.pages()[0]??await this.#context.newPage();
      this.#page.setDefaultTimeout(3000);
      this.#context.on('page',()=>{this.#hazard=true;this.#generation++;});
      this.#page.on('framenavigated',f=>{if(f===this.#page.mainFrame())this.#generation++;});
      this.#page.on('dialog',async d=>{this.#hazard=true;this.#generation++;await d.dismiss().catch(()=>{});});
      this.#page.on('filechooser',()=>{this.#hazard=true;this.#generation++;});
      if(this.preparePage) await this.preparePage(this.#page); // Only injected by source tests.
      await this.#page.goto(LOGIN_URL,{waitUntil:'domcontentloaded',timeout:30000});
      return await this.inspect();
    } catch { await this.close(); fail('browser_unavailable'); }
  }
  async #owned() {
    if(!this.#context||!this.#page||this.#page.isClosed()||this.#hazard||
       this.#context.pages().length!==1||this.#page.context()!==this.#context) fail('binding_changed');
    try {if(new URL(this.#page.url()).origin!==ORIGIN)fail('origin_mismatch');}
    catch(e) {if(e.code)throw e;fail('origin_mismatch');}
  }
  async inspect() {
    await this.#owned();
    // Only enum values leave the DOM, never page text, input values or tokens.
    return this.#page.evaluate(()=>{
      if(location.origin!=='https://app.gohighlevel.com') return 'origin_mismatch';
      const visible=e=>e.getClientRects().length>0&&getComputedStyle(e).visibility!=='hidden';
      const t=document.body?.innerText??'';
      if(/incorrect (email|password)|invalid (email|password|credentials)|wrong password|authentication failed|unable to log|login error|something went wrong/i.test(t)) return 'credentials_rejected';
      if(/verification code|verify your identity|two.factor|security code|verify your device|check your email|captcha|account recovery/i.test(t)||
        [...document.querySelectorAll('input[autocomplete="one-time-code"],iframe[src*="bframe"],iframe[title*="challenge"]')].some(visible)) return 'verification_required';
      if(document.readyState==='loading'||/Initializing\.\.\.|Loading fresh data/i.test(t)) return 'page_loading';
      if([...document.querySelectorAll('input#email,input#password')].some(visible)) return 'login_form';
      return 'identity_unverified';
    });
  }
  async waitForPage() {
    const end=Date.now()+20000;
    do {const state=await this.inspect();if(state!=='page_loading')return state;await new Promise(r=>setTimeout(r,200));}while(Date.now()<end);
    return 'page_loading';
  }
  async waitForProvider() {
    const end=Date.now()+20000;
    do {const state=await this.inspect();if(!['login_form','page_loading'].includes(state))return state;await new Promise(r=>setTimeout(r,200));}while(Date.now()<end);
    return this.inspect();
  }
  async arm() {
    await this.#owned();
    if(await this.inspect()!=='login_form') fail('form_unavailable');
    await this.#witness?.evaluate(w=>w?.dispose()).catch(()=>{});
    await this.#witness?.dispose().catch(()=>{});
    this.#witness=await this.#page.evaluateHandle(()=>{
      const vis=e=>e.getClientRects().length>0&&!e.disabled&&getComputedStyle(e).visibility!=='hidden';
      const us=[...document.querySelectorAll('input#email')].filter(vis),ps=[...document.querySelectorAll('input#password')].filter(vis);
      const bs=[...document.querySelectorAll('button[type="submit"]')].filter(vis).filter(e=>e.textContent.trim()==='Sign in');
      if(us.length!==1||ps.length!==1||bs.length!==1||us[0].type!=='text'||ps[0].type!=='password'||
         !ps[0].form||us[0].form!==ps[0].form||bs[0].form!==ps[0].form||us[0].readOnly||ps[0].readOnly||us[0].value||ps[0].value)return null;
      const w={doc:document,url:location.href,form:ps[0].form,email:us[0],password:ps[0],button:bs[0],human:false,filled:false,submitted:false};
      const human=e=>{if(e.isTrusted)w.human=true;};
      for(const type of ['pointerdown','keydown','input'])document.addEventListener(type,human,true);
      w.dispose=()=>{for(const type of ['pointerdown','keydown','input'])document.removeEventListener(type,human,true);};
      return w;
    });
    if(!await this.#witness.evaluate(w=>!!w)) fail('form_unavailable');
    this.#armedGeneration=this.#generation;
    await this.guard();
  }
  async guard() {
    await this.#owned();
    if(!this.#witness||this.#generation!==this.#armedGeneration)fail('binding_changed');
    const ok=await this.#witness.evaluate(w=>{
      const vis=e=>e.isConnected&&!e.disabled&&!e.readOnly&&e.getClientRects().length>0&&getComputedStyle(e).visibility!=='hidden';
      return w&&location.origin==='https://app.gohighlevel.com'&&location.href===w.url&&document===w.doc&&!w.human&&
        w.form.isConnected&&[w.email,w.password,w.button].every(vis)&&w.email.form===w.form&&w.password.form===w.form&&w.button.form===w.form&&
        w.email.type==='text'&&w.password.type==='password'&&w.button.type==='submit'&&w.button.textContent.trim()==='Sign in'&&
        [...document.querySelectorAll('input#email')].filter(vis).length===1&&document.querySelector('input#email')===w.email&&
        [...document.querySelectorAll('input#password')].filter(vis).length===1&&document.querySelector('input#password')===w.password&&
        [...w.form.querySelectorAll('button[type="submit"]')].filter(vis).filter(e=>e.textContent.trim()==='Sign in').length===1;
    }).catch(()=>false);
    if(!ok)fail('binding_changed');
  }
  async fill(username,password) {
    await this.guard();
    // Entire transaction is inside the private process and bound document. No
    // clipboard, model relay, credential-bearing locator or arbitrary script.
    const ok=await this.#witness.evaluate((w,{username,password})=>{
      const vis=e=>e.isConnected&&!e.disabled&&!e.readOnly&&e.getClientRects().length>0&&getComputedStyle(e).visibility!=='hidden';
      const good=()=>location.origin==='https://app.gohighlevel.com'&&document===w.doc&&location.href===w.url&&!w.human&&
        w.form.isConnected&&[w.email,w.password,w.button].every(vis)&&w.email.type==='text'&&w.password.type==='password'&&
        w.email.form===w.form&&w.password.form===w.form&&w.button.form===w.form&&
        document.querySelector('input#email')===w.email&&document.querySelector('input#password')===w.password&&
        [...document.querySelectorAll('input#email')].filter(vis).length===1&&[...document.querySelectorAll('input#password')].filter(vis).length===1;
      if(!good()||w.filled||w.email.value||w.password.value)return false;
      const put=(e,v)=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,v);e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));};
      put(w.email,username);if(!good()||w.email.value!==username)return false;
      put(w.password,password);w.filled=true;
      return good()&&w.email.value===username&&w.password.value.length===password.length;
    },{username,password});
    if(!ok)fail('binding_changed');
    await this.guard();
  }
  async submit(username) {
    await this.guard();
    // Recheck exact username and the same controls in the same JS turn as click.
    const ok=await this.#witness.evaluate((w,username)=>{
      if(w.submitted||!w.filled||w.human||location.origin!=='https://app.gohighlevel.com'||location.href!==w.url||document!==w.doc||
         !w.form.isConnected||!w.button.isConnected||w.email.value!==username||!w.password.value||
         w.button.form!==w.form||document.querySelector('input#email')!==w.email||document.querySelector('input#password')!==w.password)return false;
      w.submitted=true;w.button.click();return true;
    },username);
    if(!ok)fail('binding_changed');
  }
  async clearOwnedFields() {
    if(!this.#witness)return 'not_filled';
    try {
      const cleared=await this.#witness.evaluate(w=>{
        if(!w)return true;
        if(document!==w.doc)return true;
        // Preserve human edits, including owner MFA input.
        if(w.human)return !w.password.isConnected||w.password.value==='';
        if(w.filled)for(const e of [w.email,w.password])if(e.isConnected)e.value='';
        w.dispose();return !w.password.isConnected||w.password.value==='';
      });
      return cleared?'cleared':'cleanup_unverified';
    } catch {return this.#generation!==this.#armedGeneration?'document_discarded':'cleanup_unverified';}
  }
  async #visibleIdentity(username) {
    await this.#owned();
    if(await this.inspect()!=='identity_unverified')return false;
    const profile=this.#page.getByRole('button',{name:'Open Profile Menu',exact:true});
    if(await profile.count()!==1)return false;
    const menu=this.#page.getByRole('menu');
    if(await menu.count()===0||!await menu.first().isVisible())await profile.click();
    const identity=menu.getByText(username,{exact:true});
    return await identity.count()===1&&await identity.isVisible();
  }
  async verify(username) {
    if(!await this.#visibleIdentity(username))return false;
    await this.#page.reload({waitUntil:'domcontentloaded',timeout:30000});
    await this.waitForPage();
    return this.#visibleIdentity(username);
  }
  async screenshot(path) {
    await this.#owned();
    // All editable fields are masked, including password, OTP and recovery.
    await this.#page.screenshot({path,mask:[this.#page.locator('input,textarea,[contenteditable="true"]')],animations:'disabled'});
    await chmod(path,0o600);
  }
  async close() {
    const receipt={browser:'not_created',profile:'not_created'};
    if(this.#context){try{await this.#context.close();receipt.browser='closed';}catch{receipt.browser='cleanup_unverified';}}
    if(this.#profile){
      // Never remove the profile of a browser whose termination is unverified.
      if(!this.#context||receipt.browser==='closed') {
        try {await rm(this.#profile,{recursive:true,force:true,maxRetries:3,retryDelay:100});
          try{await access(this.#profile);receipt.profile='cleanup_unverified';}catch{receipt.profile='removed';}
        }catch{receipt.profile='cleanup_unverified';}
      }else receipt.profile='cleanup_unverified';
    }
    return receipt;
  }
}
