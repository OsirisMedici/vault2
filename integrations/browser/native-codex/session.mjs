// SPDX-License-Identifier: GPL-3.0-only
import {randomUUID} from 'node:crypto';
import {mkdir, rmdir, chmod} from 'node:fs/promises';
import {homedir, tmpdir} from 'node:os';
import {join} from 'node:path';
import {SavedAccount} from './vault.mjs';
import {IsolatedBrowser} from './browser.mjs';
import {ORIGIN, fail, reason} from './policy.mjs';

export class NativeSession {
  #id=randomUUID(); #selection; #identity; #attempted=false; #submitted=false; #lockHeld=false;
  #busy=false; #closed=false; #started=performance.now(); #timer; #vaultCleanup='not_created';
  #loginStarted; #loginEnd; #boundaries=[];
  constructor({browser=new IsolatedBrowser(),vault=new SavedAccount(),evidenceRoot=join(homedir(),'.local/share/vault2-native-evidence'),
    lockPath=join(tmpdir(),`osiris-agent-vault-browser-${process.getuid()}.lock`),ttlMs=600000}={}) {
    this.browser=browser;this.vault=vault;this.lockPath=lockPath;
    this.evidenceDir=join(evidenceRoot,this.#id);
    this.timings={openMs:0,lookupMs:0,privateFillMs:0,submissionMs:0,providerWaitMs:0,identityVerificationMs:0,cleanupMs:0};
    this.#timer=setTimeout(()=>{this.closeWhenIdle();},ttlMs);this.#timer.unref();
  }
  async #timed(key,fn) {
    const start=performance.now(),startedAt=new Date().toISOString();
    try{return await fn();}finally{
      const durationMs=performance.now()-start;this.timings[key]+=durationMs;
      this.#boundaries.push({phase:key,startedAt,endedAt:new Date().toISOString(),durationMs});
    }
  }
  async #release() {
    if(!this.#lockHeld)return 'not_acquired';
    try {await rmdir(this.lockPath);this.#lockHeld=false;return 'released';}catch{return 'release_unverified';}
  }
  async #credentialCleanup() {
    const cleanup=await this.#timed('cleanupMs',async()=>{
      const fields=await this.browser.clearOwnedFields().catch(()=> 'cleanup_unverified');
      this.#vaultCleanup=await this.vault.close().catch(()=> 'revocation_unverified');
      return {fields,clipboard:'not_used',session:this.#vaultCleanup,lock:await this.#release()};
    });
    this.lastCleanup=cleanup;
    return cleanup;
  }
  async #screenshot() {
    await mkdir(this.evidenceDir,{recursive:true,mode:0o700});await chmod(this.evidenceDir,0o700);
    const path=join(this.evidenceDir,`${randomUUID()}.png`);
    try{await this.browser.screenshot(path);return path;}catch{return undefined;}
  }
  async run(action,args={}) {
    if(this.#busy)return {state:'needs_attention',reasonCode:'operation_busy'};
    if(this.#closed&&action!=='close')return {state:'needs_attention',reasonCode:'session_invalid'};
    if(action!=='open'&&args.sessionId!==this.#id)return {state:'needs_attention',reasonCode:'session_invalid'};
    this.#busy=true;
    try {
      let result;
      try {
        if(action==='open'){
          if(this.opened)fail('session_invalid');this.opened=true;
          await this.#timed('openMs',()=>this.browser.open());
          const state=await this.browser.waitForPage();
          if(state==='login_form')await this.browser.arm();
          result={state,formReady:state==='login_form',sessionId:this.#id,origin:ORIGIN,isolatedProfile:true};
        } else if(action==='select'){
          if(this.#attempted)fail('already_attempted');
          if(this.#selection)fail('selection_invalid');
          await this.browser.arm();
          this.#loginStarted=performance.now();
          const identity=await this.#timed('lookupMs',()=>this.vault.select());
          await this.browser.guard();
          this.#identity=identity;
          this.#selection={id:randomUUID(),expires:Date.now()+300000};
          result={state:'account_selected',sessionId:this.#id,selectionId:this.#selection.id,...identity};
        } else if(action==='sign-in'){
          const selection=this.#selection;this.#selection=undefined;
          if(this.#attempted)fail('already_attempted');
          if(!selection||args.selectionId!==selection.id||Date.now()>selection.expires)fail('selection_invalid');
          // Consume before any I/O. Uncertain fill/submit can never be retried.
          this.#attempted=true;
          if(await this.browser.inspect()!=='login_form')fail('verification_required');
          await this.browser.guard();
          try {await mkdir(this.lockPath,{mode:0o700});this.#lockHeld=true;}catch{fail('lock_unavailable');}
          try {
            await this.vault.usePassword(password=>this.#timed('privateFillMs',()=>this.browser.fill(this.#identity.username,password)));
            await this.browser.guard();
            await this.#timed('submissionMs',()=>this.browser.submit(this.#identity.username));
            this.#submitted=true;
            // One observation, no resend or second submission. MFA stays owner-only.
            const observed=await this.#timed('providerWaitMs',()=>this.browser.waitForProvider());
            result={state:observed==='verification_required'?'verification_required':observed==='credentials_rejected'?'credentials_rejected':'submitted',
              observedState:observed,identityVerified:false,sessionId:this.#id};
          } finally {
            const cleanup=await this.#credentialCleanup();
            if(result)result.cleanup=cleanup;
            this.lastCleanup=cleanup;
          }
        } else if(action==='inspect'){
          result={state:await this.browser.inspect(),sessionId:this.#id,identityVerified:false};
        } else if(action==='verify'){
          if(!this.#submitted||!this.#identity)fail('identity_unverified');
          if(!this.lastCleanup||Object.values(this.lastCleanup).some(v=>/unverified/.test(v)))fail('cleanup_unverified');
          const matched=await this.#timed('identityVerificationMs',()=>this.browser.verify(this.#identity.username));
          if(matched)this.#loginEnd=performance.now();
          result={state:matched?'signed_in':'identity_unverified',identityVerified:matched,verifiedAfterReload:matched,
            sessionId:this.#id,...(matched?{username:this.#identity.username,accountId:this.#identity.accountId}:{})};
        } else if(action==='close'){
          this.#closed=true;clearTimeout(this.#timer);this.#selection=undefined;
          const cleanup=await this.#credentialCleanup();
          Object.assign(cleanup,await this.#timed('cleanupMs',()=>this.browser.close()));
          result={state:'closed',cleanup};
        } else fail('operation_failed');
      } catch(e) {
        // An error is never permission to retry a provider submission.
        const cleanup=await this.#credentialCleanup();
        this.#selection=undefined;
        result={state:'needs_attention',reasonCode:reason(e),sessionId:this.#id,identityVerified:false,attemptConsumed:this.#attempted,cleanup};
        if(action==='open') {this.#closed=true;clearTimeout(this.#timer);Object.assign(cleanup,await this.browser.close());}
      }
      if(action!=='close'&&!this.#closed)try{result.screenshotPath=await this.#screenshot();}catch{}
      if(result.cleanup&&Object.values(result.cleanup).some(v=>/unverified/.test(v)))result.cleanupVerified=false;
      result.timings={...this.timings,...this.vault.timings,sessionElapsedMs:performance.now()-this.#started,
        loginEndToEndMs:this.#loginEnd===undefined?null:this.#loginEnd-this.#loginStarted};
      result.boundaries=[...this.#boundaries];
      return result;
    } finally {this.#busy=false;}
  }
  async closeWhenIdle() {
    // Timeout/stdio disconnect cannot race a fill or revoke its session mid-call.
    while(this.#busy)await new Promise(r=>setTimeout(r,25));
    return this.run('close',{sessionId:this.#id});
  }
}
