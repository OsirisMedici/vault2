// SPDX-License-Identifier: GPL-3.0-only
import {homedir} from 'node:os';
import {join} from 'node:path';
import {readPrivateFile} from '../private-file.mjs';
import {ORIGIN, validateSelection, fail} from './policy.mjs';

// Same existing owner-assisted custody as the T3 helper. No proxy elevation,
// agent token, configuration write, broad credential listing or new grant.
export class SavedAccount {
  #token; #row; #selected; #sessionState='not_created';
  constructor({read=readPrivateFile, request=fetch, root=join(homedir(),'.local/share/agent-vault-upstream-raven')}={}) {
    this.read=read; this.request=request; this.root=root;
    this.timings={ownerSessionMs:0, credentialLookupMs:0};
  }
  async #api(path, body) {
    let r;
    try {
      r=await this.request('http://127.0.0.1:14321'+path, {
        method:body?'POST':'GET', redirect:'error', signal:AbortSignal.timeout(10000),
        headers:{...(body?{'Content-Type':'application/json'}:{}),...(this.#token?{Authorization:'Bearer '+this.#token}:{})},
        body:body?JSON.stringify(body):undefined,
      });
      if(!r.ok) fail(r.status===429?'engine_rate_limited':'engine_unavailable');
      const raw=await r.text(); if(raw.length>262144) fail('engine_unavailable');
      return JSON.parse(raw);
    } catch(e) { if(e?.code==='engine_rate_limited') throw e; fail('engine_unavailable'); }
  }
  async #reveal(key) {
    if(typeof key!=='string'||!/^BW_[A-Z0-9_]{1,200}$/.test(key)) fail('credential_unavailable');
    const start=performance.now();
    try {
      const r=await this.#api('/v1/credentials?'+new URLSearchParams({vault:'bitwarden-import',reveal:'true',key}));
      if(r.keys?.length!==1 || r.keys[0]!==key || r.credentials?.length!==1 ||
         r.credentials[0].key!==key || typeof r.credentials[0].value!=='string') fail('credential_unavailable');
      return r.credentials[0].value;
    } finally { this.timings.credentialLookupMs+=performance.now()-start; }
  }
  async select() {
    let c, manifest;
    try { c=validateSelection(JSON.parse(await this.read(join(this.root,'ghl-selection.json')))); }
    catch { fail('selection_not_configured'); }
    const start=performance.now();
    try {
      const owner=JSON.parse(await this.read(join(this.root,'demo-owner.json')));
      const auth=await this.#api('/v1/auth/login',{email:owner.email,password:owner.password,device_label:'Vault2 native Codex owner-assisted browser'});
      if(typeof auth.token!=='string'||!auth.token) fail('engine_unavailable');
      this.#token=auth.token;
      this.#sessionState='created';
      const me=await this.#api('/v1/auth/me');
      if(me.email!==owner.email||me.role!=='owner') fail('engine_unavailable');
    } finally { this.timings.ownerSessionMs+=performance.now()-start; }
    try { manifest=JSON.parse(await this.read(join(this.root,'bitwarden-import-manifest.json'),200000)); }
    catch { fail('credential_unavailable'); }
    if(manifest.vault!=='bitwarden-import'||!Array.isArray(manifest.records)) fail('credential_unavailable');
    const rows=manifest.records.filter(r=>r.sourceID===c.accountId);
    if(rows.length!==1||!rows[0].usernameKey||!rows[0].passwordKey) fail('credential_unavailable');
    let metadata;
    try { metadata=JSON.parse(await this.#reveal(rows[0].metadataKey)); }
    catch { fail('credential_unavailable'); }
    if(metadata.id!==c.accountId || !Array.isArray(metadata.login?.uris) ||
       !metadata.login.uris.some(u=>{try{return new URL(u.uri).origin===ORIGIN;}catch{return false;}})) fail('origin_mismatch');
    if(await this.#reveal(rows[0].usernameKey)!==c.username) fail('selection_invalid');
    this.#row=rows[0]; this.#selected=c;
    return c;
  }
  async usePassword(action) {
    if(!this.#selected||!this.#row) fail('selection_invalid');
    // Revalidate private selection immediately before reading the password.
    let current;
    try {current=validateSelection(JSON.parse(await this.read(join(this.root,'ghl-selection.json'))));}
    catch {fail('selection_invalid');}
    if(current.accountId!==this.#selected.accountId||current.username!==this.#selected.username) fail('selection_invalid');
    let password=await this.#reveal(this.#row.passwordKey);
    try {
      if(!password||password.length>65536) fail('credential_unavailable');
      // The callback lives inside this MCP process, never in a model tool call.
      await action(password);
    } finally { password=undefined; }
  }
  async close() {
    this.#row=undefined; this.#selected=undefined;
    if(!this.#token) return this.#sessionState;
    try {
      await this.#api('/v1/auth/logout',{});
      const r=await this.request('http://127.0.0.1:14321/v1/auth/me',{
        redirect:'error',signal:AbortSignal.timeout(10000),headers:{Authorization:'Bearer '+this.#token}});
      await r.body?.cancel();
      if(r.status!==401) return 'revocation_unverified';
      this.#token=undefined;this.#sessionState='revoked';return 'revoked';
    } catch { return 'revocation_unverified'; }
  }
}
