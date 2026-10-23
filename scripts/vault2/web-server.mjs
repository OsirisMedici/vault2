#!/usr/bin/env bun
// SPDX-License-Identifier: GPL-3.0-only
// Serve an immutable built frontend; upstream remains the sole API/auth engine.
import { realpath, stat } from 'node:fs/promises';
import { resolve, sep, extname } from 'node:path';
const root = await realpath(process.argv[2]);
if (!(await stat(resolve(root, 'index.html'))).isFile()) throw new Error('frontend_missing');
const security = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'",
  'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
};
const hosts = new Set(['127.0.0.1:14421', 'localhost:14421', 'raven.tailf4bdfc.ts.net:9444']);
const hops = ['connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade'];
const server = Bun.serve({hostname:'127.0.0.1',port:14421,maxRequestBodySize:1024*1024,idleTimeout:30,
  async fetch(request) {
    if (!hosts.has(request.headers.get('host'))) return new Response('Unrecognized host',{status:403,headers:security});
    const url = new URL(request.url);
    const api = url.pathname.startsWith('/v1/') || ['/health','/discover','/invite'].some(p=>url.pathname===p||url.pathname.startsWith(p+'/'));
    if (api) {
      const headers = new Headers(request.headers);
      for (const h of hops) headers.delete(h);
      try {
        const upstream = await fetch(new Request('http://127.0.0.1:14321'+url.pathname+url.search,{
          method:request.method,headers,body:['GET','HEAD'].includes(request.method)?undefined:request.body,
          redirect:'manual',signal:AbortSignal.timeout(30000),
        }));
        const responseHeaders = new Headers(upstream.headers);
        for (const h of hops) responseHeaders.delete(h);
        for (const [k,v] of Object.entries(security)) responseHeaders.set(k,v);
        return new Response(upstream.body,{status:upstream.status,headers:responseHeaders});
      } catch { return new Response('Vault engine unavailable',{status:503,headers:{...security,'Cache-Control':'no-store'}}); }
    }
    if (!['GET','HEAD'].includes(request.method)) return new Response('Method not allowed',{status:405,headers:security});
    try {
      const path = decodeURIComponent(url.pathname);
      if (path.includes('\0') || path.includes('\\') || path.split('/').some(p=>p.startsWith('.'))) throw 0;
      let candidate = resolve(root,'.'+path);
      if (candidate!==root&&!candidate.startsWith(root+sep)) throw 0;
      let file = Bun.file(candidate);
      if (!await file.exists() || !(await stat(candidate)).isFile()) {
        if (extname(path)) return new Response('Not found',{status:404,headers:security});
        candidate=resolve(root,'index.html');file=Bun.file(candidate);
      }
      const actual=await realpath(candidate);
      if (!actual.startsWith(root+sep)) throw 0;
      return new Response(request.method==='HEAD'?null:file,{headers:{...security,'Content-Type':file.type,
        'Cache-Control':candidate.endsWith('index.html')?'no-store':'public, max-age=31536000, immutable'}});
    } catch { return new Response('Not found',{status:404,headers:security}); }
  },
});
console.log('Vault 2 built frontend listening on 127.0.0.1:14421');
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>{server.stop(true);process.exit(0);});
