#!/usr/bin/env bun
// SPDX-License-Identifier: GPL-3.0-only
import {McpServer} from '@modelcontextprotocol/sdk/server/mcp.js';
import {StdioServerTransport} from '@modelcontextprotocol/sdk/server/stdio.js';
import {z} from 'zod';
import {readFile} from 'node:fs/promises';
import {NativeSession} from './session.mjs';

const server=new McpServer({name:'vault2-native',version:'0.1.0'});
let session;
const id=z.string().uuid();
const definitions=[
  ['vault2_open','open',{},'Open a fresh isolated, temporary GHL browser. Does not read credentials. Existing IAB, T3 and personal profiles are never attached.'],
  ['vault2_select','select',{sessionId:id},'Select only the exact account in the existing private owner selection. No password is returned.'],
  ['vault2_sign_in','sign-in',{sessionId:id,selectionId:id},'Privately fill the selected account and submit ONCE. Requires explicit owner login authorization. Never retry an uncertain result. Stop for owner MFA/CAPTCHA in the browser.'],
  ['vault2_inspect','inspect',{sessionId:id},'Observe a sanitized state and masked screenshot. Does not read codes or secrets. Owner completes MFA privately.'],
  ['vault2_verify','verify',{sessionId:id},'Require exact configured email in the visible profile menu, reload, then match again. Fail closed if the provider marker is unavailable.'],
  ['vault2_close','close',{sessionId:id},'Revoke temporary Vault owner session, verify 401, release owned lock, close owned browser and remove only its temporary profile.'],
];
let busy=false;
for(const [name,action,shape,description] of definitions) {
  server.registerTool(name,{description,inputSchema:z.object(shape).strict(),annotations:{readOnlyHint:action==='inspect',destructiveHint:action==='sign-in',openWorldHint:true}},async args=>{
    if(busy)return {content:[{type:'text',text:JSON.stringify({state:'needs_attention',reasonCode:'operation_busy'})}],isError:true};
    busy=true;
    try {
      if(action==='open'){
        if(session)return {content:[{type:'text',text:JSON.stringify({state:'needs_attention',reasonCode:'session_already_open'})}],isError:true};
        session=new NativeSession();
      }
      if(!session)return {content:[{type:'text',text:JSON.stringify({state:'needs_attention',reasonCode:'session_invalid'})}],isError:true};
      const result=await session.run(action,args);
      const content=[{type:'text',text:JSON.stringify(result)}];
      if(result.screenshotPath)try{content.push({type:'image',mimeType:'image/png',data:(await readFile(result.screenshotPath)).toString('base64')});}catch{}
      if(action==='close'&&result.state==='closed'&&result.cleanupVerified!==false)session=undefined;
      return {content,isError:result.state==='needs_attention'};
    } catch {
      // No stack/cause/engine response/Playwright call log on either output pipe.
      return {content:[{type:'text',text:JSON.stringify({state:'needs_attention',reasonCode:'operation_failed'})}],isError:true};
    } finally {busy=false;}
  });
}
let ending=false;
async function shutdown(){if(ending)return;ending=true;await session?.closeWhenIdle();await server.close();}
for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>{shutdown().finally(()=>process.exit(0));});
process.stdin.on('end',()=>{shutdown().finally(()=>process.exit(0));});
process.on('uncaughtException',()=>{shutdown().finally(()=>process.exit(1));});
process.on('unhandledRejection',()=>{shutdown().finally(()=>process.exit(1));});
await server.connect(new StdioServerTransport());
