#!/usr/bin/env bun
// SPDX-License-Identifier: GPL-3.0-only
// Harmless stdio check. --page opens an empty isolated GHL page, never selects
// an account, reads Vault, fills fields or submits. No additional chat is made.
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {parseArgs} from 'node:util';
import {fileURLToPath} from 'node:url';
import {writeFile,copyFile,chmod,mkdir} from 'node:fs/promises';
import {join} from 'node:path';
const {values}=parseArgs({options:{page:{type:'boolean',default:false},evidence:{type:'string'}}});
const client=new Client({name:'vault2-local-build-check',version:'0.1.0'});
const transport=new StdioClientTransport({command:process.execPath,args:[fileURLToPath(new URL('./server.mjs',import.meta.url))],stderr:'pipe'});
let stderrBytes=0;transport.stderr?.on('data',chunk=>{stderrBytes+=chunk.length;});
const receipt={startedAt:new Date().toISOString(),kind:'stdio-build-check',credentialsRead:false,submitted:false};
let sessionId;
const result=r=>JSON.parse(r.content.find(c=>c.type==='text').text);
try {
  await client.connect(transport);
  const listed=await client.listTools();receipt.tools=listed.tools.map(t=>t.name);
  if(listed.tools.length!==6)throw new Error();
  for(const tool of listed.tools){
    const fields=Object.keys(tool.inputSchema.properties??{});
    if(fields.some(k=>!['sessionId','selectionId'].includes(k))||tool.inputSchema.additionalProperties!==false)throw new Error();
  }
  receipt.discovery='passed';
  receipt.invalidSession=result(await client.callTool({name:'vault2_inspect',arguments:{sessionId:'11111111-1111-4111-8111-111111111111'}}));
  if(receipt.invalidSession.reasonCode!=='session_invalid')throw new Error();
  if(values.page){
    receipt.open=result(await client.callTool({name:'vault2_open',arguments:{}}));sessionId=receipt.open.sessionId;
    if(!sessionId||!receipt.open.isolatedProfile)throw new Error();
    if(values.evidence&&receipt.open.screenshotPath){await mkdir(values.evidence,{recursive:true,mode:0o700});await copyFile(receipt.open.screenshotPath,join(values.evidence,'isolated-ghl-before.png'));}
    receipt.inspect=result(await client.callTool({name:'vault2_inspect',arguments:{sessionId}}));
    if(values.evidence&&receipt.inspect.screenshotPath)await copyFile(receipt.inspect.screenshotPath,join(values.evidence,'isolated-ghl-result.png'));
    receipt.close=result(await client.callTool({name:'vault2_close',arguments:{sessionId}}));sessionId=undefined;
    if(receipt.close.cleanup?.profile!=='removed'||receipt.close.cleanup?.browser!=='closed')throw new Error();
  }
  receipt.passed=true;
}catch{receipt.passed=false;receipt.reasonCode='build_check_failed';}
finally{
  if(sessionId)try{receipt.cleanup=result(await client.callTool({name:'vault2_close',arguments:{sessionId}}));}catch{receipt.cleanup='unverified';}
  await client.close();receipt.endedAt=new Date().toISOString();receipt.stderrBytes=stderrBytes;
}
if(values.evidence){const p=join(values.evidence,'stdio-check.json');await writeFile(p,JSON.stringify(receipt,null,2)+'\n');await chmod(p,0o600);}
console.log(JSON.stringify(receipt,null,2));
if(!receipt.passed)process.exitCode=1;
