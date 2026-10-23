// SPDX-License-Identifier: GPL-3.0-only
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {runVault2Command} from './ghl-relay.js';
test('coalesced independent host requests each receive a response',async()=>{
  let writes=0;const calls=[];
  globalThis.tools={
    write_stdin:async({chars})=>{
      if(writes++===0)return {output:[{type:'tool_request',id:'1',name:'preview_status',args:{}},{type:'tool_request',id:'2',name:'t3_preview_list',args:{}}].map(x=>JSON.stringify(x)+'\n').join('')};
      const responses=chars.trim().split('\n').map(JSON.parse);assert.equal(responses.length,2);assert.deepEqual(responses.map(x=>x.id).sort(),['1','2']);
      return {output:JSON.stringify({type:'result',result:{state:'done'}})+'\n'};
    },
    mcp__t3_code__preview_status:async()=>{calls.push('status');return {structuredContent:{available:true}};},
    mcp__t3_code__t3_preview_list:async()=>{calls.push('list');return {structuredContent:{sessions:[]}};},
  };
  try{const r=await runVault2Command(1,{action:'probe-input'});assert.equal(r.result.state,'done');assert.equal(r.toolCalls,2);assert.equal(r.toolTimings.length,2);assert.deepEqual(calls.sort(),['list','status']);}finally{delete globalThis.tools;}
});
test('mutating requests cannot be run as a parallel batch',async()=>{
  globalThis.tools={write_stdin:async()=>({output:[{type:'tool_request',name:'preview_click'},{type:'tool_request',name:'preview_press'}].map(x=>JSON.stringify(x)+'\n').join('')})};
  try{await assert.rejects(runVault2Command(1,{action:'probe-input'}),/unsupported_relay_batch/);}finally{delete globalThis.tools;}
});
