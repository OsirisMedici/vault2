// SPDX-License-Identifier: GPL-3.0-only
// Run inside the trusted tool runner, which provides `tools`.
// The loop performs the whole command without model-mediated field/key relays.
// Credentials stay in ghl-session.mjs; requests contain fixed controls only.
export async function runVault2Command(sessionId, command, maxSteps=130) {
  const allowed=new Set(['preview_status','t3_preview_list','preview_click','preview_evaluate','preview_press']);
  const start=Date.now();let calls=0,buffer='';const toolTimings=[];
  let chunk=await tools.write_stdin({session_id:sessionId,chars:JSON.stringify({type:'command',...command})+'\n',yield_time_ms:250,max_output_tokens:4000});
  for(let step=0;step<maxSteps;step++){
    buffer+=chunk.output??'';const messages=[];let index;
    while((index=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,index).trim();buffer=buffer.slice(index+1);try{messages.push(JSON.parse(line));}catch{}}
    const result=messages.find(m=>m.type==='result');
    if(result)return {elapsedMs:Date.now()-start,toolCalls:calls,toolTimings,result:result.result};
    const requests=messages.filter(m=>m.type==='tool_request');
    if(requests.length){
      if(requests.some(r=>!allowed.has(r.name)))throw new Error('unsupported_relay_tool');
      if(requests.length>1&&(requests.length!==2||requests.map(r=>r.name).sort().join(',')!=='preview_status,t3_preview_list'))throw new Error('unsupported_relay_batch');
      // Only the helper's independent status/list reads are emitted together.
      // Mutations remain sequential; no request is dropped from a shared chunk.
      const responses=await Promise.all(requests.map(async request=>{
        const start=Date.now();let ok=false;
        try{
          const raw=await tools['mcp__t3_code__'+request.name](request.args);
          if(raw.isError)throw new Error('host_operation_failed');
          const result=raw.structuredContent??JSON.parse(raw.content.find(c=>c.type==='text').text);ok=true;
          return {type:'tool_response',id:request.id,result};
        }catch{return {type:'tool_response',id:request.id,error:true};}
        finally{toolTimings.push({tool:request.name,elapsedMs:Date.now()-start,ok});}
      }));
      calls+=requests.length;
      chunk=await tools.write_stdin({session_id:sessionId,chars:responses.map(r=>JSON.stringify(r)+'\n').join(''),yield_time_ms:250,max_output_tokens:4000});
    }else{
      chunk=await tools.write_stdin({session_id:sessionId,chars:'',yield_time_ms:250,max_output_tokens:4000});
    }
  }
  throw new Error('relay_step_budget_exceeded');
}
