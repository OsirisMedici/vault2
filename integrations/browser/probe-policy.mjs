// SPDX-License-Identifier: GPL-3.0-only
export function assertTabBinding(binding,status,list,expected){
  if(!status.available||status.tabId!==binding.tab||status.control?.owner!=='agent'||!status.control.ownedByCaller||!Number.isSafeInteger(status.control.generation)||status.control.generation<0||status.dialog||status.fileChooser)throw new Error('host_control_unavailable');
  if(status.url!=='https://www.figma.com/login')throw new Error('origin_mismatch');
  const matches=list.sessions?.filter(t=>t.tabId===binding.tab)??[];
  if(matches.length!==1||matches[0].threadId!==binding.thread||matches[0].profileId!==binding.profile)throw new Error('host_control_unavailable');
  if(expected&&(status.url!==expected.url||status.control.generation!==expected.generation))throw new Error('binding_changed');
  return {url:status.url,generation:status.control.generation};
}

// Fixed Figma email probe only. There is no password fill, submission or API path.
export function figmaProbeExpression({action,nonce,url}){
  if(!['arm','fill-clear'].includes(action)||!/^[-0-9a-f]{36}$/.test(nonce)||url!=='https://www.figma.com/login')throw new Error('invalid_probe');
  return `(${figmaProbe.toString()})(${JSON.stringify({action,nonce,url})})`;
}
async function figmaProbe({action,nonce,url}){
  const key='__vault2_nonsecret_probe__',start=performance.now();
  const visible=e=>e&&e.isConnected&&e.getClientRects().length>0&&!e.disabled&&!e.readOnly&&getComputedStyle(e).visibility==='visible';
  const challenge=()=>/verification code|verify your identity|captcha|account recovery/i.test(document.body?.innerText??'')||[...document.querySelectorAll('input[autocomplete="one-time-code"],iframe[title*="challenge"],iframe[src*="bframe"]')].some(visible);
  const contextOkay=()=>location.href===url&&location.origin==='https://www.figma.com'&&document.readyState==='complete'&&document.hasFocus()&&!challenge();
  if(!contextOkay())return {state:'page_not_ready'};
  const us=document.querySelectorAll('input#email'),ps=document.querySelectorAll('input#current-password');
  const email=us[0],password=ps[0];
  if(us.length!==1||ps.length!==1||!visible(email)||!visible(password)||email.type!=='email'||password.type!=='password'||!email.form||email.form!==password.form)return {state:'form_unavailable'};
  if(action==='arm'){
    if(email.value!==''||password.value!=='')return {state:'nonempty_form'};
    let permission;try{permission=await navigator.permissions.query({name:'clipboard-read'});}catch{return {state:'clipboard_unsupported'};}
    if(permission.state!=='granted')return {state:'clipboard_permission_required'};
    if(!contextOkay())return {state:'page_not_ready'};
    Object.defineProperty(document,key,{configurable:true,value:{nonce,email,password,form:email.form,expires:Date.now()+15000}});
    return {state:'armed'};
  }
  const armed=document[key];delete document[key];
  const stillBound=()=>contextOkay()&&armed?.nonce===nonce&&Date.now()<armed.expires&&armed.email===email&&armed.password===password&&armed.form===email.form&&visible(email)&&visible(password)&&email.form===password.form;
  if(!stillBound()||email.value!==''||password.value!=='')return {state:'binding_changed'};
  let permission;try{permission=await navigator.permissions.query({name:'clipboard-read'});}catch{return {state:'clipboard_unsupported'};}
  if(permission.state!=='granted')return {state:'clipboard_permission_required'};
  const readStart=performance.now();let value;
  try{value=await Promise.race([navigator.clipboard.readText(),new Promise((_,reject)=>setTimeout(()=>reject(0),1000))]);}catch{return {state:'clipboard_unavailable'};}
  const clipboardReadMs=performance.now()-readStart;
  if(!stillBound()||email.value!==''||password.value!==''||value!=='vault2-input-check+'+nonce+'@example.invalid')return {state:'clipboard_mismatch'};
  const r=email.getBoundingClientRect(),hit=document.elementFromPoint(r.left+r.width/2,r.top+r.height/2);
  if(hit!==email&&!email.contains(hit))return {state:'input_covered'};
  email.focus();if(document.activeElement!==email||!stillBound())return {state:'focus_unavailable'};
  const setValue=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
  let verified=false;
  try{
    setValue.call(email,value);email.dispatchEvent(new Event('input',{bubbles:true}));email.dispatchEvent(new Event('change',{bubbles:true}));
    verified=stillBound()&&document.activeElement===email&&email.value===value&&password.value==='';
  }finally{
    if(email.isConnected&&email.value===value){setValue.call(email,'');email.dispatchEvent(new Event('input',{bubbles:true}));email.dispatchEvent(new Event('change',{bubbles:true}));}
    value=undefined;
  }
  return {state:verified&&email.value===''?'benign_input_verified':'input_unverified',clipboardReadMs,pageTransactionMs:performance.now()-start,inputCleared:email.value===''};
}
