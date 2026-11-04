const bad=()=>{throw Error('Invalid support evidence');};
const object=v=>v&&typeof v==='object'&&!Array.isArray(v);
const modes=['interactive','autonomous'];
const mode=v=>{if(!modes.includes(v))bad();return v;};
const integer=(v,min,max)=>{if(!Number.isSafeInteger(v)||v<min||v>max)bad();return v;};
const date=v=>{if(typeof v!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(v)||!Number.isFinite(Date.parse(v)))bad();return new Date(v).toISOString();};
const bool=v=>{if(typeof v!=='boolean')bad();return v;};
export function projectTokenPostAttempt(run,result){
 try{
  if(!object(result)||!Array.isArray(result.transportMetadata)||result.transportMetadata.length>500)bad();
  const posts=result.transportMetadata.filter(p=>p?.operation==='token_post');if(!posts.length)return null;
  if(!object(run)||posts.length>2)bad();
  const allowed=['expired','missing_token','invalid_token','user_binding','origin','token_exchange_configuration','signature','unclassified'];
  return{startedAt:date(run.startedAt),completedAt:run.completedAt===undefined?null:date(run.completedAt),posts:posts.map(p=>{
   const row={mode:mode(p.mode),status:integer(p.status,100,599),category:p.error?.category??'unclassified'};
   if(!allowed.includes(row.category))bad();
   if(p.requestId!==undefined){if(typeof p.requestId!=='string'||! /^(?:[a-f0-9]{32}|[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})$/i.test(p.requestId))bad();row.requestId=p.requestId;}
   if(p.accessTokenRemainingSeconds!==undefined)row.tokenRemainingSeconds=integer(p.accessTokenRemainingSeconds,-300,300);
   if(p.sasTiming?.hostRemainingSeconds!==undefined)row.hostChallengeRemainingSeconds=integer(p.sasTiming.hostRemainingSeconds,-300,300);
   if(p.sasTiming?.providerRemainingSeconds!==undefined)row.providerChallengeRemainingSeconds=integer(p.sasTiming.providerRemainingSeconds,-300,300);
   return row;
  }),local:(result.results??[]).map(r=>{
   const row={mode:mode(r.mode)};for(const key of ['localPolicyToolVerified','revokedTokenDenied','revokedChannelDenied'])if(r[key]!==undefined)row[key]=bool(r[key]);return row;
  })};
 }catch{bad();}
}
export function projectLocalEvidence(value){
 try{if(!object(value))bad();const r={completedAt:date(value.completedAt),passed:bool(value.passed),checks:integer(value.checks,0,1000),copilotVerified:false};for(const key of ['canaryGrantsRevoked','clientsRestored'])if(value[key]!==undefined)r[key]=bool(value[key]);return r;}catch{bad();}
}
export function projectTarget(value){
 try{
  if(!object(value))bad();const r={};for(const key of ['environmentId','copilotId',...(value.tenantId===undefined?[]:['tenantId'])]){if(typeof value[key]!=='string'||! /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value[key]))bad();r[key]=value[key];}
  if(typeof value.schemaName!=='string'||! /^[A-Za-z][A-Za-z0-9_]{0,199}$/.test(value.schemaName))bad();r.schemaName=value.schemaName;return r;
 }catch{bad();}
}
export function projectBudgets(values){
 try{
  if(!Array.isArray(values)||values.length!==3)bad();let reserved=0;
  values.forEach((v,i)=>{if(!object(v)||v.max!==(i===0?2:1)||!Array.isArray(v.reserved)||v.reserved.length>v.max||new Set(v.reserved).size!==v.reserved.length||v.reserved.some(m=>!modes.includes(m))||i>0&&v.reserved.some(m=>m!=='interactive'))bad();reserved+=v.reserved.length;});
  return{approvedConversations:4,reservedConversations:reserved,remainingConversations:4-reserved,newAttemptApproved:false};
 }catch{bad();}
}
export function renderSupportCase(evidence){
 const {target,attempts,local,budget}=evidence;
 const rows=attempts.flatMap(a=>a.posts.map(p=>`| ${a.startedAt} | ${a.completedAt??'Not recorded'} | ${p.mode} | ${p.status} | ${p.category} | ${p.requestId??'Not recorded'} | ${p.hostChallengeRemainingSeconds??'Not recorded'} | ${p.providerChallengeRemainingSeconds??'Not recorded'} | ${p.tokenRemainingSeconds??'Not recorded'} |`));
 return`# Microsoft Copilot Studio Generic OAuth token-post investigation\n\nDraft for support review; not submitted. Microsoft acceptance remains UNVERIFIED.\n\nEnvironment: ${target.environmentId}\n\nAgent: ${target.schemaName}; bot ${target.copilotId}\n\n## Observed Microsoft requests\n\nPOST https://token.botframework.com/api/sas/postToken (signed query omitted). End times use the recorded completion or result-file modification time; this is an approximate trace window, not a server execution timestamp. Remaining lifetimes are measurements at the failing POST, not inferred for older requests.\n\n| Start UTC | End UTC | Mode | HTTP | Category | Microsoft request ID | Challenge host seconds | Challenge provider seconds | PF token seconds |\n|---|---|---|---|---|---|---|---|---|\n${rows.join('\n')}\n\n## Request for Microsoft\n\nPlease trace these request IDs, especially the latest fresh-lifetime request. Identify which object was considered expired: signed URL, OAuth state/session record, connection/user binding, or posted access token. Which expiration value and service clock were used? Please identify any required connection or user-binding configuration and provide a sanitized service-side exception category. Do not return tokens, cookies or signed URLs.\n\n## Client protocol\n\nThe client posts JSON containing exactly one token property to the fresh OAuth card secure URL, with application/json, no Direct Line Authorization header or cookie, redirects rejected and no POST retries. Bot/conversation/challenge binding, signed query-byte preservation and independent PF token verification are checked locally. The PF tool token has a separate tool audience and preserved human/actor/grant/mode; it is never treated as a Graph delegated user token.\n\n## Independent local evidence\n\n${local.map(l=>`- ${l.kind}: ${l.passed?'passed':'failed'}, ${l.checks} checks, ${l.completedAt}. Microsoft/Copilot acceptance not established.`).join('\n')}\n\nLocal interactive/autonomous sign-in, exchange, mTLS tool use, real expiry, renewal and revocation are separate from Microsoft token-post acceptance. Manual Copilot sign-in was operator-observed; successful secure token-post, Copilot token continuity and Copilot-originating tool calls remain UNVERIFIED. No Graph/SharePoint connection exists.\n\n## Test allowance and privacy\n\n${budget.reservedConversations} of ${budget.approvedConversations} earlier conversation allowances are reserved/consumed. This export authorizes no new attempt and changes no allowance. No Microsoft request was made to prepare it. It contains only schema-projected request IDs, bounded relative timing, non-secret target identifiers and local verification counts; no raw source receipt, access token, authorization/validation code, channel secret, cookie, signed URL/query, private key, raw vendor body or grant/human/agent identifier is attached.\n`;
}
