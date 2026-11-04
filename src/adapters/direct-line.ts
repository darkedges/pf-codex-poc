import { randomUUID,createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { CopilotError,type CopilotAdapter,type CopilotState,type CopilotPage,type DirectLineConfig,type DirectLineDependencies } from './copilot.ts';
import type { DelegatedClaims } from './token-exchange.ts';
import type {ProviderAccessClaims} from '../identity/provider-access.ts';

type Session={handle:string;binding:string;conversationId:string;userId:string;channelToken:string;channelExpiresAt:number;deadline:number;state:CopilotState;ssoExpiresAt?:number;relayProviderToken?:string;watermark?:string;activities:Map<string,string>;busy:boolean;credentials:Set<string>};
const object=(v:unknown):v is Record<string,any>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const string=(v:unknown,max=2048):v is string=>typeof v==='string'&&v.length>0&&v.length<=max&&!/[\u0000-\u001f\u007f]/.test(v);
const messageText=(v:unknown):v is string=>typeof v==='string'&&v.length>0&&v.length<=4000&&!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(v);
const digest=(v:string)=>createHash('sha256').update(v).digest('base64url');
const identity=(c:DelegatedClaims)=>JSON.stringify([c.sub,c.act.iss,c.act.sub,c.org_id,c.delegation_id,c.execution_mode,c.scope]);
const binding=(c:DelegatedClaims)=>JSON.stringify([c.iss,c.aud,identity(c)]);
const jwtPattern=/eyJ[A-Za-z0-9_-]{7,}(?:\.[A-Za-z0-9_-]+){2,4}/g;
function secureUrl(value:string){
 if(!string(value,8192)||value!==value.trim())throw new CopilotError('configuration');
 const u=new URL(value);
 if(u.protocol!=='https:'||u.username||u.password||u.hash||u.port||isIP(u.hostname)||['localhost','host.docker.internal'].includes(u.hostname)||value.includes('\\'))throw new CopilotError('configuration');
 return u;
}
function origin(value:string){const u=secureUrl(value);if(u.pathname!=='/'||u.search)throw new CopilotError('configuration');return u.origin;}

// All credentials and conversation state stay server-side. Construction alone performs no network calls.
export class DirectLineAdapter implements CopilotAdapter {
 private config:DirectLineConfig;
 private dependencies:DirectLineDependencies;
 private sessions=new Map<string,Session>();
 private knownConversations=new Map<string,number>();
 private challenges=new Map<string,number>();
 private opening=0;
 private stopped=false;
 constructor(config:DirectLineConfig,dependencies:DirectLineDependencies){
  try{
   if(Object.keys(config).some(k=>!['endpoint','brokerAudience','ssoAudience','scope','providerSso','botId','trustedOrigins','tokenPostRules','timeoutMs','maxSessions','sessionLifetimeSeconds','maxActivities'].includes(k)))throw Error();
   const endpoint=secureUrl(config.endpoint);
   if(endpoint.pathname!=='/v3/directline'||endpoint.search||!string(config.brokerAudience)||!string(config.ssoAudience)||config.brokerAudience===config.ssoAudience||!string(config.scope,100)||!/^[A-Za-z0-9:._-]+$/.test(config.scope)||!string(config.botId,256)||!Array.isArray(config.trustedOrigins)||!config.trustedOrigins.length||config.trustedOrigins.length>10||!Array.isArray(config.tokenPostRules)||!config.tokenPostRules.length||config.tokenPostRules.length>10)throw Error();
   const trustedOrigins=config.trustedOrigins.map(origin);
   const rules=config.tokenPostRules.map(r=>{
    if(Object.keys(r).some(k=>!['origin','pathPrefix','pathExact','requiredQueryParameters'].includes(k))||Number(Object.hasOwn(r,'pathPrefix'))+Number(Object.hasOwn(r,'pathExact'))!==1)throw Error();
    const path=r.pathExact??r.pathPrefix;
    if(!string(path,1000)||!path.startsWith('/')||path==='/'||(r.pathExact===undefined&&!path.endsWith('/'))||/%|\\/.test(path))throw Error();
    const approvedOrigin=origin(r.origin),u=secureUrl(approvedOrigin+path);
    if(u.pathname!==path||u.search||!Array.isArray(r.requiredQueryParameters)||!r.requiredQueryParameters.length||r.requiredQueryParameters.some(k=>!string(k,100)||!/^[A-Za-z0-9_-]+$/.test(k)))throw Error();
    return{...structuredClone(r),origin:approvedOrigin};
   });
   if(!Number.isInteger(config.timeoutMs)||config.timeoutMs<100||config.timeoutMs>30000||!Number.isInteger(config.maxSessions)||config.maxSessions<1||config.maxSessions>1000||!Number.isInteger(config.sessionLifetimeSeconds)||config.sessionLifetimeSeconds<30||config.sessionLifetimeSeconds>3600||!Number.isInteger(config.maxActivities)||config.maxActivities<10||config.maxActivities>5000||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error();
   const provider=config.providerSso;
   if(dependencies.providerSession&&(!provider||typeof dependencies.providerSession.bind!=='function'||typeof dependencies.providerSession.invalidate!=='function'))throw Error();
   const microsoftPost=rules.some(r=>r.origin==='https://token.botframework.com'&&(r.pathExact==='/api/sas/postToken'||r.pathPrefix&&'/api/sas/postToken'.startsWith(r.pathPrefix)));
   if(microsoftPost&&!provider)throw Error();
   if(provider){
    if(Object.keys(provider).sort().join()!=='audience,issuer,maxLifetimeSeconds,scope'||origin(provider.issuer)!==provider.issuer||provider.audience!==config.ssoAudience||!string(provider.scope,100)||!/^[A-Za-z0-9:._-]+$/.test(provider.scope)||!Number.isInteger(provider.maxLifetimeSeconds)||provider.maxLifetimeSeconds<1||provider.maxLifetimeSeconds>3600||typeof dependencies.providerVerifier?.verify!=='function'||typeof dependencies.bindProviderIdentity!=='function')throw Error();
   }else if(typeof dependencies.ssoVerifier?.verify!=='function')throw Error();
   if(typeof dependencies.verifier?.verify!=='function'||typeof dependencies.secret!=='function'||typeof dependencies.issueSsoToken!=='function'||typeof dependencies.authorise!=='function')throw Error();
   this.config={...structuredClone(config),endpoint:endpoint.href,trustedOrigins,tokenPostRules:rules};this.dependencies={...dependencies};
  }catch{throw new CopilotError('configuration');}
 }
 private now(){return(this.dependencies.now??Date.now)();}
 private providerClaims(value:ProviderAccessClaims){
  const p=this.config.providerSso!,now=Math.floor(this.now()/1000);
  if(!object(value)||value.iss!==p.issuer||value.aud!==p.audience||value.scope!==p.scope||!string(value.sub)||!string(value.jti)||![value.iat,value.nbf,value.exp].every(Number.isInteger)||value.iat>now+5||value.nbf>now+5||value.nbf>value.exp||value.exp<=now||value.exp<=value.iat||value.exp-value.iat>p.maxLifetimeSeconds||['act','delegation_id','execution_mode','org_id'].some(k=>(value as unknown as Record<string,unknown>)[k]!==undefined))throw new CopilotError('invalid_token');
  return value;
 }
 private claims(value:DelegatedClaims,audience:string){
  const now=Math.floor(this.now()/1000);
  if(!object(value)||value.aud!==audience||!string(value.iss)||!string(value.sub)||!object(value.act)||!string(value.act.sub)||!string(value.act.iss)||!string(value.org_id,160)||!string(value.delegation_id,160)||!['interactive','autonomous'].includes(value.execution_mode)||value.scope!==this.config.scope||![value.iat,value.nbf,value.exp].every(Number.isInteger)||value.iat>now+5||value.nbf>now+5||value.exp<=now||value.exp<=value.iat||value.exp-value.iat>300||!string(value.jti,200))throw new CopilotError('invalid_token');
  return{iss:value.iss,aud:value.aud,sub:value.sub,act:{iss:value.act.iss,sub:value.act.sub},org_id:value.org_id,delegation_id:value.delegation_id,execution_mode:value.execution_mode,scope:value.scope,iat:value.iat,nbf:value.nbf,exp:value.exp,jti:value.jti};
 }
 private async check(raw:string,expected?:string){
  if(this.stopped)throw new CopilotError('session_denied');
  let claims:DelegatedClaims;
  try{if(!string(raw,16000))throw Error();claims=this.claims(await this.bounded(()=>this.dependencies.verifier.verify(raw)),this.config.brokerAudience);}catch{throw new CopilotError('invalid_token');}
  if(expected!==undefined&&binding(claims)!==expected)throw new CopilotError('session_denied');
  try{await this.bounded(()=>this.dependencies.authorise(structuredClone(claims),{accessToken:raw}));}catch{throw new CopilotError('policy_denied');}
  if(this.stopped)throw new CopilotError('session_denied');this.claims(claims,this.config.brokerAudience);return claims;
 }
 private async bounded<T>(work:(signal:AbortSignal)=>Promise<T>):Promise<T>{
  const controller=new AbortController();let timer:ReturnType<typeof setTimeout>|undefined;
  try{return await Promise.race([Promise.resolve().then(()=>work(controller.signal)),new Promise<never>((_resolve,reject)=>{timer=setTimeout(()=>{controller.abort();reject(new CopilotError('unavailable'));},this.config.timeoutMs);})]);}
  finally{if(timer)clearTimeout(timer);}
 }
 private async response(response:Response,signal:AbortSignal,json:boolean){
  if(!response.body){if(json)throw new CopilotError('protocol_error');return undefined;}
  const reader=response.body.getReader();let length=0;const chunks:Uint8Array[]=[];
  const abort=()=>{void reader.cancel().catch(()=>{});};signal.addEventListener('abort',abort,{once:true});
  try{
   for(;;){signal.throwIfAborted();const part=await reader.read();signal.throwIfAborted();if(part.done)break;length+=part.value.byteLength;if(length>262144){abort();throw new CopilotError('protocol_error');}chunks.push(part.value);}
   if(!json)return undefined;
   if(!response.headers.get('content-type')?.toLowerCase().startsWith('application/json'))throw new CopilotError('protocol_error');
   try{return JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw new CopilotError('protocol_error');}
  }finally{signal.removeEventListener('abort',abort);reader.releaseLock();}
 }
 private async request(url:string,method:'GET'|'POST',credential:string|undefined,body:unknown,raw:string,expected:string,json=true,session?:Session){
  // Only read-only GETs can retry, once. Token/SSO/activity POSTs are never replayed automatically.
  for(let attempt=0;attempt<(method==='GET'?2:1);attempt++){
   await this.check(raw,expected);
   if(session)this.active(session);
   try{
    const result=await this.bounded(async signal=>{
     const headers:Record<string,string>={Accept:'application/json'};
     if(credential)headers.Authorization='Bearer '+credential;
     if(body!==undefined)headers['Content-Type']='application/json';
     const r=await(this.dependencies.fetch??fetch)(url,{method,headers,body:body===undefined?undefined:JSON.stringify(body),redirect:'error',signal});
     if(!r.ok){void r.body?.cancel().catch(()=>{});throw new CopilotError(r.status>=500||r.status===429?'unavailable':'protocol_error');}
     return this.response(r,signal,json);
    });
    await this.check(raw,expected);if(session)this.active(session);return result;
   }catch(error){const safe=error instanceof CopilotError?error:new CopilotError('unavailable');if(method==='GET'&&attempt===0&&safe.code==='unavailable')continue;throw safe;}
  }
  throw new CopilotError('unavailable');
 }
 private channel(value:unknown,expected?:string,issuedAt=this.now()){
  if(!object(value)||!string(value.conversationId,200)||!/^[A-Za-z0-9_-]+$/.test(value.conversationId)||!string(value.token,16000)||!Number.isInteger(value.expires_in)||value.expires_in<1||value.expires_in>86400||(expected!==undefined&&value.conversationId!==expected))throw new CopilotError('protocol_error');
  const expiresAt=issuedAt+value.expires_in*1000;if(expiresAt<=this.now())throw new CopilotError('expired');
  return{conversationId:value.conversationId,token:value.token,expiresAt};
 }
 private active(s:Session){
  if(this.sessions.get(s.handle)!==s||s.deadline<=this.now()||s.channelExpiresAt<=this.now()){this.forget(s);throw new CopilotError('expired');}
  if(s.ssoExpiresAt!==undefined&&s.ssoExpiresAt<=this.now()){this.forget(s);throw new CopilotError('sso_expired');}
 }
 private remember(s:Session,credential:string){if(!s.credentials.has(credential)&&s.credentials.size>=128)throw new CopilotError('capacity');s.credentials.add(credential);}
 private forget(session:Session){const relayToken=session.relayProviderToken;session.relayProviderToken=undefined;try{if(relayToken)this.dependencies.providerSession!.invalidate(relayToken);}finally{this.sessions.delete(session.handle);session.channelToken='';session.credentials.clear();session.activities.clear();session.state='closed';}}
 private purge(){const now=this.now();for(const s of this.sessions.values())if(s.deadline<=now||s.channelExpiresAt<=now)this.forget(s);for(const map of [this.challenges,this.knownConversations])for(const [key,expiry]of map)if(expiry<=now)map.delete(key);}
 private view(s:Session){return{handle:s.handle,state:s.state,expiresAt:Math.min(s.deadline,s.channelExpiresAt)};}
 private async trace<T>(operation:'open'|'send'|'poll'|'refresh'|'close',work:()=>Promise<T>):Promise<T>{
  if(this.stopped)throw new CopilotError('session_denied');
  const started=this.now();let outcome:'ok'|CopilotError['code']='ok';
  try{return await work();}catch(error){const safe=error instanceof CopilotError?error:new CopilotError('unavailable');outcome=safe.code;throw safe;}
  finally{try{this.dependencies.observe?.({event:'copilot_directline',operation,outcome,durationMs:Math.max(0,this.now()-started)});}catch{}}
 }
 async open(raw:string){return this.trace('open',async()=>{
  const claims=await this.check(raw),expected=binding(claims);this.purge();
  if(this.config.providerSso&&claims.execution_mode!=='interactive')throw new CopilotError('unavailable');
  if(this.sessions.size+this.opening>=this.config.maxSessions||this.knownConversations.size>=10000)throw new CopilotError('capacity');
  this.opening++;
  try{
  const secret=await this.bounded(signal=>this.dependencies.secret(signal));if(!string(secret,16000)||/\s/.test(secret))throw new CopilotError('configuration');
  const generatedAt=this.now(),userId='dl_'+randomUUID(),generated=this.channel(await this.request(this.config.endpoint+'/tokens/generate','POST',secret,{user:{id:userId},trustedOrigins:this.config.trustedOrigins},raw,expected),undefined,generatedAt);
  if(this.knownConversations.has(generated.conversationId))throw new CopilotError('protocol_error');if(this.knownConversations.size>=10000)throw new CopilotError('capacity');
  this.knownConversations.set(generated.conversationId,this.now()+86400000);
  const startedAt=this.now(),started=this.channel(await this.request(this.config.endpoint+'/conversations','POST',generated.token,undefined,raw,expected),generated.conversationId,startedAt);
  // streamUrl is deliberately ignored: polling uses only the administrator-pinned endpoint.
  const session:Session={handle:randomUUID(),binding:expected,conversationId:started.conversationId,userId,channelToken:started.token,channelExpiresAt:started.expiresAt,deadline:this.now()+this.config.sessionLifetimeSeconds*1000,state:'awaiting_oauth',activities:new Map(),busy:false,credentials:new Set([raw,secret,generated.token,started.token])};
  if(this.stopped)throw new CopilotError('session_denied');if(this.sessions.size>=this.config.maxSessions)throw new CopilotError('capacity');this.sessions.set(session.handle,session);return this.view(session);
  }finally{this.opening--;}
 });}
 private async session<T>(handle:string,raw:string,work:(s:Session,c:DelegatedClaims)=>Promise<T>):Promise<T>{
  if(!string(handle,100))throw new CopilotError('session_denied');
  const claims=await this.check(raw),session=this.sessions.get(handle);
  if(!session||session.binding!==binding(claims))throw new CopilotError('session_denied');
  this.active(session);
  if(session.busy)throw new CopilotError('session_busy');session.busy=true;
  try{this.remember(session,raw);return await work(session,claims);}catch(error){this.forget(session);throw error;}finally{session.busy=false;}
 }
 async send(handle:string,raw:string,text:string){return this.trace('send',async()=>{
  if(!messageText(text)||/eyJ[A-Za-z0-9_-]{7,}(?:\.[A-Za-z0-9_-]+){2,4}/.test(text))throw new CopilotError('invalid_request');
  return this.session(handle,raw,async s=>{
   if([...s.credentials].some(c=>text.includes(c)))throw new CopilotError('invalid_request');
   const result=await this.request(`${this.config.endpoint}/conversations/${s.conversationId}/activities`,'POST',s.channelToken,{type:'message',from:{id:s.userId},text},raw,s.binding,true,s);
   if(!object(result)||!string(result.id,512))throw new CopilotError('protocol_error');return{submitted:true as const};
  });
 });}
 private challengeUrl(value:unknown){
  try{
   if(!string(value,8192))throw Error();const u=secureUrl(value);
   if(/%(?:2f|5c|2e|25)/i.test(u.pathname))throw Error();
   const entries=[...u.searchParams];if(!entries.length||new Set(entries.map(([k])=>k)).size!==entries.length)throw Error();
   const allowed=this.config.tokenPostRules.some(r=>u.origin===r.origin&&(r.pathExact!==undefined?u.pathname===r.pathExact:u.pathname.startsWith(r.pathPrefix))&&r.requiredQueryParameters.every(k=>string(u.searchParams.get(k),8192)));
   if(!allowed)throw Error();const canonical=new URL(u);canonical.searchParams.sort();return{url:u.href,key:digest(canonical.href)};
  }catch{throw new CopilotError('oauth_invalid');}
 }
 private redact(text:string,s:Session){let result=text.replace(jwtPattern,'[credential redacted]');for(const credential of s.credentials)result=result.split(credential).join('[credential redacted]');return result;}
 async poll(handle:string,raw:string):Promise<CopilotPage>{return this.trace('poll',()=>this.session(handle,raw,async(s,claims)=>{
  const u=new URL(`${this.config.endpoint}/conversations/${s.conversationId}/activities`);if(s.watermark!==undefined)u.searchParams.set('watermark',s.watermark);
  const page=await this.request(u.href,'GET',s.channelToken,undefined,raw,s.binding,true,s);
  if(!object(page)||!Array.isArray(page.activities)||page.activities.length>100||(page.watermark!=null&&!string(page.watermark,512)))throw new CopilotError('protocol_error');
  const pending:{id:string;hash:string;challenge?:ReturnType<DirectLineAdapter['challengeUrl']>;text?:string;end:boolean}[]=[];
  const batch=new Map<string,string>();
  // Validate the complete batch before posting any credential.
  for(const activity of page.activities){
   if(!object(activity)||!string(activity.id,512)||activity.channelId!=='directline'||activity.conversation?.id!==s.conversationId||![this.config.botId,s.userId].includes(activity.from?.id)||!string(activity.type,100))throw new CopilotError('protocol_error');
   const hash=digest(JSON.stringify(activity)),previous=s.activities.get(activity.id)??batch.get(activity.id);
   if(previous!==undefined){if(previous!==hash)throw new CopilotError('protocol_error');continue;}
   if(s.activities.size+batch.size>=this.config.maxActivities)throw new CopilotError('capacity');batch.set(activity.id,hash);
   if(activity.attachments!==undefined&&!Array.isArray(activity.attachments))throw new CopilotError('protocol_error');
   const cards=(activity.attachments??[]).filter(a=>a?.contentType==='application/vnd.microsoft.card.oauth');
   if(cards.length>1||(cards.length&&(activity.from.id!==this.config.botId||activity.type!=='message')))throw new CopilotError('oauth_invalid');
   if(activity.text!==undefined&&(typeof activity.text!=='string'||activity.text.length>8000))throw new CopilotError('protocol_error');
   pending.push({id:activity.id,hash,...(cards.length?{challenge:this.challengeUrl(cards[0]?.content?.tokenPostResource?.sasUrl)}:{}),...(activity.from.id===this.config.botId&&activity.type==='message'&&activity.text?{text:activity.text}:{}),end:activity.type==='endOfConversation'});
  }
  const messages:{id:string;text:string}[]=[],hasChallenge=pending.some(p=>p.challenge);
  for(const item of pending){
   if(item.challenge){
    this.purge();this.active(s);if(this.challenges.has(item.challenge.key))throw new CopilotError('challenge_replay');if(this.challenges.size>=10000)throw new CopilotError('capacity');
    this.challenges.set(item.challenge.key,this.now()+86400000);
    const token=await this.bounded(signal=>this.dependencies.issueSsoToken({claims:structuredClone(claims),brokerToken:raw,audience:this.config.ssoAudience,scope:this.config.providerSso?.scope??this.config.scope,signal}));
    let verified:DelegatedClaims|ProviderAccessClaims;
    try{
     if(token===raw)throw Error();
     if(this.config.providerSso){
      const provider=this.providerClaims(await this.bounded(()=>this.dependencies.providerVerifier!.verify(token)));
      await this.bounded(signal=>this.dependencies.bindProviderIdentity!(structuredClone(provider),structuredClone(claims),{brokerToken:raw,signal}));verified=this.providerClaims(provider);
     }else{verified=this.claims(await this.bounded(()=>this.dependencies.ssoVerifier!.verify(token)),this.config.ssoAudience);if(identity(verified)!==identity(claims))throw Error();}
    }catch{throw new CopilotError('invalid_token');}
    this.active(s);this.remember(s,token);this.remember(s,item.challenge.url);s.ssoExpiresAt=verified.exp*1000;
    if(this.dependencies.providerSession){
     if(s.relayProviderToken)this.dependencies.providerSession.invalidate(s.relayProviderToken);
     s.relayProviderToken=token;
     await this.bounded(signal=>this.dependencies.providerSession!.bind(raw,token,signal));
    }
    await this.request(item.challenge.url,'POST',undefined,{token},raw,s.binding,false,s);
    if(this.config.providerSso)this.providerClaims(verified as ProviderAccessClaims);else this.claims(verified as DelegatedClaims,this.config.ssoAudience);s.state='token_posted';
   }
   s.activities.set(item.id,item.hash);
   if(item.end){this.forget(s);return{state:'closed',messages:[]};}
   if(!hasChallenge&&s.state==='token_posted'&&item.text)messages.push({id:digest(item.id),text:this.redact(item.text,s)});
  }
  if(page.watermark!=null)s.watermark=page.watermark;
  await this.check(raw,s.binding);this.active(s);return{state:s.state,messages};
 }));}
 async refresh(handle:string,raw:string){return this.trace('refresh',()=>this.session(handle,raw,async s=>{
  const issuedAt=this.now(),result=this.channel(await this.request(this.config.endpoint+'/tokens/refresh','POST',s.channelToken,undefined,raw,s.binding,true,s),s.conversationId,issuedAt);
  this.remember(s,result.token);s.channelToken=result.token;s.channelExpiresAt=result.expiresAt;return this.view(s);
 }));}
 async close(handle:string,raw:string){return this.trace('close',()=>this.session(handle,raw,async s=>{this.forget(s);return{closed:true as const};}));}
 /** Trusted server lifecycle only; local credential disposal, no external retry. */
 shutdown(){this.stopped=true;for(const session of this.sessions.values())this.forget(session);this.challenges.clear();this.knownConversations.clear();}
}
