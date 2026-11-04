import {createHash,randomUUID,timingSafeEqual} from 'node:crypto';
import type {DelegatedClaims,TokenVerifier} from '../adapters/token-exchange.ts';
import type {ProviderAccessClaims} from '../identity/provider-access.ts';

type RelayCode='configuration'|'invalid_request'|'invalid_token'|'binding_denied'|'policy_denied'|'unavailable'|'audit_failed';
export class ProviderRelayError extends Error {
 readonly code:RelayCode;
 constructor(code:RelayCode){super(code);this.name='ProviderRelayError';this.code=code;}
}
export type ProviderRelayConfig={
 brokerAudience:string;toolAudience:string;scope:string;callerId:string;
 provider:{issuer:string;audience:string;scope:string};
 bindingLifetimeSeconds:number;maxBindings:number;timeoutMs:number;
};
export type ProviderRelayContext={claims:Readonly<DelegatedClaims>;brokerToken:string;provider:Readonly<ProviderAccessClaims>};
export type ProviderRelayDependencies={
 brokerVerifier:TokenVerifier;providerVerifier:{verify:(token:string)=>Promise<ProviderAccessClaims>};
 // Authenticate a separately enrolled connector credential, never a claimed caller ID.
 authenticateCaller:(credential:string,signal:AbortSignal)=>Promise<string>;
 bindProviderIdentity:(provider:Readonly<ProviderAccessClaims>,broker:Readonly<DelegatedClaims>)=>Promise<void>;
 authoriseBroker:(claims:Readonly<DelegatedClaims>,evidence:{accessToken:string})=>Promise<void>;
 issueToolToken:(context:ProviderRelayContext,signal:AbortSignal)=>Promise<string>;
 toolVerifier:TokenVerifier;
 // Fixed private downstream operation with its own tool-token/PDP and workload checks.
 invokeTool:(toolToken:string,signal:AbortSignal)=>Promise<{authorized:boolean}>;
 audit:(event:{event:'copilot_tool_relay';requestId:string;phase:'bound'|'attempt'|'success'|'denied'})=>Promise<void>;
 now?:()=>number;
};
type Bound={brokerToken:string;claims:DelegatedClaims;deadline:number;cancelled?:boolean};
type Entry={retainUntil:number;bound?:Bound;active?:Bound;timer?:ReturnType<typeof setTimeout>};
const text=(s:unknown):s is string=>typeof s==='string'&&s.length>0&&s.length<=2048&&!/[\u0000-\u0020\u007f]/.test(s);
const credential=(s:unknown):s is string=>typeof s==='string'&&s.length>0&&s.length<=16000&&!/\s/.test(s);
const key=(token:string)=>createHash('sha256').update(token).digest('hex');
const identity=(c:DelegatedClaims)=>JSON.stringify([c.sub,c.act.iss,c.act.sub,c.org_id,c.delegation_id,c.execution_mode,c.scope]);

// The composition root loads this digest from enrolled custody. No request selects a caller.
export function connectionKeyAuthenticator(config:{callerId:string;sha256:string}){
 if(!text(config?.callerId)||typeof config.sha256!=='string'||!/^[a-f0-9]{64}$/.test(config.sha256))throw new ProviderRelayError('configuration');
 const digest=Buffer.from(config.sha256,'hex'),callerId=config.callerId;
 return async(value:string,signal:AbortSignal)=>{
  if(signal.aborted||!credential(value)||!timingSafeEqual(digest,createHash('sha256').update(value).digest()))throw new ProviderRelayError('invalid_token');
  return callerId;
 };
}

// Process-local preparation only. This factory opens no listener and exposes no bind API.
export class ProviderToolRelay {
 private config:ProviderRelayConfig;private deps:ProviderRelayDependencies;
 private bindings=new Map<string,Entry>();private closed=false;
 constructor(config:ProviderRelayConfig,deps:ProviderRelayDependencies){
  try{
   if(!config||Object.keys(config).sort().join()!=='bindingLifetimeSeconds,brokerAudience,callerId,maxBindings,provider,scope,timeoutMs,toolAudience')throw Error();
   if(![config.brokerAudience,config.toolAudience,config.scope,config.callerId,config.provider?.issuer,config.provider?.audience,config.provider?.scope].every(text)||new Set([config.brokerAudience,config.toolAudience,config.provider.audience]).size!==3)throw Error();
   const issuer=new URL(config.provider.issuer);if(issuer.protocol!=='https:'||issuer.username||issuer.password||issuer.search||issuer.hash)throw Error();
   if(Object.keys(config.provider).sort().join()!=='audience,issuer,scope'||!Number.isInteger(config.bindingLifetimeSeconds)||config.bindingLifetimeSeconds<1||config.bindingLifetimeSeconds>120||!Number.isInteger(config.maxBindings)||config.maxBindings<1||config.maxBindings>1000||!Number.isInteger(config.timeoutMs)||config.timeoutMs<100||config.timeoutMs>10000)throw Error();
   if(!['authenticateCaller','bindProviderIdentity','authoriseBroker','issueToolToken','invokeTool','audit'].every(k=>typeof (deps as any)?.[k]==='function')||![deps.brokerVerifier,deps.providerVerifier,deps.toolVerifier].every(v=>typeof v?.verify==='function'))throw Error();
   this.config=structuredClone(config);this.deps={...deps};
  }catch{throw new ProviderRelayError('configuration');}
 }
 private now(){return(this.deps.now??Date.now)();}
 private dates(c:{iat:number;nbf:number;exp:number},maximum:number){
  const now=Math.floor(this.now()/1000);
  if(![c.iat,c.nbf,c.exp].every(Number.isInteger)||c.iat>now+5||c.nbf>now+5||c.exp<=now||c.exp<=c.iat||c.nbf>c.exp||c.exp-c.iat>maximum)throw new ProviderRelayError('invalid_token');
 }
 private delegated(c:DelegatedClaims,audience:string,maximum:number){
  if(!c||c.aud!==audience||c.scope!==this.config.scope||![c.iss,c.sub,c.act?.iss,c.act?.sub,c.org_id,c.delegation_id,c.jti].every(text)||c.execution_mode!=='interactive')throw new ProviderRelayError('invalid_token');
  this.dates(c,maximum);return structuredClone(c);
 }
 private provider(c:ProviderAccessClaims){
  const p=this.config.provider;
  if(!c||c.iss!==p.issuer||c.aud!==p.audience||c.scope!==p.scope||![c.sub,c.jti].every(text)||['act','org_id','delegation_id','execution_mode'].some(k=>Object.hasOwn(c,k)))throw new ProviderRelayError('invalid_token');
  this.dates(c,3600);return structuredClone(c);
 }
 private purge(){
  const now=this.now();for(const [k,e] of this.bindings){if(e.retainUntil<=now){this.clearAuthority(e);this.bindings.delete(k);}else if(e.bound&&e.bound.deadline<=now)this.clearAuthority(e);}
 }
 private clearAuthority(entry:Entry){if(entry.timer)clearTimeout(entry.timer);entry.timer=undefined;if(entry.bound){entry.bound.cancelled=true;entry.bound.brokerToken='';}if(entry.active){entry.active.cancelled=true;entry.active.brokerToken='';}entry.bound=undefined;}
 // Trusted broker lifecycle hook; not an HTTP operation. Keep replay tombstone.
 invalidate(providerToken:string){if(!credential(providerToken))throw new ProviderRelayError('invalid_token');const entry=this.bindings.get(key(providerToken));if(entry)this.clearAuthority(entry);}
 close(){this.closed=true;for(const entry of this.bindings.values())this.clearAuthority(entry);this.bindings.clear();}
 private async run<T>(work:(phase:<R>(code:RelayCode,action:()=>Promise<R>)=>Promise<R>,signal:AbortSignal)=>Promise<T>){
  const controller=new AbortController(),deadline=Date.now()+this.config.timeoutMs;let timer:ReturnType<typeof setTimeout>|undefined;
  const alive=()=>{if(this.closed||controller.signal.aborted||Date.now()>=deadline)throw new ProviderRelayError('unavailable');};
  const phase=async<R>(code:RelayCode,action:()=>Promise<R>)=>{alive();try{const value=await action();alive();return value;}catch(e){if(controller.signal.aborted)throw new ProviderRelayError('unavailable');throw new ProviderRelayError(code);}};
  try{return await Promise.race([Promise.resolve().then(()=>work(phase,controller.signal)),new Promise<never>((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(new ProviderRelayError('unavailable'));},this.config.timeoutMs);})]);}
  finally{controller.abort();if(timer)clearTimeout(timer);}
 }
 // Called only by the trusted broker after selecting a registered agent/active grant.
 // Exact provider-token fingerprint provides correlation; body/chat identities do not.
 async bind(brokerToken:string,providerToken:string,signal?:AbortSignal):Promise<{expiresAt:number}>{
  if(signal?.aborted)throw new ProviderRelayError('unavailable');
  if(!credential(brokerToken)||!credential(providerToken)||brokerToken===providerToken)throw new ProviderRelayError('invalid_token');
  return this.run(async phase=>{
   const claims=this.delegated(await phase('invalid_token',()=>this.deps.brokerVerifier.verify(brokerToken)),this.config.brokerAudience,300);
   const provider=this.provider(await phase('invalid_token',()=>this.deps.providerVerifier.verify(providerToken)));
   await phase('binding_denied',()=>this.deps.bindProviderIdentity(structuredClone(provider),structuredClone(claims)));
   await phase('policy_denied',()=>this.deps.authoriseBroker(structuredClone(claims),{accessToken:brokerToken}));
   await phase('audit_failed',()=>this.deps.audit({event:'copilot_tool_relay',requestId:randomUUID(),phase:'bound'}));
   if(signal?.aborted)throw new ProviderRelayError('unavailable');
   this.delegated(claims,this.config.brokerAudience,300);this.provider(provider);this.purge();const fingerprint=key(providerToken);
   if(this.bindings.has(fingerprint)||this.bindings.size>=this.config.maxBindings)throw new ProviderRelayError('binding_denied');
   const deadline=Math.min(this.now()+this.config.bindingLifetimeSeconds*1000,claims.exp*1000,provider.exp*1000);
   const entry:Entry={retainUntil:provider.exp*1000,bound:{brokerToken,claims,deadline}};
   entry.timer=setTimeout(()=>this.clearAuthority(entry),Math.max(1,deadline-this.now()));entry.timer.unref();
   this.bindings.set(fingerprint,entry);
   return{expiresAt:deadline};
  });
 }
 async execute(providerToken:string,callerCredential:string):Promise<{authorized:true}>{
  if(!credential(providerToken)||!credential(callerCredential))throw new ProviderRelayError('invalid_token');
  return this.run(async(phase,signal)=>{
   const caller=await phase('invalid_token',()=>this.deps.authenticateCaller(callerCredential,signal));
   if(caller!==this.config.callerId)throw new ProviderRelayError('invalid_token');
   this.purge();const entry=this.bindings.get(key(providerToken)),bound=entry?.bound;
   if(!bound)throw new ProviderRelayError('binding_denied');
   // Claim once, synchronously, before any further await. Failures never restore it.
   entry!.bound=undefined;
   entry!.active=bound;
   signal.addEventListener('abort',()=>{this.clearAuthority(entry!);entry!.active=undefined;},{once:true});
   const requestId=randomUUID();
   const fresh=()=>{if(bound.cancelled||this.now()>=bound.deadline)throw new ProviderRelayError('binding_denied');this.delegated(bound.claims,this.config.brokerAudience,300);};
   const policy=async()=>{fresh();await phase('policy_denied',()=>this.deps.authoriseBroker(structuredClone(bound.claims),{accessToken:bound.brokerToken}));fresh();};
   try{
    await phase('audit_failed',()=>this.deps.audit({event:'copilot_tool_relay',requestId,phase:'attempt'}));
    fresh();const provider=this.provider(await phase('invalid_token',()=>this.deps.providerVerifier.verify(providerToken)));
    await phase('binding_denied',()=>this.deps.bindProviderIdentity(structuredClone(provider),structuredClone(bound.claims)));
    await policy();
    const toolToken=await phase('unavailable',()=>this.deps.issueToolToken({claims:structuredClone(bound.claims),brokerToken:bound.brokerToken,provider:structuredClone(provider)},signal));
    if(!credential(toolToken)||toolToken===providerToken||toolToken===bound.brokerToken)throw new ProviderRelayError('invalid_token');
    const tool=this.delegated(await phase('invalid_token',()=>this.deps.toolVerifier.verify(toolToken)),this.config.toolAudience,120);
    if(identity(tool)!==identity(bound.claims))throw new ProviderRelayError('binding_denied');
    await policy();this.provider(provider);this.delegated(tool,this.config.toolAudience,120);
    const result=await phase('unavailable',()=>this.deps.invokeTool(toolToken,signal));
    await policy();this.provider(provider);this.delegated(tool,this.config.toolAudience,120);
    if(!result||Object.keys(result).length!==1||result.authorized!==true)throw new ProviderRelayError('unavailable');
    await phase('audit_failed',()=>this.deps.audit({event:'copilot_tool_relay',requestId,phase:'success'}));
    fresh();this.provider(provider);this.delegated(tool,this.config.toolAudience,120);
    return{authorized:true};
   }catch(e){
    if(!signal.aborted)await phase('audit_failed',()=>this.deps.audit({event:'copilot_tool_relay',requestId,phase:'denied'}));
    throw e instanceof ProviderRelayError?e:new ProviderRelayError('unavailable');
   }
  });
 }
}

export type ProviderRelayApiInput={method:string;path:string;contentType:string;authorization:string;callerCredential:string;rawBody:string};
export class ProviderToolRelayApi {
 private relay:ProviderToolRelay;
 constructor(relay:ProviderToolRelay){if(!(relay instanceof ProviderToolRelay))throw new ProviderRelayError('configuration');this.relay=relay;}
 async handle(input:ProviderRelayApiInput):Promise<{status:number;body:Record<string,unknown>}>{
  try{
   if(input.method!=='POST'||input.path!=='/v1/copilot-tools/verify-access'||!/^application\/json(?:;\s*charset=utf-8)?$/i.test(input.contentType)||typeof input.rawBody!=='string'||Buffer.byteLength(input.rawBody)>1024)throw new ProviderRelayError('invalid_request');
   let body;try{body=JSON.parse(input.rawBody);}catch{throw new ProviderRelayError('invalid_request');}
   if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).length)throw new ProviderRelayError('invalid_request');
   const bearer=/^Bearer ([^\s]{1,16000})$/.exec(input.authorization);if(!bearer)throw new ProviderRelayError('invalid_token');
   return{status:200,body:await this.relay.execute(bearer[1],input.callerCredential)};
  }catch(e){const code=e instanceof ProviderRelayError?e.code:'unavailable';return{status:code==='invalid_request'?400:code==='invalid_token'?401:['binding_denied','policy_denied'].includes(code)?403:503,body:{error:code==='configuration'?'unavailable':code}};}
 }
}
