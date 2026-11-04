import {createHash} from 'node:crypto';
import type {DelegatedClaims,TokenVerifier} from '../adapters/token-exchange.ts';
import type {VerifiedLogin} from '../policy/contracts.ts';
import {ProviderRelayError,type ProviderRelayContext} from './provider-tool-relay.ts';
type LoginProof={idToken:string;nonce:string};
type Config={brokerAudience:string;scope:string;loginIssuer:string;loginAudience:string;ttlSeconds:number;maxSessions:number;timeoutMs:number};
type Dependencies={brokerVerifier:TokenVerifier;loginVerifier:{verify:(token:string,nonce:string)=>Promise<VerifiedLogin>};authorise:(c:Readonly<DelegatedClaims>,e:{accessToken:string})=>Promise<void>;exchange:(c:Readonly<DelegatedClaims>,login:LoginProof,signal:AbortSignal)=>Promise<string>;now?:()=>number};
type Entry={binding:string;deadline:number;retainUntil:number;login?:LoginProof;cancelled:boolean;timer?:ReturnType<typeof setTimeout>};
const fingerprint=(raw:string)=>createHash('sha256').update(raw).digest('hex');
const binding=(c:DelegatedClaims)=>JSON.stringify([c.iss,c.aud,c.sub,c.act?.iss,c.act?.sub,c.org_id,c.delegation_id,c.execution_mode,c.scope,c.iat,c.nbf,c.exp,c.jti]);
const text=(v:unknown,max=16000):v is string=>typeof v==='string'&&v.length>0&&v.length<=max&&!/\s/.test(v);
// Internal broker custody only: there is no public proof-registration route.
export class InteractiveRelayIssuer{
 private config:Config;private deps:Dependencies;private entries=new Map<string,Entry>();
 constructor(c:Config,d:Dependencies){
  if(!c||Object.keys(c).sort().join()!=='brokerAudience,loginAudience,loginIssuer,maxSessions,scope,timeoutMs,ttlSeconds'||![c.brokerAudience,c.scope,c.loginIssuer,c.loginAudience].every(v=>text(v,2048))||!Number.isInteger(c.ttlSeconds)||c.ttlSeconds<1||c.ttlSeconds>120||!Number.isInteger(c.maxSessions)||c.maxSessions<1||c.maxSessions>1000||!Number.isInteger(c.timeoutMs)||c.timeoutMs<100||c.timeoutMs>10000||typeof d?.brokerVerifier?.verify!=='function'||typeof d?.loginVerifier?.verify!=='function'||typeof d?.authorise!=='function'||typeof d?.exchange!=='function')throw new ProviderRelayError('configuration');
  this.config={...c};this.deps={...d};
 }
 private now(){return(this.deps.now??Date.now)();}
 private claims(c:DelegatedClaims){
  const now=Math.floor(this.now()/1000);
  if(!c||c.aud!==this.config.brokerAudience||c.scope!==this.config.scope||c.execution_mode!=='interactive'||![c.iss,c.sub,c.act?.iss,c.act?.sub,c.org_id,c.delegation_id,c.jti].every(v=>text(v,2048))||![c.iat,c.nbf,c.exp].every(Number.isInteger)||c.exp<=now||c.iat>now+5||c.nbf>now+5||c.exp<=c.iat||c.exp-c.iat>300)throw new ProviderRelayError('invalid_token');return structuredClone(c);
 }
 private clear(e:Entry){e.cancelled=true;e.login=undefined;if(e.timer)clearTimeout(e.timer);e.timer=undefined;}
 private purge(){const now=this.now();for(const [k,e]of this.entries){if(e.retainUntil<=now){this.clear(e);this.entries.delete(k);}else if(e.deadline<=now)this.clear(e);}}
 forget(brokerToken:string){if(!text(brokerToken))throw new ProviderRelayError('invalid_token');const e=this.entries.get(fingerprint(brokerToken));if(e)this.clear(e);}
 private async bounded<T>(external:AbortSignal|undefined,action:(check:()=>void,signal:AbortSignal)=>Promise<T>){
  const controller=new AbortController();let timer:ReturnType<typeof setTimeout>|undefined;
  const abort=()=>controller.abort(),check=()=>{if(controller.signal.aborted||external?.aborted)throw new ProviderRelayError('unavailable');};
  external?.addEventListener('abort',abort,{once:true});
  try{check();return await Promise.race([Promise.resolve().then(()=>action(check,controller.signal)),new Promise<never>((_,reject)=>{timer=setTimeout(()=>{abort();reject(new ProviderRelayError('unavailable'));},this.config.timeoutMs);})]);}
  catch(e){throw e instanceof ProviderRelayError?e:new ProviderRelayError('unavailable');}
  finally{controller.abort();external?.removeEventListener('abort',abort);if(timer)clearTimeout(timer);}
 }
 private async verifyLogin(login:LoginProof,c:DelegatedClaims){
  let verified:VerifiedLogin;
  try{verified=await this.deps.loginVerifier.verify(login.idToken,login.nonce);}catch{throw new ProviderRelayError('invalid_token');}
  if(verified.issuer!==this.config.loginIssuer||verified.audience!==this.config.loginAudience||verified.subject!==c.sub||!Number.isFinite(verified.expiresAt)||verified.expiresAt<=this.now())throw new ProviderRelayError('invalid_token');return verified;
 }
 private async authorise(c:DelegatedClaims,raw:string){try{await this.deps.authorise(structuredClone(c),{accessToken:raw});}catch{throw new ProviderRelayError('policy_denied');}}
 async remember(brokerToken:string,login:LoginProof,signal?:AbortSignal):Promise<{expiresAt:number}>{
  if(!text(brokerToken)||!login||Object.keys(login).sort().join()!=='idToken,nonce'||!text(login.idToken)||!text(login.nonce,256)||login.nonce.length<16)throw new ProviderRelayError('invalid_token');
  const proof={...login};
  return this.bounded(signal,async check=>{
   const claims=this.claims(await this.deps.brokerVerifier.verify(brokerToken));check();const verified=await this.verifyLogin(proof,claims);await this.authorise(claims,brokerToken);check();this.claims(claims);this.purge();
   const key=fingerprint(brokerToken);if(this.entries.has(key)||this.entries.size>=this.config.maxSessions)throw new ProviderRelayError('binding_denied');
   const deadline=Math.min(this.now()+this.config.ttlSeconds*1000,claims.exp*1000,verified.expiresAt),entry:Entry={binding:binding(claims),deadline,retainUntil:claims.exp*1000,login:proof,cancelled:false};
   entry.timer=setTimeout(()=>this.clear(entry),Math.max(1,deadline-this.now()));entry.timer.unref();this.entries.set(key,entry);return{expiresAt:deadline};
  });
 }
 async issue(context:ProviderRelayContext,signal:AbortSignal):Promise<string>{
  if(!context||!text(context.brokerToken))throw new ProviderRelayError('invalid_token');
  this.purge();const entry=this.entries.get(fingerprint(context.brokerToken));
  if(!entry?.login||entry.cancelled)throw new ProviderRelayError('binding_denied');
  const proof=entry.login;entry.login=undefined; // one use, including failure/cancellation
  try{return await this.bounded(signal,async(check,inner)=>{
   const fresh=()=>{check();if(entry.cancelled||entry.deadline<=this.now())throw new ProviderRelayError('binding_denied');};fresh();
   const claims=this.claims(await this.deps.brokerVerifier.verify(context.brokerToken));
   if(binding(claims)!==entry.binding||binding(context.claims)!==entry.binding||context.provider?.sub!==claims.sub)throw new ProviderRelayError('binding_denied');
   await this.verifyLogin(proof,claims);await this.authorise(claims,context.brokerToken);fresh();
   const token=await this.deps.exchange(structuredClone(claims),{...proof},inner);fresh();
   await this.authorise(claims,context.brokerToken);this.claims(claims);fresh();
   if(!text(token)||token===context.brokerToken||token===proof.idToken)throw new ProviderRelayError('invalid_token');return token;
  });}finally{this.clear(entry);proof.idToken='';proof.nonce='';}
 }
}
