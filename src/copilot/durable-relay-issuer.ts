import {waitForVerifiedValidFrom} from '../identity/verified-valid-from.ts';
import {relayLoginIssuers} from './login-issuer-trust.ts';
import {createHash} from 'node:crypto';
import type {DelegatedClaims,TokenVerifier} from '../adapters/token-exchange.ts';
import {ProviderRelayError,type ProviderRelayContext} from './provider-tool-relay.ts';
import type {RelayProofStore} from './relay-proof-store.ts';

type Config={brokerAudience:string;scope:string;agentAudience:string;loginIssuer:string;additionalLoginIssuers?:string[];loginAudience:string;timeoutMs:number};
type Dependencies={store:RelayProofStore;brokerVerifier:TokenVerifier;
 agentVerifier:{verify:(token:string)=>Promise<{iss:string;sub:string;aud:string;exp:number}>};
 loginVerifier:{verify:(token:string,nonce:string)=>Promise<{issuer:string;subject:string;audience:string;expiresAt:number}>};
 authorise:(claims:Readonly<DelegatedClaims>,evidence:{accessToken:string})=>Promise<void>;
 exchange:(claims:Readonly<DelegatedClaims>,proof:{agentToken:string;login:{idToken:string;nonce:string}},signal:AbortSignal)=>Promise<string>};
const text=(v:unknown):v is string=>typeof v==='string'&&v.length>0&&v.length<=16000&&!/\s/.test(v);
const digest=(v:string)=>createHash('sha256').update(v).digest('hex');
const binding=(v:any)=>JSON.stringify([v?.iss,v?.aud,v?.sub,v?.act?.iss,v?.act?.sub,v?.org_id,v?.delegation_id,v?.execution_mode,v?.scope,v?.iat,v?.nbf,v?.exp,v?.jti]);
const denied=()=>new ProviderRelayError('binding_denied');

// Consumes signed agent evidence handed off by the gateway. Never holds an agent key.
export class DurableRelayIssuer{
 private config:Config;private deps:Dependencies;private active=new Map<string,AbortController>();private closed=false;
 private loginIssuers:readonly string[];
 constructor(c:Config,d:Dependencies){
  if(!c||![c.brokerAudience,c.scope,c.agentAudience,c.loginIssuer,c.loginAudience].every(text)||!Number.isInteger(c.timeoutMs)||c.timeoutMs<100||c.timeoutMs>10000||![d?.store?.take,d?.store?.discard,d?.brokerVerifier?.verify,d?.agentVerifier?.verify,d?.loginVerifier?.verify,d?.authorise,d?.exchange].every(v=>typeof v==='function'))throw new ProviderRelayError('configuration');
  this.loginIssuers=relayLoginIssuers(c.loginIssuer,c.additionalLoginIssuers);this.config={...c};this.deps={...d};
 }
 forget(brokerToken:string){if(!text(brokerToken))throw denied();this.active.get(digest(brokerToken))?.abort();this.deps.store.discard(brokerToken);}
 close(){this.closed=true;for(const controller of this.active.values())controller.abort();}
 async issue(context:ProviderRelayContext,external:AbortSignal):Promise<string>{
  if(this.closed||!text(context?.brokerToken)||external.aborted)throw denied();
  const broker=context.brokerToken,expected=binding(context.claims),providerSubject=context.provider?.sub,key=digest(broker),controller=new AbortController(),d=this.deps,c=this.config;
  if(this.active.has(key))throw denied();
  const entry=d.store.take(broker);this.active.set(key,controller);
  const abort=()=>controller.abort();external.addEventListener('abort',abort,{once:true});
  let timer:ReturnType<typeof setTimeout>|undefined;
  const check=()=>{if(external.aborted||controller.signal.aborted||entry.expiresAt<=Date.now())throw denied();};
  const work=async()=>{
   check();const claims=await d.brokerVerifier.verify(broker);check();await waitForVerifiedValidFrom(claims,controller.signal);check();
   const now=Math.floor(Date.now()/1000);
   if(claims.aud!==c.brokerAudience||claims.scope!==c.scope||claims.execution_mode!=='interactive'||![claims.iss,claims.sub,claims.act?.iss,claims.act?.sub,claims.org_id,claims.delegation_id,claims.jti].every(text)||![claims.iat,claims.nbf,claims.exp].every(Number.isSafeInteger)||claims.iat>now||claims.nbf>now||claims.exp<=now||claims.exp<=claims.iat||claims.exp-claims.iat>300||binding(claims)!==expected||binding(claims)!==binding(entry.claims)||providerSubject!==claims.sub)throw denied();
   const agent=await d.agentVerifier.verify(entry.proof.agentToken);check();
   const human=await d.loginVerifier.verify(entry.proof.login.idToken,entry.proof.login.nonce);check();
   if(agent.iss!==claims.act.iss||agent.sub!==claims.act.sub||agent.aud!==c.agentAudience||!Number.isSafeInteger(agent.exp)||!this.loginIssuers.includes(human.issuer)||human.subject!==claims.sub||human.audience!==c.loginAudience||!Number.isSafeInteger(human.expiresAt))throw denied();
   const fresh=()=>{check();if(Math.min(claims.exp*1000,agent.exp*1000,human.expiresAt)<=Date.now())throw denied();};fresh();
   await d.authorise(structuredClone(claims),{accessToken:broker});fresh();
   const token=await d.exchange(structuredClone(claims),{agentToken:entry.proof.agentToken,login:{...entry.proof.login}},controller.signal);fresh();
   await d.authorise(structuredClone(claims),{accessToken:broker});fresh();
   if(!text(token)||[broker,entry.proof.agentToken,entry.proof.login.idToken].includes(token))throw denied();return token;
  };
  try{return await Promise.race([work(),new Promise<never>((_,reject)=>{controller.signal.addEventListener('abort',()=>reject(denied()),{once:true});timer=setTimeout(abort,c.timeoutMs);if(controller.signal.aborted||external.aborted){abort();reject(denied());}})]);}
  catch{throw denied();}
  finally{controller.abort();if(timer)clearTimeout(timer);external.removeEventListener('abort',abort);this.active.delete(key);delete entry.proof.providerToken;entry.proof.brokerToken='';entry.proof.agentToken='';entry.proof.login.idToken='';entry.proof.login.nonce='';}
 }
}
