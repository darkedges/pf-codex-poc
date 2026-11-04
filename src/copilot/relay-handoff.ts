import {waitForVerifiedValidFrom} from '../identity/verified-valid-from.ts';
import {relayLoginIssuers} from './login-issuer-trust.ts';
import {jwtVerify} from 'jose';import {createHash,randomUUID} from 'node:crypto';import {ProviderRelayError} from './provider-tool-relay.ts';import type {TokenVerifier,DelegatedClaims} from '../adapters/token-exchange.ts';
type Config={issuer:string;audience:string;keyId:string;key:CryptoKey;brokerAudience:string;scope:string;agentAudience:string;loginIssuer:string;additionalLoginIssuers?:string[];loginAudience:string;timeoutMs:number};
type Proof={providerToken?:string;brokerToken:string;agentToken:string;login:{idToken:string;nonce:string}};
type Dependencies={bindProvider?:(broker:string,provider:string,signal:AbortSignal)=>Promise<{expiresAt:number}>;invalidateProvider?:(provider:string)=>Promise<void>;brokerVerifier:TokenVerifier;agentVerifier:{verify:(raw:string)=>Promise<{iss:string;sub:string;aud:string;exp:number}>};loginVerifier:{verify:(token:string,nonce:string)=>Promise<{issuer:string;subject:string;audience:string;expiresAt:number}>};authorise:(c:Readonly<DelegatedClaims>,e:{accessToken:string})=>Promise<void>;reserveReplay:(issuer:string,jti:string,expiresAt:number)=>Promise<boolean>;accept:(proof:Readonly<Proof>,claims:Readonly<DelegatedClaims>,expiresAt:number,signal:AbortSignal)=>Promise<void>;commit:(brokerToken:string,signal:AbortSignal)=>void;discard:(brokerToken:string)=>Promise<void>;audit:(event:{event:'copilot_tool_relay';requestId:string;phase:'attempt'|'success'|'denied'})=>Promise<void>};
const text=(v:unknown,max=16000):v is string=>typeof v==='string'&&v.length>0&&v.length<=max&&!/\s/.test(v);
// Internal gateway control plane only. Never install this on the public tool route.
export class GatewayProofHandoff{
 private config:Config;private deps:Dependencies;
 private loginIssuers:readonly string[];
 constructor(c:Config,d:Dependencies){
  if(!c||![c.issuer,c.audience,c.keyId,c.brokerAudience,c.scope,c.agentAudience,c.loginIssuer,c.loginAudience].every(v=>text(v,2048))||c.key?.type!=='public'||!Number.isInteger(c.timeoutMs)||c.timeoutMs<100||c.timeoutMs>10000||![d?.brokerVerifier?.verify,d?.agentVerifier?.verify,d?.loginVerifier?.verify,d?.authorise,d?.reserveReplay,d?.accept,d?.commit,d?.discard,d?.audit].every(v=>typeof v==='function'))throw new ProviderRelayError('configuration');
  if((d.bindProvider!==undefined||d.invalidateProvider!==undefined)&&(typeof d.bindProvider!=='function'||typeof d.invalidateProvider!=='function'))throw new ProviderRelayError('configuration');
  this.loginIssuers=relayLoginIssuers(c.loginIssuer,c.additionalLoginIssuers);this.config={...c};this.deps={...d};
 }
 async receive(gatewayAssertion:string,rawBody:string,external?:AbortSignal):Promise<{registered:true;expiresAt:number}>{
  const c=this.config,d=this.deps,controller=new AbortController(),requestId=randomUUID();let timer:ReturnType<typeof setTimeout>|undefined;let provisional:Proof|undefined,completed=false;
  const abort=()=>controller.abort();external?.addEventListener('abort',abort,{once:true});
  const alive=()=>{if(controller.signal.aborted||external?.aborted)throw new ProviderRelayError('unavailable');};
  const work=async()=>{
   alive();await d.audit({event:'copilot_tool_relay',requestId,phase:'attempt'});alive();
   if(!text(gatewayAssertion)||typeof rawBody!=='string'||Buffer.byteLength(rawBody)>40000)throw new ProviderRelayError('invalid_request');
   const {payload:p,protectedHeader:h}=await jwtVerify(gatewayAssertion,c.key,{issuer:c.issuer,audience:c.audience,algorithms:['RS256'],clockTolerance:0,maxTokenAge:60,requiredClaims:['iss','sub','aud','iat','nbf','exp','jti','body_sha256']});alive();
   if(h.kid!==c.keyId||h.jku||h.jwk||h.x5u||h.x5c||p.aud!==c.audience||!text(p.sub,200)||!text(p.jti,200)||![p.iat,p.nbf,p.exp].every(Number.isInteger)||Number(p.exp)-Number(p.iat)>60||Number(p.nbf)>Number(p.exp)||p.body_sha256!==createHash('sha256').update(rawBody).digest('base64url'))throw new ProviderRelayError('invalid_token');
   if(!await d.reserveReplay(c.issuer,p.jti as string,Number(p.exp)*1000))throw new ProviderRelayError('binding_denied');alive();
   const body=JSON.parse(rawBody)as Proof;
   if(!body||Object.keys(body).sort().join()!==(d.bindProvider?'agentToken,brokerToken,login,providerToken':'agentToken,brokerToken,login')||(d.bindProvider&&!text(body.providerToken))||!text(body.brokerToken)||!text(body.agentToken)||!body.login||Object.keys(body.login).sort().join()!=='idToken,nonce'||!text(body.login.idToken)||!text(body.login.nonce,256)||body.login.nonce.length<16)throw new ProviderRelayError('invalid_request');
   const claims=await d.brokerVerifier.verify(body.brokerToken),agent=await d.agentVerifier.verify(body.agentToken),human=await d.loginVerifier.verify(body.login.idToken,body.login.nonce);alive();await waitForVerifiedValidFrom(claims,controller.signal);alive();const now=Math.floor(Date.now()/1000);
   if(claims.aud!==c.brokerAudience||claims.scope!==c.scope||claims.execution_mode!=='interactive'||![claims.iss,claims.sub,claims.act?.iss,claims.act?.sub,claims.org_id,claims.delegation_id,claims.jti].every(v=>text(v,2048))||![claims.iat,claims.nbf,claims.exp,agent.exp].every(Number.isInteger)||claims.exp<=now||claims.nbf>now||claims.iat>now||claims.exp-claims.iat>300||agent.iss!==claims.act.iss||agent.sub!==claims.act.sub||agent.aud!==c.agentAudience||agent.exp<=now||!this.loginIssuers.includes(human.issuer)||human.audience!==c.loginAudience||human.subject!==claims.sub||!Number.isFinite(human.expiresAt))throw new ProviderRelayError('invalid_token');
   await d.authorise(structuredClone(claims),{accessToken:body.brokerToken});alive();
   provisional=body;let providerExpiry=Infinity;if(d.bindProvider){providerExpiry=(await d.bindProvider(body.brokerToken,body.providerToken!,controller.signal)).expiresAt;alive();if(!Number.isSafeInteger(providerExpiry))throw new ProviderRelayError('invalid_token');}
   const expiresAt=Math.min(providerExpiry,Number(p.exp)*1000,claims.exp*1000,agent.exp*1000,human.expiresAt,Date.now()+120000);if(expiresAt<=Date.now())throw new ProviderRelayError('invalid_token');
   // accept stages unusable proof; synchronous commit follows the successful audit.
   await d.accept(structuredClone(body),structuredClone(claims),expiresAt,controller.signal);alive();
   await d.audit({event:'copilot_tool_relay',requestId,phase:'success'});alive();d.commit(body.brokerToken,controller.signal);completed=true;return{registered:true as const,expiresAt};
  };
  try{return await Promise.race([work(),new Promise<never>((_,reject)=>{controller.signal.addEventListener('abort',()=>reject(new ProviderRelayError('unavailable')),{once:true});timer=setTimeout(abort,c.timeoutMs);if(controller.signal.aborted||external?.aborted){abort();reject(new ProviderRelayError('unavailable'));}})]);}
  catch{controller.abort();if(provisional?.providerToken&&d.invalidateProvider)try{await Promise.race([d.invalidateProvider(provisional.providerToken),new Promise<void>(done=>setTimeout(done,1000))]);}catch{}if(provisional)try{await Promise.race([d.discard(provisional.brokerToken),new Promise<void>(done=>setTimeout(done,1000))]);}catch{}try{await Promise.race([d.audit({event:'copilot_tool_relay',requestId,phase:'denied'}),new Promise<void>(done=>setTimeout(done,100))]);}catch{}throw new ProviderRelayError('binding_denied');}
  finally{external?.removeEventListener('abort',abort);if(!completed)controller.abort();if(timer)clearTimeout(timer);}
 }
}
