import {randomUUID,KeyObject} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {decodeProtectedHeader,jwtVerify,SignJWT} from 'jose';
import {JwksTokenVerifier,type IssuerTrust} from '../adapters/pingfederate.ts';
import type {DelegatedClaims} from '../adapters/token-exchange.ts';
import {withDeadline} from '../m365/approved-content.ts';
import {waitForVerifiedValidFrom} from '../identity/verified-valid-from.ts';

export type MobileFederatedClaims=DelegatedClaims&{resource:string;authentication_basis:'registered-device-key';hardware_attestation:'UNVERIFIED';original_login_issuer:string;original_login_audience:string;original_auth_time:number;presence_time:number};
type Hop={trust:IssuerTrust;tokenEndpoint:string;clientId:string;clientKeyId:string;clientAssertionAudience:string;requestedResource:string};
export type MobilePfConfig={scope:string;resource:string;executionProfile?:'pf-minute-lifetimes';authority:IssuerTrust;a:Hop&{subjectTokenType:string;actorTokenType:string};b:Hop;agent:{issuer:string;audience:string;keyId:string};timeoutMs:number};
export type MobilePfAudit={action:'mobile.pf.exchange.authorized';grantId:string;scope:string;resource:string;issuerA:string;issuerB:string;audience:string};
export type MobilePfDependencies={clientAKey:CryptoKey;clientAPublicKey:CryptoKey;clientBKey:CryptoKey;clientBPublicKey:CryptoKey;agentKey:CryptoKey;fetch?:typeof fetch;
 current:(claims:Readonly<MobileFederatedClaims>,signal:AbortSignal)=>Promise<void>;
 reserve:(issuer:string,jti:string,exp:number)=>void|Promise<void>;
 audit:(event:Readonly<MobilePfAudit>)=>void|Promise<void>};
const denied=()=>new Error('mobile_pf_exchange_denied');
const configError=()=>new Error('mobile_pf_exchange_configuration');
function https(value:string){const u=new URL(value);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash)throw configError();return u;}
function uri(value:string){const u=new URL(value);if(!['https:','urn:','api:'].includes(u.protocol)||u.username||u.password||u.search||u.hash||/\s/.test(value)||value.length>2048)throw configError();}
const invariant=['sub','act','org_id','delegation_id','execution_mode','scope','resource','authentication_basis','hardware_attestation','original_login_issuer','original_login_audience','original_auth_time','presence_time'] as const;

/** Server-only two-domain exchange. No listener, key loading, grant creation,
 * PF configuration mutation, mock fallback or credential-bearing POST retry. */
export class MobilePfExchange {
 #c:MobilePfConfig;#d:MobilePfDependencies;#authority:JwksTokenVerifier;#a:JwksTokenVerifier;#b:JwksTokenVerifier;
 constructor(config:MobilePfConfig,deps:MobilePfDependencies){
  try{
   const c=structuredClone(config);
   if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||process.env.NODE_DEBUG||process.env.SSLKEYLOGFILE||!c.scope||/\s/.test(c.scope)||!c.resource||!Number.isInteger(c.timeoutMs)||c.timeoutMs<100||c.timeoutMs>30000||typeof deps.current!=='function'||typeof deps.reserve!=='function'||typeof deps.audit!=='function'||deps.agentKey?.type!=='public')throw configError();
   https(c.agent.issuer);if(!c.agent.audience||!c.agent.keyId)throw configError();
   if(new Set([c.authority.issuer,c.a.trust.issuer,c.b.trust.issuer]).size!==3||new Set([c.authority.audience,c.a.trust.audience,c.b.trust.audience]).size!==3)throw configError();
   if(c.executionProfile===undefined){if([c.authority,c.a.trust,c.b.trust].some(t=>t.maxLifetimeSeconds>60))throw configError();}
   else if(c.executionProfile!=='pf-minute-lifetimes'||c.authority.maxLifetimeSeconds!==180||c.a.trust.maxLifetimeSeconds!==120||c.b.trust.maxLifetimeSeconds!==60)throw configError();
   if(![60,180].includes(c.authority.maxLifetimeSeconds)||c.a.trust.maxLifetimeSeconds>c.authority.maxLifetimeSeconds||c.b.trust.maxLifetimeSeconds>c.a.trust.maxLifetimeSeconds||c.b.trust.maxLifetimeSeconds>60)throw configError();
   for(const t of [c.authority,c.a.trust,c.b.trust]){
    if(https(t.issuer).origin!==https(t.jwksUri).origin||JSON.stringify(t.algorithms)!=='["RS256"]'||t.maxLifetimeSeconds>180||t.maxLifetimeSeconds<1||JSON.stringify(t.actorIssuers)!==JSON.stringify([c.agent.issuer])||!isDeepStrictEqual(t.organisations,c.authority.organisations))throw configError();
   }
   if(c.a.clientId===c.b.clientId||c.a.clientKeyId===c.b.clientKeyId)throw configError();
   for(const [hop,key,pub] of [[c.a,deps.clientAKey,deps.clientAPublicKey],[c.b,deps.clientBKey,deps.clientBPublicKey]] as const){
    const endpoint=https(hop.tokenEndpoint);if(endpoint.origin!==https(hop.trust.issuer).origin||endpoint.pathname!=='/as/token.oauth2'||hop.clientAssertionAudience!==hop.trust.issuer||!hop.clientId||!hop.clientKeyId||key?.type!=='private'||key.algorithm.name!=='RSASSA-PKCS1-v1_5'||pub?.type!=='public'||pub.algorithm.name!=='RSASSA-PKCS1-v1_5')throw configError();uri(hop.requestedResource);
   }
   const pa=KeyObject.from(deps.clientAPublicKey).export({format:'jwk'}),pb=KeyObject.from(deps.clientBPublicKey).export({format:'jwk'});if(pa.n===pb.n&&pa.e===pb.e)throw configError();
   uri(c.a.subjectTokenType);uri(c.a.actorTokenType);
   this.#c=c;this.#d={...deps};
   const network:typeof fetch=(url,init)=>this.#network(url,init);
   this.#authority=new JwksTokenVerifier([c.authority],c.scope,c.timeoutMs,network);this.#a=new JwksTokenVerifier([c.a.trust],c.scope,c.timeoutMs,network);this.#b=new JwksTokenVerifier([c.b.trust],c.scope,c.timeoutMs,network);
  }catch{throw configError();}
 }
 #network(url:Parameters<typeof fetch>[0],init?:RequestInit){
  const c=this.#c,address=String(url),method=(init?.method??'GET').toUpperCase();
  if(!(method==='GET'&&[c.authority.jwksUri,c.a.trust.jwksUri,c.b.trust.jwksUri].includes(address)||method==='POST'&&[c.a.tokenEndpoint,c.b.tokenEndpoint].includes(address)))throw denied();
  return(this.#d.fetch??fetch)(url,{...init,redirect:'error',credentials:'omit'});
 }
 #claims(claims:DelegatedClaims):MobileFederatedClaims{
  const p=claims as MobileFederatedClaims,now=Math.floor(Date.now()/1000);
  if(p.execution_mode!=='interactive'||p.resource!==this.#c.resource||p.authentication_basis!=='registered-device-key'||p.hardware_attestation!=='UNVERIFIED'||typeof p.original_login_issuer!=='string'||typeof p.original_login_audience!=='string'||!p.original_login_audience||!Number.isSafeInteger(p.original_auth_time)||p.original_auth_time<=0||p.original_auth_time>now+5||!Number.isSafeInteger(p.presence_time)||p.presence_time>now+5||p.presence_time<p.original_auth_time-5||!/^[A-Za-z0-9:_-]{1,160}$/.test(p.jti))throw denied();
  https(p.original_login_issuer);return p;
 }
 #match(original:MobileFederatedClaims,next:MobileFederatedClaims,parentExp:number){
  if(invariant.some(field=>!isDeepStrictEqual(original[field],next[field]))||next.exp>parentExp||next.exp<=Math.floor(Date.now()/1000))throw denied();
 }
 async #post(hop:Hop,key:CryptoKey,pub:CryptoKey,subject:string,subjectType:string,signal:AbortSignal,actor?:string){
  const client=await withDeadline(new SignJWT({}).setProtectedHeader({alg:'RS256',kid:hop.clientKeyId,typ:'client-authentication+jwt'}).setIssuer(hop.clientId).setSubject(hop.clientId).setAudience(hop.clientAssertionAudience).setIssuedAt().setExpirationTime('60s').setJti(randomUUID()).sign(key),signal);
  await withDeadline(jwtVerify(client,pub,{issuer:hop.clientId,subject:hop.clientId,audience:hop.clientAssertionAudience,algorithms:['RS256'],clockTolerance:0,maxTokenAge:60}),signal);signal.throwIfAborted();
  const fields={grant_type:'urn:ietf:params:oauth:grant-type:token-exchange',client_id:hop.clientId,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:client,subject_token:subject,subject_token_type:subjectType,requested_token_type:'urn:ietf:params:oauth:token-type:access_token',resource:hop.requestedResource,scope:this.#c.scope,...(actor?{actor_token:actor,actor_token_type:this.#c.a.actorTokenType}:{})};
  const response=await withDeadline(this.#network(hop.tokenEndpoint,{method:'POST',signal,headers:{'Content-Type':'application/x-www-form-urlencoded',Accept:'application/json'},body:new URLSearchParams(fields)}),signal);
  if(!response.ok||response.redirected||!/^application\/json(?:;|$)/i.test(response.headers.get('content-type')??'')){void response.body?.cancel().catch(()=>{});throw denied();}
  const reader=response.body?.getReader();if(!reader)throw denied();let size=0;const chunks:Uint8Array[]=[];
  try{for(;;){const part=await withDeadline(reader.read(),signal);if(part.done)break;size+=part.value.byteLength;if(size>32768)throw denied();chunks.push(part.value);}}
  finally{void reader.cancel().catch(()=>{});}
  const result=JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if(result.token_type!=='Bearer'||result.issued_token_type!=='urn:ietf:params:oauth:token-type:access_token'||typeof result.access_token!=='string'||!result.access_token||result.access_token.length>16000||!Number.isInteger(result.expires_in)||result.expires_in<1||result.expires_in>hop.trust.maxLifetimeSeconds||result.scope!==undefined&&result.scope!==this.#c.scope||result.refresh_token!==undefined)throw denied();return result.access_token as string;
 }
 async exchange(authorityToken:string,agentToken:string,external:AbortSignal):Promise<{accessToken:string;claims:MobileFederatedClaims}>{
  try{
   if(!(external instanceof AbortSignal)||typeof authorityToken!=='string'||authorityToken.length>16000||typeof agentToken!=='string'||agentToken.length>16000)throw denied();
   const c=this.#c,d=this.#d,signal=AbortSignal.any([external,AbortSignal.timeout(c.timeoutMs)]);signal.throwIfAborted();
   const original=this.#claims(await withDeadline(this.#authority.verify(authorityToken),signal));await waitForVerifiedValidFrom(original,signal);
   const header=decodeProtectedHeader(agentToken);if(Object.keys(header).sort().join()!=='alg,kid,typ'||header.alg!=='RS256'||header.kid!==c.agent.keyId||header.typ!=='JWT')throw denied();
   const {payload:agent}=await withDeadline(jwtVerify(agentToken,d.agentKey,{issuer:c.agent.issuer,subject:original.act.sub,audience:c.agent.audience,algorithms:['RS256'],clockTolerance:0,maxTokenAge:c.authority.maxLifetimeSeconds,requiredClaims:['iss','sub','aud','iat','nbf','exp','jti','scope']}),signal);
   if(agent.aud!==c.agent.audience||agent.scope!==c.scope||!Number.isSafeInteger(agent.iat)||!Number.isSafeInteger(agent.exp)||Number(agent.exp)-Number(agent.iat)>c.authority.maxLifetimeSeconds||typeof agent.jti!=='string')throw denied();
   const current=async()=>{signal.throwIfAborted();if(Math.min(original.exp,Number(agent.exp))<=Math.floor(Date.now()/1000))throw denied();await withDeadline(d.current(structuredClone(original),signal),signal);signal.throwIfAborted();};
   await current();await withDeadline(Promise.resolve(d.reserve(original.iss,original.jti,original.exp)),signal);await current();
   const tokenA=await this.#post(c.a,d.clientAKey,d.clientAPublicKey,authorityToken,c.a.subjectTokenType,signal,agentToken),claimsA=this.#claims(await withDeadline(this.#a.verify(tokenA),signal));this.#match(original,claimsA,original.exp);await waitForVerifiedValidFrom(claimsA,signal);await current();
   const tokenB=await this.#post(c.b,d.clientBKey,d.clientBPublicKey,tokenA,'urn:ietf:params:oauth:token-type:access_token',signal),claimsB=this.#claims(await withDeadline(this.#b.verify(tokenB),signal));this.#match(original,claimsB,claimsA.exp);await waitForVerifiedValidFrom(claimsB,signal);await current();
   await withDeadline(Promise.resolve(d.audit(Object.freeze({action:'mobile.pf.exchange.authorized',grantId:original.delegation_id,scope:c.scope,resource:c.resource,issuerA:c.a.trust.issuer,issuerB:c.b.trust.issuer,audience:c.b.trust.audience}))),signal);
   await current();if(claimsB.exp<=Math.floor(Date.now()/1000))throw denied();return{accessToken:tokenB,claims:claimsB};
  }catch{throw denied();}
 }
}
