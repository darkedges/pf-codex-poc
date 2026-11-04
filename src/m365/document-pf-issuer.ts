import {randomUUID} from 'node:crypto';
import {SignJWT} from 'jose';
import {JwksTokenVerifier,PingFederateExchange,type IssuerTrust,type PingFederateConfig} from '../adapters/pingfederate.ts';
import type {DelegatedClaims} from '../adapters/token-exchange.ts';
import {withDeadline} from './approved-content.ts';
import {documentAudience} from './federated-document-reader.ts';
import {documentCapability} from './document-consent-policy.ts';
import {waitForVerifiedTokenActivation} from './verified-token-activation.ts';

type Input={grantId:string;login:{idToken:string;nonce:string};agentToken:string;audience:string;scope:string;signal:AbortSignal};
type Context=Pick<DelegatedClaims,'sub'|'act'|'org_id'|'delegation_id'|'execution_mode'|'scope'>;
type Config={authorityTrust:IssuerTrust;exchange:PingFederateConfig;clientA:{id:string;keyId:string;assertionAudience:string;tokenEndpoint:string};timeoutMs:number};
type Dependencies={clientAKey:CryptoKey;clientBKey:CryptoKey;authority:{request:(path:string,body:Record<string,unknown>)=>Promise<Record<string,unknown>>};current:(input:Input)=>Promise<Context>;authorise:(claims:Readonly<DelegatedClaims>,evidence?:{accessToken:string})=>Promise<void>;fetch?:typeof fetch};
const https=(s:string)=>{const u=new URL(s);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash)throw Error();return u;};
const same=(a:Context,b:Context)=>a.sub===b.sub&&a.act?.sub===b.act?.sub&&a.act?.iss===b.act?.iss&&a.org_id===b.org_id&&a.delegation_id===b.delegation_id&&a.execution_mode===b.execution_mode&&a.scope===b.scope;

// No key loading, listener, password login, grant creation or activation.
// current must independently verify the exact login and signed actor against
// authoritative recorded document consent; never derive context from a prompt.
export class DocumentPfIssuer{
 #config:Config;#deps:Dependencies;#authority:JwksTokenVerifier;
 constructor(config:Config,deps:Dependencies){
  try{
   const c=structuredClone(config),e=c.exchange;
   if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||!Number.isInteger(c.timeoutMs)||c.timeoutMs<100||c.timeoutMs>30000||deps.clientAKey.type!=='private'||deps.clientBKey.type!=='private'||deps.clientAKey.algorithm.name!=='RSASSA-PKCS1-v1_5'||deps.clientBKey.algorithm.name!=='RSASSA-PKCS1-v1_5'||typeof deps.current!=='function'||typeof deps.authorise!=='function'||typeof deps.authority?.request!=='function'||c.authorityTrust.audience!=='api://pf-a/document-consent-proof'||c.authorityTrust.maxLifetimeSeconds>180||e.upstream.length!==1||e.upstream[0].audience!=='api://gateway-2/documents'||e.upstream[0].maxLifetimeSeconds>120||e.downstream.audience!==documentAudience||e.downstream.maxLifetimeSeconds>60||e.scope!==documentCapability.scope||e.clientId!=='document-gateway-2'||e.clientAlgorithm!=='RS256'||e.targetParameter!=='resource'||e.requestedResource!=='urn:copilot:document:broker'||c.clientA.id!=='document-gateway-1'||!c.clientA.keyId)throw Error();
   const origin=https(e.upstream[0].issuer).origin;
   if(c.clientA.assertionAudience!==e.upstream[0].issuer||https(c.clientA.tokenEndpoint).origin!==origin||new URL(c.clientA.tokenEndpoint).pathname!=='/as/token.oauth2'||https(e.tokenEndpoint).origin!==https(e.downstream.issuer).origin||new URL(e.tokenEndpoint).pathname!=='/as/token.oauth2'||e.clientAssertionAudience!==e.downstream.issuer)throw Error();
   this.#config=c;this.#deps={...deps,current:deps.current.bind(deps),authorise:deps.authorise.bind(deps),authority:{request:deps.authority.request.bind(deps.authority)}};
   this.#authority=new JwksTokenVerifier([c.authorityTrust],documentCapability.scope,c.timeoutMs,deps.fetch);
   // Validate both exchange trust profiles before any issuance can occur.
   new PingFederateExchange(e,{clientKey:deps.clientBKey,authorise:deps.authorise,fetch:deps.fetch});
  }catch{throw Error('document_issuer_configuration');}
 }
 async issue(input:Input):Promise<string>{
  try{
   if(!input||Object.keys(input).sort().join()!=='agentToken,audience,grantId,login,scope,signal'||!input.login||Object.keys(input.login).sort().join()!=='idToken,nonce'||typeof input.login.idToken!=='string'||!input.login.idToken||input.login.idToken.length>16000||typeof input.login.nonce!=='string'||!input.login.nonce||input.login.nonce.length>256||typeof input.agentToken!=='string'||!input.agentToken||input.agentToken.length>16000||typeof input.grantId!=='string'||!/^[A-Za-z0-9:_-]{1,160}$/.test(input.grantId)||input.audience!==documentAudience||input.scope!==documentCapability.scope||!(input.signal instanceof AbortSignal))throw Error();
   const c=this.#config,d=this.#deps,signal=AbortSignal.any([input.signal,AbortSignal.timeout(c.timeoutMs)]),proof={...input,login:Object.freeze({...input.login}),signal};
   Object.freeze(proof);signal.throwIfAborted();
   const original=structuredClone(await withDeadline(d.current(proof),signal));
   if(original.delegation_id!==proof.grantId||original.execution_mode!=='interactive'||original.scope!==documentCapability.scope||!original.sub||!original.act?.sub||!original.act.iss||!original.org_id)throw Error();
   const current=async()=>{signal.throwIfAborted();if(!same(original,await withDeadline(d.current(proof),signal)))throw Error();signal.throwIfAborted();};
   const match=(claims:DelegatedClaims)=>{if(!same(original,claims))throw Error();};
   const issued=await withDeadline(d.authority.request('/v1/assertions',{grantId:proof.grantId,mode:'interactive',operation:documentCapability.scope,agentToken:proof.agentToken,login:proof.login}),signal);
   if(typeof issued.assertion!=='string'||issued.assertion.length>16000||issued.expiresIn!==180)throw Error();
   const consentClaims=await withDeadline(this.#authority.verify(issued.assertion),signal);match(consentClaims);await current();
   const assertion=await new SignJWT({}).setProtectedHeader({alg:'RS256',kid:c.clientA.keyId,typ:'client-authentication+jwt'}).setIssuer(c.clientA.id).setSubject(c.clientA.id).setAudience(c.clientA.assertionAudience).setIssuedAt().setExpirationTime('60s').setJti(randomUUID()).sign(d.clientAKey);
   const response=await withDeadline((d.fetch??fetch)(c.clientA.tokenEndpoint,{method:'POST',redirect:'error',signal,headers:{'Content-Type':'application/x-www-form-urlencoded',Accept:'application/json'},body:new URLSearchParams({grant_type:'urn:ietf:params:oauth:grant-type:token-exchange',client_id:c.clientA.id,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion,subject_token:issued.assertion,subject_token_type:'urn:example:token-type:document-consented-interactive',actor_token:proof.agentToken,actor_token_type:'urn:example:token-type:document-agent-proof',resource:'urn:copilot:document:gateway-2',scope:documentCapability.scope,requested_token_type:'urn:ietf:params:oauth:token-type:access_token'})}),signal);
   if(!response.ok)throw Error();
   const result=await withDeadline((async()=>{let size=0;const chunks:Uint8Array[]=[];for await(const chunk of response.body??[]){size+=chunk.byteLength;if(size>32768)throw Error();chunks.push(chunk);}return JSON.parse(Buffer.concat(chunks).toString('utf8'));})(),signal);
   if(result.token_type!=='Bearer'||result.issued_token_type!=='urn:ietf:params:oauth:token-type:access_token'||typeof result.access_token!=='string'||result.access_token.length>16000||!Number.isInteger(result.expires_in)||result.expires_in<1||result.expires_in>120||(result.scope!==undefined&&result.scope!==documentCapability.scope))throw Error();
   const upstreamVerifier=new JwksTokenVerifier(c.exchange.upstream,documentCapability.scope,c.timeoutMs,d.fetch);
   const upstreamClaims=await withDeadline(upstreamVerifier.verify(result.access_token),signal);match(upstreamClaims);
   if(upstreamClaims.exp>consentClaims.exp||consentClaims.exp<=Math.floor(Date.now()/1000))throw Error();
   await current();
   const exchange=new PingFederateExchange(c.exchange,{clientKey:d.clientBKey,authorise:async(claims,evidence)=>{match(claims);await current();await withDeadline(d.authorise(claims,evidence),signal);await current();},fetch:async(url,init)=>(d.fetch??fetch)(url,{...init,signal:AbortSignal.any([signal,...(init?.signal?[init.signal]:[])])})});
   const output=await withDeadline(exchange.exchange(result.access_token),signal);match(output.claims);await waitForVerifiedTokenActivation(output.claims,signal);await current();return output.accessToken;
  }catch{throw Error('document_issuance_denied');}
 }
}
