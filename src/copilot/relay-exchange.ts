import {waitForVerifiedValidFrom} from '../identity/verified-valid-from.ts';
import {SignJWT} from 'jose';
import {randomUUID} from 'node:crypto';
import type {DelegatedClaims,TokenVerifier} from '../adapters/token-exchange.ts';
import {ProviderRelayError} from './provider-tool-relay.ts';

type Config={brokerAudience:string;authorityIssuer:string;authorityAudience:string;upstreamIssuer:string;upstreamAudience:string;toolIssuer:string;toolAudience:string;scope:string;resource:string;tokenEndpoint:string;requestedResource:string;clientId:string;clientKeyId:string;clientAssertionAudience:string;timeoutMs:number};
type Proof={agentToken:string;login:{idToken:string;nonce:string}};
type Phase='authority-request'|'authority-verification'|'client-authentication'|'pf-a-request'|'pf-a-verification'|'pf-b-exchange'|'tool-verification';
type Dependencies={observe?:(event:{event:'relay_exchange';phase:Phase;outcome:'started'|'success'|'failure';validation?:{issuerMatches:boolean;audienceMatches:boolean;identityMatches:boolean;iatOffsetSeconds:number;nbfOffsetSeconds:number;lifetimeSeconds:number}})=>void;clientKey:CryptoKey;requestAssertion:(input:{grantId:string;mode:'interactive';operation:string;agentToken:string;login:Proof['login']},signal:AbortSignal)=>Promise<Record<string,unknown>>;assertionVerifier:TokenVerifier;upstreamVerifier:TokenVerifier;exchangeTool:(token:string)=>Promise<{accessToken:string;claims:DelegatedClaims}>;fetch?:typeof fetch};
const text=(v:unknown):v is string=>typeof v==='string'&&v.length>0&&v.length<=16000&&!/\s/.test(v);
const identity=(c:DelegatedClaims)=>JSON.stringify([c.sub,c.act?.iss,c.act?.sub,c.org_id,c.delegation_id,c.execution_mode,c.scope]);
const fail=()=>new ProviderRelayError('unavailable');
const https=(v:string)=>{const u=new URL(v);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash)throw fail();};

// Internal issuer callback: only verified custody context enters this boundary.
// External-agent keys are deliberately absent from the dependency contract.
export class RetainedProofExchange{
 private config:Config;private deps:Dependencies;
 constructor(c:Config,d:Dependencies){
  try{if(!c||Object.values(c).some(v=>typeof v==='string'&&!text(v))||![c.brokerAudience,c.authorityIssuer,c.authorityAudience,c.upstreamIssuer,c.upstreamAudience,c.toolIssuer,c.toolAudience,c.scope,c.resource,c.tokenEndpoint,c.requestedResource,c.clientId,c.clientKeyId,c.clientAssertionAudience].every(text)||!Number.isInteger(c.timeoutMs)||c.timeoutMs<100||c.timeoutMs>10000||d?.clientKey?.type!=='private'||![d?.requestAssertion,d?.assertionVerifier?.verify,d?.upstreamVerifier?.verify,d?.exchangeTool].every(v=>typeof v==='function')||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw fail();for(const v of [c.tokenEndpoint,c.clientAssertionAudience,c.authorityIssuer,c.upstreamIssuer,c.toolIssuer])https(v);const resource=new URL(c.requestedResource);if(!['urn:','api:','https:'].includes(resource.protocol)||resource.username||resource.password||resource.search||resource.hash)throw fail();this.config={...c};this.deps={...d};}catch{throw new ProviderRelayError('configuration');}
 }
 async exchange(input:Readonly<DelegatedClaims>,evidence:Proof,external:AbortSignal):Promise<string>{
  const c=this.config,d=this.deps;let phase:Phase='authority-request';const mark=(next:Phase)=>{phase=next;try{d.observe?.({event:'relay_exchange',phase,outcome:'started'});}catch{}};const controller=new AbortController(),abort=()=>controller.abort();let timer:ReturnType<typeof setTimeout>|undefined;
  const original=structuredClone(input),proof=structuredClone(evidence);
  const check=()=>{if(external.aborted||controller.signal.aborted||original.exp*1000<=Date.now())throw fail();};
  const verify=(claims:DelegatedClaims,issuer:string,audience:string,maxLifetime:number)=>{const now=Math.floor(Date.now()/1000);try{d.observe?.({event:'relay_exchange',phase,outcome:'started',validation:{issuerMatches:claims.iss===issuer,audienceMatches:claims.aud===audience,identityMatches:identity(claims)===identity(original),iatOffsetSeconds:claims.iat-now,nbfOffsetSeconds:claims.nbf-now,lifetimeSeconds:claims.exp-claims.iat}});}catch{}if(claims.iss!==issuer||claims.aud!==audience||identity(claims)!==identity(original)||![claims.iat,claims.nbf,claims.exp].every(Number.isInteger)||claims.iat>now||claims.nbf>now||claims.exp<=now||claims.exp<=claims.iat||claims.exp-claims.iat>maxLifetime)throw fail();};
  external.addEventListener('abort',abort,{once:true});
  const work=async()=>{
   check();if(original.aud!==c.brokerAudience||original.scope!==c.scope||original.execution_mode!=='interactive'||![original.iss,original.sub,original.act?.iss,original.act?.sub,original.org_id,original.delegation_id,original.jti,proof?.agentToken,proof?.login?.idToken,proof?.login?.nonce].every(text))throw fail();
   mark('authority-request');const issued=await d.requestAssertion({grantId:original.delegation_id,mode:'interactive',operation:c.scope,agentToken:proof.agentToken,login:{...proof.login}},controller.signal);check();
   if(!text(issued.assertion)||issued.expiresIn!==60)throw fail();
   mark('authority-verification');const assertion=await d.assertionVerifier.verify(issued.assertion);check();await waitForVerifiedValidFrom(assertion,controller.signal);check();verify(assertion,c.authorityIssuer,c.authorityAudience,60);
   if((assertion as any).operation!==c.scope||(assertion as any).resource!==c.resource)throw fail();
   mark('client-authentication');const clientAssertion=await new SignJWT({}).setProtectedHeader({alg:'RS256',kid:c.clientKeyId,typ:'client-authentication+jwt'}).setIssuer(c.clientId).setSubject(c.clientId).setAudience(c.clientAssertionAudience).setIssuedAt().setExpirationTime('60s').setJti(randomUUID()).sign(d.clientKey);check();
   mark('pf-a-request');const response=await(d.fetch??fetch)(c.tokenEndpoint,{method:'POST',redirect:'error',signal:controller.signal,headers:{'Content-Type':'application/x-www-form-urlencoded',Accept:'application/json'},body:new URLSearchParams({grant_type:'urn:ietf:params:oauth:grant-type:token-exchange',client_id:c.clientId,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:clientAssertion,subject_token:issued.assertion,subject_token_type:'urn:example:token-type:consented-interactive',actor_token:proof.agentToken,actor_token_type:'urn:example:token-type:agent-proof',resource:c.requestedResource,scope:c.scope,requested_token_type:'urn:ietf:params:oauth:token-type:access_token'})});check();
   if(response.status!==200)throw fail();let raw='';for await(const chunk of response.body??[]){check();raw+=Buffer.from(chunk).toString('utf8');if(Buffer.byteLength(raw)>32768)throw fail();}check();
   const value=JSON.parse(raw);if(!text(value.access_token)||value.token_type!=='Bearer'||value.issued_token_type!=='urn:ietf:params:oauth:token-type:access_token'||!Number.isInteger(value.expires_in)||value.expires_in<=0||value.expires_in>180||(value.scope!==undefined&&value.scope!==c.scope))throw fail();
   mark('pf-a-verification');const upstream=await d.upstreamVerifier.verify(value.access_token);check();await waitForVerifiedValidFrom(upstream,controller.signal);check();verify(upstream,c.upstreamIssuer,c.upstreamAudience,180);
   mark('pf-b-exchange');const tool=await d.exchangeTool(value.access_token);check();mark('tool-verification');await waitForVerifiedValidFrom(tool.claims,controller.signal);check();verify(tool.claims,c.toolIssuer,c.toolAudience,120);
   if(!text(tool.accessToken)||[value.access_token,issued.assertion,proof.agentToken,proof.login.idToken].includes(tool.accessToken))throw fail();try{d.observe?.({event:'relay_exchange',phase,outcome:'success'});}catch{}return tool.accessToken;
  };
  try{return await Promise.race([work(),new Promise<never>((_,reject)=>{controller.signal.addEventListener('abort',()=>reject(fail()),{once:true});timer=setTimeout(abort,c.timeoutMs);if(controller.signal.aborted||external.aborted){abort();reject(fail());}})]);}
  catch{try{d.observe?.({event:'relay_exchange',phase,outcome:'failure'});}catch{}throw fail();}
  finally{controller.abort();if(timer)clearTimeout(timer);external.removeEventListener('abort',abort);if(proof){proof.agentToken='';if(proof.login){proof.login.idToken='';proof.login.nonce='';}}}
 }
}
