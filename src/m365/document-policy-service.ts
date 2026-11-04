import {importJWK,jwtVerify,decodeProtectedHeader} from 'jose';
import {PolicyApi,type PolicyCaller} from '../policy/api.ts';import type {PolicyStore} from '../policy/store.ts';import {PolicyError,type VerifiedLogin} from '../policy/contracts.ts';import {bodyHash} from '../policy/protocol.ts';
import {GrantAuthority,type AssertionRequest,type AuthenticatedActor} from '../identity/grant-authority.ts';import type {AssertionSigner} from '../identity/assertion-signer.ts';
import {JwksTokenVerifier,type IssuerTrust} from '../adapters/pingfederate.ts';import {documentCapability,documentConsentRecorder} from './document-consent-policy.ts';import {documentAudience,documentAgentAudience} from './federated-document-reader.ts';import {withDeadline} from './approved-content.ts';

type Config={origin:string;organisation:string;authorityKey:CryptoKey;agent:{issuer:string;subject:string;keyId:string;key:CryptoKey};workloadKeys:Record<'consent'|'agent'|'reader',Record<string,unknown>>;proofTrusts:IssuerTrust[];timeoutMs:number};
type Dependencies={store:PolicyStore;signer:AssertionSigner;loginVerifier:{verify:(token:string,nonce:string)=>Promise<VerifiedLogin>};fetch?:typeof fetch};
const authorityIssuer='https://partner-a.test/document-authority',authorityAudience='api://pf-a/document-consent-proof';
const capability=(c:any)=>c?.scope===documentCapability.scope&&c?.resource===documentCapability.resource;

// No listener, registry seeding, private key loading or production mock fallback.
// Supply a document-scoped handle on the existing authoritative policy database;
// it must explicitly permit consentDurationsSeconds:[300]. This factory never
// creates a copied registry or registers workload trust with an existing service.
export async function createDocumentPolicyService(config:Config,deps:Dependencies){
 try{
  const c={...config,agent:{...config.agent},workloadKeys:structuredClone(config.workloadKeys),proofTrusts:structuredClone(config.proofTrusts)},origin=new URL(c.origin);
  if(origin.protocol!=='https:'||origin.username||origin.password||origin.search||origin.hash||origin.pathname!=='/'||origin.origin!==c.origin||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||!Number.isInteger(c.timeoutMs)||c.timeoutMs<100||c.timeoutMs>30000||c.organisation!=='partner-a'||c.agent.issuer!=='https://partner-a.test/agents'||c.agent.subject!=='partner-a:agent-research'||!c.agent.keyId||c.agent.key.type!=='public'||c.agent.key.algorithm.name!=='RSASSA-PKCS1-v1_5'||c.authorityKey.type!=='public'||c.authorityKey.algorithm.name!=='RSASSA-PKCS1-v1_5'||typeof deps.signer?.sign!=='function'||Object.keys(c.workloadKeys).sort().join()!=='agent,consent,reader'||!c.proofTrusts.length||c.proofTrusts.length>2||c.proofTrusts.some(t=>!['api://gateway-2/documents',documentAudience].includes(t.audience)||t.maxLifetimeSeconds>(t.audience===documentAudience?60:120)||JSON.stringify(t.algorithms)!=='["RS256"]'||JSON.stringify(t.organisations)!==JSON.stringify([c.organisation])||JSON.stringify(t.actorIssuers)!==JSON.stringify([c.agent.issuer])))throw Error();
  const store=deps.store,moduli=new Set(),callers:PolicyCaller[]=[];
  for(const role of ['consent','agent','reader'] as const){
   const jwk=c.workloadKeys[role];if(!jwk||Object.keys(jwk).sort().join()!=='alg,e,kid,kty,n,use'||jwk.kty!=='RSA'||jwk.alg!=='RS256'||jwk.use!=='sig'||jwk.kid!=='document-policy-'+role||typeof jwk.n!=='string'||Buffer.from(jwk.n,'base64url').length<384||moduli.has(jwk.n))throw Error();moduli.add(jwk.n);
   const key=await importJWK(jwk,'RS256');if(key instanceof Uint8Array||key.type!=='public'||Number((key.algorithm as RsaHashedKeyAlgorithm).modulusLength)<3072)throw Error();
   callers.push({id:'policy-document-'+role,kid:String(jwk.kid),key,roles:role==='agent'?['authority']:role==='consent'?['consent']:['decision'],organisations:[c.organisation],...(role==='agent'?{agent:{issuer:c.agent.issuer,subject:c.agent.subject,operations:[documentCapability.scope]}}:{})});
  }
  const bounded=<T>(value:Promise<T>)=>withDeadline(value,AbortSignal.timeout(c.timeoutMs));
  const owned=(id:string)=>{
   const g=store.grant(id),s=store.consentForGrant(id),duration=g?Number(g.expires_at)-Number(g.approved_at):NaN;
   if(!g||!s||g.recorded_by!==documentConsentRecorder||g.organisation!==c.organisation||g.agent_id!=='container-agent'||duration<=0||duration>300000||!Number.isSafeInteger(duration)||JSON.stringify(JSON.parse(String(g.scopes)))!==JSON.stringify([documentCapability.scope])||JSON.stringify(JSON.parse(String(g.resources)))!==JSON.stringify([documentCapability.resource])||JSON.stringify(JSON.parse(String(g.modes)))!=='["interactive"]')throw new PolicyError();return g;
  };
  const view=new Proxy(store,{get(target,property){
   if(property==='createConsentedGrant')return(login,agent,modes,duration,cap,workload,terms)=>{if(agent!=='container-agent'||JSON.stringify(modes)!=='["interactive"]'||duration!==300||!capability(cap)||workload!==documentConsentRecorder)throw new PolicyError();return target.createConsentedGrant(login,agent,modes,duration,cap,workload,terms);};
   if(property==='ownedGrants')return login=>target.ownedGrants(login).filter(g=>{try{owned(String(g.id));return true;}catch{return false;}});
   if(property==='revokeOwnedGrant')return(id,login,workload)=>{owned(id);return target.revokeOwnedGrant(id,login,workload);};
   if(property==='authoriseConsentedGrant')return(id,actor,mode,cap,workload,login)=>{owned(id);if(mode!=='interactive'||!capability(cap)||!login||store.consentForGrant(id)?.token_hash!==login.tokenHash)throw new PolicyError();return target.authoriseConsentedGrant(id,actor,mode,cap,workload,login);};
   if(property==='decide')return(claims,cap,workload)=>{owned(claims.delegation_id);if(claims.execution_mode!=='interactive'||claims.scope!==documentCapability.scope||!capability(cap))throw new PolicyError();return target.decide(claims,cap,workload);};
   const value=Reflect.get(target,property,target);return typeof value==='function'?value.bind(target):value;
  }});
  const loginVerifier={verify:async(token:string,nonce:string)=>{const login=await bounded(deps.loginVerifier.verify(token,nonce)),now=Date.now();if(!login||login.tokenHash!==bodyHash(token)||login.nonceHash!==bodyHash(nonce)||![login.issuedAt,login.authTime,login.expiresAt].every(Number.isSafeInteger)||login.issuedAt<now-300000||login.issuedAt>now+5000||login.authTime<now-300000||login.authTime>now+5000||login.expiresAt<=now)throw new PolicyError();return Object.freeze({...login});}};
  const signer:AssertionSigner={sign:async(payload)=>{
   const g=owned(String(payload.delegation_id));if(g.state!=='active'||Number(g.expires_at)<=Date.now())throw new PolicyError();
   const exp=Math.min(Number(payload.iat)+180,Math.floor(Number(g.expires_at)/1000),Math.floor(Number(g.consent_expires_at)/1000));if(!Number.isSafeInteger(exp)||exp<=Math.floor(Date.now()/1000))throw new PolicyError();
   const expected={...payload,exp},token=await bounded(deps.signer.sign(expected));
   const {payload:actual,protectedHeader:h}=await jwtVerify(token,c.authorityKey,{issuer:authorityIssuer,audience:authorityAudience,algorithms:['RS256'],requiredClaims:['sub','act','iat','nbf','exp','jti'],maxTokenAge:180});
   if(h.kid!=='document-authority-v1'||h.jku||h.jwk||h.x5u||h.x5c||JSON.stringify(actual)!==JSON.stringify(expected)||actual.exp!<=Math.floor(Date.now()/1000)||owned(String(payload.delegation_id)).state!=='active')throw new PolicyError();return token;
  }};
  class DocumentAuthority extends GrantAuthority{
   override async issue(input:AssertionRequest,binding?:AuthenticatedActor){
    if(input.mode!=='interactive'||!input.login)throw new PolicyError();
    const h=decodeProtectedHeader(input.agentToken);if(h.alg!=='RS256'||h.kid!==c.agent.keyId||h.jku||h.jwk||h.x5u||h.x5c)throw new PolicyError();
    const {payload:p}=await jwtVerify(input.agentToken,c.agent.key,{issuer:c.agent.issuer,subject:c.agent.subject,audience:documentAgentAudience,algorithms:['RS256'],maxTokenAge:240,requiredClaims:['iss','sub','aud','iat','nbf','exp','jti']});
    if(p.aud!==documentAgentAudience||typeof p.jti!=='string'||!p.jti||!Number.isSafeInteger(p.iat)||!Number.isSafeInteger(p.exp)||p.exp!-p.iat!>240||p.exp!<=Math.floor(Date.now()/1000))throw new PolicyError();
    const login=await loginVerifier.verify(input.login.idToken,input.login.nonce),now=Math.floor(Date.now()/1000);
    if(p.exp!<now+180||Math.floor(login.expiresAt/1000)<now+180)throw new PolicyError();
    const token=await super.issue(input,binding),{payload:issued}=await jwtVerify(token,c.authorityKey,{issuer:authorityIssuer,audience:authorityAudience,algorithms:['RS256']});
    if(issued.exp!>p.exp!||issued.exp!>Math.floor(login.expiresAt/1000))throw new PolicyError();return token;
   }
  }
  const authority=new DocumentAuthority({store:view,capability:documentCapability,issuer:authorityIssuer,audience:authorityAudience,signer,agentIssuer:c.agent.issuer,agentAudience:documentAgentAudience,agentKeyId:c.agent.keyId,agentKey:c.agent.key,loginVerifier});
  class DocumentApi extends PolicyApi{
   override async handle(input:Parameters<PolicyApi['handle']>[0]){const r=await super.handle(input);if(input.path==='/v1/assertions'&&r.status===200)r.body.expiresIn=180;return r;}
  }
  return new DocumentApi({store:view,origin:()=>c.origin,callers,authority,loginVerifier,consentPolicy:{agentId:'container-agent',capability:documentCapability,durationsSeconds:[300],modes:['interactive']},verifier:new JwksTokenVerifier(c.proofTrusts,documentCapability.scope,c.timeoutMs,deps.fetch)});
 }catch{throw new PolicyError('configuration');}
}
