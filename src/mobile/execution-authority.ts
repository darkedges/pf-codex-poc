import {randomUUID} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {decodeProtectedHeader,jwtVerify} from 'jose';
import type {PolicyStore} from '../policy/store.ts';
import type {Capability} from '../policy/contracts.ts';
import type {AssertionSigner} from '../identity/assertion-signer.ts';
import type {AuthenticatedActor} from '../identity/grant-authority.ts';
import type {MobileDeviceAuthority,MobileRequestEvidence} from './device-authority.ts';
import {withDeadline} from '../m365/approved-content.ts';
import {bodyHash} from '../policy/protocol.ts';

type Registry={store:PolicyStore;humanBindings:{issuer:string;subject:string;audience:string;principalId:string}[];agentId:string;organisation:string;capabilities:Capability[]};
type BoundGrant={enrollmentId:string;deviceConsentId:string;grantId:string;grantVersion:number;resourceConsentReference:string};
export type MobileGrantResolver={resolve(evidence:MobileRequestEvidence,capability:Capability):BoundGrant|undefined};
export type MobileIssuanceAudit={action:'mobile.assertion.authorized';grantId:string;grantVersion:number;scope:string;resource:string;organisation:string;humanRef:string;actorRef:string;issuer:string;audience:string;authenticationBasis:'registered-device-key';hardwareAttestation:'UNVERIFIED'};
type Options=Registry&{mobile:Pick<MobileDeviceAuthority,'revalidateEvidence'>;capability:Capability;issuer:string;audience:string;signer:AssertionSigner;keyId:string;publicKey:CryptoKey;
 agentIssuer:string;agentAudience:string;agentKeyId:string;agentKey:CryptoKey;workload:string;grantWorkload:string;
 deviceAssurance:'require-hardware-attestation'|'allow-unattested-poc';assertionLifetimeSeconds?:60|180;grants?:BoundGrant[];grantBindings?:MobileGrantResolver;timeoutMs?:number;audit:(event:Readonly<MobileIssuanceAudit>)=>void|Promise<void>};
export type MobileRegistryConfig=Registry;
export type MobileExecutionConfig=Options;
export type MobileGrantBinding=BoundGrant;
const deny=()=>new Error('mobile_execution_denied');
const exact=(value:unknown,keys:string[])=>{if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join()!==[...keys].sort().join())throw deny();};
function secure(value:string){const u=new URL(value);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash)throw deny();}
function registry(config:Registry,binding:Pick<MobileRequestEvidence,'human'|'agent'|'organisation'|'capabilities'>){
 const entry=config.humanBindings.find(h=>h.issuer===binding.human.issuer&&h.subject===binding.human.subject&&h.audience===binding.human.audience);
 if(!entry||binding.organisation!==config.organisation||config.store.organisation(config.organisation)?.status!=='active')throw deny();
 const human=config.store.principal(entry.principalId),agent=config.store.principal(config.agentId);
 if(!human||human.kind!=='human'||human.status!=='active'||human.subject!==entry.subject||human.organisation!==config.organisation||!agent||agent.kind!=='agent'||agent.status!=='active'||agent.organisation!==config.organisation||agent.issuer!==binding.agent.issuer||agent.subject!==binding.agent.subject)throw deny();
 if(!binding.capabilities.length||binding.capabilities.length!==config.capabilities.length||binding.capabilities.some(c=>!config.capabilities.some(allowed=>allowed.scope===c.scope&&allowed.resource===c.resource)))throw deny();
 return{human,agent};
}
function registryConfig(input:Registry):Registry{
 if(!input.humanBindings?.length||input.humanBindings.length>16||!input.agentId||!input.organisation||!input.capabilities?.length)throw deny();
 for(const h of input.humanBindings){exact(h,['issuer','subject','audience','principalId']);secure(h.issuer);if(!h.subject||!h.audience||!h.principalId)throw deny();}
 for(const c of input.capabilities){exact(c,['scope','resource']);if(typeof c.scope!=='string'||!c.scope||/\s/.test(c.scope)||typeof c.resource!=='string'||!c.resource||c.resource.length>2048)throw deny();}
 if(new Set(input.humanBindings.map(h=>JSON.stringify([h.issuer,h.subject,h.audience]))).size!==input.humanBindings.length||new Set(input.capabilities.map(c=>JSON.stringify([c.scope,c.resource]))).size!==input.capabilities.length)throw deny();
 return{store:input.store,humanBindings:structuredClone(input.humanBindings),agentId:input.agentId,organisation:input.organisation,capabilities:structuredClone(input.capabilities)};
}
/** Registry/lifecycle check only: does not create a grant or accept a device claim. */
export function createMobileRegistryCheck(input:Registry){const config=registryConfig(input);return async(binding:Pick<MobileRequestEvidence,'human'|'agent'|'organisation'|'capabilities'>)=>{try{registry(config,binding);}catch{throw deny();}};}

/** Internal resumed-interactive issuance, not a handset API. Resource grants must
 * be approved independently and bound through protected configuration. No grant
 * creation, fresh-login substitution or default hardware-assurance exception.
 */
export class MobileExecutionAuthority {
 #c:Options;
 constructor(options:Options){
  const r=registryConfig(options);secure(options.issuer);secure(options.agentIssuer);
  if(!Number.isInteger(options.timeoutMs??10000)||(options.timeoutMs??10000)<100||(options.timeoutMs??10000)>10000)throw deny();
  if(typeof options.audit!=='function')throw deny();
  if(options.assertionLifetimeSeconds!==undefined&&![60,180].includes(options.assertionLifetimeSeconds))throw deny();
  if(!options.audience||options.publicKey?.type!=='public'||options.agentKey?.type!=='public'||!options.agentAudience||!options.agentKeyId||!options.keyId||!options.workload||!options.grantWorkload||!['require-hardware-attestation','allow-unattested-poc'].includes(options.deviceAssurance)||typeof options.signer?.sign!=='function'||typeof options.mobile?.revalidateEvidence!=='function'||!r.capabilities.some(c=>c.scope===options.capability?.scope&&c.resource===options.capability?.resource))throw deny();
  const fixed=options.grants!==undefined,dynamic=options.grantBindings!==undefined;if(fixed===dynamic||fixed&&(!Array.isArray(options.grants)||options.grants.length>128)||dynamic&&typeof options.grantBindings?.resolve!=='function')throw deny();
  for(const g of options.grants??[]){exact(g,['enrollmentId','deviceConsentId','grantId','grantVersion','resourceConsentReference']);if(!g.enrollmentId||!g.deviceConsentId||!g.grantId||!g.resourceConsentReference||g.resourceConsentReference===g.deviceConsentId||!Number.isSafeInteger(g.grantVersion)||g.grantVersion<1)throw deny();}
  if(options.grants&&new Set(options.grants.map(g=>JSON.stringify([g.enrollmentId,g.deviceConsentId]))).size!==options.grants.length)throw deny();
  this.#c={...options,...r,capability:structuredClone(options.capability),grants:options.grants?structuredClone(options.grants):undefined};
 }
 #grant(e:MobileRequestEvidence){
  const c=this.#c,{human,agent}=registry(c,e),bound=c.grantBindings?c.grantBindings.resolve(e,c.capability):c.grants!.find(g=>g.enrollmentId===e.enrollmentId&&g.deviceConsentId===e.consentId);
  if(!bound||!e.capabilities.some(v=>v.scope===c.capability.scope&&v.resource===c.capability.resource))throw deny();
  exact(bound,['enrollmentId','deviceConsentId','grantId','grantVersion','resourceConsentReference']);if(bound.enrollmentId!==e.enrollmentId||bound.deviceConsentId!==e.consentId||bound.resourceConsentReference===e.consentId||!Number.isSafeInteger(bound.grantVersion)||bound.grantVersion<1)throw deny();
  const g=c.store.grant(bound.grantId);
  if(!g||g.state!=='active'||Number(g.version)!==bound.grantVersion||g.human_id!==human.id||g.agent_id!==agent.id||g.organisation!==c.organisation||g.recorded_by!==c.grantWorkload||g.consent_reference!==bound.resourceConsentReference||Number(g.expires_at)<=Date.now()||Number(g.expires_at)>e.enrollmentExpiresAt||Number(g.consent_expires_at)<Number(g.expires_at))throw deny();
  if(JSON.stringify(JSON.parse(String(g.modes)))!=='["interactive"]'||JSON.stringify(JSON.parse(String(g.scopes)))!==JSON.stringify([c.capability.scope])||JSON.stringify(JSON.parse(String(g.resources)))!==JSON.stringify([c.capability.resource]))throw deny();
  return g;
 }
 async issue(evidence:unknown,agentToken:string,binding:AuthenticatedActor){
  try{
   const c=this.#c,signal=AbortSignal.timeout(c.timeoutMs??10000),e=await withDeadline(c.mobile.revalidateEvidence(evidence),signal);
   if(e.requestPath!=='/v1/mobile/chat/messages')throw deny();
   if(c.deviceAssurance!=='allow-unattested-poc'||e.hardwareAttestation!=='UNVERIFIED')throw deny();
   exact(binding,['issuer','subject','operation','organisation','workload']);
   if(binding.issuer!==c.agentIssuer||binding.subject!==e.agent.subject||binding.operation!==c.capability.scope||binding.organisation!==e.organisation||binding.workload!==c.workload||e.agent.issuer!==c.agentIssuer)throw deny();
   if(typeof agentToken!=='string'||agentToken.length>16000)throw deny();const h=decodeProtectedHeader(agentToken);exact(h,['alg','kid','typ']);if(h.alg!=='RS256'||h.kid!==c.agentKeyId||h.typ!=='JWT')throw deny();
   const lifetime=c.assertionLifetimeSeconds??60;
   const {payload:a}=await jwtVerify(agentToken,c.agentKey,{issuer:c.agentIssuer,subject:e.agent.subject,audience:c.agentAudience,algorithms:['RS256'],clockTolerance:0,maxTokenAge:lifetime,requiredClaims:['iss','sub','aud','iat','nbf','exp','jti','scope']});
   if(a.aud!==c.agentAudience||a.scope!==c.capability.scope||typeof a.jti!=='string'||!Number.isSafeInteger(a.iat)||!Number.isSafeInteger(a.exp)||Number(a.exp)-Number(a.iat)>lifetime)throw deny();
   const g=this.#grant(e),now=Math.floor(Date.now()/1000),exp=Math.min(now+lifetime,Math.floor(e.expiresAt/1000),Math.floor(Number(g.expires_at)/1000),Number(a.exp));if(exp<=now)throw deny();
   if(lifetime===180)c.store.consumeMobileAssertion(c.workload,a.jti,Number(a.exp));else c.store.consumeAssertion(c.workload,a.jti,Number(a.exp));
   const payload={iss:c.issuer,aud:c.audience,sub:e.human.subject,act:{iss:e.agent.issuer,sub:e.agent.subject},actor_iss:e.agent.issuer,actor_sub:e.agent.subject,org_id:e.organisation,delegation_id:String(g.id),execution_mode:'interactive',scope:c.capability.scope,operation:c.capability.scope,resource:c.capability.resource,authentication_basis:'registered-device-key',hardware_attestation:'UNVERIFIED',original_login_issuer:e.human.issuer,original_login_audience:e.human.audience,original_auth_time:Math.floor(e.human.authTime/1000),presence_time:Math.floor(e.verifiedAt/1000),iat:now,nbf:now,exp,jti:randomUUID()};
   signal.throwIfAborted();const token=await withDeadline(c.signer.sign(payload),signal);
   const checked=await jwtVerify(token,c.publicKey,{issuer:c.issuer,audience:c.audience,algorithms:['RS256'],clockTolerance:0,maxTokenAge:60});
   exact(checked.protectedHeader,['alg','kid','typ']);if(checked.protectedHeader.kid!==c.keyId||checked.protectedHeader.typ!=='JWT'||!isDeepStrictEqual(checked.payload,payload))throw deny();
   await withDeadline(c.mobile.revalidateEvidence(evidence),signal);this.#grant(e);signal.throwIfAborted();
   await withDeadline(Promise.resolve(c.audit(Object.freeze({action:'mobile.assertion.authorized',grantId:String(g.id),grantVersion:Number(g.version),scope:c.capability.scope,resource:c.capability.resource,organisation:e.organisation,humanRef:bodyHash(JSON.stringify([e.human.issuer,e.human.subject])),actorRef:bodyHash(JSON.stringify([e.agent.issuer,e.agent.subject])),issuer:c.issuer,audience:c.audience,authenticationBasis:'registered-device-key',hardwareAttestation:'UNVERIFIED'}))),signal);
   await withDeadline(c.mobile.revalidateEvidence(evidence),signal);this.#grant(e);signal.throwIfAborted();if(exp<=Math.floor(Date.now()/1000))throw deny();return token;
  }catch{throw deny();}
 }
}
