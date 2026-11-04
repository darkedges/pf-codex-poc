import {bodyHash} from '../policy/protocol.ts';
import type {Capability} from '../policy/contracts.ts';
import type {MobileResourceInput} from '../policy/store.ts';
import type {MobileDeviceAuthority,MobileRequestEvidence} from './device-authority.ts';
import {createMobileRegistryCheck,type MobileRegistryConfig,type MobileGrantBinding} from './execution-authority.ts';
import {parseMobileFields} from './flat-json.ts';
type Options=MobileRegistryConfig&{mobile:Pick<MobileDeviceAuthority,'revalidateEvidence'>;description:string;workload:string};
const denied=()=>new Error('mobile_resource_consent_denied');
/** Resource consent is independent of device enrollment. The protected policy
 * extension and its grants commit in one SQLite transaction, never on a phone. */
export class MobileResourceConsent {
 #c:Options;#hash:string;#termsHash:string;#current:ReturnType<typeof createMobileRegistryCheck>;
 constructor(options:Options){
  if(typeof options.description!=='string'||!options.description||options.description.length>2000||!/^[A-Za-z0-9:_-]{1,160}$/.test(options.workload)||typeof options.mobile?.revalidateEvidence!=='function')throw denied();
  this.#current=createMobileRegistryCheck(options);
  this.#c={...options,humanBindings:structuredClone(options.humanBindings),capabilities:structuredClone(options.capabilities)};
  this.#termsHash=bodyHash(JSON.stringify({version:1,description:options.description,capabilities:options.capabilities,expiry:'absolute-device-enrollment'}));
  this.#hash=bodyHash(JSON.stringify({version:1,humanBindings:options.humanBindings,agentId:options.agentId,organisation:options.organisation,termsHash:this.#termsHash,workload:options.workload}));
  options.store.prepareMobileResources(this.#hash);
 }
 terms(){return{termsHash:this.#termsHash,description:this.#c.description};}
 async #evidence(value:unknown,path:string,raw?:string){
  const e=await this.#c.mobile.revalidateEvidence(value);if(e.requestPath!==path||(raw!==undefined&&e.requestBodyHash!==bodyHash(raw)))throw denied();await this.#current(e);return e;
 }
 #input(e:MobileRequestEvidence,mode:'auto'|'manual'):MobileResourceInput{
  const c=this.#c,h=c.humanBindings.find(h=>h.issuer===e.human.issuer&&h.subject===e.human.subject&&h.audience===e.human.audience);if(!h)throw denied();
  return{enrollmentId:e.enrollmentId,deviceConsentId:e.consentId,humanId:h.principalId,agentId:c.agentId,organisation:c.organisation,termsHash:this.#termsHash,mode,expiresAt:e.enrollmentExpiresAt,capabilities:c.capabilities,workload:c.workload,loginIssuer:e.human.issuer,loginAudience:e.human.audience,authTime:e.human.authTime};
 }
 bindings(e:MobileRequestEvidence):(MobileGrantBinding&Capability)[]{
  const bundle=this.#c.store.mobileResourceBundle(this.#hash,e.enrollmentId,e.consentId);if(!bundle||bundle.consent.state!=='active'||Number(bundle.consent.expires_at)<=Date.now())return[];
  const input=this.#input(e,'auto');
  if(bundle.consent.human_id!==input.humanId||bundle.consent.agent_id!==input.agentId||bundle.consent.organisation!==input.organisation||bundle.consent.terms_hash!==this.#termsHash||bundle.consent.login_issuer!==e.human.issuer||bundle.consent.login_audience!==e.human.audience||Number(bundle.consent.auth_time)!==e.human.authTime||Number(bundle.consent.expires_at)!==e.enrollmentExpiresAt||bundle.grants.length!==this.#c.capabilities.length)throw denied();
  return bundle.grants.map(b=>{
   const g=this.#c.store.grant(String(b.grant_id));if(!g||g.state!=='active'||Number(g.version)!==Number(b.grant_version)||g.human_id!==input.humanId||g.agent_id!==input.agentId||g.recorded_by!==this.#c.workload||g.consent_reference!==bundle.consent.id||Number(g.expires_at)!==e.enrollmentExpiresAt||JSON.stringify(JSON.parse(String(g.scopes)))!==JSON.stringify([b.scope])||JSON.stringify(JSON.parse(String(g.resources)))!==JSON.stringify([b.resource])||JSON.stringify(JSON.parse(String(g.modes)))!=='["interactive"]')throw denied();
   return{enrollmentId:e.enrollmentId,deviceConsentId:e.consentId,grantId:String(b.grant_id),grantVersion:Number(b.grant_version),resourceConsentReference:String(bundle.consent.id),scope:String(b.scope),resource:String(b.resource)};
  });
 }
 resolve(e:MobileRequestEvidence,capability:Capability):MobileGrantBinding|undefined{
  const binding=this.bindings(e).find(b=>b.scope===capability.scope&&b.resource===capability.resource);if(!binding)return undefined;
  const {scope,resource,...result}=binding;return result;
 }
 async authoriseChat(value:unknown){
  try{const e=await this.#evidence(value,'/v1/mobile/chat/messages');if(this.bindings(e).length!==this.#c.capabilities.length)throw denied();}catch{throw denied();}
 }
 async approve(value:unknown,rawBody:string,signal?:AbortSignal){
  try{
   const input=parseMobileFields(rawBody,['termsHash','mode']);if(input.termsHash!==this.#termsHash||!['auto','manual'].includes(input.mode))throw denied();
   const e=await this.#evidence(value,'/v1/mobile/access/approve',rawBody);
   signal?.throwIfAborted();
   this.#c.store.approveMobileResources(this.#hash,this.#input(e,input.mode as 'auto'|'manual'));
   try{await this.#c.mobile.revalidateEvidence(value);await this.#current(e);signal?.throwIfAborted();this.bindings(e);}catch{this.#c.store.revokeMobileResources(this.#hash,this.#input(e,'manual'));throw denied();}
   return{approved:true,revoked:false,termsHash:this.#termsHash,expiresAt:e.enrollmentExpiresAt};
  }catch{throw denied();}
 }
 async status(value:unknown,rawBody='{}'){
  try{parseMobileFields(rawBody,[]);const e=await this.#evidence(value,'/v1/mobile/access/status',rawBody),bundle=this.#c.store.mobileResourceBundle(this.#hash,e.enrollmentId,e.consentId);return{approved:bundle?.consent.state==='active'&&this.bindings(e).length>0,revoked:bundle?.consent.state==='revoked',termsHash:this.#termsHash,expiresAt:e.enrollmentExpiresAt};}catch{throw denied();}
 }
 async revoke(value:unknown,rawBody='{}'){
  try{parseMobileFields(rawBody,[]);const e=await this.#evidence(value,'/v1/mobile/access/revoke',rawBody);this.#c.store.revokeMobileResources(this.#hash,this.#input(e,'manual'));return{approved:false,revoked:true,termsHash:this.#termsHash,expiresAt:e.enrollmentExpiresAt};}catch{throw denied();}
 }
}
