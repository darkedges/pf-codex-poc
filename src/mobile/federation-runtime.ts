import {randomUUID,KeyObject} from 'node:crypto';
import {decodeJwt} from 'jose';
import {VaultTransitSigner} from '../identity/assertion-signer.ts';
import type {PolicyStore} from '../policy/store.ts';
import type {MobileDeviceAuthority,MobileRequestEvidence} from './device-authority.ts';
import type {MobileResourceConsent} from './resource-consent.ts';
import {MobileExecutionAuthority,type MobileRegistryConfig,type MobileIssuanceAudit} from './execution-authority.ts';
import {MobilePfExchange,type MobilePfConfig,type MobilePfDependencies,type MobilePfAudit,type MobileFederatedClaims} from './pf-exchange.ts';
import {withDeadline} from '../m365/approved-content.ts';
import {bodyHash} from '../policy/protocol.ts';
import {JwksTokenVerifier} from '../adapters/pingfederate.ts';

export type MobileFederationConfig={mode:'pingfederate';registry:Omit<MobileRegistryConfig,'store'>;pf:MobilePfConfig;agentSubject:string;authorityKeyId:string;authorityPublicKey:CryptoKey;
 workload:string;grantWorkload:string;replayCaller:string;deviceAssurance:'require-hardware-attestation'|'allow-unattested-poc';timeoutMs:number};
export type MobileFederationDependencies={store:PolicyStore;mobile:MobileDeviceAuthority;resources:MobileResourceConsent;agentSigner:VaultTransitSigner;authoritySigner:VaultTransitSigner;
 clientAKey:CryptoKey;clientAPublicKey:CryptoKey;clientBKey:CryptoKey;clientBPublicKey:CryptoKey;agentKey:CryptoKey;fetch?:typeof fetch;audit:(event:Readonly<MobileIssuanceAudit|MobilePfAudit>)=>void|Promise<void>};
const denied=()=>new Error('mobile_federation_unavailable');
type Active={evidence:unknown;grantId:string;grantVersion:number;signal:AbortSignal};
type Lease=Active&{expiresAt:number};

/** One fixed capability per protected runtime. Build separate instances for
 * documents and chat. No keys are loaded, listeners opened or trust enrolled.
 * Hosted composition must supply approved Vault-backed custody and live policy.
 */
export class MobileFederationRuntime {
 #c:MobileFederationConfig;#d:MobileFederationDependencies;#authority:MobileExecutionAuthority;#exchange:MobilePfExchange;
 #contexts=new Map<string,Active>();#controllers=new Set<AbortController>();#closed=false;
 #leases=new Map<string,Lease>();#broker:JwksTokenVerifier;
 get profile(){return structuredClone(this.#c.pf);}
 constructor(config:MobileFederationConfig,deps:MobileFederationDependencies){
  try{
   const c=structuredClone(config),d=deps,p=c.pf;
   if(c.mode!=='pingfederate'||!['m365.document.read','copilot.invoke'].includes(p.scope)||p.resource!=='sharepoint:approved-research'||!(d.agentSigner instanceof VaultTransitSigner)||!(d.authoritySigner instanceof VaultTransitSigner)||d.agentSigner===d.authoritySigner||!p.authority.keyIds.includes(c.authorityKeyId)||!Number.isInteger(c.timeoutMs)||c.timeoutMs<100||c.timeoutMs>10000||!c.agentSubject||![c.workload,c.grantWorkload,c.replayCaller].every(v=>/^[A-Za-z0-9:_-]{1,160}$/.test(v))||c.workload===c.replayCaller)throw denied();
   if(c.authorityPublicKey?.type!=='public'||d.agentKey?.type!=='public')throw denied();
   const authorityPublic=KeyObject.from(c.authorityPublicKey).export({format:'jwk'}),agentPublic=KeyObject.from(d.agentKey).export({format:'jwk'});if(authorityPublic.n===agentPublic.n&&authorityPublic.e===agentPublic.e)throw denied();
   const agent=d.store.principal(c.registry.agentId);if(!agent||agent.kind!=='agent'||agent.issuer!==p.agent.issuer||agent.subject!==c.agentSubject||agent.organisation!==c.registry.organisation)throw denied();
   this.#c=c;this.#d={...d};
   this.#authority=new MobileExecutionAuthority({...c.registry,store:d.store,mobile:d.mobile,capability:{scope:p.scope,resource:p.resource},issuer:p.authority.issuer,audience:p.authority.audience,signer:d.authoritySigner,keyId:c.authorityKeyId,publicKey:c.authorityPublicKey,agentIssuer:p.agent.issuer,agentAudience:p.agent.audience,agentKeyId:p.agent.keyId,agentKey:d.agentKey,workload:c.workload,grantWorkload:c.grantWorkload,deviceAssurance:c.deviceAssurance,assertionLifetimeSeconds:c.pf.authority.maxLifetimeSeconds as 60|180,grantBindings:d.resources,timeoutMs:c.timeoutMs,audit:d.audit});
   const exchangeDeps:MobilePfDependencies={clientAKey:d.clientAKey,clientAPublicKey:d.clientAPublicKey,clientBKey:d.clientBKey,clientBPublicKey:d.clientBPublicKey,agentKey:d.agentKey,fetch:d.fetch,
    current:(claims,signal)=>this.#current(claims,signal),
    reserve:(issuer,jti,exp)=>{if(this.#closed||issuer!==p.authority.issuer)throw denied();if(p.authority.maxLifetimeSeconds===180)d.store.consumeMobileAssertion(c.replayCaller,jti,exp);else d.store.consumeAssertion(c.replayCaller,jti,exp);},audit:d.audit};
   this.#exchange=new MobilePfExchange(p,exchangeDeps);
   this.#broker=new JwksTokenVerifier([p.b.trust],p.scope,c.timeoutMs,(url,init)=>{if(String(url)!==p.b.trust.jwksUri)throw denied();return(d.fetch??fetch)(url,{...init,redirect:'error',credentials:'omit'});});
  }catch{throw denied();}
 }
 async #evidence(value:unknown,signal:AbortSignal){
  if(this.#closed)throw denied();signal.throwIfAborted();const e=await withDeadline(this.#d.mobile.revalidateEvidence(value),signal);await withDeadline(this.#d.resources.authoriseChat(value),signal);if(this.#closed)throw denied();signal.throwIfAborted();return e;
 }
 async #current(claims:Readonly<MobileFederatedClaims>,signal:AbortSignal){
  const slot=this.#contexts.get(claims.jti);if(!slot||slot.signal.aborted||this.#closed)throw denied();
  const e=await this.#evidence(slot.evidence,signal),c=this.#c,grant=this.#d.resources.resolve(e,{scope:c.pf.scope,resource:c.pf.resource});
  if(!grant||grant.grantId!==slot.grantId||grant.grantVersion!==slot.grantVersion||claims.iss!==c.pf.authority.issuer||claims.aud!==c.pf.authority.audience||claims.sub!==e.human.subject||claims.act.iss!==e.agent.issuer||claims.act.sub!==e.agent.subject||claims.org_id!==e.organisation||claims.delegation_id!==grant.grantId||claims.execution_mode!=='interactive'||claims.scope!==c.pf.scope||claims.resource!==c.pf.resource||claims.authentication_basis!=='registered-device-key'||claims.hardware_attestation!=='UNVERIFIED'||claims.original_login_issuer!==e.human.issuer||claims.original_login_audience!==e.human.audience||claims.original_auth_time!==Math.floor(e.human.authTime/1000)||claims.presence_time!==Math.floor(e.verifiedAt/1000)||claims.exp*1000>e.expiresAt)throw denied();
 }
 async issue(evidence:unknown,external:AbortSignal){
  let jti:string|undefined;const controller=new AbortController();
  try{
   this.#prune();if(!(external instanceof AbortSignal)||this.#closed||this.#controllers.size>=64||this.#leases.size>=128)throw denied();this.#controllers.add(controller);
   const c=this.#c,d=this.#d,signal=AbortSignal.any([external,controller.signal,AbortSignal.timeout(c.timeoutMs)]),e=await this.#evidence(evidence,signal);
   const grant=d.resources.resolve(e,{scope:c.pf.scope,resource:c.pf.resource});if(!grant)throw denied();
   const now=Math.floor(Date.now()/1000),agentToken=await withDeadline(d.agentSigner.sign({iss:c.pf.agent.issuer,sub:c.agentSubject,aud:c.pf.agent.audience,scope:c.pf.scope,iat:now,nbf:now,exp:now+c.pf.authority.maxLifetimeSeconds,jti:randomUUID()}),signal);
   await this.#evidence(evidence,signal);
   const authority=await withDeadline(this.#authority.issue(evidence,agentToken,{issuer:c.pf.agent.issuer,subject:c.agentSubject,organisation:e.organisation,operation:c.pf.scope,workload:c.workload}),signal);
   // issue() already verifies the exact signed payload. This only indexes the
   // pending server context; the exchange verifies it again against pinned JWKS.
   const payload=decodeJwt(authority);if(typeof payload.jti!=='string'||this.#contexts.has(payload.jti))throw denied();jti=payload.jti;
   this.#contexts.set(jti,{evidence,grantId:grant.grantId,grantVersion:grant.grantVersion,signal});
   const output=await withDeadline(this.#exchange.exchange(authority,agentToken,signal),signal);await this.#evidence(evidence,signal);
   if(output.claims.exp*1000>e.expiresAt||this.#leases.has(bodyHash(output.accessToken)))throw denied();
   this.#leases.set(bodyHash(output.accessToken),{evidence,grantId:grant.grantId,grantVersion:grant.grantVersion,signal:external,expiresAt:Math.min(output.claims.exp*1000,e.expiresAt)});return output;
  }catch{throw denied();}
  finally{controller.abort();this.#controllers.delete(controller);if(jti)this.#contexts.delete(jti);}
 }
 #prune(){for(const [id,lease]of this.#leases)if(lease.expiresAt<=Date.now()||lease.signal.aborted)this.#leases.delete(id);}
 async authorise(accessToken:string,external:AbortSignal):Promise<MobileFederatedClaims>{
  try{
   if(!(external instanceof AbortSignal)||this.#closed||typeof accessToken!=='string'||!accessToken||accessToken.length>16000)throw denied();this.#prune();
   const lease=this.#leases.get(bodyHash(accessToken));if(!lease)throw denied();
   const c=this.#c,signal=AbortSignal.any([external,lease.signal,AbortSignal.timeout(c.timeoutMs)]),e=await this.#evidence(lease.evidence,signal),claims=await withDeadline(this.#broker.verify(accessToken),signal) as MobileFederatedClaims;
   const grant=this.#d.resources.resolve(e,{scope:c.pf.scope,resource:c.pf.resource});
   if(!grant||grant.grantId!==lease.grantId||grant.grantVersion!==lease.grantVersion||claims.iss!==c.pf.b.trust.issuer||claims.aud!==c.pf.b.trust.audience||claims.sub!==e.human.subject||claims.act.iss!==e.agent.issuer||claims.act.sub!==e.agent.subject||claims.org_id!==e.organisation||claims.delegation_id!==grant.grantId||claims.execution_mode!=='interactive'||claims.resource!==c.pf.resource||claims.authentication_basis!=='registered-device-key'||claims.hardware_attestation!=='UNVERIFIED'||claims.original_login_issuer!==e.human.issuer||claims.original_login_audience!==e.human.audience||claims.original_auth_time!==Math.floor(e.human.authTime/1000)||claims.presence_time!==Math.floor(e.verifiedAt/1000)||claims.exp*1000>lease.expiresAt)throw denied();
   await this.#evidence(lease.evidence,signal);if(this.#closed||lease.expiresAt<=Date.now())throw denied();signal.throwIfAborted();return claims;
  }catch{throw denied();}
 }
 close(){this.#closed=true;for(const controller of this.#controllers)controller.abort();this.#contexts.clear();this.#leases.clear();}
}
