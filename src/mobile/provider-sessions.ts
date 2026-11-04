import {randomUUID} from 'node:crypto';
import {SignJWT} from 'jose';
import {ProviderAccessVerifier,type ProviderAccessTrust} from '../identity/provider-access.ts';
import {withDeadline} from '../m365/approved-content.ts';
import {waitForVerifiedValidFrom} from '../identity/verified-valid-from.ts';
import type {MobileRequestEvidence} from './device-authority.ts';
import {bodyHash} from '../policy/protocol.ts';

type Human=MobileRequestEvidence['human'];
type RecordValue={schema:1;state:'ready'|'refreshing'|'revoked';enrollmentId:string;enrollmentExpiresAt:number;human:Human;clientId:string;accessToken:string;accessExpiresAt:number;refreshToken:string};
type StoreConfig={origin:string;mount:string;token:()=>string;timeoutMs:number;fetch?:typeof fetch};
const failure=()=>Error('mobile_provider_signin_required');
const opaque=(v:unknown,max=16000):v is string=>typeof v==='string'&&v.length>0&&v.length<=max&&!/[\s\u0000-\u001f\u007f]/.test(v);
function secure(v:string){const u=new URL(v);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash)throw failure();return u;}
async function json(response:Response,max:number,signal:AbortSignal){
 if(!/^application\/json(?:;|$)/i.test(response.headers.get('content-type')??''))throw failure();
 const reader=response.body?.getReader();if(!reader)throw failure();let n=0;const chunks:Uint8Array[]=[];
 try{for(;;){const p=await withDeadline(reader.read(),signal);if(p.done)break;n+=p.value.byteLength;if(n>max)throw failure();chunks.push(p.value);}return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));}
 finally{void reader.cancel().catch(()=>{});reader.releaseLock();}
}
/** Exact KV-v2 data path, CAS writes, no list/history/redirect/retry operations.
 * The deployment must use a dedicated mount with max_versions=1 and a scoped
 * renewable workload token. This class does not create either or load secrets. */
export class VaultMobileProviderStore {
 #c:StoreConfig;
 constructor(c:StoreConfig){if(secure(c.origin).origin!==c.origin||!/^mobile-[a-z0-9-]{1,48}$/.test(c.mount)||!Number.isInteger(c.timeoutMs)||c.timeoutMs<100||c.timeoutMs>10000||typeof c.token!=='function'||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw failure();this.#c={...c};}
 async #call(id:string,signal:AbortSignal,write?:{version:number;value:RecordValue}){
  if(!/^[\w-]{43}$/.test(id))throw failure();const c=this.#c,token=c.token();if(!opaque(token,4096))throw failure();
  const result=await withDeadline((c.fetch??fetch)(c.origin+'/v1/'+c.mount+'/data/'+id,{method:write?'POST':'GET',redirect:'error',credentials:'omit',signal:AbortSignal.any([signal,AbortSignal.timeout(c.timeoutMs)]),headers:{Accept:'application/json','Content-Type':'application/json','X-Vault-Token':token},...(write?{body:JSON.stringify({options:{cas:write.version},data:write.value})}:{})}),signal);
  if(!write&&result.status===404){void result.body?.cancel().catch(()=>{});return null;}if(result.status!==200||result.redirected){void result.body?.cancel().catch(()=>{});throw failure();}return json(result,60000,signal);
 }
 async read(id:string,signal:AbortSignal):Promise<{version:number;value:RecordValue}|null>{try{const r=await this.#call(id,signal);if(r===null)return null;const version=r?.data?.metadata?.version,value=r?.data?.data;if(!Number.isSafeInteger(version)||version<1||!value||value.enrollmentId!==id)throw failure();return{version,value};}catch{throw failure();}}
 async write(id:string,version:number,value:RecordValue,signal:AbortSignal){try{if(!Number.isSafeInteger(version)||version<0)throw failure();const r=await this.#call(id,signal,{version,value});if(r?.data?.version!==version+1)throw failure();return version+1;}catch{throw failure();}}
}
type Config={trust:ProviderAccessTrust;tokenEndpoint:string;clientId:string;keyId:string;clientKey:CryptoKey;timeoutMs:number;minimumValiditySeconds?:number};
type Dependencies={store:VaultMobileProviderStore;revalidate:(value:unknown)=>Promise<MobileRequestEvidence>;authorise:(value:unknown)=>Promise<void>;fetch?:typeof fetch};
const same=(a:Human,b:Human)=>a?.issuer===b?.issuer&&a.subject===b.subject&&a.audience===b.audience&&a.authTime===b.authTime;
/** Provider credentials are not execution authority or Graph delegated tokens.
 * enroll() is an internal completion hook, called only after actual PF login
 * plus the device signature succeeded. Nothing in this class is a phone route. */
export class MobileProviderSessions {
 #c:Config;#d:Dependencies;#verifier:ProviderAccessVerifier;#busy=new Set<string>();#closed=false;#stop=new AbortController();
 constructor(c:Config,d:Dependencies){
  if(!Number.isInteger(c.minimumValiditySeconds??60)||(c.minimumValiditySeconds??60)<60||(c.minimumValiditySeconds??60)>c.trust.maxLifetimeSeconds)throw failure();
  if(secure(c.tokenEndpoint).origin!==secure(c.trust.issuer).origin||new URL(c.tokenEndpoint).pathname!=='/as/token.oauth2'||new URL(c.trust.jwksUri).origin!==new URL(c.trust.issuer).origin||!opaque(c.clientId)||!opaque(c.keyId)||c.clientKey?.type!=='private'||c.clientKey.algorithm.name!=='RSASSA-PKCS1-v1_5'||!Number.isInteger(c.timeoutMs)||c.timeoutMs<100||c.timeoutMs>10000||!(d.store instanceof VaultMobileProviderStore)||typeof d.revalidate!=='function'||typeof d.authorise!=='function')throw failure();
  this.#c={...c,trust:structuredClone(c.trust)};this.#d={...d};this.#verifier=new ProviderAccessVerifier(c.trust,c.timeoutMs,(url,init)=>{if(String(url)!==c.trust.jwksUri)throw failure();return(d.fetch??fetch)(url,{...init,redirect:'error',credentials:'omit'});});
 }
 get profile(){return{trust:structuredClone(this.#c.trust),clientId:this.#c.clientId};}
 async #claims(token:string,subject:string,signal:AbortSignal){const claims=await withDeadline(this.#verifier.verify(token),signal);if(claims.sub!==subject)throw failure();await waitForVerifiedValidFrom(claims,signal);if(claims.exp*1000<=Date.now()+5000)throw failure();return claims;}
 async enroll(completion:{enrollmentId:string;enrollmentExpiresAt:number},human:Human,tokens:{accessToken:string;refreshToken:string}){
  try{
   if(this.#closed||!/^[\w-]{43}$/.test(completion.enrollmentId)||!Number.isSafeInteger(completion.enrollmentExpiresAt)||completion.enrollmentExpiresAt<=Date.now()||completion.enrollmentExpiresAt>Date.now()+30*86400000||human.issuer!==this.#c.trust.issuer||human.audience!==this.#c.clientId||!Number.isSafeInteger(human.authTime)||human.authTime<Date.now()-300000||human.authTime>Date.now()+5000||!opaque(tokens.refreshToken,4096))throw failure();
   const signal=AbortSignal.any([this.#stop.signal,AbortSignal.timeout(this.#c.timeoutMs)]),claims=await this.#claims(tokens.accessToken,human.subject,signal),old=await this.#d.store.read(completion.enrollmentId,signal);
   const value:RecordValue={schema:1,state:'ready',enrollmentId:completion.enrollmentId,enrollmentExpiresAt:completion.enrollmentExpiresAt,human:{issuer:human.issuer,subject:human.subject,audience:human.audience,authTime:human.authTime},clientId:this.#c.clientId,accessToken:tokens.accessToken,accessExpiresAt:claims.exp*1000,refreshToken:tokens.refreshToken};
   await this.#d.store.write(completion.enrollmentId,old?.version??0,value,signal);signal.throwIfAborted();
  }catch{throw failure();}
 }
 async #current(value:unknown,signal:AbortSignal){if(this.#closed)throw failure();const e=await withDeadline(this.#d.revalidate(value),signal);await withDeadline(this.#d.authorise(value),signal);if(this.#closed)throw failure();signal.throwIfAborted();return e;}
 async get(value:unknown,external:AbortSignal):Promise<string>{
  let id:string|undefined,locked=false;
  try{
   const signal=AbortSignal.any([external,this.#stop.signal,AbortSignal.timeout(this.#c.timeoutMs)]),e=await this.#current(value,signal);id=e.enrollmentId;
   if(this.#busy.has(id)||this.#busy.size>=128)throw failure();this.#busy.add(id);locked=true;
   const found=await this.#d.store.read(id,signal),r=found?.value;
   if(!found||!r||Object.keys(r).sort().join()!=='accessExpiresAt,accessToken,clientId,enrollmentExpiresAt,enrollmentId,human,refreshToken,schema,state'||r.schema!==1||r.state!=='ready'||r.enrollmentId!==id||r.enrollmentExpiresAt!==e.enrollmentExpiresAt||r.enrollmentExpiresAt<=Date.now()||!same(r.human,e.human)||r.clientId!==this.#c.clientId||!opaque(r.accessToken)||!opaque(r.refreshToken,4096))throw failure();
   const minimum=(this.#c.minimumValiditySeconds??60)*1000;
   if(r.accessExpiresAt>Date.now()+minimum){const claims=await this.#claims(r.accessToken,e.human.subject,signal);if(claims.exp*1000!==r.accessExpiresAt)throw failure();await this.#current(value,signal);return r.accessToken;}
   // Persist the spent state before transmitting. A lost response/crash requires
   // fresh sign-in; it must never cause a second use of the same refresh token.
   const version=await this.#d.store.write(id,found.version,{...r,state:'refreshing',accessToken:'',refreshToken:'',accessExpiresAt:0},signal);
   await this.#current(value,signal);const c=this.#c,assertion=await withDeadline(new SignJWT({}).setProtectedHeader({alg:'RS256',kid:c.keyId,typ:'client-authentication+jwt'}).setIssuer(c.clientId).setSubject(c.clientId).setAudience(c.trust.issuer).setIssuedAt().setExpirationTime('60s').setJti(randomUUID()).sign(c.clientKey),signal);
   const response=await withDeadline((this.#d.fetch??fetch)(c.tokenEndpoint,{method:'POST',redirect:'error',credentials:'omit',signal,headers:{'Content-Type':'application/x-www-form-urlencoded',Accept:'application/json'},body:new URLSearchParams({grant_type:'refresh_token',refresh_token:r.refreshToken,scope:c.trust.scope,client_id:c.clientId,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion})}),signal);
   if(response.status!==200||response.redirected)throw failure();const result=await json(response,40000,signal);
   if(result?.token_type!=='Bearer'||result.scope!==c.trust.scope||!opaque(result.access_token)||!opaque(result.refresh_token,4096)||result.refresh_token===r.refreshToken||!Number.isInteger(result.expires_in)||result.expires_in<1||result.expires_in>c.trust.maxLifetimeSeconds)throw failure();
   const claims=await this.#claims(result.access_token,e.human.subject,signal);if(claims.exp*1000<=Date.now()+minimum)throw failure();await this.#current(value,signal);
   await this.#d.store.write(id,version,{...r,state:'ready',accessToken:result.access_token,refreshToken:result.refresh_token,accessExpiresAt:claims.exp*1000},signal);
   await this.#current(value,signal);return result.access_token;
  }catch{throw failure();}finally{if(id&&locked)this.#busy.delete(id);}
 }
 async retire(value:unknown){
  try{const signal=AbortSignal.any([this.#stop.signal,AbortSignal.timeout(this.#c.timeoutMs)]),e=await withDeadline(this.#d.revalidate(value),signal);if(e.requestPath!=='/v1/mobile/access/revoke'||e.requestBodyHash!==bodyHash('{}'))throw failure();const found=await this.#d.store.read(e.enrollmentId,signal);if(!found)return;if(found.value.enrollmentExpiresAt!==e.enrollmentExpiresAt||!same(found.value.human,e.human))throw failure();await this.#d.store.write(e.enrollmentId,found.version,{...found.value,state:'revoked',accessToken:'',refreshToken:'',accessExpiresAt:0},signal);}catch{throw failure();}
 }
 close(){this.#closed=true;this.#stop.abort();}
}
