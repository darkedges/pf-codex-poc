import {createPublicKey,randomBytes,timingSafeEqual} from 'node:crypto';
import {bodyHash} from '../policy/protocol.ts';
import type {MobileDeviceAuthority} from './device-authority.ts';

type Oidc={start(state:string,nonce:string,verifier:string):Promise<string>;redeem(code:string,verifier:string,nonce:string):Promise<{idToken:string}>};
type Options={origin:string;authorizationEndpoint:string;authority:Pick<MobileDeviceAuthority,'termsHash'|'beginEnrollment'>;oidc:Oidc;now?:()=>number};
type Pending={deviceKey:string;claimHash:string;nonce:string;verifier:string;expires:number};
type Returned={deviceKey:string;claimHash:string;nonce:string;idToken:string;expires:number};
const failure=()=>new Error('mobile_login_not_completed');
function exact(value:unknown,keys:string[]){if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join()!==keys.sort().join())throw failure();}
function opaque(value:unknown){if(typeof value!=='string'||!/^[\w-]{43}$/.test(value)||Buffer.from(value,'base64url').toString('base64url')!==value)throw failure();return value;}
const fresh=()=>randomBytes(32).toString('base64url');

/** Server-side external-browser handoff, with no public listener or token-return API.
 * Pending transactions intentionally die on restart. Long-lived enrollments live in
 * MobileDeviceAuthority instead. Inject the configured PKCE OidcClient, never a mock.
 */
export class MobileLoginHandoff {
 #pending=new Map<string,Pending>();#returned=new Map<string,Returned>();
 #closed=false;#inflight=0;
 #origin:string;#endpoint:string;#authority:Options['authority'];#oidc:Oidc;#now:()=>number;
 constructor(options:Options){
  const origin=new URL(options.origin),endpoint=new URL(options.authorizationEndpoint);
  if(origin.protocol!=='https:'||origin.origin!==options.origin||endpoint.protocol!=='https:'||endpoint.username||endpoint.password||endpoint.search||endpoint.hash)throw failure();
  this.#origin=origin.origin;this.#endpoint=endpoint.href;this.#authority=options.authority;this.#oidc=options.oidc;this.#now=options.now??Date.now;
 }
 #prune(){const now=this.#now();for(const [id,p] of this.#pending)if(p.expires<=now)this.#pending.delete(id);for(const [id,r] of this.#returned)if(r.expires<=now)this.#returned.delete(id);}
 async start(input:{devicePublicKeySpki:string;claimHash:string}){
  let state:string|undefined;
  try{
   if(this.#closed)throw failure();
   exact(input,['devicePublicKeySpki','claimHash']);opaque(input.claimHash);
   if(typeof input.devicePublicKeySpki!=='string'||input.devicePublicKeySpki.length>1024||!/^[\w-]+$/.test(input.devicePublicKeySpki))throw failure();
   const der=Buffer.from(input.devicePublicKeySpki,'base64url'),key=createPublicKey({key:der,format:'der',type:'spki'});
   if(der.toString('base64url')!==input.devicePublicKeySpki||key.asymmetricKeyType!=='ec'||key.asymmetricKeyDetails?.namedCurve!=='prime256v1'||!key.export({type:'spki',format:'der'}).equals(der))throw failure();
   this.#prune();if(this.#pending.size+this.#returned.size+this.#inflight>=64)throw failure();
   state=fresh();const p:Pending={deviceKey:input.devicePublicKeySpki,claimHash:input.claimHash,nonce:fresh(),verifier:fresh(),expires:this.#now()+300000};
   this.#pending.set(state,p);
   const authorizationUrl=await this.#oidc.start(state,p.nonce,p.verifier),url=new URL(authorizationUrl),pinned=new URL(this.#endpoint);
   if(this.#closed||url.origin!==pinned.origin||url.pathname!==pinned.pathname||url.username||url.password||url.hash||this.#now()>=p.expires)throw failure();
   return{authorizationUrl,expiresAt:p.expires};
  }catch{if(state)this.#pending.delete(state);throw failure();}
 }
 async callback(input:{state:string;code:string}){
  let redeeming=false;
  try{
   if(this.#closed)throw failure();
   exact(input,['state','code']);opaque(input.state);this.#prune();const p=this.#pending.get(input.state);this.#pending.delete(input.state);
   if(!p||typeof input.code!=='string'||!input.code||input.code.length>4096)throw failure();
   this.#inflight++;redeeming=true;
   const result=await this.#oidc.redeem(input.code,p.verifier,p.nonce);
   if(this.#closed||this.#now()>=p.expires||typeof result.idToken!=='string'||!result.idToken||result.idToken.length>16000)throw failure();
   this.#prune();if(this.#returned.size>=64)throw failure();
   const handoff=fresh();this.#returned.set(handoff,{deviceKey:p.deviceKey,claimHash:p.claimHash,nonce:p.nonce,idToken:result.idToken,expires:this.#now()+120000});
   const url=new URL('/mobile/return',this.#origin);url.searchParams.set('handoff',handoff);
   return{returnUrl:url.href};
  }catch{throw failure();}finally{if(redeeming)this.#inflight--;}
 }
 async claim(input:{handoff:string;claimSecret:string;sessionPublicKeySpki:string;termsHash:string}){
  let claiming=false;
  try{
   if(this.#closed)throw failure();
   exact(input,['handoff','claimSecret','sessionPublicKeySpki','termsHash']);opaque(input.handoff);
   this.#prune();const r=this.#returned.get(input.handoff);this.#returned.delete(input.handoff);
   if(!r||!timingSafeEqual(Buffer.from(bodyHash(opaque(input.claimSecret))),Buffer.from(r.claimHash))||input.termsHash!==this.#authority.termsHash)throw failure();
   this.#inflight++;claiming=true;
   const result=await this.#authority.beginEnrollment({idToken:r.idToken,nonce:r.nonce},{devicePublicKeySpki:r.deviceKey,sessionPublicKeySpki:input.sessionPublicKeySpki,termsHash:input.termsHash});
   if(this.#closed)throw failure();return result;
  }catch{throw failure();}finally{if(claiming)this.#inflight--;}
 }
 close(){this.#closed=true;this.#pending.clear();this.#returned.clear();}
}
