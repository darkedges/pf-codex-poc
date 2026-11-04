import {OidcClient} from '../identity/oidc.ts';
import {MobileDeviceAuthority} from './device-authority.ts';
import {MobileProviderSessions} from './provider-sessions.ts';
import {bodyHash} from '../policy/protocol.ts';
import type {VerifiedLogin} from '../policy/contracts.ts';

type Pending={login:VerifiedLogin;tokens:{accessToken:string;refreshToken:string};expires:number};
const failure=()=>Error('mobile_provider_signin_required');
/** Keeps provider credentials out of MobileLoginHandoff and phone responses.
 * Only the actual device authority's successful signature completion can enroll
 * them. Pending credentials are volatile and cannot recover across a restart. */
export class MobileProviderEnrollment {
 #oidc:OidcClient;#mobile:MobileDeviceAuthority;#provider:MobileProviderSessions;
 #redeemed=new Map<string,Pending>();#challenges=new Map<string,Pending>();#closed=false;
 constructor(oidc:OidcClient,mobile:MobileDeviceAuthority,provider:MobileProviderSessions){if(!(oidc instanceof OidcClient)||!(mobile instanceof MobileDeviceAuthority)||!(provider instanceof MobileProviderSessions))throw failure();this.#oidc=oidc;this.#mobile=mobile;this.#provider=provider;}
 #prune(){for(const map of [this.#redeemed,this.#challenges])for(const [id,r]of map)if(r.expires<=Date.now())map.delete(id);if(this.#closed||this.#redeemed.size+this.#challenges.size>=128)throw failure();}
 readonly oidc={
  start:(state:string,nonce:string,verifier:string)=>{this.#prune();return this.#oidc.start(state,nonce,verifier);},
  redeem:async(code:string,verifier:string,nonce:string)=>{
   try{this.#prune();const r=await this.#oidc.redeem(code,verifier,nonce);this.#prune();if(!r.providerCredential||this.#redeemed.has(r.login.tokenHash))throw failure();this.#redeemed.set(r.login.tokenHash,{login:r.login,tokens:r.providerCredential,expires:Date.now()+120000});return{idToken:r.idToken};}catch{throw failure();}
  }
 };
 get authority(){return{
  termsHash:this.#mobile.termsHash,
  beginEnrollment:async(proof:{idToken:string;nonce:string},input:Parameters<MobileDeviceAuthority['beginEnrollment']>[1])=>{
   try{this.#prune();const hash=bodyHash(proof.idToken),r=this.#redeemed.get(hash);this.#redeemed.delete(hash);if(!r||r.login.nonceHash!==bodyHash(proof.nonce))throw failure();const c=await this.#mobile.beginEnrollment(proof,input);this.#prune();this.#challenges.set(c.challengeId,r);return c;}catch{throw failure();}
  },
  completeEnrollment:async(input:Parameters<MobileDeviceAuthority['completeEnrollment']>[0])=>{
   try{this.#prune();const r=this.#challenges.get(input.challengeId);this.#challenges.delete(input.challengeId);if(!r)throw failure();const completion=await this.#mobile.completeEnrollment(input);this.#prune();await this.#provider.enroll(completion,{issuer:r.login.issuer,subject:r.login.subject,audience:r.login.audience,authTime:r.login.authTime},r.tokens);if(this.#closed)throw failure();return completion;}catch{throw failure();}
  },
  beginResume:this.#mobile.beginResume.bind(this.#mobile),completeResume:this.#mobile.completeResume.bind(this.#mobile),authorize:this.#mobile.authorize.bind(this.#mobile)
 };}
 close(){this.#closed=true;this.#redeemed.clear();this.#challenges.clear();}
}
