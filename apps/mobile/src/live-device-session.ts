import type {NativeDevice} from './device-contract.ts';
import {derToP1363} from './proof.ts';
import {ForegroundProof} from './foreground-proof.ts';
import type {MobileRequestPath} from './foreground-proof.ts';

export type DeviceChallenge={challengeId:string;challenge:string;expiresAt:number};
export type DeviceSession={enrollmentId:string;enrollmentExpiresAt:number;sessionId:string;sessionExpiresAt:number;serverTime:number};
export type EnrollmentKeys={devicePublicKeySpki:string;sessionPublicKeySpki:string};
export type MobileSessionTransport={
 beginResume(input:{enrollmentId:string;sessionPublicKeySpki:string}):Promise<DeviceChallenge>;
 completeEnrollment(input:{challengeId:string;signature:string}):Promise<DeviceSession>;
 completeResume(input:{challengeId:string;signature:string}):Promise<DeviceSession>;
};
function decode(value:string,max:number){
 if(typeof value!=='string'||!value||value.length>max||!/^[\w-]+$/.test(value))throw Error();
 return Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
}
/** Protocol controller only. No mock fallback, storage, arbitrary URLs or provider tokens. */
export class LiveDeviceSession {
 #native:NativeDevice;#transport:MobileSessionTransport;#proof:ForegroundProof;#session:DeviceSession|null=null;
 #generation=0;#busy=false;
 constructor(origin:string,native:NativeDevice,transport:MobileSessionTransport){this.#native=native;this.#transport=transport;this.#proof=new ForegroundProof(origin);}
 async resume(enrollmentId:string){
  if(typeof enrollmentId!=='string'||!enrollmentId||enrollmentId.length>256)throw Error('mobile_unlock_not_completed');
  return this.#unlock('resume',async keys=>this.#transport.beginResume({enrollmentId,sessionPublicKeySpki:keys.sessionPublicKeySpki}),enrollmentId);
 }
 // Invoke only after BFF browser sign-in handoff returns, while the app is foreground.
 // The injected callback exchanges a one-use phone-bound handoff, never a PF token.
 async enroll(begin:(keys:EnrollmentKeys)=>Promise<DeviceChallenge>){return this.#unlock('enroll',begin);}
 async #unlock(kind:'enroll'|'resume',begin:(keys:EnrollmentKeys)=>Promise<DeviceChallenge>,expectedEnrollment?:string){
  if(this.#busy||this.#session)throw Error('mobile_operation_in_progress');
  const generation=++this.#generation;this.#busy=true;
  const check=()=>{if(generation!==this.#generation)throw Error();};
  try{
   const status=await this.#native.getStatus();check();if(!status.available)throw Error();
   const metadata=await this.#native.createKey();check();if(!['tee','strongbox'].includes(metadata.securityLevel))throw Error();
   const sessionPublicKeySpki=await this.#proof.create();check();
   const c=await begin({devicePublicKeySpki:metadata.publicKeySpki,sessionPublicKeySpki});check();
   if(!c||Object.keys(c).sort().join()!=='challenge,challengeId,expiresAt'||typeof c.challengeId!=='string'||!/^[a-f0-9-]{36}$/.test(c.challengeId)||typeof c.challenge!=='string'||!new RegExp('^'+kind+':[A-Za-z0-9_-]{43}$').test(c.challenge)||!Number.isSafeInteger(c.expiresAt)||c.expiresAt<=Date.now()||c.expiresAt>Date.now()+120000)throw Error();
   const proof=await this.#native.signChallenge({challenge:c.challenge});check();
   if(proof.challenge!==c.challenge||proof.publicKeySpki!==metadata.publicKeySpki||proof.algorithm!=='SHA256withECDSA-DER'||Date.now()>=c.expiresAt)throw Error();
   const key=await crypto.subtle.importKey('spki',decode(metadata.publicKeySpki,1024),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
   if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,derToP1363(decode(proof.signature,128)),new TextEncoder().encode('federated-copilot/mobile-presence/v1\n'+c.challenge)))throw Error();check();
   const complete=kind==='enroll'?this.#transport.completeEnrollment.bind(this.#transport):this.#transport.completeResume.bind(this.#transport);
   const session=await complete({challengeId:c.challengeId,signature:proof.signature});check();
   if(!session||Object.keys(session).sort().join()!=='enrollmentExpiresAt,enrollmentId,serverTime,sessionExpiresAt,sessionId'||typeof session.enrollmentId!=='string'||!session.enrollmentId||session.enrollmentId.length>256||(expectedEnrollment!==undefined&&session.enrollmentId!==expectedEnrollment)||!Number.isSafeInteger(session.serverTime)||Math.abs(session.serverTime-Date.now())>300000||!Number.isSafeInteger(session.enrollmentExpiresAt)||session.enrollmentExpiresAt<=session.serverTime||session.enrollmentExpiresAt>session.serverTime+30*86400000||session.sessionExpiresAt>session.enrollmentExpiresAt)throw Error();
   this.#proof.bind({sessionId:session.sessionId,sessionExpiresAt:session.sessionExpiresAt,serverTime:session.serverTime});this.#session={...session};
   return{enrollmentId:session.enrollmentId,enrollmentExpiresAt:session.enrollmentExpiresAt};
  }catch{
   if(generation===this.#generation){this.#proof.lock();this.#session=null;try{await this.#native.lock();}catch{}}
   throw Error('mobile_unlock_not_completed');
  }finally{if(generation===this.#generation)this.#busy=false;}
 }
 async request(body:string,path?:MobileRequestPath){
  const generation=this.#generation,session=this.#session;if(!session)throw Error('mobile_session_locked');
  const proof=await this.#proof.sign(body,path);if(generation!==this.#generation)throw Error('mobile_session_locked');
  return{sessionId:session.sessionId,proof,body};
 }
 async lock(){++this.#generation;this.#busy=false;this.#session=null;this.#proof.lock();try{await this.#native.lock();}catch{/* Remain locked. */}}
}
