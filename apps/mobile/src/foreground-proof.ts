import {encode} from './device-contract.ts';

type Session={sessionId:string;sessionExpiresAt:number;serverTime:number};
export type MobileRequestPath='/v1/mobile/chat/messages'|'/v1/mobile/chat/result'|'/v1/mobile/chat/cancel'|'/v1/mobile/access/status'|'/v1/mobile/access/approve'|'/v1/mobile/access/revoke';
const bytes=(value:string)=>new TextEncoder().encode(value);
/** Ephemeral foreground proof only: no key export, persistence, provider token or grant. */
export class ForegroundProof {
 #origin:string;#now:()=>number;#beforeCreate:()=>Promise<void>;#generation=0;
 #key:CryptoKey|null=null;#session:Session|null=null;#elapsed:()=>number;#anchorElapsed=0;
 constructor(origin:string,now=()=>Date.now(),beforeCreate=async()=>{},elapsed=()=>performance.now()){
  const u=new URL(origin);if(u.protocol!=='https:'||u.origin!==origin)throw Error('invalid_mobile_origin');
  this.#origin=origin;this.#now=now;this.#beforeCreate=beforeCreate;this.#elapsed=elapsed;
 }
 async create(){
  this.lock();const generation=this.#generation;await this.#beforeCreate();
  const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
  const publicKey=encode(new Uint8Array(await crypto.subtle.exportKey('spki',pair.publicKey)));
  if(generation!==this.#generation)throw Error('mobile_session_locked');
  this.#key=pair.privateKey;return publicKey;
 }
 bind(session:Session){
  if(!this.#key||!session||Object.keys(session).sort().join()!=='serverTime,sessionExpiresAt,sessionId'||typeof session.sessionId!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(session.sessionId)||!Number.isSafeInteger(session.serverTime)||session.serverTime<=0||Math.abs(session.serverTime-this.#now())>300000||!Number.isSafeInteger(session.sessionExpiresAt)||session.sessionExpiresAt<=session.serverTime||session.sessionExpiresAt>session.serverTime+15*60000)throw Error('invalid_mobile_session');
  const elapsed=this.#elapsed();if(!Number.isFinite(elapsed)||elapsed<0)throw Error('invalid_mobile_session');this.#anchorElapsed=elapsed;this.#session={...session};
 }
 #time(){const elapsed=this.#elapsed()-this.#anchorElapsed;if(!this.#session||!Number.isFinite(elapsed)||elapsed<0)throw Error('mobile_session_locked');return this.#session.serverTime+elapsed;}
 async sign(body:string,path:MobileRequestPath='/v1/mobile/chat/messages'){
  if(!['/v1/mobile/chat/messages','/v1/mobile/chat/result','/v1/mobile/chat/cancel','/v1/mobile/access/status','/v1/mobile/access/approve','/v1/mobile/access/revoke'].includes(path))throw Error('invalid_mobile_path');
  const generation=this.#generation,key=this.#key,session=this.#session,now=this.#time();
  if(!key||!session||session.sessionExpiresAt<=now||typeof body!=='string'||bytes(body).length>16000)throw Error('mobile_session_locked');
  const iat=Math.floor(now/1000),exp=Math.min(iat+60,Math.floor(session.sessionExpiresAt/1000));if(exp<=iat)throw Error('mobile_session_expired');
  const payload={iss:session.sessionId,sub:session.sessionId,aud:this.#origin,iat,nbf:iat,exp,jti:crypto.randomUUID(),htm:'POST',htu:this.#origin+path,body_hash:encode(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes(body))))};
  const unsigned=encode(bytes(JSON.stringify({alg:'ES256',typ:'fc-mobile-request+jwt'})))+'.'+encode(bytes(JSON.stringify(payload)));
  const signature=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,bytes(unsigned));
  if(generation!==this.#generation||this.#time()>=exp*1000)throw Error('mobile_session_locked');
  return unsigned+'.'+encode(new Uint8Array(signature));
 }
 lock(){++this.#generation;this.#key=null;this.#session=null;}
}
