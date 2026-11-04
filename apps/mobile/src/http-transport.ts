import type {DeviceChallenge,DeviceSession,MobileSessionTransport} from './live-device-session.ts';
import {encode} from './device-contract.ts';
import type {MobileRequestPath} from './foreground-proof.ts';
export type ResourceConsentStatus={approved:boolean;revoked:boolean;termsHash:string;expiresAt:number};
export class MobileTransportError extends Error {
 readonly code='mobile_service_request_failed';readonly httpStatus?:number;
 constructor(status?:number){super('mobile_service_request_failed');if(Number.isInteger(status)&&Number(status)>=100&&Number(status)<=599)this.httpStatus=status;}
}
const fail=()=>new MobileTransportError();
function secureOrigin(value:string){const u=new URL(value);if(u.protocol!=='https:'||u.origin!==value)throw fail();return u.origin;}
export function parseMobileReturn(value:string,origin:string){
 const expected=secureOrigin(origin),u=new URL(value),handoff=u.searchParams.get('handoff');
 if(value.length>1024||u.origin!==expected||u.username||u.password||u.pathname!=='/mobile/return'||u.hash||[...u.searchParams.keys()].join()!=='handoff'||!handoff||!/^[\w-]{43}$/.test(handoff))throw fail();
 const decoded=Uint8Array.from(atob(handoff.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));if(encode(decoded)!==handoff)throw fail();return handoff;
}
/** Fixed-route HTTPS client. No provider token, cookies, redirect following or retries. */
export class MobileHttpsTransport implements MobileSessionTransport {
 #origin:string;#provider:URL;#fetch:typeof fetch;#pending=new Set<AbortController>();#serverClock:{time:number;elapsed:number}|null=null;
 constructor(origin:string,authorizationEndpoint:string,fetcher:typeof fetch=fetch){
  this.#origin=secureOrigin(origin);const u=new URL(authorizationEndpoint);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash)throw fail();this.#provider=u;this.#fetch=fetcher.bind(globalThis);
 }
 async #call<T>(path:string,body?:string,proof?:{sessionId:string;proof:string},parent?:AbortSignal):Promise<T>{
  const controller=new AbortController();this.#pending.add(controller);const timer=setTimeout(()=>controller.abort(),10000);
  const abort=()=>controller.abort();parent?.addEventListener('abort',abort,{once:true});if(parent?.aborted)abort();
  let reader:ReadableStreamDefaultReader<Uint8Array>|undefined;
  const cancel=()=>{void reader?.cancel().catch(()=>{});};controller.signal.addEventListener('abort',cancel,{once:true});
  try{
   controller.signal.throwIfAborted();
   if(body!==undefined&&new TextEncoder().encode(body).length>16000)throw fail();
   const response=await this.#fetch(this.#origin+path,{method:body===undefined?'GET':'POST',headers:body===undefined?{Accept:'application/json'}:{Accept:'application/json','Content-Type':'application/json',...(proof?{'X-Mobile-Session':proof.sessionId,'X-Mobile-Proof':proof.proof}:{})},body,signal:controller.signal,redirect:'error',credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer',mode:'cors'});
   if(!response.ok)throw new MobileTransportError(response.status);
   if(response.redirected||!/^application\/json(?:;|$)/i.test(response.headers.get('content-type')??'')||Number(response.headers.get('content-length')??0)>16000)throw fail();
   reader=response.body?.getReader();if(!reader)throw fail();let size=0;const chunks:Uint8Array[]=[];
   while(true){if(controller.signal.aborted)throw fail();const part=await reader.read();if(controller.signal.aborted)throw fail();if(part.done)break;size+=part.value.byteLength;if(size>16000)throw fail();chunks.push(part.value);}
   const all=new Uint8Array(size);let offset=0;for(const chunk of chunks){all.set(chunk,offset);offset+=chunk.byteLength;}
   const result=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(all));if(!result||typeof result!=='object'||Array.isArray(result))throw fail();return result as T;
  }catch(error){throw error instanceof MobileTransportError?error:fail();}
  finally{clearTimeout(timer);parent?.removeEventListener('abort',abort);controller.signal.removeEventListener('abort',cancel);if(reader){await reader.cancel().catch(()=>{});reader.releaseLock();}this.#pending.delete(controller);}
 }
 async config(){const r=await this.#call<{termsHash:string}>('/v1/mobile/config');if(Object.keys(r).join()!=='termsHash'||typeof r.termsHash!=='string'||!/^[\w-]{43}$/.test(r.termsHash))throw fail();return r;}
 async startLogin(input:{devicePublicKeySpki:string;claimHash:string}){
  const r=await this.#call<{authorizationUrl:string;expiresAt:number}>('/v1/mobile/login/start',JSON.stringify(input));
  const u=new URL(r.authorizationUrl);if(Object.keys(r).sort().join()!=='authorizationUrl,expiresAt'||u.origin!==this.#provider.origin||u.pathname!==this.#provider.pathname||u.username||u.password||u.hash||!Number.isSafeInteger(r.expiresAt)||r.expiresAt<=Date.now()||r.expiresAt>Date.now()+300000)throw fail();return r;
 }
 claim(input:{handoff:string;claimSecret:string;sessionPublicKeySpki:string;termsHash:string}){return this.#call<DeviceChallenge>('/v1/mobile/enrollment/claim',JSON.stringify(input));}
 beginResume(input:{enrollmentId:string;sessionPublicKeySpki:string}){return this.#call<DeviceChallenge>('/v1/mobile/session/challenge',JSON.stringify(input));}
 async #completeSession(path:string,input:{challengeId:string;signature:string}){const r=await this.#call<DeviceSession>(path,JSON.stringify(input));if(!Number.isSafeInteger(r.serverTime)||Math.abs(r.serverTime-Date.now())>300000)throw fail();this.#serverClock={time:r.serverTime,elapsed:performance.now()};return r;}
 completeEnrollment(input:{challengeId:string;signature:string}){return this.#completeSession('/v1/mobile/enrollment/complete',input);}
 completeResume(input:{challengeId:string;signature:string}){return this.#completeSession('/v1/mobile/session/complete',input);}
 async chat(input:{sessionId:string;proof:string;body:string},sign?:(body:string,path:MobileRequestPath)=>Promise<{sessionId:string;proof:string;body:string}>):Promise<{answer:string}>{
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),55000);this.#pending.add(controller);
  try{
   const r=await this.#call<Record<string,unknown>>('/v1/mobile/chat/messages',input.body,input,controller.signal);
   if(Object.keys(r).join()==='answer'&&typeof r.answer==='string'&&r.answer.length<=16000)return{answer:r.answer};
   if(!sign||Object.keys(r).sort().join()!=='jobId,status'||r.status!=='pending'||typeof r.jobId!=='string'||!/^[\w-]{43}$/.test(r.jobId))throw fail();
   const body=JSON.stringify({jobId:r.jobId});
   for(let i=0;i<55;i++){
    await new Promise<void>((resolve,reject)=>{if(controller.signal.aborted){reject(fail());return;}const abort=()=>{clearTimeout(wait);reject(fail());};const wait=setTimeout(()=>{controller.signal.removeEventListener('abort',abort);resolve();},1000);controller.signal.addEventListener('abort',abort,{once:true});});
    const proof=await sign(body,'/v1/mobile/chat/result');controller.signal.throwIfAborted();if(proof.sessionId!==input.sessionId||proof.body!==body)throw fail();
    const result=await this.#call<Record<string,unknown>>('/v1/mobile/chat/result',body,proof,controller.signal);
    if(Object.keys(result).join()==='status'&&result.status==='pending')continue;
    if(Object.keys(result).sort().join()==='answer,status'&&result.status==='complete'&&typeof result.answer==='string'&&result.answer.length<=16000)return{answer:result.answer};
    throw fail();
   }
   throw fail();
  }catch{throw fail();}
  finally{clearTimeout(timer);this.#pending.delete(controller);}
 }
 async resourceTerms(){const r=await this.#call<{termsHash:string;description:string}>('/v1/mobile/access/terms');if(Object.keys(r).sort().join()!=='description,termsHash'||typeof r.termsHash!=='string'||!/^[\w-]{43}$/.test(r.termsHash)||typeof r.description!=='string'||!r.description||r.description.length>2000)throw fail();return r;}
 async #consent(path:string,input:{sessionId:string;proof:string;body:string}){
  const r=await this.#call<ResourceConsentStatus>(path,input.body,input);
  const now=this.#serverClock?this.#serverClock.time+performance.now()-this.#serverClock.elapsed:Date.now();
  if(Object.keys(r).sort().join()!=='approved,expiresAt,revoked,termsHash'||typeof r.approved!=='boolean'||typeof r.revoked!=='boolean'||r.approved&&r.revoked||typeof r.termsHash!=='string'||!/^[\w-]{43}$/.test(r.termsHash)||!Number.isSafeInteger(r.expiresAt)||r.expiresAt<=now||r.expiresAt>now+30*86400000)throw fail();return r;
 }
 resourceStatus(input:{sessionId:string;proof:string;body:string}){return this.#consent('/v1/mobile/access/status',input);}
 approveResources(input:{sessionId:string;proof:string;body:string}){return this.#consent('/v1/mobile/access/approve',input);}
 revokeResources(input:{sessionId:string;proof:string;body:string}){return this.#consent('/v1/mobile/access/revoke',input);}
 cancelPending(){for(const controller of this.#pending)controller.abort();}
}
