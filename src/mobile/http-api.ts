import {randomUUID} from 'node:crypto';
import type {MobileDeviceAuthority} from './device-authority.ts';
import type {MobileLoginHandoff} from './login-handoff.ts';
import type {MobileResourceConsent} from './resource-consent.ts';
import {parseMobileFields as parse} from './flat-json.ts';
import type {MobileChatJobs} from './chat-jobs.ts';

type Authority=Pick<MobileDeviceAuthority,'termsHash'|'beginResume'|'completeEnrollment'|'completeResume'|'authorize'>;
type Handoff=Pick<MobileLoginHandoff,'start'|'callback'|'claim'>;
type Evidence=Awaited<ReturnType<MobileDeviceAuthority['authorize']>>;
type Options={origin:string;authority:Authority;handoff:Handoff;timeoutMs?:number;
 resourceConsent?:Pick<MobileResourceConsent,'terms'|'approve'|'status'|'revoke'|'authoriseChat'>;
 jobs?:MobileChatJobs;
 execute?:(input:{evidence:Evidence;question:string;signal:AbortSignal})=>Promise<{answer:string}>;
 observe?:(event:{route:string;status:number;durationMs:number})=>void};
const routes=new Map([
 ['/v1/mobile/login/start',['devicePublicKeySpki','claimHash']],
 ['/v1/mobile/enrollment/claim',['handoff','claimSecret','sessionPublicKeySpki','termsHash']],
 ['/v1/mobile/enrollment/complete',['challengeId','signature']],
 ['/v1/mobile/session/challenge',['enrollmentId','sessionPublicKeySpki']],
 ['/v1/mobile/session/complete',['challengeId','signature']],
 ['/v1/mobile/chat/messages',['question']],
 ['/v1/mobile/chat/result',['jobId']],
 ['/v1/mobile/chat/cancel',['jobId']],
 ['/v1/mobile/access/approve',['termsHash','mode']],
 ['/v1/mobile/access/status',[]],
 ['/v1/mobile/access/revoke',[]]
]);
async function body(request:Request,signal:AbortSignal){
 const reader=request.body?.getReader();if(!reader)throw Error();const chunks:Uint8Array[]=[];let size=0;
 const abort=()=>{void reader.cancel().catch(()=>{});};signal.addEventListener('abort',abort,{once:true});
 try{while(true){if(signal.aborted)throw Error();const {done,value}=await reader.read();if(signal.aborted)throw Error();if(done)break;size+=value.byteLength;if(size>16000)throw Error();chunks.push(value);}return new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks));}
 finally{signal.removeEventListener('abort',abort);await reader.cancel().catch(()=>{});reader.releaseLock();}
}

/** Fetch-style handler only. Hosting/TLS/proxy admission must be configured separately. */
export class MobileHttpApi {
 #options:Options;#origin:string;#active=0;#window=Date.now();#admitted=0;
 constructor(options:Options){
  const u=new URL(options.origin);if(u.protocol!=='https:'||u.origin!==options.origin||!Number.isInteger(options.timeoutMs??10000)||(options.timeoutMs??10000)<1000||(options.timeoutMs??10000)>30000)throw Error('invalid_mobile_api_configuration');
  if(options.jobs&&options.execute)throw Error('invalid_mobile_api_configuration');
  this.#origin=u.origin;this.#options={...options};
 }
 async handle(request:Request):Promise<Response>{
  const started=Date.now(),id=randomUUID(),url=new URL(request.url),origin=request.headers.get('origin');
  const allowedOrigin=origin==='https://localhost'||origin===this.#origin;
  const headers:Record<string,string>={'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'; base-uri 'none'",'X-Request-ID':id};
  if(allowedOrigin){headers['Access-Control-Allow-Origin']=origin!;headers.Vary='Origin';}
  const response=(status:number,data:unknown={error:'mobile_request_rejected'})=>new Response(status===204?null:JSON.stringify(data),{status,headers:{...headers,'Content-Type':'application/json; charset=utf-8'}});
  if(url.origin!==this.#origin||request.url.length>8192)return response(400);
  if(origin!==null&&!allowedOrigin)return response(403);
  if(this.#active>=16)return response(503,{error:'mobile_temporarily_unavailable'});
  if(Date.now()-this.#window>=60000){this.#window=Date.now();this.#admitted=0;}if(++this.#admitted>120)return response(429,{error:'mobile_rate_limited'});
  const route=routes.has(url.pathname)||['/v1/mobile/config','/v1/mobile/access/terms','/mobile/callback','/mobile/return'].includes(url.pathname)?url.pathname:'unknown';
  if(route==='unknown')return response(404);
  if(request.method==='OPTIONS'){
   if(!allowedOrigin||!routes.has(route)||request.headers.get('access-control-request-method')!=='POST')return response(403);
   const requested=(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(v=>v.trim()).filter(Boolean);
   if(requested.some(h=>!['content-type','x-mobile-session','x-mobile-proof'].includes(h)))return response(403);
   return new Response(null,{status:204,headers:{...headers,'Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Content-Type, X-Mobile-Session, X-Mobile-Proof'}});
  }
  const controller=new AbortController();const abort=()=>controller.abort();request.signal.addEventListener('abort',abort,{once:true});if(request.signal.aborted)abort();
  this.#active++;let timer:ReturnType<typeof setTimeout>|undefined;
  const work=(async()=>{
   try{
    if(controller.signal.aborted)return response(408);
    if(request.method==='GET'){
     if(route==='/v1/mobile/config'&&!url.search)return response(200,{termsHash:this.#options.authority.termsHash});
     if(route==='/v1/mobile/access/terms'&&!url.search)return this.#options.resourceConsent?response(200,this.#options.resourceConsent.terms()):response(503,{error:'mobile_resource_consent_not_configured'});
     if(route==='/mobile/return')return response(200,{status:'return_to_installed_app'});
     if(route!=='/mobile/callback')return response(405);
     const query=[...url.searchParams.keys()].sort();if(query.join()!=='code,state')return response(400);
     const result=await this.#options.handoff.callback({state:url.searchParams.get('state')!,code:url.searchParams.get('code')!});
     if(controller.signal.aborted)return response(408);
     const target=new URL(result.returnUrl);if(target.origin!==this.#origin||target.username||target.password||target.pathname!=='/mobile/return'||target.hash||[...target.searchParams.keys()].join()!=='handoff'||!/^[\w-]{43}$/.test(target.searchParams.get('handoff')??''))throw Error();
     return new Response(null,{status:303,headers:{...headers,Location:target.href}});
    }
    if(request.method!=='POST'||!routes.has(route))return response(405);
    if(!allowedOrigin)return response(403);
    if(request.headers.has('authorization')||request.headers.has('cookie'))return response(400);
    if(url.search)return response(400);
    if(!/^application\/json(?:;\s*charset=utf-8)?$/i.test(request.headers.get('content-type')??'')||request.headers.has('content-encoding'))return response(415);
    const length=request.headers.get('content-length');if(length!==null&&(!/^\d{1,6}$/.test(length)||Number(length)>16000))return response(413);
    let raw:string,input:Record<string,string>;try{raw=await body(request,controller.signal);input=parse(raw,routes.get(route)!);}catch{return response(400);}
    if(controller.signal.aborted)return response(408);
    const a=this.#options.authority,h=this.#options.handoff;
    let result:unknown;
    switch(route){
     case '/v1/mobile/login/start':result=await h.start({devicePublicKeySpki:input.devicePublicKeySpki,claimHash:input.claimHash});break;
     case '/v1/mobile/enrollment/claim':result=await h.claim({handoff:input.handoff,claimSecret:input.claimSecret,sessionPublicKeySpki:input.sessionPublicKeySpki,termsHash:input.termsHash});break;
     case '/v1/mobile/enrollment/complete':result=await a.completeEnrollment({challengeId:input.challengeId,signature:input.signature});break;
     case '/v1/mobile/session/challenge':result=await a.beginResume({enrollmentId:input.enrollmentId,sessionPublicKeySpki:input.sessionPublicKeySpki});break;
     case '/v1/mobile/session/complete':result=await a.completeResume({challengeId:input.challengeId,signature:input.signature});break;
     case '/v1/mobile/access/approve':
     case '/v1/mobile/access/status':
     case '/v1/mobile/access/revoke':{
      const session=request.headers.get('x-mobile-session'),proof=request.headers.get('x-mobile-proof');if(!session||!proof)return response(401);
      if(!this.#options.resourceConsent)return response(503,{error:'mobile_resource_consent_not_configured'});
      const evidence=await a.authorize(session,proof,{method:'POST',path:route,body:raw});if(controller.signal.aborted)return response(408);
      const consent=this.#options.resourceConsent;
      result=route.endsWith('/approve')?await consent.approve(evidence,raw,controller.signal):route.endsWith('/revoke')?await consent.revoke(evidence,raw):await consent.status(evidence,raw);break;
     }
     case '/v1/mobile/chat/result':
     case '/v1/mobile/chat/cancel':{
      const session=request.headers.get('x-mobile-session'),proof=request.headers.get('x-mobile-proof');if(!session||!proof)return response(401);
      if(!this.#options.jobs||!this.#options.resourceConsent)return response(503,{error:'mobile_chat_not_configured'});
      if(!/^[\w-]{43}$/.test(input.jobId))return response(400);
      const evidence=await a.authorize(session,proof,{method:'POST',path:route,body:raw});if(controller.signal.aborted)return response(408);
      if(route.endsWith('/cancel')){await this.#options.jobs.cancel(evidence,input.jobId);result={status:'cancelled'};}
      else result=await this.#options.jobs.result(evidence,input.jobId);
      break;
     }
     case '/v1/mobile/chat/messages':{
      if(!input.question.trim()||input.question.length>2000||/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(input.question))return response(400);
      const session=request.headers.get('x-mobile-session'),proof=request.headers.get('x-mobile-proof');if(!session||!proof)return response(401);
      const evidence=await a.authorize(session,proof,{method:'POST',path:route,body:raw});
      if(controller.signal.aborted)return response(408);
      if(!this.#options.execute&&!this.#options.jobs)return response(503,{error:'mobile_chat_not_configured'});
      if(!this.#options.resourceConsent)return response(503,{error:'mobile_resource_consent_not_configured'});
      await this.#options.resourceConsent.authoriseChat(evidence);if(controller.signal.aborted)return response(408);
      if(this.#options.jobs){const job=await this.#options.jobs.start(evidence,input.question,controller.signal);return controller.signal.aborted?response(408):response(202,job);}
      const answer=await this.#options.execute({evidence,question:input.question,signal:controller.signal});
      if(!answer||typeof answer.answer!=='string'||answer.answer.length>16000)throw Error();
      if(controller.signal.aborted)return response(408);
      await this.#options.resourceConsent.authoriseChat(evidence);
      result={answer:answer.answer};break;
     }
    }
    return controller.signal.aborted?response(408):response(200,result);
   }catch{return controller.signal.aborted?response(408):response(401,{error:'mobile_authorization_denied'});}
  })().finally(()=>{this.#active--;request.signal.removeEventListener('abort',abort);});
  const deadline=new Promise<Response>(resolve=>{timer=setTimeout(()=>{controller.abort();resolve(response(504,{error:'mobile_request_timed_out'}));},this.#options.timeoutMs??10000);});
  const result=await Promise.race([work,deadline]);if(timer)clearTimeout(timer);
  try{this.#options.observe?.({route,status:result.status,durationMs:Date.now()-started});}catch{}
  return result;
 }
}
