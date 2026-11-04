import {randomBytes} from 'node:crypto';
import type {MobileRequestEvidence} from './device-authority.ts';
import {bodyHash} from '../policy/protocol.ts';
import {withDeadline} from '../m365/approved-content.ts';

type Options={timeoutMs:number;capacity:number;
 revalidate(value:unknown):Promise<MobileRequestEvidence>;
 authorise(evidence:unknown):Promise<void>;
 execute(input:{evidence:MobileRequestEvidence;question:string;signal:AbortSignal}):Promise<{answer:string}>};
type Slot={id:string;evidence:MobileRequestEvidence;source:MobileRequestEvidence;controller:AbortController;expires:number;
 timer:ReturnType<typeof setTimeout>;answer?:string};
const denied=()=>Error('mobile_chat_job_denied');
const same=(a:MobileRequestEvidence,b:MobileRequestEvidence)=>a.sessionId===b.sessionId&&a.enrollmentId===b.enrollmentId&&a.consentId===b.consentId&&a.human.issuer===b.human.issuer&&a.human.subject===b.human.subject&&a.human.audience===b.human.audience&&a.agent.issuer===b.agent.issuer&&a.agent.subject===b.agent.subject&&a.organisation===b.organisation;

/** In-memory, bounded foreground work. Polling never renews the original
 * evidence. No listener, automatic retry, provider credentials or disk history.
 * Hosting must authenticate every start/result/cancel request independently. */
export class MobileChatJobs {
 #o:Options;#slots=new Map<string,Slot>();#running=new Set<Slot>();#starting=0;#closed=false;#spent=new WeakSet<object>();
 constructor(options:Options){
  if(!Number.isInteger(options.timeoutMs)||options.timeoutMs<25||options.timeoutMs>55000||!Number.isInteger(options.capacity)||options.capacity<1||options.capacity>64||!['revalidate','authorise','execute'].every(k=>typeof options[k]==='function'))throw denied();
  this.#o={...options};
 }
 #drop(slot:Slot){slot.controller.abort();clearTimeout(slot.timer);slot.answer=undefined;this.#slots.delete(slot.id);}
 async #current(slot:Slot,reader?:unknown){
  if(this.#closed||slot.controller.signal.aborted||slot.expires<=Date.now()||this.#slots.get(slot.id)!==slot)throw denied();
  const signal=slot.controller.signal,e=await withDeadline(this.#o.revalidate(slot.source),signal);
  if(!same(e,slot.evidence))throw denied();
  if(reader!==undefined){const r=await withDeadline(this.#o.revalidate(reader),signal);if(!same(e,r))throw denied();}
  await withDeadline(this.#o.authorise(slot.source),signal);
  if(this.#closed||slot.expires<=Date.now()||slot.controller.signal.aborted||this.#slots.get(slot.id)!==slot)throw denied();
 }
 async start(value:unknown,question:string,external:AbortSignal=new AbortController().signal):Promise<{status:'pending';jobId:string}>{
  const deadline=Date.now()+this.#o.timeoutMs;
  let slot:Slot|undefined,admitted=false;const controller=new AbortController(),validation=AbortSignal.any([external,controller.signal,AbortSignal.timeout(this.#o.timeoutMs)]);
  try{
   if(this.#closed||this.#starting+this.#running.size>=this.#o.capacity||this.#slots.size>=this.#o.capacity||typeof question!=='string'||!question.trim()||question.length>2000||/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(question))throw denied();
   this.#starting++;admitted=true;
   const e=await withDeadline(this.#o.revalidate(value),validation);
   if(e.requestPath!=='/v1/mobile/chat/messages'||e.requestBodyHash!==bodyHash(JSON.stringify({question})))throw denied();
   await withDeadline(this.#o.authorise(value),validation);validation.throwIfAborted();
   if(!value||typeof value!=='object'||this.#closed||this.#spent.has(value)||e.expiresAt<=Date.now()||this.#slots.size>=this.#o.capacity||[...this.#slots.values(),...this.#running].some(s=>s.evidence.sessionId===e.sessionId))throw denied();
   this.#spent.add(value);
   const id=randomBytes(32).toString('base64url'),expires=Math.min(e.expiresAt,deadline);
   slot={id,evidence:e,source:value as MobileRequestEvidence,controller,expires,timer:setTimeout(()=>{if(slot)this.#drop(slot);},Math.max(1,expires-Date.now()))};
   this.#slots.set(id,slot);this.#running.add(slot);
   void this.#run(slot,question);return{status:'pending',jobId:id};
  }catch{if(slot)this.#drop(slot);controller.abort();throw denied();}
  finally{if(admitted)this.#starting--;}
 }
 async #run(slot:Slot,question:string){
  try{
   await this.#current(slot);
   const result=await this.#o.execute({evidence:slot.source,question,signal:slot.controller.signal});
   if(!result||typeof result.answer!=='string'||!result.answer.trim()||result.answer.length>16000)throw denied();
   await this.#current(slot);slot.answer=result.answer;
  }catch{this.#drop(slot);}
  finally{this.#running.delete(slot);}
 }
 async result(evidence:unknown,id:string):Promise<{status:'pending'}|{status:'complete';answer:string}>{
  // A bad reader must not cancel another session's job.
  try{
   if(typeof id!=='string'||!/^[\w-]{43}$/.test(id))throw denied();const slot=this.#slots.get(id);if(!slot)throw denied();
   await this.#current(slot,evidence);if(this.#slots.get(id)!==slot||slot.controller.signal.aborted)throw denied();
   if(slot.answer===undefined)return{status:'pending'};
   const answer=slot.answer;this.#drop(slot);return{status:'complete',answer};
  }catch{throw denied();}
 }
 async cancel(evidence:unknown,id:string){
  try{const slot=this.#slots.get(id);if(!slot)throw denied();await this.#current(slot,evidence);this.#drop(slot);}catch{throw denied();}
 }
 close(){this.#closed=true;for(const slot of this.#slots.values())this.#drop(slot);for(const slot of this.#running)slot.controller.abort();}
}
