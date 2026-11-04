import {withDeadline} from '../m365/approved-content.ts';
type Options={policy:'mobile-provider-store'|'mobile-agent-sign'|'mobile-authority-sign';maxTtlSeconds:300;authenticate:(signal:AbortSignal)=>Promise<unknown>;onFailure?:()=>void};
const fail=()=>Error('mobile_workload_unavailable');
/** Fresh certificate login before expiry; no operator token, unseal, broad
 * renewal permission, automatic network retry or secret-bearing diagnostics. */
export class MobileWorkloadLease {
 #o:Options;#value='';#expires=0;#closed=false;#pending?:Promise<void>;#timer?:ReturnType<typeof setTimeout>;#stop=new AbortController();
 constructor(o:Options){if(!['mobile-provider-store','mobile-agent-sign','mobile-authority-sign'].includes(o.policy)||o.maxTtlSeconds!==300||typeof o.authenticate!=='function')throw fail();this.#o={...o};}
 start(){return this.#pending??=this.#authenticate().finally(()=>{this.#pending=undefined;});}
 async #authenticate(){
  try{if(this.#closed)throw fail();const now=Date.now(),signal=AbortSignal.any([this.#stop.signal,AbortSignal.timeout(10000)]),auth=await withDeadline(this.#o.authenticate(signal),signal) as {client_token?:unknown;policies?:unknown;num_uses?:unknown;lease_duration?:unknown};
   if(this.#closed||signal.aborted||typeof auth?.client_token!=='string'||!auth.client_token||auth.client_token.length>4096||/[\s\u0000-\u001f\u007f]/.test(auth.client_token)||JSON.stringify(auth.policies)!==JSON.stringify([this.#o.policy])||auth.num_uses!==0||!Number.isInteger(auth.lease_duration)||Number(auth.lease_duration)<60||Number(auth.lease_duration)>this.#o.maxTtlSeconds)throw fail();
   const expires=now+Number(auth.lease_duration)*1000;if(expires<=Date.now()+30000)throw fail();this.#value=auth.client_token;this.#expires=expires;clearTimeout(this.#timer);this.#timer=setTimeout(()=>{void this.start().catch(()=>{});},expires-Date.now()-30000);this.#timer.unref();
  }catch{this.close();try{this.#o.onFailure?.();}catch{}throw fail();}
 }
 token(){if(this.#closed||!this.#value||this.#expires<=Date.now()+5000)throw fail();return this.#value;}
 close(){this.#closed=true;this.#stop.abort();clearTimeout(this.#timer);this.#value='';this.#expires=0;}
}
