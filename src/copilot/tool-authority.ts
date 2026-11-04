import type {DelegatedClaims,TokenVerifier} from '../adapters/token-exchange.ts';
import {randomUUID} from 'node:crypto';
import type {ToolAuditEvidence} from './tool-audit.ts';

export class ToolAccessError extends Error {
  code:'configuration'|'invalid_token'|'policy_denied'|'tool_failed'|'audit_failed';
  constructor(code:ToolAccessError['code']){super(code);this.name='ToolAccessError';this.code=code;}
}
type Options<T>={
  verifier:TokenVerifier;
  authorise:(claims:Readonly<DelegatedClaims>,evidence:{accessToken:string})=>Promise<void>;
  // Fixed server-side operation; request text cannot select a resource or callback.
  operation:(claims:Readonly<DelegatedClaims>,signal:AbortSignal)=>Promise<T>;
  timeoutMs:number;
  audit?:(event:ToolAuditEvidence)=>Promise<void>;
  observe?:(event:{event:'protected_tool';outcome:'success'|'failure';code?:ToolAccessError['code'];durationMs:number})=>void;
};
export class PolicyProtectedTool<T>{
  private options:Options<T>;
  constructor(options:Options<T>){
    if(!options||typeof options.verifier?.verify!=='function'||typeof options.authorise!=='function'||typeof options.operation!=='function'||options.audit!==undefined&&typeof options.audit!=='function'||!Number.isInteger(options.timeoutMs)||options.timeoutMs<100||options.timeoutMs>30000)throw new ToolAccessError('configuration');
    this.options={...options};
  }
  async execute(accessToken:string):Promise<T>{
    const started=Date.now(),controller=new AbortController(),c=this.options,requestId=randomUUID();let verified:DelegatedClaims|undefined;
    const phase=async<R>(code:ToolAccessError['code'],action:()=>Promise<R>):Promise<R>=>{
      const remaining=c.timeoutMs-(Date.now()-started);
      if(remaining<=0){controller.abort();throw new ToolAccessError(code);}
      let timer:ReturnType<typeof setTimeout>|undefined;
      try{const result=await Promise.race([Promise.resolve().then(action),new Promise<never>((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(new ToolAccessError(code));},remaining);})]);if(Date.now()-started>=c.timeoutMs)throw new ToolAccessError(code);return result;}
      catch{throw new ToolAccessError(code);}finally{if(timer)clearTimeout(timer);}
    };
    const observe=(outcome:'success'|'failure',code?:ToolAccessError['code'])=>{try{c.observe?.({event:'protected_tool',outcome,...(code?{code}:{}),durationMs:Date.now()-started});}catch{/* Telemetry cannot authorize or deny. */}};
    try{
      if(typeof accessToken!=='string'||!accessToken||accessToken.length>16000)throw new ToolAccessError('invalid_token');
      const claims=await phase('invalid_token',()=>c.verifier.verify(accessToken));
      const fresh=()=>{if(!Number.isInteger(claims.exp)||claims.exp<=Math.floor(Date.now()/1000))throw new ToolAccessError('invalid_token');};
      fresh();
      verified=claims;
      if(c.audit)await phase('audit_failed',()=>c.audit!({requestId,outcome:'attempt',claims:structuredClone(claims)}));
      await phase('policy_denied',()=>c.authorise(structuredClone(claims),{accessToken}));
      fresh();
      const result=await phase('tool_failed',()=>c.operation(structuredClone(claims),controller.signal));
      await phase('policy_denied',()=>c.authorise(structuredClone(claims),{accessToken}));
      fresh();if(c.audit)await phase('audit_failed',()=>c.audit!({requestId,outcome:'success',claims:structuredClone(claims)}));fresh();observe('success');return result;
    }catch(error){
      controller.abort();let safe=error instanceof ToolAccessError?error:new ToolAccessError('tool_failed');
      if(c.audit&&safe.code!=='audit_failed'){
       let timer:ReturnType<typeof setTimeout>|undefined;
       try{await Promise.race([c.audit({requestId,outcome:'denied',code:safe.code,...(verified?{claims:structuredClone(verified)}:{})}),new Promise<never>((_,reject)=>{timer=setTimeout(()=>reject(Error()),100);})]);}catch{safe=new ToolAccessError('audit_failed');}finally{if(timer)clearTimeout(timer);}
      }
      observe('failure',safe.code);throw safe;
    }
  }
}
