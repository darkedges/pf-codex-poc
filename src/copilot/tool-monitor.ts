export class ToolMonitor {
 private counters={requests:0,rateLimited:0,overloaded:0,senderDenied:0,tlsRejected:0,toolSuccess:0,policyDenied:0,invalidToken:0,toolFailed:0,auditFailed:0,readinessTransitions:0};
 private state:'unknown'|'ready'|'not_ready'='unknown';
 private increment(key:keyof ToolMonitor['counters']){this.counters[key]=Math.min(Number.MAX_SAFE_INTEGER,this.counters[key]+1);}
 observe(input:Record<string,unknown>):Record<string,unknown>|undefined{
  if(input.event==='tool_http'&&['tool','liveness','readiness','metrics','other'].includes(String(input.operation))&&Number.isInteger(input.status)&&Number(input.status)>=100&&Number(input.status)<=599){
   this.increment('requests');if(input.status===429)this.increment('rateLimited');if(input.status===503&&input.code==='overloaded')this.increment('overloaded');if(input.status===403&&input.code==='sender_denied')this.increment('senderDenied');
   return{event:'tool_http',operation:input.operation,status:input.status,...(['overloaded','rate_limited','sender_denied'].includes(String(input.code))?{code:input.code}:{})};
  }
  if(input.event==='tool_tls_rejected'){this.increment('tlsRejected');return{event:'tool_tls_rejected'};}
  if(input.event==='protected_tool'&&['success','failure'].includes(String(input.outcome))){
   if(input.outcome==='success')this.increment('toolSuccess');
   else{const key={policy_denied:'policyDenied',invalid_token:'invalidToken',tool_failed:'toolFailed',audit_failed:'auditFailed'}[String(input.code)];if(!key)return undefined;this.increment(key as keyof ToolMonitor['counters']);}
   return{event:'protected_tool',outcome:input.outcome,...(input.outcome==='failure'?{code:input.code}:{}),...(typeof input.durationMs==='number'&&Number.isFinite(input.durationMs)?{durationMs:Math.max(0,Math.min(60000,input.durationMs))}:{})};
  }
 }
 readiness(ready:boolean){const next=ready?'ready':'not_ready';if(next!==this.state){this.state=next;this.increment('readinessTransitions');return{event:'tool_readiness',state:next};}}
 snapshot(certificateExpiry:number,auditHealthy:boolean){const seconds=Math.max(0,Math.floor((certificateExpiry-Date.now())/1000));return{counters:{...this.counters},readiness:this.state,auditHealthy,certificateExpiresInSeconds:seconds,certificateExpiring:seconds<=7*86400};}
}
