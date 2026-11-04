const operations=new Set(['open','send','poll','refresh','close']);
const outcomes=new Set(['ok','configuration','invalid_request','invalid_token','policy_denied','session_denied','session_busy','expired','sso_expired','oauth_invalid','challenge_replay','protocol_error','unavailable','capacity']);
/** Reconstruct only fixed categories and bounded timings. Never serialize input objects. */
export function mobileCopilotDiagnostics(save:(events:unknown[])=>void,now=Date.now){
 let events:{at:number;operation:string;outcome:string;durationMs:number}[]=[];
 const maintain=()=>{try{events=events.filter(e=>e.at>now()-86400000);save(structuredClone(events));}catch{}};
 const observe=(value:unknown)=>{
  try{
   const v=value as Record<string,unknown>;
   if(v?.event!=='copilot_directline'||!operations.has(String(v.operation))||!outcomes.has(String(v.outcome))||!Number.isSafeInteger(v.durationMs)||Number(v.durationMs)<0||Number(v.durationMs)>120000)return;
   const at=now();events=events.filter(e=>e.at>at-86400000).slice(-127);
   events.push({at,operation:String(v.operation),outcome:String(v.outcome),durationMs:Number(v.durationMs)});
   save(structuredClone(events));
  }catch{/* Diagnostics must not change authorization or execution. */}
 };
 return Object.assign(observe,{maintain});
}
