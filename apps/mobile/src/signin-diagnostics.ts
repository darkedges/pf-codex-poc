export const signInStages=['signin_button','session_lock','pending_clear','local_reset','biometric_check','device_key','pending_login','backend_login','browser_launch','browser_return','pending_return','backend_config','return_claim','device_enrollment','enrollment_save','resource_access','app_background','cancelled'] as const;
export type SignInStage=typeof signInStages[number];
type Outcome='started'|'passed'|'failed'|'cancelled';
const codes=new Set(['mobile_service_request_failed','mobile_browser_unavailable','mobile_browser_state_unavailable','mobile_browser_url_rejected','mobile_browser_missing','mobile_browser_launch_failed','mobile_login_unavailable','device_key_unavailable','device_proof_unavailable','invalid_device_challenge','biometric_not_completed','device_locked','mobile_reference_unavailable']);
type Event={stage:SignInStage;outcome:Outcome;elapsedMs:number;code?:string;httpStatus?:number};
/** Local memory only. Accept fixed categories, never error messages or payloads. */
export class SignInDiagnostics {
 #events:Event[]=[];#startedAt:string|null=null;#start=0;
 begin(){this.#events=[];this.#startedAt=new Date().toISOString();this.#start=performance.now();this.record('signin_button','started');}
 record(stage:SignInStage,outcome:Outcome,detail?:{code?:unknown;httpStatus?:unknown}){
  if(!this.#startedAt||!signInStages.includes(stage)||!['started','passed','failed','cancelled'].includes(outcome))return;
  const code=typeof detail?.code==='string'&&codes.has(detail.code)?detail.code:undefined,status=detail?.httpStatus;
  this.#events.push({stage,outcome,elapsedMs:Math.max(0,Math.min(86400000,Math.round(performance.now()-this.#start))),...(code?{code}:{}),...(Number.isInteger(status)&&Number(status)>=100&&Number(status)<=599?{httpStatus:Number(status)}:{})});
  if(this.#events.length>48)this.#events.shift();
 }
 snapshot(){return{schema:1,appVersion:'0.2.4',build:'v9-clock-fix',startedAt:this.#startedAt,events:structuredClone(this.#events)};}
 report(){return JSON.stringify(this.snapshot(),null,2);}
}
