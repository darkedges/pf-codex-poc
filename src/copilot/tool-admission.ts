import {performance} from 'node:perf_hooks';
export type ToolAdmissionLimits={maxConcurrentRequests:number;perWorkloadRequestsPerMinute:number;maxConnections:number};
export const defaultToolLimits:ToolAdmissionLimits={maxConcurrentRequests:16,perWorkloadRequestsPerMinute:60,maxConnections:128};
export class ToolAdmission {
 private active=0;private draining=false;
 private buckets:Map<string,{tokens:number;at:number}>;
 private limits:ToolAdmissionLimits;private now:()=>number;
 constructor(limits:ToolAdmissionLimits,pins:string[],now=()=>performance.now()){
  if(!limits||Object.keys(limits).sort().join(',')!=='maxConcurrentRequests,maxConnections,perWorkloadRequestsPerMinute'.split(',').sort().join(',')||!Number.isInteger(limits.maxConcurrentRequests)||limits.maxConcurrentRequests<1||limits.maxConcurrentRequests>256||!Number.isInteger(limits.perWorkloadRequestsPerMinute)||limits.perWorkloadRequestsPerMinute<1||limits.perWorkloadRequestsPerMinute>600||!Number.isInteger(limits.maxConnections)||limits.maxConnections<limits.maxConcurrentRequests||limits.maxConnections>1024||!pins.length||pins.length>20)throw Error('Invalid tool admission configuration');
  this.limits={...limits};this.now=now;this.buckets=new Map(pins.map(pin=>[pin,{tokens:limits.perWorkloadRequestsPerMinute,at:now()}]));
 }
 drain(){this.draining=true;}
 enter(pin:string):{allowed:true;release:()=>void}|{allowed:false;status:number;code:string;retryAfter?:number}{
  const bucket=this.buckets.get(pin);if(!bucket)return{allowed:false,status:403,code:'sender_denied'};
  if(this.draining||this.active>=this.limits.maxConcurrentRequests)return{allowed:false,status:503,code:'overloaded',retryAfter:1};
  const now=this.now(),rate=this.limits.perWorkloadRequestsPerMinute;
  bucket.tokens=Math.min(rate,bucket.tokens+Math.max(0,now-bucket.at)*rate/60000);bucket.at=Math.max(now,bucket.at);
  if(bucket.tokens<1)return{allowed:false,status:429,code:'rate_limited',retryAfter:Math.ceil((1-bucket.tokens)*60/rate)};
  bucket.tokens--;this.active++;let released=false;
  return{allowed:true,release:()=>{if(!released){released=true;this.active--;}}};
 }
}
