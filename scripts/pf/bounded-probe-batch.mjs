import {performance} from 'node:perf_hooks';
export async function runBoundedProbeBatch(options,request){
 if(!Number.isInteger(options?.requests)||options.requests<1||options.requests>128||!Number.isInteger(options.concurrency)||options.concurrency<1||options.concurrency>32||typeof request!=='function')throw Error('Invalid bounded load probe');
 const start=performance.now(),durations=[],counts={requests:options.requests,completed:0,accepted:0,rateLimited:0,overloaded:0,unexpected:0,networkErrors:0};let next=0;
 await Promise.all(Array.from({length:Math.min(options.concurrency,options.requests)},async()=>{
  for(;;){if(next++>=options.requests)return;const at=performance.now();
   try{const response=await request();if(response.status===200)counts.accepted++;else if(response.status===429)counts.rateLimited++;else if(response.status===503)counts.overloaded++;else if(response.error)counts.networkErrors++;else counts.unexpected++;}
   catch{counts.networkErrors++;}finally{counts.completed++;durations.push(performance.now()-at);}
  }
 }));
 durations.sort((a,b)=>a-b);return{...counts,durationMs:Math.round(performance.now()-start),p95Ms:Math.round(durations[Math.ceil(durations.length*.95)-1])};
}
