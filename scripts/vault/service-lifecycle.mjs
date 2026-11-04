export function onceAsync(action){let promise;return(...args)=>promise??=(async()=>action(...args))();}
export function servicePlan(v){
 if(!v||Object.keys(v).sort().join()!=='image,instance,ownerSid,retentionDays'||! /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v.instance)||! /^sha256:[a-f0-9]{64}$/.test(v.image)||! /^S-1-5-21-(?:\d+-){3}\d+$/.test(v.ownerSid)||![null,1,7].includes(v.retentionDays))throw Error('Explicit local service operations settings required');
 return{...v,network:'federated-copilot-local-private',tool:'federated-copilot-local-tool',backend:'federated-copilot-local-backend',subnet:'10.236.250.32/28',hostPorts:[],automaticRestart:false,automaticLeaseRenewal:false,auditMaxBytes:1048576,auditFiles:2};
}
export function ownedResource(resource,plan){return [plan.tool,plan.backend,plan.network].includes(resource.name)&&resource.labels?.['federated-copilot.local-service']===plan.instance;}
export function inspectRecordedContainer(name,plan,command){
 const lookup=['ps','-aq','--filter','name=^/'+name+'$'];if(!command(lookup))return null;
 let value;try{value=JSON.parse(command(['inspect',name]))[0];}catch{if(!command(lookup))return null;throw Error('Container state unavailable');}
 if(!ownedResource({name:value.Name.replace(/^\//,''),labels:value.Config.Labels},plan))throw Error('Foreign service container; recovery refused');return value;
}
