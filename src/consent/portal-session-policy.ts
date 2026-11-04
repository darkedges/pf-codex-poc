import {PolicyError} from '../policy/contracts.ts';
export type PortalSessionPolicy={maxSessions:number;maxConcurrent:1};
export function portalSessionPolicy(value:unknown):Readonly<PortalSessionPolicy>{
 const v=value as PortalSessionPolicy;
 if(!v||Object.keys(v).sort().join()!=='maxConcurrent,maxSessions'||!Number.isInteger(v.maxSessions)||v.maxSessions<2||v.maxSessions>25||v.maxConcurrent!==1)throw new PolicyError('configuration');
 return Object.freeze({maxSessions:v.maxSessions,maxConcurrent:1});
}
export function portalSuccessfulPredecessor(value:unknown){
 const v=value as {runId:string;journalSha256:string;windowSha256:string;resultSha256:string};
 if(!v||Object.keys(v).sort().join()!=='journalSha256,resultSha256,runId,windowSha256'||typeof v.runId!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v.runId)||![v.journalSha256,v.windowSha256,v.resultSha256].every(h=>typeof h==='string'&&/^[a-f0-9]{64}$/.test(h)))throw new PolicyError('configuration');
 return{runId:v.runId,journalSha256:v.journalSha256,windowSha256:v.windowSha256,resultSha256:v.resultSha256};
}
