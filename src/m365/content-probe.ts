import {createHash} from 'node:crypto';import {readApprovedText,validateApprovedDocument,withDeadline,type ApprovedDocument} from './approved-content.ts';import type {GraphAppTokenSource} from './graph-documents.ts';
type Config={runId:string;tenantId:string;clientId:string;document:ApprovedDocument;expectedSha256:string};
type Receipt={planHash:string;status:string;tokenRequests:number;graphRequests:number;sharePointDownloads:number;at:string;transportPhase?:string;transportStatus?:number;failedMetadataChecks?:string[];failedRedirectChecks?:string[];contentTypeCategory?:string};
type Dependencies={assertApproved:()=>Promise<void>;getToken:GraphAppTokenSource['getToken'];fetch:typeof fetch;read:()=>Promise<Receipt|undefined>;write:(state:Receipt)=>Promise<void>;lock:<T>(fn:()=>Promise<T>)=>Promise<T>};
export class ContentProbeError extends Error{constructor(code:string){super(code);this.name='ContentProbeError';}}
export function planSharePointContentProbe(value:unknown){
 try{const c=value as Config;if(!c||typeof c!=='object'||Array.isArray(c)||Object.keys(c).sort().join()!=='clientId,document,expectedSha256,runId,tenantId'||!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(c.runId)||![c.tenantId,c.clientId].every(v=>typeof v==='string'&&/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(v))||!/^[a-f0-9]{64}$/.test(c.expectedSha256))throw Error();
 const document=validateApprovedDocument(c.document);if(document.alias!=='poc-sample'||document.name!=='federated-copilot-poc.txt')throw Error();
 const requested={runId:c.runId,tenantId:c.tenantId,clientId:c.clientId,document,expectedSha256:c.expectedSha256},limits={maxBrokerTokenRequests:1,maxGraphRequests:2,maxSharePointDownloads:1,authorisation:'owner-approved-operator-probe'};
 return{requested,...limits,hash:createHash('sha256').update(JSON.stringify({requested,...limits})).digest('hex')};
 }catch{throw new ContentProbeError('invalid_configuration');}
}
// Operator-only integrity test. No synthetic PF human/actor identity and no claim
// that this separate owner-approved allowance is external delegated authority.
export async function runSharePointContentProbe(value:unknown,approvedHash:string,deps:Dependencies){
 const plan=planSharePointContentProbe(value);if(approvedHash!==plan.hash)throw new ContentProbeError('approval_required');
 return deps.lock(async()=>{
  if(await deps.read())throw new ContentProbeError('allowance_already_consumed');
  try{await deps.assertApproved();}catch{throw new ContentProbeError('approval_unavailable');}
  const signal=AbortSignal.timeout(60000),d=plan.requested.document,graphPath='https://graph.microsoft.com/v1.0/drives/'+d.driveId+'/items/'+d.itemId,metadataUrl=graphPath+'?$select=id,name,size,eTag,file,parentReference,sharepointIds';
  let state:Receipt={planHash:plan.hash,status:'token-request-intent',tokenRequests:1,graphRequests:0,sharePointDownloads:0,at:new Date().toISOString()};await deps.write(state);
  const authorise=async()=>{signal.throwIfAborted();await withDeadline(deps.assertApproved(),signal);const persisted=await deps.read();if(!persisted||persisted.planHash!==plan.hash||persisted.status!==state.status||persisted.tokenRequests!==1||persisted.graphRequests!==state.graphRequests||persisted.sharePointDownloads!==state.sharePointDownloads||['finished','failed'].includes(persisted.status))throw Error();};
  try{
   await authorise();const token=await withDeadline(deps.getToken(),signal);
   const transport:typeof fetch=async(input,init)=>{
    await authorise();const url=String(input),headers=new Headers(init?.headers);if(init?.method!=='GET')throw Error();
    if(url===metadataUrl||url===graphPath+'/content'){
     if(state.graphRequests>=2||headers.get('Authorization')!=='Bearer '+token.value)throw Error();
     state={...state,status:url===metadataUrl?'metadata-request-intent':'content-request-intent',graphRequests:state.graphRequests+1};
    }else{
     if(state.sharePointDownloads!==0||new URL(url).origin!==new URL(d.siteUrl).origin||headers.has('Authorization')||headers.has('Cookie')||init?.redirect!=='error')throw Error();
     state={...state,status:'download-request-intent',sharePointDownloads:1};
    }
    await deps.write(state);const requestSignal=AbortSignal.any([signal,AbortSignal.timeout(10000)]);return withDeadline(deps.fetch(input,{...init,signal:requestSignal}),requestSignal);
   };
   const result=await readApprovedText({document:d,appToken:token,authorise,signal,fetch:transport,observe:e=>{state={...state,transportPhase:e.phase,...(e.status===undefined?{}:{transportStatus:e.status}),...(e.failedChecks?{failedMetadataChecks:e.failedChecks}:{}),...(e.failedRedirectChecks?{failedRedirectChecks:e.failedRedirectChecks}:{}),...(e.contentTypeCategory?{contentTypeCategory:e.contentTypeCategory}:{})};}});
   if(result.byteLength!==d.maxBytes||result.sha256!==plan.requested.expectedSha256){state={...state,transportPhase:'integrity'};throw Error();}await authorise();
   state={...state,status:'finished'};await deps.write(state);
   return{status:'verified-operator-sample-content',runId:plan.requested.runId,planHash:plan.hash,authorisation:'owner-approved-operator-probe',brokerTokenAcquisitions:1,graphRequests:state.graphRequests,sharePointDownloads:state.sharePointDownloads,sampleBytes:result.byteLength,contentSha256:result.sha256,federatedDocumentRead:'UNVERIFIED',budgetCountsAreConservative:true};
  }catch{state={...state,status:'failed'};await deps.write(state);throw new ContentProbeError('content_probe_failed');}
 });
}
