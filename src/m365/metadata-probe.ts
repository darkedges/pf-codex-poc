import {createHash} from 'node:crypto';import type {GraphAppTokenSource} from './graph-documents.ts';
type Config={runId:string;tenantId:string;clientId:string;siteId:string;siteUrl:string;fileName:string;sampleBytes:number;sampleSha256:string};
type Receipt={planHash:string;status:string;tokenRequests:number;metadataRequests:number;at:string;failurePhase?:string};
type Dependencies={getToken:GraphAppTokenSource['getToken'];fetch:typeof fetch;read:()=>Promise<Receipt|undefined>;write:(value:Receipt)=>Promise<void>;lock:<T>(fn:()=>Promise<T>)=>Promise<T>};
export class MetadataProbeError extends Error{constructor(code:string){super(code);this.name='MetadataProbeError';}}
const guid=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(v),id=(v:unknown):v is string=>typeof v==='string'&&/^[A-Za-z0-9_!-]{1,200}$/.test(v);
export function planSharePointMetadataProbe(value:unknown){
 try{
  const c=value as Config;if(!c||typeof c!=='object'||Array.isArray(c)||Object.keys(c).sort().join()!=='clientId,fileName,runId,sampleBytes,sampleSha256,siteId,siteUrl,tenantId'||typeof c.runId!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(c.runId)||!guid(c.tenantId)||!guid(c.clientId)||!/^https:\/\/[a-z0-9-]+\.sharepoint\.com\/sites\/[A-Za-z0-9_-]+$/.test(c.siteUrl)||!/^federated-copilot-poc\.txt$/.test(c.fileName)||!Number.isSafeInteger(c.sampleBytes)||c.sampleBytes<1||c.sampleBytes>65536||!/^[a-f0-9]{64}$/.test(c.sampleSha256))throw Error();
  const parts=c.siteId?.split(',');if(parts?.length!==3||parts[0]!==new URL(c.siteUrl).hostname||!guid(parts[1])||!guid(parts[2]))throw Error();
  const requested={runId:c.runId,tenantId:c.tenantId,clientId:c.clientId,siteId:c.siteId,siteUrl:c.siteUrl,fileName:c.fileName,sampleBytes:c.sampleBytes,sampleSha256:c.sampleSha256},paths=['/sites/'+c.siteId+'?$select=id,webUrl','/sites/'+c.siteId+'/drive/root:/'+c.fileName+'?$select=id,name,size,file,parentReference,sharepointIds'];
  return{requested,paths,maxBrokerTokenRequests:1,maxMetadataRequests:2,documentReads:0,hash:createHash('sha256').update(JSON.stringify({requested,paths,maxBrokerTokenRequests:1,maxMetadataRequests:2,documentReads:0})).digest('hex')};
 }catch{throw new MetadataProbeError('invalid_configuration');}
}
async function json(response:Response,signal:AbortSignal){if(response.status!==200)throw Error();const reader=response.body?.getReader();if(!reader)throw Error();let size=0;const chunks:Uint8Array[]=[];try{while(true){const value=await reader.read();signal.throwIfAborted();if(value.done)break;size+=value.value.byteLength;if(size>16384)throw Error();chunks.push(value.value);}return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,size)));}finally{void reader.cancel().catch(()=>{});}}
// Explicit operator transport probe. Does not supply synthetic PF identities or
// claim an external human/agent grant, and never requests any document content.
export async function runSharePointMetadataProbe(value:unknown,approvedHash:string,deps:Dependencies){
 const plan=planSharePointMetadataProbe(value),c=plan.requested;if(plan.hash!==approvedHash)throw new MetadataProbeError('approval_required');
 return deps.lock(async()=>{
  if(await deps.read())throw new MetadataProbeError('allowance_already_consumed');
  let state:Receipt={planHash:plan.hash,status:'token-request-intent',tokenRequests:1,metadataRequests:0,at:new Date().toISOString()},phase='app-token';await deps.write(state);
  try{
   const token=await deps.getToken();if(!token||typeof token.value!=='string'||!token.value||/\s/.test(token.value)||token.value.length>32768||!Number.isSafeInteger(token.expiresAt)||token.expiresAt<=Date.now()+30000)throw Error();
   const get=async(path:string)=>{if(state.metadataRequests>=2||!plan.paths.includes(path)||token.expiresAt<=Date.now()+1000)throw Error();state={...state,status:'metadata-request-intent',metadataRequests:state.metadataRequests+1};await deps.write(state);const signal=AbortSignal.timeout(10000),response=await deps.fetch('https://graph.microsoft.com/v1.0'+path,{method:'GET',redirect:'error',signal,headers:{Authorization:'Bearer '+token.value,Accept:'application/json'}});return json(response,signal);};
   phase='site-metadata';const site=await get(plan.paths[0]);if(site.id!==c.siteId||site.webUrl!==c.siteUrl)throw Error();
   phase='file-metadata';const file=await get(plan.paths[1]),parts=c.siteId.split(',');
   if(!id(file.id)||file.name!==c.fileName||file.size!==c.sampleBytes||file.file?.mimeType!=='text/plain'||!id(file.parentReference?.driveId)||file.sharepointIds?.siteId?.toLowerCase()!==parts[1]||file.sharepointIds?.webId?.toLowerCase()!==parts[2]||!guid(file.sharepointIds?.listItemUniqueId?.toLowerCase()))throw Error();
   const candidate={alias:'poc-sample',resource:'sharepoint:approved-research',siteId:c.siteId,siteUrl:c.siteUrl,driveId:file.parentReference.driveId,itemId:file.id,uniqueId:file.sharepointIds.listItemUniqueId.toLowerCase(),name:c.fileName,maxBytes:c.sampleBytes};
   state={...state,status:'finished'};await deps.write(state);return{status:'verified-app-auth-and-file-metadata',planHash:plan.hash,candidate,brokerTokenAcquisitions:1,metadataRequests:2,documentContentReads:0,sampleContentVerified:false,federatedDocumentRead:'UNVERIFIED',budgetCountsAreConservative:true};
  }catch{state={...state,status:'failed',failurePhase:phase};await deps.write(state);throw new MetadataProbeError('probe_failed_'+phase);}
 });
}
