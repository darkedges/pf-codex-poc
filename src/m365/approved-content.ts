import {createHash} from 'node:crypto';
export type ApprovedDocument={alias:string;resource:string;siteId:string;siteUrl:string;driveId:string;itemId:string;uniqueId:string;name:string;maxBytes:number};
export class ApprovedContentError extends Error{constructor(){super('unavailable');this.name='ApprovedContentError';}}
export type MetadataCheckName='item'|'name'|'size'|'version'|'mime'|'drive'|'parent_site'|'site_collection'|'web'|'unique_file';
type RedirectCheckName='https'|'same_origin'|'no_credentials'|'no_fragment'|'download_path'|'single_unique_id'|'unique_file';
type ContentTypeCategory='text_plain'|'octet_stream'|'missing'|'other';
export type ContentTransportObservation={phase:'metadata'|'content'|'download'|'body'|'authorisation';outcome:'returned'|'failure';status?:number;failedChecks?:MetadataCheckName[];failedRedirectChecks?:RedirectCheckName[];contentTypeCategory?:ContentTypeCategory};
const guid=(s:unknown):s is string=>typeof s==='string'&&/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(s),id=(s:unknown):s is string=>typeof s==='string'&&/^[A-Za-z0-9_!-]{1,200}$/.test(s);
export function validateApprovedDocument(value:ApprovedDocument):ApprovedDocument{
 const d=structuredClone(value);
 if(!d||Object.keys(d).sort().join()!=='alias,driveId,itemId,maxBytes,name,resource,siteId,siteUrl,uniqueId'||!id(d.alias)||!/^sharepoint:[a-z0-9-]{1,100}$/.test(d.resource)||!id(d.driveId)||!id(d.itemId)||!guid(d.uniqueId)||!/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,100}\.txt$/.test(d.name)||!Number.isInteger(d.maxBytes)||d.maxBytes<1||d.maxBytes>65536||!/^https:\/\/[a-z0-9-]+\.sharepoint\.com\/sites\/[A-Za-z0-9_-]+$/.test(d.siteUrl))throw new ApprovedContentError();
 const p=d.siteId.split(',');if(p.length!==3||p[0]!==new URL(d.siteUrl).hostname||!guid(p[1])||!guid(p[2]))throw new ApprovedContentError();return Object.freeze(d);
}
export async function withDeadline<T>(promise:Promise<T>,signal:AbortSignal):Promise<T>{signal.throwIfAborted();return new Promise((resolve,reject)=>{const stop=()=>reject(new ApprovedContentError());signal.addEventListener('abort',stop,{once:true});promise.then(resolve,reject).finally(()=>signal.removeEventListener('abort',stop));});}
async function bytes(response:Response,max:number,signal:AbortSignal){const size=response.headers.get('content-length');if(size!==null&&(!/^\d+$/.test(size)||Number(size)>max))throw Error();const chunks:Uint8Array[]=[];let total=0;const reader=response.body?.getReader();if(!reader)return Buffer.alloc(0);try{while(true){const r=await withDeadline(reader.read(),signal);if(r.done)break;total+=r.value.byteLength;if(total>max)throw Error();chunks.push(r.value);}return Buffer.concat(chunks,total);}finally{void reader.cancel().catch(()=>{});}}
// Internal transport primitive, not an API or a source of identity/authority.
// Production callers must supply independent verified-proof/current-policy checks.
// Explicit operator probes must enforce their separate durable reviewed allowance.
export async function readApprovedText(options:{document:ApprovedDocument;appToken:{value:string;expiresAt:number};authorise:()=>Promise<void>;signal:AbortSignal;fetch?:typeof fetch;observe?:(event:ContentTransportObservation)=>void}){
 let phase:ContentTransportObservation['phase']='authorisation',status:number|undefined,failedChecks:MetadataCheckName[]=[],failedRedirectChecks:RedirectCheckName[]=[],contentTypeCategory:ContentTypeCategory|undefined;
 const observe=(outcome:'returned'|'failure')=>{try{options.observe?.({phase,outcome,...(status===undefined?{}:{status}),...(failedChecks.length?{failedChecks:[...failedChecks]}:{}),...(failedRedirectChecks.length?{failedRedirectChecks:[...failedRedirectChecks]}:{}),...(contentTypeCategory?{contentTypeCategory}:{})});}catch{}};
 try{
  const d=validateApprovedDocument(options.document),token=options.appToken,{signal,authorise}=options;
  if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||typeof authorise!=='function'||typeof token?.value!=='string'||!token.value||token.value.length>32768||/\s/.test(token.value)||!Number.isSafeInteger(token.expiresAt)||token.expiresAt<=Date.now()+1000)throw Error();
  const graph=async(path:string,extra:Record<string,string>={})=>{await withDeadline(authorise(),signal);if(token.expiresAt<=Date.now()+1000)throw Error();const r=await withDeadline((options.fetch??fetch)('https://graph.microsoft.com/v1.0'+path,{method:'GET',redirect:'manual',signal,headers:{Accept:'application/json',Authorization:'Bearer '+token.value,...extra}}),signal);signal.throwIfAborted();return r;};
  const path='/drives/'+d.driveId+'/items/'+d.itemId;
  phase='metadata';const metadata=await graph(path+'?$select=id,name,size,eTag,file,parentReference,sharepointIds');status=metadata.status;observe('returned');if(metadata.status!==200)throw Error();
  const m=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await bytes(metadata,16384,signal))),p=d.siteId.split(',');
  // The measured tenant response uses the SPSite GUID here; other responses use
  // the composite Graph site ID. Admit only the configured collection or composite,
  // never a web-only/foreign GUID. Independent site/web/file bindings remain required.
  const parentSite=m.parentReference?.siteId,parentSiteMatches=parentSite===undefined||typeof parentSite==='string'&&(parentSite.toLowerCase()===d.siteId.toLowerCase()||guid(parentSite)&&parentSite.toLowerCase()===p[1].toLowerCase());
  const checks:Record<MetadataCheckName,boolean>={item:m.id===d.itemId,name:m.name===d.name,size:Number.isInteger(m.size)&&m.size>=0&&m.size<=d.maxBytes,version:typeof m.eTag==='string'&&!!m.eTag&&m.eTag.length<=200&&!/[\r\n]/.test(m.eTag),mime:m.file?.mimeType==='text/plain',drive:m.parentReference?.driveId===d.driveId,parent_site:parentSiteMatches,site_collection:typeof m.sharepointIds?.siteId==='string'&&m.sharepointIds.siteId.toLowerCase()===p[1].toLowerCase(),web:typeof m.sharepointIds?.webId==='string'&&m.sharepointIds.webId.toLowerCase()===p[2].toLowerCase(),unique_file:typeof m.sharepointIds?.listItemUniqueId==='string'&&m.sharepointIds.listItemUniqueId.toLowerCase()===d.uniqueId.toLowerCase()};
  failedChecks=(Object.keys(checks)as MetadataCheckName[]).filter(k=>!checks[k]);if(failedChecks.length)throw Error();
  phase='content';let response=await graph(path+'/content',{'If-Match':m.eTag,Accept:'text/plain'});status=response.status;observe('returned');
  if(response.status===302){
   const location=response.headers.get('location');if(!location||location.length>8192)throw Error();const target=new URL(location),site=new URL(d.siteUrl),keys=[...target.searchParams.keys()].filter(k=>k.toLowerCase()==='uniqueid');
   const redirectChecks:Record<RedirectCheckName,boolean>={https:target.protocol==='https:',same_origin:target.origin===site.origin,no_credentials:!target.username&&!target.password,no_fragment:!target.hash,download_path:['/_layouts/15/download.aspx',site.pathname+'/_layouts/15/download.aspx'].includes(target.pathname),single_unique_id:keys.length===1&&target.searchParams.getAll(keys[0]).length===1,unique_file:keys.length===1&&target.searchParams.get(keys[0])?.replace(/^\{|\}$/g,'').toLowerCase()===d.uniqueId.toLowerCase()};
   failedRedirectChecks=(Object.keys(redirectChecks)as RedirectCheckName[]).filter(k=>!redirectChecks[k]);if(failedRedirectChecks.length)throw Error();
   phase='download';await withDeadline(authorise(),signal);response=await withDeadline((options.fetch??fetch)(target.href,{method:'GET',redirect:'error',signal,headers:{Accept:'text/plain'}}),signal);status=response.status;observe('returned');
  }
  const contentType=response.headers.get('content-type');contentTypeCategory=contentType===null?'missing':/^text\/plain(?:\s*;|$)/i.test(contentType)?'text_plain':/^application\/octet-stream(?:\s*;|$)/i.test(contentType)?'octet_stream':'other';
  if(response.status!==200||!/^text\/plain(?:\s*;\s*charset=(?:utf-8|us-ascii))?$/i.test(contentType??''))throw Error();
  phase='body';const raw=await bytes(response,d.maxBytes,signal);if(raw.byteLength!==m.size)throw Error();const text=new TextDecoder('utf-8',{fatal:true}).decode(raw);phase='authorisation';await withDeadline(authorise(),signal);signal.throwIfAborted();return{text,byteLength:raw.byteLength,sha256:createHash('sha256').update(raw).digest('hex')};
 }catch{observe('failure');throw new ApprovedContentError();}
}
