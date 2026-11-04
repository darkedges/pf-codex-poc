import {createHash} from 'node:crypto';
import {validateApprovedDocument,readApprovedText,withDeadline,type ApprovedDocument} from '../m365/approved-content.ts';
import type {GraphAppTokenSource} from '../m365/graph-documents.ts';
import type {DelegatedClaims} from '../adapters/token-exchange.ts';

type Config={siteId:string;siteUrl:string;resource:'sharepoint:approved-research';audience:string;maxDocuments:number;maxNodes:number;maxRequests:number;timeoutMs:number};
type Dependencies={verify:(token:string)=>Promise<DelegatedClaims&{resource:string}>;authorise:(claims:Readonly<DelegatedClaims>,evidence:{accessToken:string})=>Promise<void>;tokenSource:GraphAppTokenSource;fetch?:typeof fetch};
export type Grounding={documents:{name:string;text:string}[];unsupportedCount:number;fingerprint:string};
const denied=()=>Error('mobile_documents_unavailable');
const id=(v:unknown):v is string=>typeof v==='string'&&/^[A-Za-z0-9_!-]{1,200}$/.test(v);
const guid=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(v);
const select='id,name,size,eTag,file,folder,remoteItem,deleted,parentReference,sharepointIds';
async function json(r:Response,signal:AbortSignal){if(r.status!==200||r.redirected||!/^application\/json(?:;|$)/i.test(r.headers.get('content-type')??''))throw denied();const reader=r.body?.getReader();if(!reader)throw denied();const chunks:Uint8Array[]=[];let total=0;try{for(;;){const p=await withDeadline(reader.read(),signal);if(p.done)break;total+=p.value.length;if(total>131072)throw denied();chunks.push(p.value);}return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));}finally{void reader.cancel().catch(()=>{});reader.releaseLock();}}
/** Site-scoped enumeration, not Graph search. No caller-selected site, item,
 * scope or URL. Content is transient, bounded UTF-8 text; other formats remain
 * explicitly unsupported. Every selected file repeats independent metadata,
 * exact-site and If-Match checks through the existing approved-content reader. */
export class ApprovedSiteDocuments {
 #c:Config;#d:Dependencies;
 constructor(c:Config,d:Dependencies){
  validateApprovedDocument({alias:'validation',resource:c.resource,siteId:c.siteId,siteUrl:c.siteUrl,driveId:'validation',itemId:'validation',uniqueId:'11111111-1111-1111-1111-111111111111',name:'validation.txt',maxBytes:65536});
  if(c.resource!=='sharepoint:approved-research'||!c.audience||!Number.isInteger(c.maxDocuments)||c.maxDocuments<1||c.maxDocuments>16||!Number.isInteger(c.maxNodes)||c.maxNodes<1||c.maxNodes>256||!Number.isInteger(c.maxRequests)||c.maxRequests<1||c.maxRequests>64||!Number.isInteger(c.timeoutMs)||c.timeoutMs<100||c.timeoutMs>45000||typeof d.verify!=='function'||typeof d.authorise!=='function'||typeof d.tokenSource?.getToken!=='function')throw denied();this.#c={...c};this.#d={...d};
 }
 async read(question:string,proof:string,external:AbortSignal):Promise<Grounding>{
  try{
   if(typeof question!=='string'||!question.trim()||question.length>2000||typeof proof!=='string'||!proof||proof.length>16000)throw denied();
   const c=this.#c,d=this.#d,signal=AbortSignal.any([external,AbortSignal.timeout(c.timeoutMs)]);let requests=0,binding:string|undefined;
   const check=async()=>{signal.throwIfAborted();const p=await withDeadline(d.verify(proof),signal),now=Math.floor(Date.now()/1000);if(p.aud!==c.audience||p.scope!=='m365.document.read'||p.resource!==c.resource||p.execution_mode!=='interactive'||!p.sub||!p.act?.iss||!p.act.sub||!p.org_id||!p.delegation_id||p.exp<=now)throw denied();const stamp=JSON.stringify([p.iss,p.aud,p.sub,p.act,p.org_id,p.delegation_id,p.jti,p.exp]);if(binding!==undefined&&binding!==stamp)throw denied();binding=stamp;await withDeadline(d.authorise(p,{accessToken:proof}),signal);signal.throwIfAborted();};
   await check();const token=await withDeadline(d.tokenSource.getToken(),signal);if(!token?.value||/\s/.test(token.value)||token.value.length>32768||token.expiresAt<=Date.now()+5000)throw denied();
   const transport:typeof fetch=async(url,init)=>{if(++requests>c.maxRequests)throw denied();return(d.fetch??fetch)(url,init);};
   const list=async(path:string,fields:string)=>{
    const values:any[]=[];let skip:string|undefined;const seen=new Set<string>();
    do{
     await check();if(token.expiresAt<=Date.now()+1000)throw denied();const u=new URL('https://graph.microsoft.com/v1.0'+path);u.search=new URLSearchParams({'$select':fields,'$top':'50',...(skip?{'$skiptoken':skip}:{})}).toString();
     const r=await withDeadline(transport(u.href,{method:'GET',redirect:'manual',credentials:'omit',signal,headers:{Accept:'application/json',Authorization:'Bearer '+token.value}}),signal),page=await json(r,signal);
     if(!Array.isArray(page.value)||page.value.length>50)throw denied();values.push(...page.value);if(values.length>c.maxNodes)throw denied();skip=undefined;
     if(page['@odata.nextLink']!==undefined){const raw=page['@odata.nextLink'];if(typeof raw!=='string'||raw.length>8192)throw denied();const next=new URL(raw);if(next.origin!==u.origin||next.pathname!==u.pathname||next.username||next.password||next.hash||[...next.searchParams.keys()].some(k=>!['$select','$top','$skiptoken'].includes(k))||[...next.searchParams.keys()].some(k=>next.searchParams.getAll(k).length!==1)||(next.searchParams.has('$select')&&next.searchParams.get('$select')!==fields)||(next.searchParams.has('$top')&&next.searchParams.get('$top')!=='50'))throw denied();const s=next.searchParams.get('$skiptoken');if(!s||s.length>4096||seen.has(s))throw denied();seen.add(s);skip=s;}
    }while(skip);return values;
   };
   const drives=await list('/sites/'+encodeURIComponent(c.siteId)+'/drives','id,driveType,webUrl');if(drives.length>8)throw denied();
   const files:ApprovedDocument[]=[],identities=new Set<string>(),folders=new Set<string>();let nodes=0,unsupportedCount=0;
   const parts=c.siteId.toLowerCase().split(','),site=new URL(c.siteUrl);
   for(const drive of drives){
    if(!id(drive.id)||drive.driveType!=='documentLibrary'||typeof drive.webUrl!=='string')throw denied();const web=new URL(drive.webUrl);if(web.origin!==site.origin||web.username||web.password||web.hash||!web.pathname.startsWith(site.pathname+'/'))throw denied();
    const queue=[{path:'/drives/'+drive.id+'/root/children',depth:0}];
    while(queue.length){const folder=queue.shift()!;if(folder.depth>5||folders.has(folder.path))throw denied();folders.add(folder.path);
     for(const item of await list(folder.path,select)){
      if(++nodes>c.maxNodes||!id(item.id)||typeof item.name!=='string'||item.name.length>255||item.parentReference?.driveId!==drive.id)throw denied();
      const identity=drive.id+':'+item.id;if(identities.has(identity))throw denied();identities.add(identity);
      if(item.remoteItem||item.deleted){unsupportedCount++;continue;}
      if(item.folder){queue.push({path:'/drives/'+drive.id+'/items/'+item.id+'/children',depth:folder.depth+1});continue;}
      if(item.file?.mimeType!=='text/plain'||!Number.isInteger(item.size)||item.size<0||item.size>65536||!/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,100}\.txt$/.test(item.name)){unsupportedCount++;continue;}
      const sp=item.sharepointIds,parent=item.parentReference?.siteId;if(typeof sp?.siteId!=='string'||sp.siteId.toLowerCase()!==parts[1]||typeof sp.webId!=='string'||sp.webId.toLowerCase()!==parts[2]||!guid(sp.listItemUniqueId)||(parent!==undefined&&(typeof parent!=='string'||![c.siteId.toLowerCase(),parts[1]].includes(parent.toLowerCase()))))throw denied();
      files.push(validateApprovedDocument({alias:'file-'+files.length,resource:c.resource,siteId:c.siteId,siteUrl:c.siteUrl,driveId:drive.id,itemId:item.id,uniqueId:sp.listItemUniqueId,name:item.name,maxBytes:65536}));if(files.length>c.maxDocuments)throw denied();
     }
    }
   }
   const documents:{name:string;text:string;sha256:string;id:string}[]=[];let total=0;
   for(const file of files.sort((a,b)=>a.name.localeCompare(b.name)||a.itemId.localeCompare(b.itemId))){const content=await readApprovedText({document:file,appToken:token,authorise:check,signal,fetch:transport});total+=content.byteLength;if(total>262144)throw denied();documents.push({name:file.name,text:content.text,sha256:content.sha256,id:file.driveId+':'+file.itemId});}
   await check();const fingerprint=createHash('sha256').update(JSON.stringify(documents.map(v=>[v.id,v.name,v.sha256]))).digest('hex');
   // Query terms rank data locally. They never become Graph paths or authority.
   const terms=[...new Set(question.toLowerCase().match(/[\p{L}\p{N}]{3,40}/gu)??[])].slice(0,32);
   const ranked=documents.map(doc=>{const lower=doc.text.toLowerCase();let score=0,offset=-1;for(const term of terms){const p=lower.indexOf(term);if(p>=0){score++;if(offset<0||p<offset)offset=p;}}return{...doc,score,offset};}).sort((a,b)=>b.score-a.score||a.name.localeCompare(b.name)).slice(0,3);
   return{documents:ranked.map(v=>({name:v.name,text:v.text.slice(Math.max(0,v.offset-100),Math.max(0,v.offset-100)+750)})),unsupportedCount,fingerprint};
  }catch{throw denied();}
 }
}
