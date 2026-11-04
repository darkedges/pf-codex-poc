import {validateApprovedDocument,readApprovedText,withDeadline as bounded,type ApprovedDocument} from './approved-content.ts';
import type {DelegatedClaims,TokenVerifier} from '../adapters/token-exchange.ts';
export class GraphDocumentError extends Error{constructor(code='unavailable'){super(code);this.name='GraphDocumentError';}}
export type {ApprovedDocument} from './approved-content.ts';
export interface GraphAppTokenSource{getToken():Promise<{value:string;expiresAt:number}>}
type Config={documents:ApprovedDocument[];proofAudience:string;timeoutMs:number};
type Dependencies={verifier:TokenVerifier;authorise:(claims:Readonly<DelegatedClaims>,evidence:{accessToken:string;capability:{scope:string;resource:string}})=>Promise<void>;tokenSource:GraphAppTokenSource;fetch?:typeof fetch;observe?:(event:{event:'graph_document_read';outcome:'success'|'failure';bytes:number;durationMs:number})=>void};
function freeze(c:DelegatedClaims){return Object.freeze({...c,act:Object.freeze({...c.act})});}
// Closed resource adapter: aliases come from operator configuration, identities only
// from the configured verifier, and every outbound boundary consults current policy.
export class GraphDocumentAdapter{
 #documents:ApprovedDocument[];#deps:Dependencies;#timeout:number;#audience:string;
 constructor(config:Config,deps:Dependencies){
  try{
   if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||!Number.isInteger(config.timeoutMs)||config.timeoutMs<100||config.timeoutMs>30000||typeof config.proofAudience!=='string'||!config.proofAudience||!Array.isArray(config.documents)||!config.documents.length||config.documents.length>16||new Set(config.documents.map(d=>d.alias)).size!==config.documents.length||typeof deps.verifier?.verify!=='function'||typeof deps.authorise!=='function'||typeof deps.tokenSource?.getToken!=='function')throw Error();
   this.#documents=config.documents.map(validateApprovedDocument);this.#deps={...deps};this.#timeout=config.timeoutMs;this.#audience=config.proofAudience;
  }catch{throw new GraphDocumentError('configuration');}
 }
 async readDocument(delegatedToken:string,alias:string){
  const started=Date.now(),signal=AbortSignal.timeout(this.#timeout);let count=0,success=false;
  try{
   const d=this.#documents.find(v=>v.alias===alias);if(!d)throw new GraphDocumentError('unknown_resource');if(typeof delegatedToken!=='string'||!delegatedToken||delegatedToken.length>16000)throw Error();
   const c=freeze(await bounded(this.#deps.verifier.verify(delegatedToken),signal)),now=Math.floor(Date.now()/1000);
   if(c.aud!==this.#audience||!c.iss||!c.sub||!c.act?.iss||!c.act.sub||!c.org_id||!c.delegation_id||!c.jti||c.scope!=='m365.document.read'||!['interactive','autonomous'].includes(c.execution_mode)||![c.iat,c.nbf,c.exp].every(Number.isSafeInteger)||c.iat>now||c.nbf>now||c.exp<=now||c.exp<=c.iat)throw new GraphDocumentError('invalid_token');
   const authorise=async()=>{signal.throwIfAborted();if(c.exp*1000<=Date.now())throw Error();await bounded(this.#deps.authorise(c,{accessToken:delegatedToken,capability:{scope:'m365.document.read',resource:d.resource}}),signal);signal.throwIfAborted();};
   await authorise();const token=await bounded(this.#deps.tokenSource.getToken(),signal);if(typeof token?.value!=='string'||!token.value||token.value.length>32768||/\s/.test(token.value)||!Number.isSafeInteger(token.expiresAt)||token.expiresAt<=Date.now()+5000)throw Error();
   const content=await readApprovedText({document:d,appToken:token,authorise,signal,fetch:this.#deps.fetch});count=content.byteLength;const text=content.text;
   const identity={iss:c.iss,aud:c.aud,sub:c.sub,act:{...c.act},org_id:c.org_id,delegation_id:c.delegation_id,execution_mode:c.execution_mode,scope:c.scope};success=true;
   return{alias:d.alias,resource:d.resource,name:d.name,text,untrustedDocument:true as const,identity};
  }catch(e){throw e instanceof GraphDocumentError?e:new GraphDocumentError();}
  finally{try{this.#deps.observe?.({event:'graph_document_read',outcome:success?'success':'failure',bytes:count,durationMs:Date.now()-started});}catch{}}
 }
}
