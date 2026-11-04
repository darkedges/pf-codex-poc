import type {PolicyStore} from '../policy/store.ts';import type {VerifiedLogin} from '../policy/contracts.ts';import {bodyHash} from '../policy/protocol.ts';import {DocumentChatJournal,type ChatConsentKind,type ChatOperation} from './document-chat-journal.ts';
type Proof={idToken:string;nonce:string};type Policy={request(path:string,body:Record<string,unknown>):Promise<Record<string,any>>};
type Input={chat:{grantId:string;providerToken:string;login:Proof};document:{grantId:string;login:Proof};question:string};
type Options={requireConsentChoice?:boolean;journal:DocumentChatJournal;store:PolicyStore;profile:{humanId:string;agentId:string;organisation:string};loginVerifier:{verify(token:string,nonce:string):Promise<VerifiedLogin>};policies:Record<ChatConsentKind,Policy>;findGrant(hash:string):Promise<string|null>;perform(input:Input,controls:{reserve(kind:ChatOperation):void;confirmDocument():Promise<void>;cleanupChat():Promise<{revoked:true}>}):Promise<{answer:string;source:{name:string}}>};
const exact=(v:any,keys:string[])=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===[...keys].sort().join();
export function createDocumentChatControl(options:Options){
 const {journal,store}=options,profile={...options.profile},cap=(kind:ChatConsentKind)=>({scope:kind==='chat'?'copilot.invoke':'m365.document.read',resource:'sharepoint:approved-research'});
 const available=()=>{const s=journal.snapshot();if(s.closed||s.expired)throw Error('document_chat_unavailable');};
 const verify=async(p:Proof)=>{if(!exact(p,['idToken','nonce'])||typeof p.idToken!=='string'||p.idToken.length>16000||typeof p.nonce!=='string'||p.nonce.length>256)throw Error('document_chat_denied');const login=await options.loginVerifier.verify(p.idToken,p.nonce);if(login.tokenHash!==bodyHash(p.idToken)||login.nonceHash!==bodyHash(p.nonce))throw Error('document_chat_denied');return login;};
 const owned=(kind:ChatConsentKind,hash:string,id:string)=>{
  const g=store.grant(id),s=store.consentForGrant(id),duration=g?Number(g.expires_at)-Number(g.approved_at):NaN,intent=journal.consent(kind);if(!intent||Number(g?.approved_at)<intent.createdAt)throw Error('document_chat_foreign_consent');
  if(!g||!s||s.token_hash!==hash||g.human_id!==profile.humanId||g.agent_id!==profile.agentId||g.organisation!==profile.organisation||g.recorded_by!==(kind==='chat'?'policy-consent':'policy-document-consent')||!Number.isSafeInteger(duration)||duration<=0||duration>(kind==='chat'?3600000:300000)||JSON.stringify(JSON.parse(String(g.scopes)))!==JSON.stringify([cap(kind).scope])||JSON.stringify(JSON.parse(String(g.resources)))!==JSON.stringify([cap(kind).resource])||JSON.stringify(JSON.parse(String(g.modes)))!=='["interactive"]')throw Error('document_chat_consent_denied');return g;
 };
 const recoverOne=async(kind:ChatConsentKind)=>{
  const c=journal.consent(kind);if(!c||c.state==='recovered')return;if(!c.proofHash)throw Error('document_chat_cleanup_pending');let id=c.grantId;
  if(!id){id=await options.findGrant(c.proofHash);if(!id)throw Error('document_chat_cleanup_pending');owned(kind,c.proofHash,id);journal.attachGrantForRecovery(kind,c.proofHash,id);}
  const g=owned(kind,c.proofHash,id);if(g.state!=='revoked')store.revokeGrant(id,'document-chat-cleanup');
  if(owned(kind,c.proofHash,id).state!=='revoked')throw Error('document_chat_cleanup_pending');journal.markRevoked(kind,id);
 };
 const recover=async()=>{let failed=false;for(const kind of ['document','chat'] as const)try{await recoverOne(kind);}catch{failed=true;}if(failed||journal.pending().length)throw Error('document_chat_cleanup_pending');if(journal.consent('chat'))journal.finish();return{pending:0};};
 const policy=(kind:ChatConsentKind):Policy=>({request:async(path,body)=>{
  if(!['/v1/consents/preview','/v1/consents/approve','/v1/consents/revoke'].includes(path))throw Error('document_chat_denied');
  const login=await verify({idToken:body.idToken as string,nonce:body.nonce as string}),c=journal.consent(kind);
  if(path.endsWith('/revoke')){if(!c||c.proofHash!==login.tokenHash||c.grantId!==body.grantId)throw Error('document_chat_denied');await recoverOne(kind);if(journal.pending().length===0)journal.finish();return{revoked:true};}
  available();const preview=await options.policies[kind].request('/v1/consents/preview',{idToken:body.idToken,nonce:body.nonce}),human=store.principal(profile.humanId),agent=store.principal(profile.agentId);
  if(preview.capability?.scope!==cap(kind).scope||preview.capability?.resource!==cap(kind).resource||preview.human?.subject!==human?.subject||preview.human?.organisation!==profile.organisation||preview.agent?.subject!==agent?.subject||preview.agent?.issuer!==agent?.issuer)throw Error('document_chat_policy_binding');
  if(path.endsWith('/preview'))return{...preview,grants:(preview.grants??[]).filter(g=>c?.grantId===g.id)};
  if(!exact(body,['idToken','nonce','modes','durationSeconds','termsHash'])||JSON.stringify(body.modes)!=='["interactive"]'||body.durationSeconds!==(kind==='chat'?3600:300)||body.termsHash!==preview.termsHash)throw Error('document_chat_denied');
  if(options.requireConsentChoice&&journal.consentChoice()===null)throw Error('document_chat_choice_required');journal.beginConsent(kind,login.tokenHash);const result=await options.policies[kind].request(path,body);
  if(typeof result.grantId!=='string')throw Error('document_chat_consent_unconfirmed');owned(kind,login.tokenHash,result.grantId);journal.attachGrant(kind,login.tokenHash,result.grantId);return result;
 }});
 return{policies:{chat:policy('chat'),document:policy('document')},recover,
  execute:async(input:Input)=>{
   available();if(!exact(input,['chat','document','question'])||!exact(input.chat,['grantId','providerToken','login'])||!exact(input.document,['grantId','login'])||typeof input.question!=='string'||!input.question.trim()||input.question.length>2000||typeof input.chat.providerToken!=='string'||!input.chat.providerToken||input.chat.providerToken.length>16000)throw Error('document_chat_denied');
   const a=await verify(input.chat.login),b=await verify(input.document.login);if(a.subject!==b.subject||a.issuer!==b.issuer||a.audience!==b.audience||a.tokenHash===b.tokenHash)throw Error('document_chat_identity_denied');
   for(const [kind,login]of [['chat',a],['document',b]] as const){const c=journal.consent(kind),id=input[kind].grantId;if(!c||c.grantId!==id||c.proofHash!==login.tokenHash||owned(kind,login.tokenHash,id).state!=='active')throw Error('document_chat_consent_denied');}
   journal.beginTurn();
   try{const result=await options.perform(input,{reserve:kind=>journal.consume(kind),confirmDocument:()=>recoverOne('document'),cleanupChat:async()=>{await recoverOne('chat');return{revoked:true};}});if(typeof result.answer!=='string'||!result.answer||result.answer.length>8000||typeof result.source?.name!=='string')throw Error();return{...result,cleanupConfirmed:true as const};}
   catch{throw Error('document_chat_unverified');}
   finally{try{await recover();}catch{throw Error('document_chat_cleanup_pending');}}
  }
 };
}
