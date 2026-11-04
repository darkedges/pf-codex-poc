import {randomBytes,timingSafeEqual} from 'node:crypto';import type {VerifiedLogin} from '../policy/contracts.ts';import type {PortalResponse} from './portal.ts';import {documentChatView} from './document-chat-view.ts';
type Proof={idToken:string;nonce:string};type Human={idToken:string;nonce:string;login:VerifiedLogin};type Kind='chat'|'document';
type Options={origin:string;authorizationOrigin:string;agent:{issuer:string;subject:string};available():boolean;recordConsentChoice(automatic:boolean):Promise<{recorded:true}>;oidc:{start(state:string,nonce:string,verifier:string):Promise<string>;redeem(code:string,verifier:string,nonce:string):Promise<{idToken:string;login:VerifiedLogin}>};provider:{start(state:string,verifier:string):Promise<string>|string;redeem(code:string,verifier:string,human:string):Promise<{token:string;claims:{sub:string;exp:number}}>};policies:Record<Kind,{request(path:string,body:Record<string,unknown>):Promise<Record<string,any>>}>;execute(input:{chat:{grantId:string;providerToken:string;login:Proof};document:{grantId:string;login:Proof};question:string}):Promise<{answer:string;source:{name:string};cleanupConfirmed:true}>};
type Session={autoApprove?:boolean;setupFailed?:boolean;csrf:string;expiresAt:number;chat?:Human;document?:Human;chatGrant?:string;documentGrant?:string;provider?:{token:string;expiresAt:number};pending?:{kind:Kind|'provider';state:string;nonce:string;verifier:string};busy?:boolean;attempted?:boolean;revoked?:boolean;answer?:{answer:string;source:{name:string}}};
type Input={method:string;path:string;headers:{cookie?:string;origin?:string};body?:string};
const secret=()=>randomBytes(32).toString('base64url'),cookieName='__Host-fc-document-chat',escape=(s:string)=>s.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
const equal=(a:string,b:string)=>/^[A-Za-z0-9_-]{43}$/.test(a)&&a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
// Isolated chat browser controller. No key/Graph/Direct Line access, listener or
// fallback. Policy wrappers must durably journal consent intent before issuing
// it, bind responses to the exact proofs, and independently reconcile cleanup.
export class DocumentChatPortal{
 #options:Options;#sessions=new Map<string,Session>();
 constructor(options:Options){for(const o of [options.origin,options.authorizationOrigin]){const u=new URL(o);if(u.protocol!=='https:'||u.origin!==o||u.username||u.password||u.search||u.hash)throw Error('document_portal_configuration');}if(!options.agent.issuer||!options.agent.subject||typeof options.available!=='function')throw Error('document_portal_configuration');this.#options={...options,agent:{...options.agent}};}
 #cookie(id:string,age=300){return`${cookieName}=${id}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${age}`;}
 #reply(status:number,body='',headers:Record<string,string>={}):PortalResponse{return{status,html:body,headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Content-Security-Policy':`default-src 'none'; style-src 'unsafe-inline'; form-action 'self' ${this.#options.authorizationOrigin}; base-uri 'none'; frame-ancestors 'none'`,...headers}};}
 #form(s:Session,path:string,label:string){return`<form method="post" action="${path}"><input type="hidden" name="csrf" value="${s.csrf}"><button type="submit">${label}</button></form>`;}
 #signInForm(s:Session){return`<form method="post" action="/login"><input type="hidden" name="csrf" value="${s.csrf}"><label><input type="checkbox" name="autoApprove" value="true" checked> Automatically approve chat and sample-document access</label><p>With this selected, signing in approves one question for the registered research agent and one read of federated-copilot-poc.txt. Chat permission lasts at most one hour; document permission lasts five minutes. Both are revoked after the attempt. No other file or site is available. Clear this option to review each approval separately. Your question is never submitted automatically.</p><button type="submit">Sign in</button></form>`;}
 async #automatic(s:Session):Promise<PortalResponse>{
  try{
   if(!s.autoApprove||s.setupFailed||s.attempted||s.revoked||s.expiresAt<=Date.now())throw Error();
   if(!s.chatGrant){const p=await this.#preview(s,'chat'),r=await this.#options.policies.chat.request('/v1/consents/approve',{...this.#proof(s,'chat'),modes:['interactive'],durationSeconds:3600,termsHash:p.termsHash});if(typeof r.grantId!=='string'||!r.grantId)throw Error();s.chatGrant=r.grantId;}
   if(!s.provider){const pending={kind:'provider' as const,state:secret(),nonce:secret(),verifier:secret()};s.pending=pending;return this.#reply(302,'',{Location:this.#redirect(await this.#options.provider.start(pending.state,pending.verifier))});}
   if(!s.document){const pending={kind:'document' as const,state:secret(),nonce:secret(),verifier:secret()};s.pending=pending;return this.#reply(302,'',{Location:this.#redirect(await this.#options.oidc.start(pending.state,pending.nonce,pending.verifier))});}
   if(!s.documentGrant){const p=await this.#preview(s,'document'),r=await this.#options.policies.document.request('/v1/consents/approve',{...this.#proof(s,'document'),modes:['interactive'],durationSeconds:300,termsHash:p.termsHash});if(typeof r.grantId!=='string'||!r.grantId)throw Error();s.documentGrant=r.grantId;}
   return this.#reply(303,'',{Location:'/'});
  }catch{s.setupFailed=true;delete s.pending;try{await this.#revoke(s);}catch{}throw Error('document_chat_setup_failed');}
 }
 #page(s:Session){let body='<h1>Chat with your approved document</h1><p>One question and the synthetic SharePoint sample will be sent to Copilot Studio. Chat and document permissions remain separate. You can approve both during sign-in or review each approval separately. Microsoft conversation and execution-trace protection has not been verified.</p>';
  if(s.answer)body=documentChatView({csrf:s.csrf,ready:false,answer:s.answer});
  else if(s.revoked)body+='<h2>Access revoked</h2>';
  else if(s.setupFailed)body+='<h2>Sign-in setup did not complete</h2><p>No automatic retry was made. Revoke access or sign out.</p>';
  else if(s.attempted)body+='<h2>Answer not verified</h2><p>No automatic retry was made. Revoke access or sign out.</p>';
  else if(!this.#options.available())body+='<p>Live chat is not enabled.</p>';
  else if(!s.chat)body+=this.#signInForm(s);
  else if(!s.chatGrant)body+=`<p>Approve one Copilot chat for ${escape(s.chat.login.subject)}. The website permits one question; you can revoke access here.</p>`+this.#form(s,'/approve','Approve one chat');
  else if(!s.provider)body+=this.#form(s,'/provider-login','Connect your Copilot sign-in');
  else if(!s.document)body+='<p>Sign in again to create fresh, separately bound document consent for the same account.</p>'+this.#form(s,'/login','Confirm document identity');
  else if(!s.documentGrant)body+='<p>Allow one read of the approved synthetic sample for this answer. Document permission expires after five minutes and is revoked before the read result is released. No other site or file is available.</p>'+this.#form(s,'/approve','Approve document access');
  else body+=documentChatView({csrf:s.csrf,ready:true});
  if(s.chatGrant&&!s.revoked)body+=this.#form(s,'/revoke','Revoke access');if(s.chat)body+=this.#form(s,'/logout','Sign out');
  return`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Federated document chat</title><style>body{font:17px/1.6 system-ui;color:#183c37;background:#f3f5f2}main{max-width:760px;margin:5vh auto;padding:28px}button,textarea{font:inherit;padding:12px}textarea{display:block;width:90%;min-height:100px}button{background:#146b59;color:white;border:0;border-radius:8px}form{margin:18px 0}</style><main>${body}</main></html>`;
 }
 #new(s?:Session){if(this.#sessions.size>=100)throw Error();const id=secret(),session=s?{...s,csrf:secret(),busy:false}:{csrf:secret(),expiresAt:Date.now()+300000};this.#sessions.set(id,session);return{id,session};}
 #proof(s:Session,kind:Kind){const h=s[kind];if(!h||!h.idToken||s.expiresAt<=Date.now()||h.login.expiresAt<=Date.now())throw Error();return{idToken:h.idToken,nonce:h.nonce};}
 #redirect(value:string){const u=new URL(value);if(u.origin!==this.#options.authorizationOrigin||u.username||u.password||u.hash)throw Error();return u.href;}
 async #preview(s:Session,kind:Kind){const p=await this.#options.policies[kind].request('/v1/consents/preview',this.#proof(s,kind));if(p.capability?.scope!==(kind==='chat'?'copilot.invoke':'m365.document.read')||p.capability?.resource!=='sharepoint:approved-research'||p.human?.subject!==s.chat?.login.subject||p.agent?.subject!==this.#options.agent.subject||p.agent?.issuer!==this.#options.agent.issuer||!p.modes?.includes('interactive')||!p.durationsSeconds?.includes(kind==='chat'?3600:300)||typeof p.termsHash!=='string')throw Error();return p;}
 async #revoke(s:Session){if(s.revoked)return;for(const kind of ['document','chat'] as const){const grant=s[kind==='chat'?'chatGrant':'documentGrant'];if(grant){const r=await this.#options.policies[kind].request('/v1/consents/revoke',{...this.#proof(s,kind),grantId:grant});if(r.revoked!==true)throw Error();}}s.revoked=true;delete s.provider;delete s.pending;}
 async handle(input:Input):Promise<PortalResponse>{
  for(const [id,s]of this.#sessions)if(s.expiresAt<=Date.now()&&(!s.chatGrant||s.revoked))this.#sessions.delete(id);
  try{
   if(input.path.length>8192||!input.path.startsWith('/'))throw Error();const u=new URL(input.path,this.#options.origin);if(u.origin!==this.#options.origin||u.hash)throw Error();
   const cookies=(input.headers.cookie??'').split(';').map(v=>v.trim().split('=')).filter(p=>p[0]===cookieName),id=cookies.length===1?cookies[0][1]:'',s=this.#sessions.get(id);
   if(input.method==='GET'&&input.path==='/'){const fresh=s&&s.expiresAt>Date.now()?{id,session:s}:this.#new();return this.#reply(200,this.#page(fresh.session),{'Set-Cookie':this.#cookie(fresh.id)});}
   if(input.method==='GET'&&['/callback','/provider-callback'].includes(u.pathname)){
    if(!s||s.busy||s.expiresAt<=Date.now()||!s.pending||!this.#options.available())throw Error();const p=s.pending;
    if((p.kind==='provider')!==(u.pathname==='/provider-callback')||[...u.searchParams.keys()].some(k=>!['code','state','iss'].includes(k)||u.searchParams.getAll(k).length!==1)||!equal(u.searchParams.get('state')??'',p.state)||!u.searchParams.get('code'))throw Error();delete s.pending;s.busy=true;
    try{
     if(p.kind==='provider'){if(!s.chat||!s.chatGrant||s.provider||u.searchParams.has('iss'))throw Error();const result=await this.#options.provider.redeem(u.searchParams.get('code')!,p.verifier,s.chat.login.subject);if(result.claims.sub!==s.chat.login.subject||result.claims.exp*1000<=Date.now())throw Error();s.provider={token:result.token,expiresAt:result.claims.exp*1000};s.csrf=secret();return s.autoApprove?await this.#automatic(s):this.#reply(303,'',{Location:'/'});}
     const result=await this.#options.oidc.redeem(u.searchParams.get('code')!,p.verifier,p.nonce),h={...result,nonce:p.nonce};
     if(u.searchParams.has('iss')&&u.searchParams.get('iss')!==h.login.issuer||h.login.expiresAt<=Date.now()||h.login.authTime<Date.now()-300000||h.login.issuedAt<Date.now()-300000)throw Error();
     if(p.kind==='document'&&(!s.chat||h.login.subject!==s.chat.login.subject||h.login.issuer!==s.chat.login.issuer||h.login.audience!==s.chat.login.audience||h.login.tokenHash===s.chat.login.tokenHash))throw Error();
     s[p.kind]=h;s.expiresAt=Math.min(s.expiresAt,h.login.expiresAt,h.login.authTime+300000,h.login.issuedAt+300000);const fresh=this.#new(s);this.#sessions.delete(id);const next=fresh.session.autoApprove?await this.#automatic(fresh.session):this.#reply(303,'',{Location:'/'});return{...next,headers:{...next.headers,'Set-Cookie':this.#cookie(fresh.id)}};
    }catch{if(s.autoApprove){s.setupFailed=true;try{await this.#revoke(s);}catch{}}throw Error('document_chat_setup_failed');}finally{s.busy=false;}
   }
   if(input.method!=='POST'||u.search||!['/login','/approve','/provider-login','/check','/revoke','/logout'].includes(u.pathname))return this.#reply(404);
   if(!s||s.busy||s.expiresAt<=Date.now()||input.headers.origin!==this.#options.origin||Buffer.byteLength(input.body??'')>8192)throw Error();const form=new URLSearchParams(input.body??'');if([...form.keys()].some(k=>k!=='csrf'&&(u.pathname!=='/check'||k!=='question')&&(u.pathname!=='/login'||!!s.chat||k!=='autoApprove'))||form.getAll('csrf').length!==1||!equal(form.get('csrf')??'',s.csrf)||form.getAll('question').length>1||form.getAll('autoApprove').length>1||form.has('autoApprove')&&form.get('autoApprove')!=='true')throw Error();s.busy=true;
   try{
    if(u.pathname==='/revoke'||u.pathname==='/logout'){await this.#revoke(s);if(u.pathname==='/logout'){this.#sessions.delete(id);return this.#reply(303,'',{Location:'/','Set-Cookie':this.#cookie('',0)});}}
    else{
     if(!this.#options.available()||s.attempted||s.setupFailed||s.revoked)throw Error();
     if(u.pathname==='/login'){if(!s.chat){const automatic=form.get('autoApprove')==='true',recorded=await this.#options.recordConsentChoice(automatic);if(recorded.recorded!==true)throw Error();s.autoApprove=automatic;}const kind:Kind=!s.chat?'chat':'document';if(kind==='document'&&(!s.chatGrant||!s.provider||s.document))throw Error();const pending={kind,state:secret(),nonce:secret(),verifier:secret()};s.pending=pending;return this.#reply(302,'',{Location:this.#redirect(await this.#options.oidc.start(pending.state,pending.nonce,pending.verifier))});}
     if(u.pathname==='/approve'){const kind:Kind=!s.chatGrant?'chat':'document';if(kind==='document'&&(!s.provider||!s.document||s.documentGrant))throw Error();const preview=await this.#preview(s,kind),r=await this.#options.policies[kind].request('/v1/consents/approve',{...this.#proof(s,kind),modes:['interactive'],durationSeconds:kind==='chat'?3600:300,termsHash:preview.termsHash});if(typeof r.grantId!=='string'||!r.grantId)throw Error();s[kind==='chat'?'chatGrant':'documentGrant']=r.grantId;}
     else if(u.pathname==='/provider-login'){if(!s.chat||!s.chatGrant||s.provider)throw Error();const pending={kind:'provider' as const,state:secret(),nonce:secret(),verifier:secret()};s.pending=pending;return this.#reply(302,'',{Location:this.#redirect(await this.#options.provider.start(pending.state,pending.verifier))});}
     else if(u.pathname==='/check'){
      if(!s.chatGrant||!s.documentGrant||!s.provider||s.provider.expiresAt<=Date.now()||!form.get('question')||form.get('question')!.length>2000)throw Error();
      for(const kind of ['chat','document'] as const){const p=await this.#preview(s,kind),grant=s[kind==='chat'?'chatGrant':'documentGrant'];if(!Array.isArray(p.grants)||!p.grants.some(g=>g.id===grant&&g.state==='active'&&g.expiresAt>Date.now()))throw Error();}
      const providerToken=s.provider.token;delete s.provider;s.attempted=true;const result=await this.#options.execute({chat:{grantId:s.chatGrant,providerToken,login:this.#proof(s,'chat')},document:{grantId:s.documentGrant,login:this.#proof(s,'document')},question:form.get('question')!});
      if(result.cleanupConfirmed!==true||typeof result.answer!=='string'||!result.answer||result.answer.length>8000||typeof result.source?.name!=='string')throw Error();s.answer={answer:result.answer,source:{name:result.source.name}};s.revoked=true;s.chat!.idToken='';s.document!.idToken='';
     }
    }
    s.csrf=secret();return this.#reply(303,'',{Location:'/'});
   }finally{s.busy=false;}
  }catch{return this.#reply(403,'<h1>Request could not be completed</h1><p>No automatic retry was made. Return to review your access.</p><a href="/">Return to chat</a>');}
 }
}
