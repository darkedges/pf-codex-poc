import {randomBytes,timingSafeEqual} from 'node:crypto';
import {PolicyError,type VerifiedLogin} from '../policy/contracts.ts';
import type {PortalResponse} from './portal.ts';

type Login={login:VerifiedLogin;idToken:string};
type Proof={idToken:string;nonce:string};
export type AgentPortalOptions={
 origin:string;
 authorizationOrigin?:string;
 repeatableSessions?:boolean;
 signInEnabled?:()=>boolean;
 capability:{scope:string;resource:string};agent:{issuer:string;subject:string};
 oidc:{start(state:string,nonce:string,verifier:string):Promise<string>;redeem(code:string,verifier:string,nonce:string):Promise<Login>};
 provider:{start(state:string,verifier:string):string|Promise<string>;redeem(code:string,verifier:string,human:string):Promise<{token:string;claims:{sub:string;exp:number}}>};
 policy:{request(path:string,body:Record<string,unknown>):Promise<Record<string,unknown>>};
 // The live implementation must reserve a durable allowance before any Microsoft request.
 execute(proof:{grantId:string;providerToken:string;login:Proof}):Promise<{authorized:true}>;
};
type Session={csrf:string;expiresAt:number;pending?:{kind:'human'|'provider';state:string;nonce:string;verifier:string;expiresAt:number};human?:Login&{nonce:string};grantId?:string;provider?:{token:string;expiresAt:number};busy?:boolean;attempted?:boolean;verified?:boolean;revoked?:boolean};
type Input={method:string;path:string;headers:{cookie?:string;origin?:string};body?:string};
const secret=()=>randomBytes(32).toString('base64url');
const equal=(a:string,b:string)=>/^[A-Za-z0-9_-]{43}$/.test(a)&&a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const escape=(v:string)=>v.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
const cookieName='__Host-fc-agent';

// No listener, secret-file access, lab login, mock fallback or Microsoft transport.
// This is an interactive, one-check session controller, not a general chat endpoint.
export class AgentPortal{
 private options:AgentPortalOptions;
 private sessions=new Map<string,Session>();
 constructor(options:AgentPortalOptions){
  const origin=new URL(options.origin);
  if(origin.protocol!=='https:'||origin.username||origin.password||origin.pathname!=='/'||origin.search||origin.hash)throw new PolicyError('configuration');
  if(options.repeatableSessions!==undefined&&typeof options.repeatableSessions!=='boolean')throw new PolicyError('configuration');
  if(options.authorizationOrigin!==undefined){const authorization=new URL(options.authorizationOrigin);if(authorization.protocol!=='https:'||authorization.origin!==options.authorizationOrigin)throw new PolicyError('configuration');}
  if(!options.capability?.scope||!options.capability.resource||!options.agent?.issuer||!options.agent.subject)throw new PolicyError('configuration');
  this.options={...options,capability:{...options.capability},agent:{...options.agent},origin:origin.origin};
 }
 private reply(status:number,html='',headers:Record<string,string>={}):PortalResponse{return{status,html,headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Referrer-Policy':status===200?'same-origin':'no-referrer','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Content-Security-Policy':`default-src 'none'; style-src 'unsafe-inline'; form-action 'self'${this.options.authorizationOrigin?' '+this.options.authorizationOrigin:''}; base-uri 'none'; frame-ancestors 'none'`,...headers}};}
 private authorizationRedirect(value:string){const url=new URL(value);if(url.protocol!=='https:'||url.username||url.password||url.hash||this.options.authorizationOrigin&&url.origin!==this.options.authorizationOrigin)throw new PolicyError();return url.href;}
 private cookie(id:string,maxAge=300){return`${cookieName}=${id}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;}
 private create(){if(this.sessions.size>=200)throw new PolicyError('unavailable');const id=secret(),session:Session={csrf:secret(),expiresAt:Date.now()+300000};this.sessions.set(id,session);return{id,session};}
 private page(content:string){return`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Federated agent</title><style>body{margin:0;background:#f3f5f2;color:#183c37;font:17px/1.6 system-ui,sans-serif}main{max-width:720px;margin:8vh auto;padding:28px}header{font-weight:700;margin-bottom:50px}h1{font-size:42px;line-height:1.15;letter-spacing:-.035em}.card{background:white;padding:28px;border:1px solid #d7e2dc;border-radius:16px;margin:24px 0}button{font:600 16px system-ui;background:#146b59;color:white;border:0;padding:13px 20px;border-radius:8px;cursor:pointer}form{margin:16px 0}small,footer{color:#526b65}a{color:#146b59}</style><main><header>Federated agent · Integration PoC</header>${content}<footer>Access is limited to the approved diagnostic. Microsoft 365 documents are not connected.</footer></main></html>`;}
 private form(s:Session,path:string,label:string){return`<form method="post" action="${path}"><input type="hidden" name="csrf" value="${s.csrf}"><button type="submit">${label}</button></form>`;}
 private render(s:Session){
  let content='<h1>Your identity.<br>Your agent.<br>Your permission.</h1><p>Sign in, approve access, then check a live delegated connection to Copilot Studio.</p>';
  if(!s.human)content+=this.options.signInEnabled?.()===false?'<section class="card"><h2>Live testing is not enabled</h2><p>The access check is being prepared. Sign-in will be available when this test is activated.</p></section>':`<section class="card"><h2>Start with sign-in</h2><p>Use your organisation’s PingFederate account.</p>${this.form(s,'/login','Sign in')}</section>`;
  else{
   content+=`<p>Signed in as <strong>${escape(s.human.login.subject)}</strong>.</p><section class="card">`;
   if(s.revoked)content+='<h2>Access revoked</h2><p>This permission can no longer be used.</p>';
   else if(!s.grantId)content+=`<h2>Approve one access check</h2><p>Allow the registered research agent to invoke the delegated access diagnostic while you are signed in. Permission expires after one hour and can be revoked here. The website allows one check per approval.</p><p><small>This PoC passes your provider token through a Microsoft tool input. Protection from Microsoft execution traces has not been verified.</small></p>${this.form(s,'/approve','Approve access')}`;
   else if(s.verified)content+='<h2>Delegated access verified</h2><p>Copilot Studio completed the approved access diagnostic.</p>';
   else if(s.attempted)content+='<h2>Check not verified</h2><p>This attempt has ended. No automatic retry will be made.</p>';
   else if(!s.provider)content+=`<h2>Connect your Copilot sign-in</h2><p>Complete the provider sign-in for the same account.</p>${this.form(s,'/provider-login','Continue sign-in')}`;
   else content+=`<h2>Ready for the live check</h2><p>This sends one fixed diagnostic to the published agent.</p>${this.form(s,'/check','Check delegated access')}`;
   content+='</section>';
   if(s.grantId&&!s.revoked)content+=this.form(s,'/revoke','Revoke access');
   content+=this.form(s,'/logout',this.options.repeatableSessions&&(s.attempted||s.revoked)?'Sign out and start again':s.grantId&&!s.revoked?'Revoke and sign out':'Sign out');
  }
  return this.page(content);
 }
 private proof(s:Session):Proof{if(!s.human||s.expiresAt<=Date.now())throw new PolicyError();return{idToken:s.human.idToken,nonce:s.human.nonce};}
 private async preview(proof:Proof,human:string){
  const p=await this.options.policy.request('/v1/consents/preview',proof),c=p.capability as any,a=p.agent as any,h=p.human as any;
  if(c?.scope!==this.options.capability.scope||c?.resource!==this.options.capability.resource||a?.issuer!==this.options.agent.issuer||a?.subject!==this.options.agent.subject||h?.subject!==human)throw new PolicyError();
  return p;
 }
 private async revoke(s:Session){if(s.grantId&&!s.revoked){await this.options.policy.request('/v1/consents/revoke',{...this.proof(s),grantId:s.grantId});s.revoked=true;}delete s.provider;delete s.pending;s.verified=false;}
 async handle(input:Input):Promise<PortalResponse>{
  // Retain expired owned-grant pointers for operator recovery; never silently turn
  // a lost browser session into a revoked-grant claim. Live hosting needs durable recovery.
  for(const [id,s]of this.sessions)if(s.expiresAt<=Date.now()){
   delete s.human;delete s.provider;delete s.pending;
   if(!s.grantId||s.revoked)this.sessions.delete(id);
  }
  try{
   if(input.path.length>8192||!input.path.startsWith('/'))throw new PolicyError('invalid_request');
   const url=new URL(input.path,this.options.origin);if(url.origin!==this.options.origin||url.hash)throw new PolicyError('invalid_request');
   const matches=(input.headers.cookie??'').split(';').map(v=>v.trim().split('=')).filter(([name])=>name===cookieName);
   const id=matches.length===1?matches[0][1]:'',s=this.sessions.get(id);
   if(input.method==='GET'&&url.pathname==='/'&&!url.search){
    if(s&&s.expiresAt>Date.now())return this.reply(200,this.render(s));
    const fresh=this.create();return this.reply(200,this.render(fresh.session),{'Set-Cookie':this.cookie(fresh.id)});
   }
   if(input.method==='GET'&&['/callback','/provider-callback'].includes(url.pathname)){
    if(!s||s.busy||s.expiresAt<=Date.now())throw new PolicyError();
    const p=s.pending,kind=url.pathname==='/callback'?'human':'provider',params=url.searchParams;
    if(!p||p.kind!==kind||p.expiresAt<=Date.now()||[...params.keys()].some(k=>!['code','state','iss'].includes(k)||params.getAll(k).length!==1)||!equal(params.get('state')??'',p.state)||!params.get('code'))throw new PolicyError();
    delete s.pending;s.busy=true;
    try{
     if(kind==='human'){
      const result=await this.options.oidc.redeem(params.get('code')!,p.verifier,p.nonce);
      if(params.has('iss')&&params.get('iss')!==result.login.issuer)throw new PolicyError();
      await this.preview({idToken:result.idToken,nonce:p.nonce},result.login.subject);
      const deadline=Math.min(result.login.expiresAt,result.login.issuedAt+300000,result.login.authTime+300000,Date.now()+300000);
      if(deadline<=Date.now())throw new PolicyError();
      const fresh=this.create();fresh.session.human={...result,nonce:p.nonce};fresh.session.expiresAt=deadline;this.sessions.delete(id);
      return this.reply(303,'',{Location:'/','Set-Cookie':this.cookie(fresh.id)});
     }
     if(params.has('iss'))throw new PolicyError('invalid_request');
     this.proof(s);if(!s.grantId||s.revoked||s.attempted)throw new PolicyError();
     const result=await this.options.provider.redeem(params.get('code')!,p.verifier,s.human!.login.subject);
     if(result.claims.sub!==s.human!.login.subject||result.claims.exp*1000<=Date.now())throw new PolicyError();
     s.provider={token:result.token,expiresAt:result.claims.exp*1000};s.csrf=secret();
     return this.reply(303,'',{Location:'/'});
    }finally{s.busy=false;}
   }
   if(input.method!=='POST'||url.search||!['/login','/approve','/provider-login','/check','/revoke','/logout'].includes(url.pathname))return this.reply(404,this.page('<h1>Page not found</h1>'));
   if(!s||s.expiresAt<=Date.now()||input.headers.origin!==this.options.origin)throw new PolicyError();
   const raw=input.body??'';if(Buffer.byteLength(raw)>1024)throw new PolicyError('invalid_request');
   const form=new URLSearchParams(raw);if([...form.keys()].some(k=>k!=='csrf')||form.getAll('csrf').length!==1)throw new PolicyError('invalid_request');
   if(!equal(form.get('csrf')??'',s.csrf))throw new PolicyError();if(s.busy)throw new PolicyError('conflict');
   s.busy=true;
   try{
    if(url.pathname==='/login'){
     if(this.options.signInEnabled?.()===false)throw new PolicyError('unavailable');
     if(s.human||s.grantId)throw new PolicyError('conflict');
     const p={kind:'human' as const,state:secret(),nonce:secret(),verifier:secret(),expiresAt:Date.now()+300000};s.pending=p;
     return this.reply(302,'',{Location:this.authorizationRedirect(await this.options.oidc.start(p.state,p.nonce,p.verifier))});
    }
    if(url.pathname==='/logout'){
     await this.revoke(s);this.sessions.delete(id);return this.reply(303,'',{Location:'/','Set-Cookie':this.cookie('',0)});
    }
    const proof=this.proof(s);
    if(url.pathname==='/approve'){
     if(s.grantId)throw new PolicyError('conflict');
     const preview=await this.preview(proof,s.human!.login.subject);
     if(!Array.isArray(preview.durationsSeconds)||!preview.durationsSeconds.includes(3600)||!Array.isArray(preview.modes)||!preview.modes.includes('interactive')||typeof preview.termsHash!=='string')throw new PolicyError();
     const result=await this.options.policy.request('/v1/consents/approve',{...proof,termsHash:preview.termsHash,modes:['interactive'],durationSeconds:3600});
     if(typeof result.grantId!=='string'||!result.grantId)throw new PolicyError('unavailable');s.grantId=result.grantId;
    }else if(url.pathname==='/revoke')await this.revoke(s);
    else{
     if(!s.grantId||s.revoked)throw new PolicyError();if(s.attempted)throw new PolicyError('conflict');
     const preview=await this.preview(proof,s.human!.login.subject);
     if(!Array.isArray(preview.grants)||!preview.grants.some(g=>g.id===s.grantId&&g.state==='active'&&g.expiresAt>Date.now()))throw new PolicyError();
     if(url.pathname==='/provider-login'){
      if(s.provider)throw new PolicyError('conflict');const p={kind:'provider' as const,state:secret(),nonce:secret(),verifier:secret(),expiresAt:Date.now()+120000};s.pending=p;
     return this.reply(302,'',{Location:this.authorizationRedirect(await this.options.provider.start(p.state,p.verifier))});
     }
     if(!s.provider||s.provider.expiresAt<=Date.now())throw new PolicyError();
     const token=s.provider.token;delete s.provider;s.attempted=true;
     try{const result=await this.options.execute({grantId:s.grantId,providerToken:token,login:proof});s.verified=result?.authorized===true;}catch{s.verified=false;}
    }
    s.csrf=secret();return this.reply(303,'',{Location:'/'});
   }finally{s.busy=false;}
  }catch(e){const code=e instanceof PolicyError?e.code:'unavailable';return this.reply(code==='invalid_request'?400:code==='conflict'?409:code==='unavailable'?503:403,this.page('<h1>Request could not be completed</h1><p>No automatic retry was made. Return to review your access.</p><a href="/">Return to the agent</a>'));}
 }
}
