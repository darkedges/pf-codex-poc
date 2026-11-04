import { randomBytes,timingSafeEqual } from 'node:crypto';
import { PolicyError,type VerifiedLogin,type Capability } from '../policy/contracts.ts';
type Login={login:VerifiedLogin;idToken:string};
type Options={origin:string;capability:Capability;oidc:{start:(state:string,nonce:string,verifier:string)=>Promise<string>;redeem:(code:string,verifier:string,nonce:string)=>Promise<Login>};policy:{request:(path:string,body:Record<string,unknown>)=>Promise<Record<string,unknown>>};execute?:(grantId:string,mode:string,login:{idToken:string;nonce:string})=>Promise<{subject:string;actor:string;mode:string}>};
type Session={csrf:string;expiresAt:number;pending?:{state:string;nonce:string;verifier:string;expiresAt:number};login?:Login&{nonce:string};approving?:boolean;approved?:boolean;message?:string;result?:{subject:string;actor:string;mode:string}};
type Input={method:string;path:string;headers:{cookie?:string;origin?:string};body?:string};
export type PortalResponse={status:number;headers:Record<string,string>;html:string};
const secret=()=>randomBytes(32).toString('base64url');
const escape=(value:unknown)=>String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
const equal=(a:string,b:string)=>a.length===b.length&&a.length<=256&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
function page(content:string){return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Delegated access</title><style>
*{box-sizing:border-box}body{margin:0;background:#f5f4ef;color:#172d35;font:16px/1.6 system-ui,Segoe UI,sans-serif}main{max-width:840px;margin:auto;padding:38px 24px 64px}header{display:flex;justify-content:space-between;align-items:center;margin-bottom:55px}.brand{font-weight:750;letter-spacing:.02em}.badge{font-size:12px;border:1px solid #d1d9d5;border-radius:24px;padding:5px 12px;color:#526b68}h1{font-size:clamp(32px,5vw,46px);line-height:1.15;letter-spacing:-.04em;margin:0 0 18px}h2{font-size:21px;margin:0 0 10px}p{color:#51666b}.card{background:white;border:1px solid #dbe0da;border-radius:16px;padding:26px;margin-top:22px}.row{display:flex;justify-content:space-between;gap:20px;padding:12px 0;border-bottom:1px solid #edf0ec}.label{color:#60716e}.value{font-weight:600;overflow-wrap:anywhere;text-align:right}label{display:block;margin:14px 0}select{font:inherit;border:1px solid #b8c9c2;border-radius:6px;padding:8px;background:white}button{font:600 15px system-ui;border:0;background:#0b6558;color:white;padding:13px 20px;border-radius:8px;cursor:pointer}.secondary{background:#e9efeb;color:#244b42}.danger{background:#fff0ec;color:#8a3726;border:1px solid #edcfc5}.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:22px}.actions form{margin:0}.note{font-size:14px}.notice{padding:15px 20px;background:#e3f0e6;border:1px solid #c7decf;border-radius:9px;margin:20px 0}.reference{font:13px ui-monospace,monospace;overflow-wrap:anywhere;color:#526965}footer{margin-top:30px;font-size:13px;color:#6c7975}input[type=checkbox]{width:18px;height:18px;vertical-align:middle;margin-right:8px}a{color:#0b6558}small{color:#60716e}</style><main><header><div class="brand">Delegated access</div><span class="badge">Local integration environment</span></header>${content}<footer>Your sign-in stays with your identity provider. Access can be revoked at any time.</footer></main></html>`;}
export class ConsentPortal{
 private options:Options;
 private sessions=new Map<string,Session>();
 private cookieName:string;
 constructor(options:Options){const u=new URL(options.origin);if(u.protocol!=='https:'||u.username||u.password||u.pathname!=='/'||u.hash||u.search||!options.capability?.scope||!options.capability.resource)throw new PolicyError('configuration');this.options={...options,capability:structuredClone(options.capability),origin:u.origin};this.cookieName='__Host-fc-consent-'+(u.port||'443');}
 private reply(status:number,html='',headers:Record<string,string>={}):PortalResponse{return{status,html,headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",...headers}};}
 private cookie(id:string){return`${this.cookieName}=${id}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600`;}
 private create(){if(this.sessions.size>=1000)throw new PolicyError('unavailable');const id=secret(),session:Session={csrf:secret(),expiresAt:Date.now()+600000};this.sessions.set(id,session);return{id,session};}
 private form(session:Session,action:string,controls:string,label:string,buttonClass=''){return`<form method="post" action="${action}"><input type="hidden" name="csrf" value="${session.csrf}">${controls}<button class="${buttonClass}" type="submit">${label}</button></form>`;}
 private async render(session:Session){
  if(!session.login)return page(`<h1>Give your agent<br>permission to help.</h1><p>Sign in to review the agent, its permitted access, and how long that access should last.</p><section class="card"><h2>Start with your identity</h2><p>You will sign in with your organisation before approving any access.</p>${this.form(session,'/login','','Sign in to review access')}</section>`);
  const proof={idToken:session.login.idToken,nonce:session.login.nonce},options=await this.options.policy.request('/v1/consents/preview',proof);
  const human=options.human as {subject:string},agent=options.agent as {subject:string},capability=options.capability as {scope:string;resource:string},grants=options.grants as {id:string;state:string;expiresAt:number;modes:string[]}[];
  if(capability.scope!==this.options.capability.scope||capability.resource!==this.options.capability.resource)throw new PolicyError();
  const durationOptions=(options.durationsSeconds as number[]).filter(d=>[3600,86400].includes(d)).map(d=>`<option value="${d}">${d===3600?'1 hour':'24 hours'}</option>`).join('');
  const background=(options.modes as string[]).includes('autonomous')?'<label><input type="checkbox" name="autonomous" value="on">Also allow background work while I am away</label>':'';
  let html=`<h1>Review delegated access</h1><p>Signed in as <strong>${escape(human.subject)}</strong>. Choose the permission you want to give this agent.</p>${session.message?`<div class="notice" role="status">${escape(session.message)}</div>`:''}`;
  if(!session.approved)html+=`<section class="card"><h2>Research agent</h2><div class="row"><span class="label">Registered agent</span><span class="value">${escape(agent.subject)}</span></div><div class="row"><span class="label">Permission</span><span class="value">Invoke the research assistant<br><small>${escape(capability.scope)}</small></span></div><div class="row"><span class="label">Resource</span><span class="value">Approved research only<br><small>${escape(capability.resource)}</small></span></div>${this.form(session,'/approve',`<input type="hidden" name="termsHash" value="${escape(options.termsHash)}"><label>Access expires after <select name="duration">${durationOptions}</select></label>${background}<p class="note">Interactive access is included. Background access is optional and ends at the same expiry.</p>`,'Approve access')}</section>`;
  else html+='<p class="note">To approve another permission, sign in again.</p>';
  for(const grant of grants){
   const active=grant.state==='active'&&grant.expiresAt>Date.now();
   const modes=Array.isArray(grant.modes)?grant.modes:[];
   html+=`<section class="card"><h2>${active?'Approved access':'Inactive access'}</h2><p class="reference">Reference ${escape(grant.id)}</p><div class="row"><span class="label">Execution</span><span class="value">${modes.includes('autonomous')?'Interactive and background':'Interactive only'}</span></div><div class="row"><span class="label">Expires</span><span class="value">${escape(new Date(grant.expiresAt).toLocaleString('en-AU',{timeZone:'Australia/Sydney'}))} Sydney</span></div>`;
   if(active)html+=`<div class="actions">${this.form(session,'/revoke',`<input type="hidden" name="grantId" value="${escape(grant.id)}">`,'Revoke access','danger')}${this.options.execute?modes.map(mode=>this.form(session,'/execute',`<input type="hidden" name="grantId" value="${escape(grant.id)}"><input type="hidden" name="mode" value="${escape(mode)}">`,mode==='autonomous'?'Check background access':'Check interactive access','secondary')).join(''):''}</div>`;
   html+='</section>';
  }
  if(session.result)html+=`<section class="card"><h2>Access check passed</h2><p>The permission was verified for ${escape(session.result.subject)} and ${escape(session.result.actor)} in ${escape(session.result.mode)} mode.</p></section>`;
  html+=`<div class="actions">${this.form(session,'/login','','Sign in again','secondary')}${this.form(session,'/logout','','Sign out','secondary')}</div>`;
  return page(html);
 }
 async handle(input:Input):Promise<PortalResponse>{
  for(const[id,s]of this.sessions)if(s.expiresAt<=Date.now())this.sessions.delete(id);
  try{
   if(input.path.length>8192||!input.path.startsWith('/'))throw new PolicyError('invalid_request');
   const url=new URL(input.path,this.options.origin);if(url.origin!==this.options.origin||url.hash)throw new PolicyError('invalid_request');
   const cookies=(input.headers.cookie??'').split(';').map(c=>c.trim().split('='));const matches=cookies.filter(([name])=>name===this.cookieName);
   let id=matches.length===1?matches[0][1]:'',session=this.sessions.get(id);
   if(input.method==='GET'&&url.pathname==='/'){
    let setCookie:Record<string,string>={};if(!session){const created=this.create();id=created.id;session=created.session;setCookie={'Set-Cookie':this.cookie(id)};}
    return this.reply(200,await this.render(session),setCookie);
   }
   if(input.method==='GET'&&url.pathname==='/callback'){
    const params=url.searchParams,allowed=['code','state','iss','error','error_description'];
    if(!session?.pending||session.pending.expiresAt<=Date.now()||[...params.keys()].some(k=>!allowed.includes(k)||params.getAll(k).length!==1)||params.has('error')||!equal(params.get('state')??'',session.pending.state))throw new PolicyError();
    const transaction=session.pending;delete session.pending;
    const result=await this.options.oidc.redeem(params.get('code')??'',transaction.verifier,transaction.nonce);
    if(params.has('iss')&&params.get('iss')!==result.login.issuer)throw new PolicyError();
    await this.options.policy.request('/v1/consents/preview',{idToken:result.idToken,nonce:transaction.nonce});
    this.sessions.delete(id);const fresh=this.create();fresh.session.login={...result,nonce:transaction.nonce};fresh.session.expiresAt=Math.min(result.login.expiresAt,result.login.issuedAt+300000,result.login.authTime+300000,Date.now()+300000);
    return this.reply(303,'',{Location:'/','Set-Cookie':this.cookie(fresh.id)});
   }
   if(input.method!=='POST'||url.search||!['/login','/approve','/revoke','/execute','/logout'].includes(url.pathname))return this.reply(404,page('<h1>Page not found</h1>'));
   if(input.headers.origin!==this.options.origin||!session)throw new PolicyError();
   const raw=input.body??'';if(Buffer.byteLength(raw)>8192)throw new PolicyError('invalid_request');
   const fields=new URLSearchParams(raw),allowed=url.pathname==='/approve'?['csrf','duration','autonomous','termsHash']:url.pathname==='/revoke'?['csrf','grantId']:url.pathname==='/execute'?['csrf','grantId','mode']:['csrf'];
   if([...fields.keys()].some(k=>!allowed.includes(k)||fields.getAll(k).length!==1))throw new PolicyError('invalid_request');
   if(!equal(fields.get('csrf')??'',session.csrf))throw new PolicyError();
   if(url.pathname==='/logout'){this.sessions.delete(id);return this.reply(303,'',{Location:'/','Set-Cookie':`${this.cookieName}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`});}
   if(url.pathname==='/login'){
    delete session.login;delete session.result;session.approved=false;const transaction={state:secret(),nonce:secret(),verifier:secret(),expiresAt:Date.now()+300000};session.pending=transaction;
    return this.reply(302,'',{Location:await this.options.oidc.start(transaction.state,transaction.nonce,transaction.verifier)});
   }
   if(!session.login||session.expiresAt<=Date.now())throw new PolicyError();
   const proof={idToken:session.login.idToken,nonce:session.login.nonce};
   if(url.pathname==='/approve'){
    if(session.approving||session.approved)throw new PolicyError('conflict');
    if(!['3600','86400'].includes(fields.get('duration')??'')||(fields.has('autonomous')&&fields.get('autonomous')!=='on'))throw new PolicyError('invalid_request');
    session.approving=true;try{await this.options.policy.request('/v1/consents/approve',{...proof,termsHash:fields.get('termsHash')??'',modes:fields.has('autonomous')?['interactive','autonomous']:['interactive'],durationSeconds:Number(fields.get('duration'))});session.approved=true;session.message='Access approved. You remain in control of this permission.';}finally{session.approving=false;}
   }else if(url.pathname==='/revoke'){await this.options.policy.request('/v1/consents/revoke',{...proof,grantId:fields.get('grantId')??''});session.message='Access revoked. Further requests using this permission will be denied.';delete session.result;}
   else{if(!this.options.execute||!['interactive','autonomous'].includes(fields.get('mode')??''))throw new PolicyError();session.result=await this.options.execute(fields.get('grantId')??'',fields.get('mode')!,proof);session.message='Access check completed.';}
   session.csrf=secret();return this.reply(303,'',{Location:'/'});
  }catch(error){const code=error instanceof PolicyError?error.code:'unavailable';return this.reply(code==='invalid_request'?400:code==='conflict'?409:code==='unavailable'?503:403,page('<h1>Request could not be completed</h1><p>Start a fresh sign-in to review your current permissions.</p><a href="/">Return to delegated access</a>'));}
 }
}
