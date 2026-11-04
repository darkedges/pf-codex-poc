import test from 'node:test';
import assert from 'node:assert/strict';
import {AgentPortal} from '../../src/consent/agent-portal.ts';
const origin='https://agent.test';
const csrf=(html:string)=>html.match(/name="csrf" value="([^"]+)"/)![1];
const cookie=(r:any)=>r.headers['Set-Cookie'].split(';')[0];
function setup(settings:{executeFailure?:boolean;revokeFailure?:boolean;wrongCapability?:boolean;holdExecute?:Promise<void>;signInEnabled?:boolean;asyncProvider?:boolean;authorizationOrigin?:string;repeatableSessions?:boolean}={}){
 let oidcState='',providerState='',runs=0,revokes=0,redeems=0;let grantState='active';
 const login={issuer:'https://private-pf.test',subject:'partner:user',audience:'portal',issuedAt:Date.now(),authTime:Date.now(),expiresAt:Date.now()+300000,tokenHash:'hash',nonceHash:'nonce-hash'};
 const capability={scope:'copilot.invoke',resource:'approved-diagnostic'},agent={issuer:'https://agents.test',subject:'partner:agent'};
 const portal=new AgentPortal({origin,capability,agent,authorizationOrigin:settings.authorizationOrigin,repeatableSessions:settings.repeatableSessions,signInEnabled:()=>settings.signInEnabled!==false,oidc:{start:async(state)=>{oidcState=state;return'https://pf.test/authorize';},redeem:async()=>({login,idToken:'PRIVATE-ID-TOKEN'})},
  provider:{start:(state)=>{providerState=state;return settings.asyncProvider?Promise.resolve('https://pf.test/provider'):'https://pf.test/provider';},redeem:async(_code,_verifier,subject)=>{assert.equal(subject,login.subject);redeems++;return{token:'PRIVATE-PROVIDER-TOKEN',claims:{sub:subject,exp:Math.floor(Date.now()/1000)+120}};}},
  policy:{request:async(path,body)=>{
   assert.equal(body.idToken,'PRIVATE-ID-TOKEN');
   if(path.endsWith('/preview'))return{capability:settings.wrongCapability?{...capability,resource:'other'}:capability,agent,human:{subject:login.subject},termsHash:'reviewed-terms',modes:['interactive','autonomous'],durationsSeconds:[3600],grants:[{id:'owned-grant',state:grantState,expiresAt:Date.now()+60000}]};
   if(path.endsWith('/approve')){assert.deepEqual(body.modes,['interactive']);assert.equal(body.durationSeconds,3600);return{grantId:'owned-grant'};}
   assert.equal(body.grantId,'owned-grant');if(settings.revokeFailure)throw Error('private failure');grantState='revoked';revokes++;return{};
  }},execute:async(proof)=>{runs++;await settings.holdExecute;if(settings.executeFailure)throw Error('PRIVATE-PROVIDER-TOKEN');assert.equal(proof.grantId,'owned-grant');assert.equal(proof.providerToken,'PRIVATE-PROVIDER-TOKEN');assert.equal(proof.login.idToken,'PRIVATE-ID-TOKEN');return{authorized:true};}});
 return{portal,oidcState:()=>oidcState,providerState:()=>providerState,runs:()=>runs,revokes:()=>revokes,redeems:()=>redeems};
}
const input=(method:string,path:string,c='',body='',requestOrigin=origin)=>({method,path,headers:{cookie:c,origin:requestOrigin},body});
test('browser form policy allows only self and the explicitly trusted authorization origin',async()=>{
 const s=setup({authorizationOrigin:'https://pf.test'}),home=await s.portal.handle(input('GET','/'));
 assert.match(home.headers['Content-Security-Policy'],/form-action 'self' https:\/\/pf\.test;/);
 assert.equal((await s.portal.handle(input('POST','/login',cookie(home),'csrf='+csrf(home.html)))).status,302);
});
test('trusted authorization origin rejects paths, credentials, insecure and injected policy sources',()=>{
 for(const authorizationOrigin of ['http://pf.test','https://pf.test/path','https://user@pf.test','https://pf.test?x=y',"https://pf.test; script-src *"])
  assert.throws(()=>setup({authorizationOrigin}));
});
test('an unexpected authorization redirect is denied despite a successful provider response',async()=>{
 const s=setup({authorizationOrigin:'https://other.test'}),home=await s.portal.handle(input('GET','/'));
 const result=await s.portal.handle(input('POST','/login',cookie(home),'csrf='+csrf(home.html)));
 assert.equal(result.status,403);assert.equal(result.headers.Location,undefined);
});
test('only rendered form pages allow same-origin referrers; OAuth redirects suppress them',async()=>{
 const s=setup(),home=await s.portal.handle(input('GET','/'));
 assert.equal(home.headers['Referrer-Policy'],'same-origin');
 const result=await s.portal.handle(input('POST','/login',cookie(home),'csrf='+csrf(home.html)));
 assert.equal(result.status,302);assert.equal(result.headers['Referrer-Policy'],'no-referrer');
});
async function post(s:ReturnType<typeof setup>,c:string,path:string,extra:Record<string,string>={}){const page=await s.portal.handle(input('GET','/',c));return s.portal.handle(input('POST',path,c,new URLSearchParams({csrf:csrf(page.html),...extra}).toString()));}
async function signedIn(s:ReturnType<typeof setup>){const home=await s.portal.handle(input('GET','/')),c=cookie(home);assert.equal((await post(s,c,'/login')).status,302);const callback=await s.portal.handle(input('GET','/callback?code=code&state='+s.oidcState(),c));assert.equal(callback.status,303);return cookie(callback);}
async function approved(s:ReturnType<typeof setup>){const c=await signedIn(s);assert.equal((await post(s,c,'/approve')).status,303);return c;}
async function ready(s:ReturnType<typeof setup>){const c=await approved(s);assert.equal((await post(s,c,'/provider-login')).status,302);assert.equal((await s.portal.handle(input('GET','/provider-callback?code=provider-code&state='+s.providerState(),c))).status,303);return c;}

test('browser sign-in, consent, provider login and a single fixed diagnostic keep credentials server-side',async()=>{
 const s=setup(),c=await ready(s);assert.equal((await post(s,c,'/check')).status,303);assert.equal(s.runs(),1);
 const page=await s.portal.handle(input('GET','/',c));assert.match(page.html,/Delegated access verified/);
 assert.ok(!page.html.includes('PRIVATE-'));assert.ok(!page.html.includes('owned-grant'));assert.ok(!page.html.includes('autonomous'));
 assert.equal((await post(s,c,'/check')).status,409);assert.equal(s.runs(),1);
 assert.equal((await post(s,c,'/revoke')).status,303);assert.equal(s.revokes(),1);
});
test('repeatable UI signs out explicitly and requires fresh login/consent before another check',async()=>{
 const s=setup({repeatableSessions:true}),c=await ready(s);await post(s,c,'/check');const result=await s.portal.handle(input('GET','/',c));assert.match(result.html,/Sign out and start again/);assert.equal((await post(s,c,'/logout')).status,303);assert.equal(s.revokes(),1);const fresh=await s.portal.handle(input('GET','/',c));assert.match(fresh.html,/Start with sign-in/);assert.ok(!fresh.html.includes('Delegated access verified'));assert.equal((await post(s,cookie(fresh),'/check')).status,403);assert.equal(s.runs(),1);
});
test('another browser and replayed callback cannot complete provider sign-in',async()=>{
 const s=setup(),c=await approved(s);await post(s,c,'/provider-login');const other=cookie(await s.portal.handle(input('GET','/'))),path='/provider-callback?code=code&state='+s.providerState();
 assert.equal((await s.portal.handle(input('GET',path,other))).status,403);assert.equal(s.redeems(),0);
 assert.equal((await s.portal.handle(input('GET',path,c))).status,303);assert.equal((await s.portal.handle(input('GET',path,c))).status,403);assert.equal(s.redeems(),1);
});
test('forms cannot override human, grant, mode, scope, provider token or chat text',async()=>{
 const s=setup(),c=await ready(s);
 for(const name of ['sub','grantId','mode','scope','token','prompt'])assert.equal((await post(s,c,'/check',{[name]:'forged'})).status,400);
 assert.equal(s.runs(),0);
 assert.equal((await s.portal.handle(input('POST','/check',c,'csrf=wrong'))).status,403);
 const page=await s.portal.handle(input('GET','/',c));assert.equal((await s.portal.handle(input('POST','/check',c,'csrf='+csrf(page.html),'https://evil.test'))).status,403);assert.equal(s.runs(),0);
});
test('revocation before execution blocks the operation and destroys the retained provider token',async()=>{
 const s=setup(),c=await ready(s);await post(s,c,'/revoke');assert.equal((await post(s,c,'/check')).status,403);assert.equal(s.runs(),0);
});
test('sign out requires grant revocation before discarding the session',async()=>{
 const s=setup(),c=await ready(s),out=await post(s,c,'/logout');assert.equal(out.status,303);assert.match(out.headers['Set-Cookie'],/Max-Age=0/);assert.equal(s.revokes(),1);
 assert.equal((await s.portal.handle(input('POST','/check',c,'csrf=old'))).status,403);assert.equal(s.runs(),0);
});
test('execute needs every sign-in and approval step',async()=>{
 const s=setup(),c=await signedIn(s);assert.equal((await post(s,c,'/check')).status,403);assert.equal((await post(s,c,'/provider-login')).status,403);assert.equal(s.runs(),0);
});
test('failed live execution consumes the session attempt without revealing its error or retrying',async()=>{
 const s=setup({executeFailure:true}),c=await ready(s);assert.equal((await post(s,c,'/check')).status,303);
 const page=await s.portal.handle(input('GET','/',c));assert.match(page.html,/Check not verified/);assert.ok(!page.html.includes('PRIVATE-'));
 assert.equal((await post(s,c,'/check')).status,409);assert.equal(s.runs(),1);
});
test('concurrent checks cannot double-spend the in-memory session attempt',async()=>{
 let release!:()=>void;const holdExecute=new Promise<void>(done=>{release=done;}),s=setup({holdExecute}),c=await ready(s);
 const first=post(s,c,'/check');await new Promise(done=>setImmediate(done));
 assert.equal((await post(s,c,'/check')).status,409);release();assert.equal((await first).status,303);assert.equal(s.runs(),1);
});
test('failed revocation does not claim sign-out or discard the owned grant',async()=>{
 const s=setup({revokeFailure:true}),c=await ready(s),out=await post(s,c,'/logout');assert.equal(out.status,503);assert.equal(out.headers['Set-Cookie'],undefined);
 const page=await s.portal.handle(input('GET','/',c));assert.match(page.html,/Revoke access/);assert.ok(!page.html.includes('Access revoked'));
});
test('policy resource substitution prevents completing human sign-in',async()=>{
 const s=setup({wrongCapability:true}),home=await s.portal.handle(input('GET','/')),c=cookie(home);await post(s,c,'/login');
 assert.equal((await s.portal.handle(input('GET','/callback?code=code&state='+s.oidcState(),c))).status,403);assert.equal(s.runs(),0);
});
test('expired browser session cannot invoke or retain usable credentials',async()=>{
 const s=setup(),c=await ready(s),original=Date.now;try{const future=original()+301000;Date.now=()=>future;
  assert.equal((await s.portal.handle(input('POST','/check',c,'csrf=old'))).status,403);assert.equal(s.runs(),0);
  const page=await s.portal.handle(input('GET','/',c));assert.ok(!page.html.includes('partner:user'));assert.ok(!page.html.includes('PRIVATE-'));
 }finally{Date.now=original;}
});
test('a staging heartbeat disables sign-in even with an existing valid form',async()=>{
 const settings={signInEnabled:true},s=setup(settings),home=await s.portal.handle(input('GET','/')),c=cookie(home);settings.signInEnabled=false;
 const page=await s.portal.handle(input('GET','/',c));assert.match(page.html,/Live testing is not enabled/);assert.ok(!page.html.includes('action="/login"'));
 assert.equal((await s.portal.handle(input('POST','/login',c,'csrf='+csrf(home.html)))).status,503);assert.equal(s.oidcState(),'');
});
test('provider authorization redirect can be obtained asynchronously through controller RPC',async()=>{
 const s=setup({asyncProvider:true}),c=await approved(s),result=await post(s,c,'/provider-login');assert.equal(result.status,302);assert.equal(result.headers.Location,'https://pf.test/provider');
});
