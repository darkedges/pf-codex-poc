import test,{before,after,afterEach} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {importPKCS8} from 'jose';
import {startConsent} from '../../scripts/pf/run-consent.mjs';
import {startPolicy} from '../../scripts/pf/run-policy.mjs';
import {LocalBrowser,forms} from '../live/local-browser.mjs';
import {read,load} from '../../scripts/pf/common.mjs';
import {profile} from '../../scripts/pf/config.mjs';
import {issueConsentedUpstream} from '../../scripts/pf/consent-exchange.ts';
import {localToolAuthority} from '../../scripts/pf/consent-tool-exchange.ts';
import {toolExchangeConfig} from '../../scripts/pf/copilot-tool-profile.mjs';
import {PingFederateExchange} from '../../src/adapters/pingfederate.ts';
import {PolicyClient} from '../../src/policy/client.ts';
import {PolicyStore} from '../../src/policy/store.ts';
import {capability} from '../../scripts/pf/policy-setup.ts';
import {OidcClient} from '../../src/identity/oidc.ts';
import {readFileSync} from 'node:fs';import {resolve} from 'node:path';import {root} from '../../scripts/pf/common.mjs';
let portal,authority;
const grants=[];
before(async()=>{portal=await startConsent();authority=await localToolAuthority(process.env.POLICY_API_ORIGIN!);});
afterEach(async()=>{while(grants.length)await grants.shift().revoke();});
after(async()=>{if(portal)await portal.stop();});
async function grant(){
 const b=new LocalBrowser(portal.origin),home=await b.request(portal.origin+'/');
 const login=await b.submit(forms(home.html).find(f=>f.action==='/login'));
 const approval=await b.submit(forms(login.html).find(f=>'pf.pass'in f.fields),{'pf.username':profile.human,'pf.pass':read('login-password'),'pf.ok':'clicked'});
 const review=await b.submit(forms(approval.html).find(f=>'pf.oauth.authz.consent'in f.fields),{'pf.oauth.authz.consent':'allow'});
 const result=await b.submit(forms(review.html).find(f=>f.action==='/approve'),{duration:'3600',autonomous:'on'}),revoke=forms(result.html).find(f=>f.action==='/revoke');assert.ok(revoke);
 let revoked=false;const g={id:revoke.fields.grantId,revoke:async()=>{if(!revoked){assert.equal((await b.submit(revoke,{},{noRedirect:true})).status,303);const store=new PolicyStore(process.env.POLICY_DATABASE!,[capability]);try{assert.equal(store.grant(revoke.fields.grantId)?.state,'revoked');}finally{store.close();}revoked=true;}}};grants.push(g);return g;
}
async function loginProof(){
 const c=new OidcClient({...load('oidc-config.json'),redirectUri:portal.origin+'/callback',clientKey:await importPKCS8(read('consent-oidc.private.pem'),'RS256')});
 const state=randomBytes(24).toString('hex'),nonce=randomBytes(24).toString('hex'),verifier=randomBytes(32).toString('base64url');
 const b=new LocalBrowser(portal.origin),login=await b.request(await c.start(state,nonce,verifier));
 const approval=await b.submit(forms(login.html).find(f=>'pf.pass'in f.fields),{'pf.username':profile.human,'pf.pass':read('login-password'),'pf.ok':'clicked'});
 await b.submit(forms(approval.html).find(f=>'pf.oauth.authz.consent'in f.fields),{'pf.oauth.authz.consent':'allow'},{captureCallback:true});
 const result=await c.redeem(new URL(b.callback).searchParams.get('code'),verifier,nonce);return{idToken:result.idToken,nonce};
}
async function policy(origin=process.env.POLICY_API_ORIGIN!,cap=capability,role='tool'){return new PolicyClient({origin,clientId:'policy-'+role,keyId:'copilot-policy-'+role,key:await importPKCS8(read('policy-'+role+'.private.pem'),'RS256'),capability:cap,timeoutMs:1000});}
for(const mode of ['interactive','autonomous'])test(`real ${mode} tool token is checked by independent HTTPS PDP before/after release and use`,async()=>{
 const g=await grant(),issued=await authority.issue(g.id,mode,mode==='interactive'?await loginProof():undefined);
 let calls=0;const tool=authority.tool(async claims=>{calls++;assert.equal(claims.sub,profile.human);assert.deepEqual(claims.act,{sub:profile.agent,iss:profile.agentIssuer});assert.equal(claims.delegation_id,g.id);assert.equal(claims.execution_mode,mode);return{status:'approved'};});
 assert.deepEqual(await tool.execute(issued.accessToken),{status:'approved'});assert.equal(calls,1);
});
test('revocation before exchange prevents issuance with still-valid signed upstream proof',async()=>{
 const g=await grant(),source=await issueConsentedUpstream(g.id,'autonomous');await g.revoke();await assert.rejects(authority.exchange.exchange(source),e=>e.code==='policy_denied');
});
for(const mode of ['interactive','autonomous'])test(`revocation during real PF issuance suppresses ${mode} tool token release`,async()=>{
 const g=await grant(),source=await issueConsentedUpstream(g.id,mode,mode==='interactive'?await loginProof():undefined),p=await policy();let posts=0;
 const exchange=new PingFederateExchange(toolExchangeConfig(),{clientKey:await importPKCS8(readFileSync(resolve(root,'.local/copilot/pf-sso-exchange.private.pem'),'utf8'),'RS256'),authorise:p.authorise,
  fetch:async(url,init)=>{const result=await fetch(url,init);if(init?.method==='POST'){posts++;assert.equal(result.status,200);await g.revoke();}return result;}});
 await assert.rejects(exchange.exchange(source),e=>e.code==='policy_denied');assert.equal(posts,1);
});
test('revocation after issuance prevents tool invocation',async()=>{
 const g=await grant(),issued=await authority.issue(g.id,'autonomous');await g.revoke();let called=false;
 const tool=authority.tool(async()=>{called=true;return'private';});await assert.rejects(tool.execute(issued.accessToken),e=>e.code==='policy_denied');assert.equal(called,false);
});
test('revocation during tool execution prevents result release',async()=>{
 const g=await grant(),issued=await authority.issue(g.id,'autonomous');const tool=authority.tool(async()=>{await g.revoke();return'private-result';});
 await assert.rejects(tool.execute(issued.accessToken),e=>e.code==='policy_denied'&&!String(e).includes('private-result'));
});
test('tool workload has no registry administration and cannot choose another resource',async()=>{
 const g=await grant(),issued=await authority.issue(g.id,'autonomous'),p=await policy();
 await assert.rejects(p.request('/v1/registry/organisations',{id:profile.org}),e=>e.code==='forbidden');
 const wrongResource=await policy(undefined,{scope:capability.scope,resource:'sharepoint:unapproved'});
 await assert.rejects(wrongResource.authorise(issued.claims,{accessToken:issued.accessToken}));
});
test('default policy profile rejects tool issuer even when registry contains it',async()=>{
 const g=await grant(),issued=await authority.issue(g.id,'autonomous');
 const other=await startPolicy({...process.env,POLICY_COPILOT_TOOL_PROFILE:undefined});
 try{const p=await policy(other.origin,capability,'gateway');await assert.rejects(p.authorise(issued.claims,{accessToken:issued.accessToken}));}finally{await other.stop();}
});
test('actual policy service outage blocks exchange and tool invocation',async()=>{
 const g=await grant(),source=await issueConsentedUpstream(g.id,'autonomous'),issued=await authority.exchange.exchange(source);
 const other=await startPolicy(),unavailable=await localToolAuthority(other.origin);await other.stop();
 await assert.rejects(unavailable.exchange.exchange(source),e=>e.code==='policy_denied');let called=false;
 const tool=unavailable.tool(async()=>{called=true;});await assert.rejects(tool.execute(issued.accessToken),e=>e.code==='policy_denied');assert.equal(called,false);
});
test('suspension blocks signed proof and an already issued tool token',async()=>{
 const g=await grant(),source=await issueConsentedUpstream(g.id,'autonomous'),issued=await authority.exchange.exchange(source);
 const store=new PolicyStore(process.env.POLICY_DATABASE!,[capability]);try{store.suspend('agent','container-agent','test-admin');}finally{store.close();}
 await assert.rejects(authority.exchange.exchange(source),e=>e.code==='policy_denied');let called=false;
 const tool=authority.tool(async()=>{called=true;});await assert.rejects(tool.execute(issued.accessToken),e=>e.code==='policy_denied');assert.equal(called,false);
});
