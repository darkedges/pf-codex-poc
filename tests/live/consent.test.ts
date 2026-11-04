import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import { startConsent } from '../../scripts/pf/run-consent.mjs';
import { LocalBrowser,forms } from './local-browser.mjs';
import { profile } from '../../scripts/pf/config.mjs';
import { read,load,call,nodes } from '../../scripts/pf/common.mjs';
import { runConsentedExchange } from '../../scripts/pf/consent-exchange.ts';
import { PolicyStore } from '../../src/policy/store.ts';
import { capability } from '../../scripts/pf/policy-setup.ts';
import { OidcClient } from '../../src/identity/oidc.ts';
import { importPKCS8,importJWK,SignJWT,jwtVerify } from 'jose';
import { startPolicy } from '../../scripts/pf/run-policy.mjs';
import { bodyHash } from '../../src/policy/protocol.ts';
import { randomUUID } from 'node:crypto';
import { signProof } from '../../scripts/pf/harness.mjs';
import { authorityTrust } from '../../scripts/pf/authority-config.mjs';
import { decodeProtectedHeader } from 'jose';
let portal:Awaited<ReturnType<typeof startConsent>>;
before(async()=>{portal=await startConsent();});after(async()=>{if(portal)await portal.stop();});
async function login(browser:LocalBrowser,username=profile.human,passwordFile='login-password',captureCallback=false){
 const home=await browser.request(portal.origin+'/');assert.equal(home.status,200);
 const form=forms(home.html).find(f=>f.action==='/login');assert.ok(form);
 const pf=await browser.submit(form);assert.equal(pf.status,200);
 const credentials=forms(pf.html).find(f=>'pf.pass'in f.fields);assert.ok(credentials,'Real PF login form must be shown');
 const approval=await browser.submit(credentials,{'pf.username':username,'pf.pass':read(passwordFile),'pf.ok':'clicked'});assert.equal(approval.status,200);
 const approve=forms(approval.html).find(f=>'pf.oauth.authz.consent'in f.fields);assert.ok(approve,'PF consent form must be shown');
 return browser.submit(approve,{'pf.oauth.authz.consent':'allow'},{captureCallback});
}

test('real consent authority authenticates workload requests and persists replay across service processes',async()=>{
 const browser=new LocalBrowser(portal.origin),review=await login(browser),form=forms(review.html).find(f=>f.action==='/approve');assert.ok(form);
 const approved=await browser.submit(form,{duration:'3600',autonomous:'on'}),revoke=forms(approved.html).find(f=>f.action==='/revoke');assert.ok(revoke);const grantId=revoke.fields.grantId;
 const actorKey=await importPKCS8(read('agent.private.pem'),'RS256'),workloadKey=await importPKCS8(read('policy-agent.private.pem'),'RS256');
 const agentToken=await new SignJWT({sub:profile.agent}).setProtectedHeader({alg:'RS256',kid:'copilot-agent'}).setIssuer(profile.agentIssuer).setAudience('api://pf-a/agent-proof').setIssuedAt().setNotBefore('0s').setExpirationTime('120s').setJti(randomUUID()).sign(actorKey);
 const raw=JSON.stringify({grantId,mode:'autonomous',operation:capability.scope,agentToken}),jti=randomUUID();
 async function request(origin:string,body=raw,authenticated=true){
  const assertion=await new SignJWT({method:'POST',body_sha256:bodyHash(raw)}).setProtectedHeader({alg:'RS256',kid:'copilot-policy-agent',typ:'policy-request+jwt'}).setIssuer('policy-agent').setSubject('policy-agent').setAudience(origin+'/v1/assertions').setIssuedAt().setExpirationTime('60s').setJti(jti).sign(workloadKey);
  return fetch(origin+'/v1/assertions',{method:'POST',redirect:'error',headers:{'Content-Type':'application/json',Authorization:authenticated?'Policy '+assertion:''},body});
 }
 const origin=process.env.POLICY_API_ORIGIN!;
 assert.equal((await request(origin,raw,false)).status,401);
 assert.equal((await request(origin,JSON.stringify({...JSON.parse(raw),operation:'arbitrary.graph'}))).status,401);
 const issued=await request(origin);assert.equal(issued.status,200);const result=await issued.json();
 const publicKey=await importJWK(authorityTrust().keys.find(k=>k.kid===decodeProtectedHeader(result.assertion).kid),'RS256');const verified=await jwtVerify(result.assertion,publicKey,{issuer:profile.consentAuthorityIssuer,audience:'api://pf-a/consent-proof'});
 assert.equal(verified.payload.sub,profile.human);assert.equal(verified.payload.operation,capability.scope);assert.deepEqual(verified.payload.act,{iss:profile.agentIssuer,sub:profile.agent});
 assert.equal((await request(origin)).status,401);
 const second=await startPolicy();try{assert.equal((await request(second.origin)).status,401,'Previously consumed jti must reject even with a fresh valid signature/audience at another process');}finally{await second.stop();}
 assert.equal((await browser.submit(revoke)).status,200);await assert.rejects(runConsentedExchange(grantId,'autonomous'));
});
test('real PF login and explicit consent create a revocable grant supporting both exchange modes',async()=>{
 const browser=new LocalBrowser(portal.origin),review=await login(browser);assert.equal(review.status,200,'OIDC callback must complete');assert.ok(review.html.includes(profile.human));assert.ok(!/eyJ[\w-]+\.[\w-]+\.[\w-]+/.test(review.html));
 const approve=forms(review.html).find(f=>f.action==='/approve');assert.ok(approve);
 const approved=await browser.submit(approve,{duration:'3600',autonomous:'on'});assert.equal(approved.status,200);assert.ok(approved.html.includes('Access approved'));
 const revoke=forms(approved.html).find(f=>f.action==='/revoke');assert.ok(revoke);const grantId=revoke.fields.grantId;
 const store=new PolicyStore(process.env.POLICY_DATABASE!,[capability]);try{assert.equal(store.grant(grantId)?.approved_by,profile.human);assert.equal(store.consentForGrant(grantId)?.issuer,load('oidc-config.json').issuer);}finally{store.close();}
 for(const mode of ['interactive','autonomous']){const action=forms(approved.html).find(f=>f.action==='/execute'&&f.fields.mode===mode);assert.ok(action);const result=await browser.submit(action);assert.equal(result.status,200);assert.ok(result.html.includes('Access check passed'));approved.html=result.html;}
 assert.equal((await runConsentedExchange(grantId,'autonomous')).subject,profile.human,'Background execution must work without any human ID token');
 await assert.rejects(runConsentedExchange(grantId,'interactive'),undefined,'Interactive execution requires a current human login');
 const callback=await browser.request(browser.callback);assert.equal(callback.status,403,'Callback replay must reject');
 const current=await browser.request(portal.origin+'/'),revokeCurrent=forms(current.html).find(f=>f.action==='/revoke');assert.ok(revokeCurrent);assert.equal((await browser.submit(revokeCurrent)).status,200);
 await assert.rejects(runConsentedExchange(grantId,'autonomous'));
});
test('forged consent fields and cross-session callback cannot create a grant',async()=>{
 const browser=new LocalBrowser(portal.origin),review=await login(browser);assert.equal(review.status,200);const approve=forms(review.html).find(f=>f.action==='/approve');assert.ok(approve);
 const tampered=await browser.submit(approve,{duration:'3600',sub:'partner-a:admin'});assert.equal(tampered.status,400);
 const fresh=await browser.request(portal.origin+'/'),csrfForm=forms(fresh.html).find(f=>f.action==='/approve');assert.ok(csrfForm);
 assert.equal((await browser.submit(csrfForm,{duration:'3600',csrf:'forged'})).status,403);
 assert.equal((await browser.submit(csrfForm,{duration:'3600'},{origin:'https://evil.test'})).status,403);
 const attacker=new LocalBrowser(portal.origin);assert.equal((await attacker.request(browser.callback)).status,403);
});
test('a different real PF subject is not silently registered for delegated access',async()=>{
 const browser=new LocalBrowser(portal.origin);const result=await login(browser,'partner-a:user-other','other-login-password');assert.equal(result.status,403);
});
test('PF A rejects a real authorization code redeemed with the wrong PKCE verifier',async()=>{
 const browser=new LocalBrowser(portal.origin);await login(browser,profile.human,'login-password',true);assert.ok(browser.callback);
 const code=new URL(browser.callback).searchParams.get('code');assert.ok(code);
 const client=new OidcClient({...load('oidc-config.json'),redirectUri:portal.origin+'/callback',clientKey:await importPKCS8(read('consent-oidc.private.pem'),'RS256')});
 await assert.rejects(client.redeem(code,'incorrect-verifier-01234567890123456789012345678901234567','nonce-for-invalid-pkce'));
});
test('background permission requires explicit human opt-in',async()=>{
 const browser=new LocalBrowser(portal.origin),review=await login(browser);assert.equal(review.status,200);const form=forms(review.html).find(f=>f.action==='/approve');assert.ok(form);
 const approved=await browser.submit(form,{duration:'3600'});assert.equal(approved.status,200);const revoke=forms(approved.html).find(f=>f.action==='/revoke');assert.ok(revoke);
 await assert.rejects(runConsentedExchange(revoke.fields.grantId,'autonomous'));
 assert.equal((await browser.submit(revoke)).status,200);
});
test('retained synthetic authority cannot impersonate the browser-consent authority',async()=>{
 const now=Math.floor(Date.now()/1000);
 const subject=await signProof('delegation',{sub:profile.human,actor_sub:profile.agent,actor_iss:profile.agentIssuer,org_id:profile.org,delegation_id:profile.grant,execution_mode:'autonomous',scope:profile.scope},profile.delegationIssuer,'api://pf-a/consent-proof');
 const actor=await signProof('agent',{sub:profile.agent},profile.agentIssuer,'api://pf-a/agent-proof');
 const assertion=await new SignJWT({iss:'consent-gateway-1',sub:'consent-gateway-1',aud:nodes.a.issuer,iat:now,exp:now+60,jti:randomUUID()}).setProtectedHeader({alg:'RS256',kid:'copilot-consent-gateway-1',typ:'client-authentication+jwt'}).sign(await importPKCS8(read('consent-gateway-1.private.pem'),'RS256'));
 const r=await call(nodes.a.issuer+'/as/token.oauth2',{method:'POST',form:true,body:{grant_type:'urn:ietf:params:oauth:grant-type:token-exchange',client_id:'consent-gateway-1',client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion,subject_token:subject,subject_token_type:'urn:example:token-type:consented-autonomous',actor_token:actor,actor_token_type:'urn:example:token-type:agent-proof',resource:'urn:copilot:consent:gateway-2',scope:profile.scope,requested_token_type:'urn:ietf:params:oauth:token-type:access_token'}});
 assert.ok(r.status>=400&&r.status<500,'The legacy fixture authority must not mint consent-backed PF tokens');
});
