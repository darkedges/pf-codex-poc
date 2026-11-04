import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {SignJWT,importPKCS8,createLocalJWKSet,jwtVerify,decodeJwt} from 'jose';
import {admin,call,nodes,root,load,read} from '../../scripts/pf/common.mjs';
import {profile} from '../../scripts/pf/config.mjs';
import {copilotProfile as p} from '../../scripts/pf/copilot-config.mjs';
import {localPublicRequest,LocalPublicBrowser,forms} from './public-origin.mjs';
import {LocalBrowser} from '../live/local-browser.mjs';
import {startConsent} from '../../scripts/pf/run-consent.mjs';
import {issueConsentedUpstream} from '../../scripts/pf/consent-exchange.ts';
import {OidcClient} from '../../src/identity/oidc.ts';
let portal,grantId,revoke,browser,keys,agedSource;
const paths=new Set<string>();
before(async()=>{
 portal=await startConsent();browser=new LocalBrowser(portal.origin);
 const home=await browser.request(portal.origin+'/'),login=await browser.submit(forms(home.html).find(f=>f.action==='/login'));
 const approval=await browser.submit(forms(login.html).find(f=>'pf.pass'in f.fields),{'pf.username':profile.human,'pf.pass':read('login-password'),'pf.ok':'clicked'});
 const review=await browser.submit(forms(approval.html).find(f=>'pf.oauth.authz.consent'in f.fields),{'pf.oauth.authz.consent':'allow'});
 const approved=await browser.submit(forms(review.html).find(f=>f.action==='/approve'),{duration:'3600',autonomous:'on'});
 revoke=forms(approved.html).find(f=>f.action==='/revoke');assert.ok(revoke);grantId=revoke.fields.grantId;
 keys=createLocalJWKSet((await call(nodes.b.issuer+'/pf/JWKS')).value);
 agedSource=await issueConsentedUpstream(grantId,'autonomous');
});
after(async()=>{try{if(revoke)await browser.submit(revoke);}finally{if(portal)await portal.stop();}});
async function exchange(subject,extra={},publicHost=false){
 const assertion=await new SignJWT({}).setProtectedHeader({alg:'RS256',kid:'copilot-sso-exchange',typ:'client-authentication+jwt'})
  .setIssuer(p.toolClientId).setSubject(p.toolClientId).setAudience(publicHost?p.toolIssuer:nodes.b.issuer).setIssuedAt().setExpirationTime('60s').setJti(randomUUID())
  .sign(await importPKCS8(readFileSync(resolve(root,'.local/copilot/pf-sso-exchange.private.pem'),'utf8'),'RS256'));
 const body={client_id:p.toolClientId,client_assertion:assertion,
  client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',grant_type:'urn:ietf:params:oauth:grant-type:token-exchange',subject_token:subject,
  subject_token_type:'urn:ietf:params:oauth:token-type:access_token',requested_token_type:'urn:ietf:params:oauth:token-type:access_token',resource:'urn:copilot:delegated:tool',scope:'copilot.invoke',...extra};
 return publicHost?localPublicRequest(p.toolIssuer+'/as/token.oauth2',body):call(nodes.b.issuer+'/as/token.oauth2',{method:'POST',form:true,body});
}
async function verifyTool(source,mode){
 const response=await exchange(source,{},true);assert.equal(response.status,200,'Actual PF public-host tool issuance must succeed');
 const {payload}=await jwtVerify(response.value.access_token,keys,{issuer:p.toolIssuer,audience:p.toolAudience,algorithms:['RS256'],clockTolerance:5});
 const upstream=decodeJwt(source);for(const name of ['sub','org_id','delegation_id','execution_mode','scope'])assert.equal(payload[name],upstream[name]);
 assert.deepEqual(payload.act,upstream.act);assert.equal(payload.execution_mode,mode);assert.ok(payload.exp<=upstream.exp-5);assert.ok(payload.exp-payload.iat<=120);
}
test('public virtual issuers advertise exact public metadata while localhost stays unchanged',async()=>{
 for(const [node,origin]of [['a',p.loginIssuer],['b',p.toolIssuer]]){
  const r=await localPublicRequest(origin+'/.well-known/openid-configuration');assert.equal(r.status,200);assert.equal(r.value.issuer,origin);
  for(const field of ['authorization_endpoint','token_endpoint','jwks_uri'])assert.equal(new URL(r.value[field]).origin,origin);
  assert.equal((await call(nodes[node].issuer+'/.well-known/openid-configuration')).value.issuer,nodes[node].issuer);
 }
 await assert.rejects(async()=>localPublicRequest('https://unapproved.example/.well-known/openid-configuration'));
});
test('real public-host human login retains subject and cannot become tool authority',async()=>{
 const b=new LocalPublicBrowser(),state=randomBytes(24).toString('hex');
 const auth=new URL(p.loginIssuer+'/as/authorization.oauth2');auth.search=new URLSearchParams({client_id:p.loginClientId,response_type:'code',scope:'copilot.login',redirect_uri:p.callback,state,pfidpadapterid:'consentHTMLForm',resource:'urn:copilot:login'}).toString();
 const login=await b.request(auth);assert.equal(login.status,200);
 const form=forms(login.html).find(f=>'pf.pass'in f.fields);assert.ok(form,'Public-host authorization must show PF login');
 const approval=await b.submit(form,{'pf.username':profile.human,'pf.pass':read('login-password'),'pf.ok':'clicked'});
 const consent=forms(approval.html).find(f=>'pf.oauth.authz.consent'in f.fields);assert.ok(consent);
 const result=await b.submit(consent,{'pf.oauth.authz.consent':'allow'});assert.ok(result.callback);assert.equal(result.callback.searchParams.get('state'),state);
 const code=result.callback.searchParams.get('code');assert.ok(code);
 const secret=readFileSync(resolve(root,'.local/copilot/pf-generic-oauth-client-secret.txt'),'utf8').trim();
 const response=await localPublicRequest(p.loginIssuer+'/as/token.oauth2',{client_id:p.loginClientId,client_secret:secret,grant_type:'authorization_code',redirect_uri:p.callback,code});
 assert.equal(response.status,200);
 const aKeys=createLocalJWKSet((await call(nodes.a.issuer+'/pf/JWKS')).value);
 const {payload}=await jwtVerify(response.value.access_token,aKeys,{issuer:p.loginIssuer,audience:p.loginAudience,algorithms:['RS256'],clockTolerance:5});
 assert.equal(payload.sub,profile.human);for(const claim of ['act','delegation_id','execution_mode','org_id'])assert.equal(payload[claim],undefined);
 assert.ok((await exchange(response.value.access_token)).status>=400);
 const replay=await localPublicRequest(p.loginIssuer+'/as/token.oauth2',{client_id:p.loginClientId,client_secret:secret,grant_type:'authorization_code',redirect_uri:p.callback,code});assert.ok(replay.status>=400);
 for(const path of b.paths)paths.add(path.replace(/^\/as\/[A-Za-z0-9_-]+\/resume\//,'/as/{transaction}/resume/'));
 writeFileSync(resolve(root,'.local/copilot/public-browser-paths.json'),JSON.stringify({paths:[...paths],callback:p.callback,publicNetworkUsed:false},null,2));
});
test('actual autonomous tool token preserves identity and narrows expiry',async()=>{await verifyTool(await issueConsentedUpstream(grantId,'autonomous'),'autonomous');});
test('actual interactive tool token requires fresh OIDC login and preserves identity',async()=>{
 const c=new OidcClient({...load('oidc-config.json'),redirectUri:portal.origin+'/callback',clientKey:await importPKCS8(read('consent-oidc.private.pem'),'RS256')});
 const state=randomBytes(24).toString('hex'),nonce=randomBytes(24).toString('hex'),verifier=randomBytes(32).toString('base64url');
 const redirect=await c.start(state,nonce,verifier),b=new LocalBrowser(portal.origin);
 const login=await b.request(redirect),approval=await b.submit(forms(login.html).find(f=>'pf.pass'in f.fields),{'pf.username':profile.human,'pf.pass':read('login-password'),'pf.ok':'clicked'});
 await b.submit(forms(approval.html).find(f=>'pf.oauth.authz.consent'in f.fields),{'pf.oauth.authz.consent':'allow'},{captureCallback:true});
 assert.ok(b.callback);const code=new URL(b.callback).searchParams.get('code'),identity=await c.redeem(code,verifier,nonce);
 await verifyTool(await issueConsentedUpstream(grantId,'interactive',{idToken:identity.idToken,nonce}),'interactive');
 await assert.rejects(issueConsentedUpstream(grantId,'interactive'));
});
test('tool client rejects wrong resource, scope escalation and tampered signed subject',async()=>{
 const source=await issueConsentedUpstream(grantId,'autonomous');
 for(const extra of [{resource:'api://copilot-broker'},{scope:'arbitrary.graph'}])assert.ok((await exchange(source,extra)).status>=400);
 const parts=source.split('.');parts[1]=Buffer.from(JSON.stringify({...decodeJwt(source),sub:'partner-a:admin'})).toString('base64url');assert.ok((await exchange(parts.join('.'))).status>=400);
});
test('actual signed upstream with insufficient remaining lifetime is rejected', {timeout:140000},async()=>{
 const until=(decodeJwt(agedSource).exp-72)*1000;
 while(Date.now()<until)await new Promise(done=>setTimeout(done,Math.min(1000,until-Date.now())));
 const result=await exchange(agedSource);assert.ok(result.status>=400);assert.equal(result.value?.access_token,undefined);
});
