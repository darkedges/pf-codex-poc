import test from 'node:test';import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';import {readFileSync} from 'node:fs';import {resolve} from 'node:path';
import {jwtVerify,createLocalJWKSet} from 'jose';
import {LocalPublicBrowser,forms} from './public-origin.mjs';
import {publicLoginRequest as request} from '../../scripts/copilot/public-login-http.mjs';
import {copilotProfile as p} from '../../scripts/pf/copilot-config.mjs';
import {profile} from '../../scripts/pf/config.mjs';
import {root,read,admin} from '../../scripts/pf/common.mjs';
const secret=readFileSync(resolve(root,'.local/copilot/pf-generic-oauth-client-secret.txt'),'utf8').trim();
let issuedCode;
function authorization(redirect=p.callback){return p.loginIssuer+'/as/authorization.oauth2?'+new URLSearchParams({client_id:p.loginClientId,response_type:'code',scope:'copilot.login',redirect_uri:redirect,state:randomBytes(24).toString('hex'),pfidpadapterid:'consentHTMLForm',resource:'urn:copilot:login'});}
function redeem(code,clientSecret=secret){return request(p.loginIssuer+'/as/token.oauth2',{client_id:p.loginClientId,client_secret:clientSecret,grant_type:'authorization_code',redirect_uri:p.callback,code});}
test('actual public edge login issues a pinned subject-only token without contacting Microsoft',async()=>{
 const browser=new LocalPublicBrowser(request),url=authorization(),state=new URL(url).searchParams.get('state');
 const login=await browser.request(url);assert.equal(login.status,200);const form=forms(login.html).find(f=>'pf.pass'in f.fields);assert.ok(form);
 const approval=await browser.submit(form,{'pf.username':profile.human,'pf.pass':read('login-password'),'pf.ok':'clicked'});assert.equal(approval.status,200);
 const consent=forms(approval.html).find(f=>'pf.oauth.authz.consent'in f.fields);assert.ok(consent);
 const callback=await browser.submit(consent,{'pf.oauth.authz.consent':'allow'});assert.ok(callback.callback);assert.equal(callback.callback.searchParams.get('state'),state);
 issuedCode=callback.callback.searchParams.get('code');assert.ok(issuedCode);
 const response=await redeem(issuedCode);assert.equal(response.status,200);assert.equal(response.value.token_type,'Bearer');assert.ok(response.value.access_token);
 const published=await request(p.loginIssuer+'/pf/JWKS');assert.equal(published.status,200);const keys=createLocalJWKSet(published.value);
 const {payload}=await jwtVerify(response.value.access_token,async(header,jwt)=>{if(header.kid!=='copilot-login-signing'||header.jku||header.jwk||header.x5u||header.x5c)throw Error('Unapproved signing key');return keys(header,jwt);},{issuer:p.loginIssuer,audience:p.loginAudience,algorithms:['RS256'],clockTolerance:5,requiredClaims:['iss','sub','aud','iat','nbf','exp','jti']});
 assert.equal(payload.sub,profile.human);assert.equal(payload.aud,p.loginAudience);assert.equal(payload.exp-payload.iat,p.loginLifetimeSeconds);assert.ok(payload.exp>Math.floor(Date.now()/1000));
 for(const name of ['act','delegation_id','execution_mode','org_id'])assert.equal(payload[name],undefined);
 assert.equal((await admin('b','oauth/clients/'+p.toolClientId)).enabled,false);
});
test('actual public authorization code cannot be redeemed twice',async()=>{
 assert.ok(issuedCode);const response=await redeem(issuedCode);assert.ok([400,401].includes(response.status));assert.equal(response.value?.access_token,undefined);
});
test('actual public token endpoint rejects an incorrect dedicated client credential',async()=>{
 const response=await redeem('deliberately-invalid-code','deliberately-invalid-secret');assert.ok([400,401].includes(response.status));assert.equal(response.value?.access_token,undefined);assert.equal(response.value?.error,'invalid_client');
});
test('unregistered redirect URI is rejected before login and never followed',async()=>{
 const response=await request(authorization('https://unapproved.example/callback'));assert.ok(!forms(response.html).some(f=>'pf.pass'in f.fields));
 if(response.location)assert.equal(new URL(response.location,p.loginIssuer).origin,p.loginIssuer);
 assert.ok(!response.value?.access_token);
});
