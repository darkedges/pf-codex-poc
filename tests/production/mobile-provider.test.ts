import test from 'node:test';import assert from 'node:assert/strict';
import {generateKeyPair,exportJWK,SignJWT,jwtVerify,decodeJwt} from 'jose';
import {VaultMobileProviderStore,MobileProviderSessions} from '../../src/mobile/provider-sessions.ts';
const issuer='https://pf.example.test',origin='https://vault.example.test',keys=await generateKeyPair('RS256'),client=await generateKeyPair('RS256');
const trust={issuer,jwksUri:issuer+'/pf/JWKS',audience:'api://copilot-login',scope:'copilot.login',keyIds:['provider'],maxLifetimeSeconds:3600};
async function fixture(minimumValiditySeconds=60){
 let version=0,record,posts=0,revoked=false,fail=false;const valid=new WeakSet(),writes=[];
 const signed=async(sub='human',lifetime=3600)=>{const now=Math.floor(Date.now()/1000);return new SignJWT({iss:issuer,sub,aud:trust.audience,scope:trust.scope,iat:now,nbf:now,exp:now+lifetime,jti:crypto.randomUUID()}).setProtectedHeader({alg:'RS256',kid:'provider'}).sign(keys.privateKey);};
 const e={enrollmentId:'a'.repeat(43),enrollmentExpiresAt:Date.now()+30*86400000,consentId:'consent',sessionId:'foreground',human:{issuer,subject:'human',audience:'mobile-client',authTime:Date.now()},agent:{issuer:'https://agents.example.test',subject:'agent'},organisation:'org',expiresAt:Date.now()+60000};valid.add(e);
 const transport=async(url,init)=>{
  if(String(url)===origin+'/v1/mobile-provider/data/'+e.enrollmentId){assert.equal(new Headers(init.headers).get('X-Vault-Token'),'synthetic-vault-fixture');if(init.method==='POST'){const b=JSON.parse(init.body);assert.equal(b.options.cas,version);record=structuredClone(b.data);writes.push(record);version++;return Response.json({data:{version}});}return record?Response.json({data:{metadata:{version},data:record}}):Response.json({},{status:404});}
  if(String(url)===trust.jwksUri)return Response.json({keys:[{...await exportJWK(keys.publicKey),kid:'provider',alg:'RS256',use:'sig'}]});
  assert.equal(url,issuer+'/as/token.oauth2');posts++;const body=new URLSearchParams(init.body);assert.equal(body.get('grant_type'),'refresh_token');assert.equal(body.get('refresh_token'),'initial-fixture-refresh');assert.equal(body.get('scope'),trust.scope);assert.ok(!body.has('client_secret'));await jwtVerify(body.get('client_assertion'),client.publicKey,{issuer:'mobile-client',subject:'mobile-client',audience:issuer});if(fail)throw Error('private failure');return Response.json({access_token:await signed(),refresh_token:'rotated-fixture-refresh',token_type:'Bearer',expires_in:3600,scope:trust.scope});
 };
 const store=new VaultMobileProviderStore({origin,mount:'mobile-provider',token:()=> 'synthetic-vault-fixture',timeoutMs:1000,fetch:transport});
 const config={trust,tokenEndpoint:issuer+'/as/token.oauth2',clientId:'mobile-client',keyId:'client',clientKey:client.privateKey,timeoutMs:1000,minimumValiditySeconds};
 const sessions=new MobileProviderSessions(config,{store,revalidate:async v=>{if(!valid.has(v)||revoked)throw Error('private revocation');return structuredClone(v);},authorise:async()=>{if(revoked)throw Error();},fetch:transport});
 return{e,store,sessions,config,transport,signed,writes,posts:()=>posts,record:()=>record,expire:()=>{record.accessExpiresAt=Date.now()-1;},fail:()=>{fail=true;},revoke:()=>{revoked=true;}};
}
test('Vault-held provider session renews with signed client authentication and preserves absolute enrollment',async()=>{
 const f=await fixture(),token=await f.signed();await f.sessions.enroll({enrollmentId:f.e.enrollmentId,enrollmentExpiresAt:f.e.enrollmentExpiresAt},f.e.human,{accessToken:token,refreshToken:'initial-fixture-refresh'});
 assert.equal(await f.sessions.get(f.e,new AbortController().signal),token);assert.equal(f.posts(),0);f.expire();
 const renewed=await f.sessions.get(f.e,new AbortController().signal);assert.notEqual(renewed,token);assert.equal(f.posts(),1);assert.equal(f.record().enrollmentExpiresAt,f.e.enrollmentExpiresAt);assert.equal(f.record().refreshToken,'rotated-fixture-refresh');assert.equal(f.writes[1].state,'refreshing');assert.equal(f.writes[1].refreshToken,'');f.sessions.close();
});
test('revoked or copied device evidence and substituted provider subject deny release',async()=>{
 const f=await fixture();await assert.rejects(f.sessions.enroll({enrollmentId:f.e.enrollmentId,enrollmentExpiresAt:f.e.enrollmentExpiresAt},f.e.human,{accessToken:await f.signed('other'),refreshToken:'fixture'}));
 await f.sessions.enroll({enrollmentId:f.e.enrollmentId,enrollmentExpiresAt:f.e.enrollmentExpiresAt},f.e.human,{accessToken:await f.signed(),refreshToken:'initial-fixture-refresh'});await assert.rejects(f.sessions.get({...f.e},new AbortController().signal));f.revoke();await assert.rejects(f.sessions.get(f.e,new AbortController().signal));assert.equal(f.posts(),0);f.sessions.close();
});
test('ambiguous refresh failure spends the credential and never automatically replays it',async()=>{
 const f=await fixture();await f.sessions.enroll({enrollmentId:f.e.enrollmentId,enrollmentExpiresAt:f.e.enrollmentExpiresAt},f.e.human,{accessToken:await f.signed(),refreshToken:'initial-fixture-refresh'});f.expire();f.fail();
 await assert.rejects(f.sessions.get(f.e,new AbortController().signal),/mobile_provider_signin_required/);await assert.rejects(f.sessions.get(f.e,new AbortController().signal));assert.equal(f.posts(),1);assert.equal(f.record().state,'refreshing');assert.equal(f.record().accessToken,'');f.sessions.close();
});
test('a provider token that would expire during foreground chat is refreshed before opening that chat',async()=>{const f=await fixture(960);await f.sessions.enroll({enrollmentId:f.e.enrollmentId,enrollmentExpiresAt:f.e.enrollmentExpiresAt},f.e.human,{accessToken:await f.signed(),refreshToken:'initial-fixture-refresh'});const short=await f.signed('human',120);f.record().accessToken=short;f.record().accessExpiresAt=Number(decodeJwt(short).exp)*1000;const ready=await f.sessions.get(f.e,new AbortController().signal);assert.notEqual(ready,short);assert.equal(f.posts(),1);assert.ok(Number(decodeJwt(ready).exp)*1000>Date.now()+960000);f.sessions.close();});
