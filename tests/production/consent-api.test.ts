import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair } from 'jose';
import { PolicyApi } from '../../src/policy/api.ts';
import { PolicyClient } from '../../src/policy/client.ts';
import { PolicyStore } from '../../src/policy/store.ts';
const key=await generateKeyPair('RS256'),capability={scope:'copilot.invoke',resource:'sharepoint:approved-research'};
const login={issuer:'https://pf.test',subject:'partner:user',audience:'portal',issuedAt:Date.now(),authTime:Date.now(),expiresAt:Date.now()+60000,tokenHash:'a'.repeat(43),nonceHash:'b'.repeat(43)};
function setup(){
 const store=new PolicyStore(':memory:',[capability]);store.registerOrganisation('partner','admin');store.registerPrincipal({id:'human',kind:'human',issuer:login.issuer,subject:login.subject,organisation:'partner',tokenIssuers:[login.issuer]},'admin');store.registerPrincipal({id:'agent',kind:'agent',issuer:'https://agent.test',subject:'partner:agent',organisation:'partner'},'admin');
 const api=new PolicyApi({store,origin:()=> 'https://policy.test',callers:[{id:'portal',kid:'portal-key',key:key.publicKey,roles:['consent'],organisations:['partner']}],verifier:{verify:async()=>{throw Error();}},loginVerifier:{verify:async(token,nonce)=>{if(token!=='signed-id-token'||nonce!=='bound-nonce')throw Error();return login;}},consentPolicy:{agentId:'agent',capability,durationsSeconds:[3600,86400],modes:['interactive','autonomous']}});
 const client=new PolicyClient({origin:'https://policy.test',clientId:'portal',keyId:'portal-key',key:key.privateKey,capability,timeoutMs:1000,fetch:async(url,init)=>{const r=await api.handle({method:'POST',path:new URL(String(url)).pathname,authorization:(init?.headers as Record<string,string>).Authorization,rawBody:String(init?.body)});return Response.json(r.body,{status:r.status});}});
 return{store,client};
}
test('consent role creates a human-owned grant only from verified OIDC evidence',async()=>{
 const s=setup();try{const preview=await s.client.request('/v1/consents/preview',{idToken:'signed-id-token',nonce:'bound-nonce'});assert.equal((preview.human as {subject:string}).subject,login.subject);const result=await s.client.request('/v1/consents/approve',{idToken:'signed-id-token',nonce:'bound-nonce',modes:['interactive','autonomous'],durationSeconds:3600,termsHash:preview.termsHash});assert.equal(s.store.grant(String(result.grantId))?.approved_by,login.subject);await assert.rejects(s.client.request('/v1/consents/approve',{idToken:'signed-id-token',nonce:'bound-nonce',modes:['interactive'],durationSeconds:3600,termsHash:preview.termsHash}));await s.client.request('/v1/consents/revoke',{idToken:'signed-id-token',nonce:'bound-nonce',grantId:result.grantId});assert.equal(s.store.grant(String(result.grantId))?.state,'revoked');}finally{s.store.close();}
});
test('forged proof, human substitution, excess scope and administrative bypass reject',async()=>{
 const s=setup();try{for(const body of [{idToken:'forged',nonce:'bound-nonce',modes:['interactive'],durationSeconds:3600},{idToken:'signed-id-token',nonce:'bound-nonce',modes:['interactive'],durationSeconds:3600,humanId:'other'},{idToken:'signed-id-token',nonce:'bound-nonce',modes:['interactive'],durationSeconds:3600,scopes:['admin']},{idToken:'signed-id-token',nonce:'bound-nonce',modes:['autonomous'],durationSeconds:3600}])await assert.rejects(s.client.request('/v1/consents/approve',body));await assert.rejects(s.client.request('/v1/grants',{id:'bypass'}));assert.equal(s.store.ownedGrants(login).length,0);}finally{s.store.close();}
});
test('approval requires the exact reviewed permission snapshot',async()=>{
 const s=setup();try{await assert.rejects(s.client.request('/v1/consents/approve',{idToken:'signed-id-token',nonce:'bound-nonce',modes:['interactive'],durationSeconds:3600}));}finally{s.store.close();}
});
test('an authenticated owner can revoke after the agent is suspended',async()=>{
 const s=setup();try{
  const proof={idToken:'signed-id-token',nonce:'bound-nonce'},preview=await s.client.request('/v1/consents/preview',proof);
  const grant=await s.client.request('/v1/consents/approve',{...proof,modes:['interactive'],durationSeconds:3600,termsHash:preview.termsHash});
  s.store.suspend('agent','agent','admin');
  assert.equal((await s.client.request('/v1/consents/revoke',{...proof,grantId:grant.grantId})).revoked,true);
  assert.equal(s.store.grant(String(grant.grantId))?.state,'revoked');
 }finally{s.store.close();}
});
test('revocation still requires verified owner proof and the owned grant',async()=>{
 const s=setup();try{
  const proof={idToken:'signed-id-token',nonce:'bound-nonce'},preview=await s.client.request('/v1/consents/preview',proof);
  const own=await s.client.request('/v1/consents/approve',{...proof,modes:['interactive'],durationSeconds:3600,termsHash:preview.termsHash});
  s.store.registerPrincipal({id:'other',kind:'human',issuer:login.issuer,subject:'partner:other',organisation:'partner',tokenIssuers:[login.issuer]},'admin');
  s.store.createGrant({id:'other-grant',humanId:'other',agentId:'agent',organisation:'partner',modes:['interactive'],scopes:[capability.scope],resources:[capability.resource],expiresAt:Date.now()+60000,consent:{reference:'other-approval',approvedAt:Date.now()-100,expiresAt:Date.now()+120000}},'admin');
  s.store.suspend('agent','agent','admin');
  for(const body of [{...proof,grantId:'unknown'},{...proof,grantId:'other-grant'},{...proof,idToken:'forged',grantId:own.grantId},{...proof,nonce:'wrong',grantId:own.grantId}])await assert.rejects(s.client.request('/v1/consents/revoke',body));
  assert.equal(s.store.grant(String(own.grantId))?.state,'active');assert.equal(s.store.grant('other-grant')?.state,'active');
 }finally{s.store.close();}
});
