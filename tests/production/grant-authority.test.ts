import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair,SignJWT,jwtVerify } from 'jose';
import { randomUUID } from 'node:crypto';
import { DevelopmentSigner } from '../../src/identity/assertion-signer.ts';
import { GrantAuthority } from '../../src/identity/grant-authority.ts';
import { PolicyStore } from '../../src/policy/store.ts';
const agent=await generateKeyPair('RS256'),signer=await generateKeyPair('RS256');
const capability={scope:'copilot.invoke',resource:'sharepoint:approved-research'},login={issuer:'https://pf.test',subject:'partner:user',audience:'portal',issuedAt:Date.now(),authTime:Date.now(),expiresAt:Date.now()+120000,tokenHash:'a'.repeat(43),nonceHash:'b'.repeat(43)};
async function proof(patch={}){const now=Math.floor(Date.now()/1000);return new SignJWT({iss:'https://agent.test',aud:'api://pf-a/agent-proof',sub:'partner:agent',iat:now,nbf:now,exp:now+120,jti:randomUUID(),...patch}).setProtectedHeader({alg:'RS256',kid:'agent-key'}).sign(agent.privateKey);}
function setup(){const store=new PolicyStore(':memory:',[capability]);store.registerOrganisation('partner','admin');store.registerPrincipal({id:'human',kind:'human',issuer:login.issuer,subject:login.subject,organisation:'partner',tokenIssuers:[login.issuer]},'admin');store.registerPrincipal({id:'agent',kind:'agent',issuer:'https://agent.test',subject:'partner:agent',organisation:'partner'},'admin');const {grantId}=store.createConsentedGrant(login,'agent',['interactive','autonomous'],3600,capability,'portal');const authority=new GrantAuthority({store,capability,issuer:'https://authority.test',audience:'api://pf-a/consent-proof',signer:new DevelopmentSigner(signer.privateKey,'authority-key'),agentIssuer:'https://agent.test',agentAudience:'api://pf-a/agent-proof',agentKeyId:'agent-key',agentKey:agent.publicKey,loginVerifier:{verify:async(token,nonce)=>{if(token!=='real-id-token'||nonce!=='bound-nonce')throw Error();return login;}}});return{store,grantId,authority};}
test('autonomous proof derives human/actor from consent without a human access token',async()=>{
 const s=setup();try{const raw=await s.authority.issue({grantId:s.grantId,mode:'autonomous',agentToken:await proof()});const {payload}=await jwtVerify(raw,signer.publicKey,{issuer:'https://authority.test',audience:'api://pf-a/consent-proof'});assert.equal(payload.sub,login.subject);assert.deepEqual(payload.act,{iss:'https://agent.test',sub:'partner:agent'});assert.ok(Number(payload.exp)-Number(payload.iat)<=60);s.store.revokeGrant(s.grantId,'admin');await assert.rejects(s.authority.issue({grantId:s.grantId,mode:'autonomous',agentToken:await proof()}));}finally{s.store.close();}
});
test('interactive proof requires current verified human login',async()=>{
 const s=setup();try{const agentToken=await proof();await assert.rejects(s.authority.issue({grantId:s.grantId,mode:'interactive',agentToken}));await assert.rejects(s.authority.issue({grantId:s.grantId,mode:'interactive',agentToken,login:{idToken:'forged',nonce:'bound-nonce'}}));assert.equal(typeof await s.authority.issue({grantId:s.grantId,mode:'interactive',agentToken,login:{idToken:'real-id-token',nonce:'bound-nonce'}}),'string');}finally{s.store.close();}
});
for(const patch of [{sub:'other'},{iss:'https://evil.test'},{aud:'other'},{exp:1}])test('invalid agent proof cannot acquire grant-backed authority',async()=>{
 const s=setup();try{await assert.rejects(s.authority.issue({grantId:s.grantId,mode:'autonomous',agentToken:await proof(patch)}));}finally{s.store.close();}
});

