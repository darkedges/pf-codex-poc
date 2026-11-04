import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair,SignJWT,jwtVerify } from 'jose';
import { randomUUID } from 'node:crypto';
import { PolicyApi } from '../../src/policy/api.ts';
import { PolicyStore } from '../../src/policy/store.ts';
import { bodyHash } from '../../src/policy/protocol.ts';
import { GrantAuthority } from '../../src/identity/grant-authority.ts';
import { DevelopmentSigner,type AssertionSigner } from '../../src/identity/assertion-signer.ts';
const workload=await generateKeyPair('RS256'),actor=await generateKeyPair('RS256'),signing=await generateKeyPair('RS256');
const cap={scope:'copilot.invoke',resource:'sharepoint:approved-research'},origin='https://policy.test',path='/v1/assertions';
const login={issuer:'https://pf.test',subject:'partner:user',audience:'portal',issuedAt:Date.now(),authTime:Date.now(),expiresAt:Date.now()+120000,tokenHash:'a'.repeat(43),nonceHash:'b'.repeat(43)};
function setup(signer:AssertionSigner=new DevelopmentSigner(signing.privateKey,'authority'),callerPatch={}){
 const store=new PolicyStore(':memory:',[cap]);store.registerOrganisation('partner','admin');
 store.registerPrincipal({id:'human',kind:'human',issuer:login.issuer,subject:login.subject,organisation:'partner',tokenIssuers:[login.issuer]},'admin');
 store.registerPrincipal({id:'agent',kind:'agent',issuer:'https://agent.test',subject:'agent:one',organisation:'partner'},'admin');
 const {grantId}=store.createConsentedGrant(login,'agent',['interactive','autonomous'],3600,cap,'portal');
 const authority=new GrantAuthority({store,capability:cap,issuer:'https://authority.test',audience:'api://proof',signer,agentIssuer:'https://agent.test',agentAudience:'api://agent',agentKeyId:'actor',agentKey:actor.publicKey,loginVerifier:{verify:async()=>login}});
 const api=new PolicyApi({store,origin:()=>origin,callers:[{id:'workload',kid:'workload',key:workload.publicKey,roles:['authority'],organisations:['partner'],agent:{issuer:'https://agent.test',subject:'agent:one',operations:['copilot.invoke']},...callerPatch}],verifier:{verify:async()=>{throw Error();}},authority});
 return{store,grantId,api};
}
async function request(s:ReturnType<typeof setup>,patch={},signedPatch={}){
 const agentToken=await new SignJWT({sub:'agent:one'}).setIssuer('https://agent.test').setAudience('api://agent').setIssuedAt().setNotBefore('0s').setExpirationTime('120s').setJti(randomUUID()).setProtectedHeader({alg:'RS256',kid:'actor'}).sign(actor.privateKey);
 const body={grantId:s.grantId,mode:'autonomous',operation:'copilot.invoke',agentToken,...patch},rawBody=JSON.stringify(body);
 const token=await new SignJWT({method:'POST',body_sha256:bodyHash(rawBody),...signedPatch}).setIssuer('workload').setSubject('workload').setAudience(origin+path).setIssuedAt().setExpirationTime('60s').setJti(randomUUID()).setProtectedHeader({alg:'RS256',kid:'workload',typ:'policy-request+jwt'}).sign(workload.privateKey);
 return{method:'POST',path,rawBody,authorization:'Policy '+token};
}
test('authenticated authority derives identities and binds the approved operation',async()=>{
 const s=setup();try{const input=await request(s),r=await s.api.handle(input);assert.equal(r.status,200);const {payload}=await jwtVerify(String(r.body.assertion),signing.publicKey,{issuer:'https://authority.test',audience:'api://proof'});assert.equal(payload.sub,login.subject);assert.deepEqual(payload.act,{iss:'https://agent.test',sub:'agent:one'});assert.equal(payload.operation,'copilot.invoke');assert.equal(payload.resource,cap.resource);assert.equal((await s.api.handle(input)).status,401);}finally{s.store.close();}
});
for(const patch of [{sub:'forged'},{resource:'sharepoint:other'},{operation:'graph.anything'},{grantId:'unknown'},{mode:'interactive'}])test('authority rejects forged fields or unapproved issuance',async()=>{
 const s=setup();try{assert.notEqual((await s.api.handle(await request(s,patch))).status,200);}finally{s.store.close();}
});
test('request signature binds grant, mode and operation; anonymous issuance fails',async()=>{
 const s=setup();try{const input=await request(s);assert.equal((await s.api.handle({...input,authorization:''})).status,401);for(const patch of [{grantId:'other'},{mode:'interactive'},{operation:'other'}])assert.equal((await s.api.handle({...input,rawBody:JSON.stringify({...JSON.parse(input.rawBody),...patch})})).status,401);}finally{s.store.close();}
});
test('workload cannot borrow another actor credential',async()=>{
 const s=setup();try{const agentToken=await new SignJWT({sub:'agent:other'}).setIssuer('https://agent.test').setAudience('api://agent').setIssuedAt().setNotBefore('0s').setExpirationTime('120s').setJti(randomUUID()).setProtectedHeader({alg:'RS256',kid:'actor'}).sign(actor.privateKey);assert.equal((await s.api.handle(await request(s,{agentToken}))).status,403);}finally{s.store.close();}
});
test('revocation during signing prevents assertion release',async()=>{
 let s:ReturnType<typeof setup>;const dev=new DevelopmentSigner(signing.privateKey,'authority');s=setup({sign:async p=>{const token=await dev.sign(p);s.store.revokeGrant(s.grantId,'admin');return token;}});
 try{assert.equal((await s.api.handle(await request(s))).status,403);}finally{s.store.close();}
});
test('signer outage cannot issue and response never includes service details',async()=>{
 const s=setup({sign:async()=>{throw Error('SECRET');}});try{const r=await s.api.handle(await request(s));assert.notEqual(r.status,200);assert.ok(!JSON.stringify(r).includes('SECRET'));}finally{s.store.close();}
});
test('workload rotation accepts configured overlap and rejects a retired key',async()=>{
 const current=await generateKeyPair('RS256');
 const s=setup(undefined,{key:current.publicKey,kid:'current',previousKeys:[{key:workload.publicKey,kid:'workload'}]});
 try{assert.equal((await s.api.handle(await request(s))).status,200);const input=await request(s);const token=await new SignJWT({method:'POST',body_sha256:bodyHash(input.rawBody)}).setIssuer('workload').setSubject('workload').setAudience(origin+path).setIssuedAt().setExpirationTime('60s').setJti(randomUUID()).setProtectedHeader({alg:'RS256',kid:'current',typ:'policy-request+jwt'}).sign(current.privateKey);assert.equal((await s.api.handle({...input,authorization:'Policy '+token})).status,200);}finally{s.store.close();}
 const retired=setup(undefined,{key:current.publicKey,kid:'current'});try{assert.equal((await retired.api.handle(await request(retired))).status,401);}finally{retired.store.close();}
});
for(const patch of [{roles:['decision']},{organisations:['other']}])test('decision-only or cross-organisation workload cannot issue',async()=>{
 const s=setup(undefined,patch);try{assert.equal((await s.api.handle(await request(s))).status,403);}finally{s.store.close();}
});
test('suspended agent and missing consent evidence cannot issue',async()=>{
 const s=setup();try{s.store.suspend('agent','agent','admin');assert.equal((await s.api.handle(await request(s))).status,403);}finally{s.store.close();}
 const t=setup();try{t.store.createGrant({id:'administrative',humanId:'human',agentId:'agent',organisation:'partner',modes:['autonomous'],scopes:[cap.scope],resources:[cap.resource],expiresAt:Date.now()+60000,consent:{reference:'admin-ref',approvedAt:Date.now(),expiresAt:Date.now()+120000}},'admin');assert.equal((await t.api.handle(await request(t,{grantId:'administrative'}))).status,403);}finally{t.store.close();}
});
