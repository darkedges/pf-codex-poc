import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, SignJWT } from 'jose';
import { createHash,randomUUID } from 'node:crypto';
import { PolicyStore } from '../../src/policy/store.ts';
import { PolicyApi } from '../../src/policy/api.ts';
import { PolicyClient } from '../../src/policy/client.ts';
const pair=await generateKeyPair('RS256');
const adminPair=await generateKeyPair('RS256');
const cap={scope:'copilot.invoke',resource:'sharepoint:approved-research'};
const identity={iss:'https://pf.test',aud:'api://gateway-2',sub:'partner:user',act:{iss:'https://agent.test',sub:'partner:agent'},org_id:'partner',delegation_id:'grant-1',execution_mode:'interactive',scope:cap.scope};
const origin='https://policy.test';
test('signed dependency health proves workload/replay-store access without user tokens or grants',async()=>{
 const s=setup(true,'https://private.test');try{
  const r=await request(s.api,'/v1/health',{},'gateway',{aud:'https://private.test/v1/health'});
  assert.deepEqual(r.response,{status:200,body:{ready:true}});assert.equal(s.verifications(),0);assert.equal((await s.api.handle(r.input)).status,401);
  assert.equal((await request(s.api,'/v1/health',{},'admin')).response.status,403);
  assert.equal((await request(s.api,'/v1/health',{token:'untrusted'},'gateway',{aud:'https://private.test/v1/health'})).response.status,400);
  assert.equal(s.store.grant('grant-1')?.state,'active');
 }finally{s.store.close();}
});
test('decision-only caller has one configured private origin, never a forwarded-header audience',async()=>{
 const privateOrigin='https://private-policy.test:7443',s=setup(true,privateOrigin);
 try{
  const body={token:'signed-proof',capability:cap};
  const accepted=await request(s.api,'/v1/decisions',body,'gateway',{aud:privateOrigin+'/v1/decisions'});
  assert.equal(accepted.response.status,200);assert.equal((await s.api.handle(accepted.input)).status,401);
  assert.equal((await request(s.api,'/v1/decisions',body)).response.status,401);
  assert.equal((await request(s.api,'/v1/decisions',body,'gateway',{aud:'https://unapproved.test/v1/decisions'})).response.status,401);
  assert.equal((await request(s.api,'/v1/grants/grant-1/revoke',{},'gateway',{aud:privateOrigin+'/v1/grants/grant-1/revoke'})).response.status,401);
  assert.equal((await request(s.api,'/v1/grants/grant-1/revoke',{},'admin')).response.status,200);
 }finally{s.store.close();}
});
test('private decision origin cannot be configured for administrators or malformed origins',()=>{
 for(const decisionOrigin of ['http://private.test','https://private.test/extra','https://private.test?x=y'])assert.throws(()=>setup(true,decisionOrigin),/configuration/);
 assert.throws(()=>new PolicyApi({store:{} as never,origin:()=>origin,callers:[{id:'admin',kid:'key',key:pair.publicKey,roles:['decision','grant-admin'],organisations:['partner'],decisionOrigin:'https://private.test'}],verifier:{verify:async()=>identity as never}}),/configuration/);
});
function setup(seed=true,decisionOrigin?:string){
 const store=new PolicyStore(':memory:',[cap]);
 if(seed){
 store.registerOrganisation('partner','admin');
 store.registerPrincipal({id:'human',kind:'human',issuer:'https://human.test',subject:identity.sub,organisation:'partner',tokenIssuers:[identity.iss]},'admin');
 store.registerPrincipal({id:'agent',kind:'agent',issuer:identity.act.iss,subject:identity.act.sub,organisation:'partner'},'admin');
 store.createGrant({id:'grant-1',humanId:'human',agentId:'agent',organisation:'partner',modes:['interactive','autonomous'],scopes:[cap.scope],resources:[cap.resource],expiresAt:Date.now()+60000,consent:{reference:'approval',approvedAt:Date.now()-100,expiresAt:Date.now()+120000}},'admin');
 }
 let verifications=0;
 const api=new PolicyApi({store,origin:()=>origin,callers:[{id:'gateway',kid:'gateway-key',key:pair.publicKey,roles:['decision'],organisations:['partner'],...(decisionOrigin?{decisionOrigin}:{})},{id:'admin',kid:'gateway-key',key:adminPair.publicKey,roles:['grant-admin','registry-admin'],organisations:['partner']}],verifier:{verify:async token=>{verifications++;if(token!=='signed-proof')throw Error('SECRET');return structuredClone(identity)as never;}}});
 const client=new PolicyClient({origin,clientId:'gateway',keyId:'gateway-key',key:pair.privateKey,capability:cap,timeoutMs:1000,fetch:async(url,init)=>{
  const r=await api.handle({method:'POST',path:new URL(String(url)).pathname,authorization:(init?.headers as Record<string,string>).Authorization,rawBody:String(init?.body)});
  return Response.json(r.body,{status:r.status});
 }});
 return{store,api,client,verifications:()=>verifications};
}
async function request(api:PolicyApi,path:string,value:unknown,client='gateway',patch={},signedRaw?:string){
 const rawBody=JSON.stringify(value);const now=Math.floor(Date.now()/1000);
 const assertion=await new SignJWT({iss:client,sub:client,aud:origin+path,iat:now,exp:now+60,jti:randomUUID(),method:'POST',body_sha256:createHash('sha256').update(signedRaw??rawBody).digest('base64url'),...patch}).setProtectedHeader({alg:'RS256',kid:'gateway-key',typ:'policy-request+jwt'}).sign(client==='admin'?adminPair.privateKey:pair.privateKey);
 const input={method:'POST',path,authorization:'Policy '+assertion,rawBody};
 return{input,response:await api.handle(input)};
}
test('policy independently verifies token; authenticated gateway receives a current decision',async()=>{
 const s=setup();try{await s.client.authorise(identity as never,{accessToken:'signed-proof'});assert.equal(s.verifications(),1);s.store.revokeGrant('grant-1','admin');await assert.rejects(s.client.authorise(identity as never,{accessToken:'signed-proof'}));}finally{s.store.close();}
});
test('unsigned claims and anonymous policy requests have no authority',async()=>{
 const s=setup();try{assert.equal((await s.api.handle({method:'POST',path:'/v1/decisions',authorization:'',rawBody:JSON.stringify(identity)})).status,401);const r=await request(s.api,'/v1/decisions',{...identity,capability:cap});assert.equal(r.response.status,400);assert.equal(s.verifications(),0);}finally{s.store.close();}
});
test('signed body tampering, wrong audience, expired assertion and replay fail closed',async()=>{
 const s=setup();try{
  const body={token:'signed-proof',capability:cap};
  assert.equal((await request(s.api,'/v1/decisions',body,'gateway',{},'different')).response.status,401);
  for(const patch of [{aud:'https://evil.test'},{exp:1},{sub:'other'}])assert.equal((await request(s.api,'/v1/decisions',body,'gateway',patch)).response.status,401);
  const r=await request(s.api,'/v1/decisions',body);assert.equal(r.response.status,200);assert.equal((await s.api.handle(r.input)).status,401);
 }finally{s.store.close();}
});
test('decision caller cannot administer grants; admin can revoke with scoped authority',async()=>{
 const s=setup();try{assert.equal((await request(s.api,'/v1/grants/grant-1/revoke',{})).response.status,403);assert.equal((await request(s.api,'/v1/grants/grant-1/revoke',{},'gateway',{iss:'admin',sub:'admin'})).response.status,401);assert.equal((await request(s.api,'/v1/grants/grant-1/revoke',{},'admin')).response.status,200);await assert.rejects(s.client.authorise(identity as never,{accessToken:'signed-proof'}));}finally{s.store.close();}
});
test('invalid subject token and missing token evidence deny without exposing credentials',async()=>{
 const s=setup();try{await assert.rejects(s.client.authorise(identity as never));await assert.rejects(s.client.authorise(identity as never,{accessToken:'SECRET'}),e=>!String(e).includes('SECRET'));}finally{s.store.close();}
});
test('scoped administration registers identities and records explicit approval before granting',async()=>{
 const s=setup(false);try{
  assert.equal((await request(s.api,'/v1/registry/organisations',{id:'partner'},'admin')).response.status,201);
  for(const p of [{id:'human',kind:'human',issuer:'https://human.test',subject:identity.sub,organisation:'partner',tokenIssuers:[identity.iss]},{id:'agent',kind:'agent',issuer:identity.act.iss,subject:identity.act.sub,organisation:'partner'}])assert.equal((await request(s.api,'/v1/registry/principals',p,'admin')).response.status,201);
  const grant={id:'grant-1',humanId:'human',agentId:'agent',organisation:'partner',modes:['interactive'],scopes:[cap.scope],resources:[cap.resource],expiresAt:Date.now()+60000};
  assert.equal((await request(s.api,'/v1/grants',grant,'admin')).response.status,400);
  assert.equal(s.store.grant('grant-1'),undefined);
  assert.equal((await request(s.api,'/v1/grants',{...grant,consent:{reference:'signed-admin-approval',approvedAt:Date.now(),expiresAt:Date.now()+120000}},'admin')).response.status,201);
  assert.equal(s.store.grant('grant-1')?.approved_by,'admin');
  await s.client.authorise(identity as never,{accessToken:'signed-proof'});
 }finally{s.store.close();}
});
test('administration cannot cross organisations and decision callers cannot register agents',async()=>{
 const s=setup();try{
  assert.equal((await request(s.api,'/v1/registry/organisations',{id:'other'},'admin')).response.status,403);
  assert.equal((await request(s.api,'/v1/registry/principals',{id:'rogue'},'gateway')).response.status,403);
  const r=await request(s.api,'/v1/decisions',{token:'signed-proof',capability:{...cap,resource:'sharepoint:other'}});assert.equal(r.response.status,403);
 }finally{s.store.close();}
});
test('forged workload signatures cannot obtain policy decisions',async()=>{
 const s=setup();try{
  const r=await request(s.api,'/v1/decisions',{token:'signed-proof',capability:cap});
  const parts=r.input.authorization.slice(7).split('.');const signature=Buffer.from(parts[2],'base64url');signature[0]^=1;parts[2]=signature.toString('base64url');
  assert.equal((await s.api.handle({...r.input,authorization:'Policy '+parts.join('.')})).status,401);
 }finally{s.store.close();}
});
test('policy outage, redirects and malformed permit responses never authorise',async()=>{
 for(const transport of [async()=>{throw Error('SECRET');},async()=>Response.json({error:'SECRET'},{status:503}),async()=>new Response('',{status:302,headers:{Location:'https://evil.test'}}),async()=>Response.json({permit:true})]){
  const c=new PolicyClient({origin,clientId:'gateway',keyId:'gateway-key',key:pair.privateKey,capability:cap,timeoutMs:100,fetch:transport});
  await assert.rejects(c.authorise(identity as never,{accessToken:'signed-proof'}),e=>!String(e).includes('SECRET'));
 }
});
test('database failure cannot reuse a previous permit',async()=>{
 const s=setup();await s.client.authorise(identity as never,{accessToken:'signed-proof'});s.store.close();await assert.rejects(s.client.authorise(identity as never,{accessToken:'signed-proof'}));
});
