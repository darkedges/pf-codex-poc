import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {randomUUID} from 'node:crypto';
import {JwksTokenVerifier} from '../../src/adapters/pingfederate.ts';
import {PolicyStore} from '../../src/policy/store.ts';
import {PolicyApi} from '../../src/policy/api.ts';
import {PolicyClient} from '../../src/policy/client.ts';
import {PolicyProtectedTool} from '../../src/copilot/tool-authority.ts';
import {ToolApi} from '../../src/copilot/tool-api.ts';
const signing=await generateKeyPair('RS256'),workload=await generateKeyPair('RS256');
const cap={scope:'copilot.invoke',resource:'sharepoint:approved-research'},origin='https://policy.test';
const trust={issuer:'https://tool-issuer.test',jwksUri:'https://tool-issuer.test/pf/JWKS',audience:'api://copilot-tool',algorithms:['RS256'],keyIds:['tool-key'],organisations:['partner'],actorIssuers:['https://agent.test'],maxLifetimeSeconds:120};
const claims={iss:trust.issuer,aud:trust.audience,sub:'partner:user',act:{iss:'https://agent.test',sub:'partner:agent'},org_id:'partner',delegation_id:'grant-1',execution_mode:'autonomous',scope:cap.scope};
async function signed(patch={}){const now=Math.floor(Date.now()/1000);return new SignJWT({...claims,iat:now,nbf:now,exp:now+60,jti:randomUUID(),...patch}).setProtectedHeader({alg:'RS256',kid:'tool-key'}).sign(signing.privateKey);}
async function setup(){
 const store=new PolicyStore(':memory:',[cap]);store.registerOrganisation('partner','bootstrap');
 store.registerPrincipal({id:'human',kind:'human',issuer:'https://human.test',subject:claims.sub,organisation:'partner',tokenIssuers:[trust.issuer]},'bootstrap');
 store.registerPrincipal({id:'agent',kind:'agent',issuer:claims.act.iss,subject:claims.act.sub,organisation:'partner'},'bootstrap');
 store.createGrant({id:'grant-1',humanId:'human',agentId:'agent',organisation:'partner',modes:['interactive','autonomous'],scopes:[cap.scope],resources:[cap.resource],expiresAt:Date.now()+60000,consent:{reference:'approved',approvedAt:Date.now()-100,expiresAt:Date.now()+120000}},'bootstrap');
 const verifier=new JwksTokenVerifier([trust],cap.scope,1000,async()=>Response.json({keys:[{...await exportJWK(signing.publicKey),kid:'tool-key',use:'sig',alg:'RS256'}]}));
 const api=new PolicyApi({store,origin:()=>origin,callers:[{id:'tool',kid:'workload-key',key:workload.publicKey,roles:['decision'],organisations:['partner']}],verifier});
 let decisions=0;
 const policy=new PolicyClient({origin,clientId:'tool',keyId:'workload-key',key:workload.privateKey,capability:cap,timeoutMs:1000,fetch:async(url,init)=>{
  decisions++;const r=await api.handle({method:'POST',path:new URL(String(url)).pathname,authorization:init.headers.Authorization,rawBody:String(init.body)});return Response.json(r.body,{status:r.status});
 }});
 return{store,verifier,policy,decisions:()=>decisions};
}
for(const mode of ['interactive','autonomous'])test(`tool gate independently verifies and checks online policy twice: ${mode}`,async()=>{
 const s=await setup();try{let calls=0;const tool=new PolicyProtectedTool({verifier:s.verifier,authorise:s.policy.authorise,timeoutMs:1000,operation:async identity=>{calls++;assert.equal(identity.sub,claims.sub);assert.deepEqual(identity.act,claims.act);return{result:'approved'};}});
 assert.deepEqual(await tool.execute(await signed({execution_mode:mode})),{result:'approved'});assert.equal(calls,1);assert.equal(s.decisions(),2);
 }finally{s.store.close();}
});
for(const mode of ['interactive','autonomous'])test(`tool HTTP contract uses JOSE and independent signed policy decisions: ${mode}`,async()=>{
 const s=await setup();try{
  const api=new ToolApi(new PolicyProtectedTool({verifier:s.verifier,authorise:s.policy.authorise,timeoutMs:1000,operation:async c=>{
   assert.equal(c.sub,claims.sub);assert.deepEqual(c.act,claims.act);assert.equal(c.delegation_id,claims.delegation_id);assert.equal(c.org_id,claims.org_id);assert.equal(c.execution_mode,mode);assert.equal(c.aud,trust.audience);return{authorized:true};
  }}));
  const request={method:'POST',path:'/v1/tools/verify-access',authorization:'Bearer '+await signed({execution_mode:mode}),rawBody:'{}'};
  assert.deepEqual(await api.handle(request),{status:200,body:{authorized:true}});assert.equal(s.decisions(),2);
  assert.equal((await api.handle({...request,authorization:'Bearer '+await signed({aud:'api://copilot-broker'})})).status,401);
  s.store.revokeGrant('grant-1','admin');assert.equal((await api.handle(request)).status,403);
 }finally{s.store.close();}
});
for(const patch of [{sub:'partner:other'},{act:{iss:claims.act.iss,sub:'partner:other-agent'}},{delegation_id:'unknown'},{org_id:'other'},{execution_mode:'invented'},{aud:'api://copilot-broker'},{scope:'arbitrary.graph'}])test('identity/capability substitution cannot invoke a tool',async()=>{
 const s=await setup();try{let called=false;const tool=new PolicyProtectedTool({verifier:s.verifier,authorise:s.policy.authorise,timeoutMs:1000,operation:async()=>{called=true;return'private';}});await assert.rejects(tool.execute(await signed(patch)));assert.equal(called,false);}finally{s.store.close();}
});
test('revocation during operation suppresses its result',async()=>{
 const s=await setup();try{const tool=new PolicyProtectedTool({verifier:s.verifier,authorise:s.policy.authorise,timeoutMs:1000,operation:async()=>{s.store.revokeGrant('grant-1','admin');return'private-result';}});await assert.rejects(tool.execute(await signed()),e=>e.code==='policy_denied'&&!String(e).includes('private-result'));}finally{s.store.close();}
});
test('policy outage prevents operation and sanitizes errors',async()=>{
 const s=await setup();try{let called=false;const tool=new PolicyProtectedTool({verifier:s.verifier,authorise:async()=>{throw Error('SECRET');},timeoutMs:1000,operation:async()=>{called=true;}});await assert.rejects(tool.execute(await signed()),e=>e.code==='policy_denied'&&!String(e).includes('SECRET'));assert.equal(called,false);}finally{s.store.close();}
});
for(const [kind,id]of [['agent','agent'],['human','human'],['organisation','partner']]as const)test(`suspended ${kind} is denied without running the tool`,async()=>{
 const s=await setup();try{s.store.suspend(kind,id,'admin');let called=false;const tool=new PolicyProtectedTool({verifier:s.verifier,authorise:s.policy.authorise,timeoutMs:1000,operation:async()=>{called=true;}});await assert.rejects(tool.execute(await signed()));assert.equal(called,false);}finally{s.store.close();}
});
test('token expiry during operation prevents release even within verifier clock tolerance',async()=>{
 const s=await setup();try{const token=await signed({exp:Math.floor(Date.now()/1000)+1});
 const tool=new PolicyProtectedTool({verifier:s.verifier,authorise:s.policy.authorise,timeoutMs:3000,operation:async()=>{await new Promise(done=>setTimeout(done,1100));return'private-result';}});
 await assert.rejects(tool.execute(token),e=>['invalid_token','policy_denied'].includes(e.code)&&!String(e).includes('private-result'));
 }finally{s.store.close();}
});
test('operation deadline aborts and cannot release a late result',async()=>{
 const s=await setup();try{let aborted=false;const tool=new PolicyProtectedTool({verifier:s.verifier,authorise:s.policy.authorise,timeoutMs:100,operation:async(_claims,signal)=>new Promise(done=>signal.addEventListener('abort',()=>{aborted=true;done('late');},{once:true}))});await assert.rejects(tool.execute(await signed()),e=>e.code==='tool_failed');assert.equal(aborted,true);}finally{s.store.close();}
});
test('missing policy configuration cannot construct a tool',async()=>{assert.throws(()=>new PolicyProtectedTool({verifier:{verify:async()=>claims},operation:async()=>{},timeoutMs:1000}as never));});
test('restricted audit records verified outcomes, and audit failure blocks operation/result release',async()=>{
 const s=await setup();try{
  const records:any[]=[];let fail=false,calls=0;
  const tool=new PolicyProtectedTool({verifier:s.verifier,authorise:s.policy.authorise,timeoutMs:1000,audit:async event=>{if(fail)throw Error('PRIVATE');records.push(event);},operation:async()=>{calls++;return'approved';}});
  assert.equal(await tool.execute(await signed()),'approved');assert.deepEqual(records.map(r=>r.outcome),['attempt','success']);assert.equal(records[0].claims.sub,claims.sub);assert.ok(!('accessToken'in records[0]));
  await assert.rejects(tool.execute('unsigned'));assert.equal(records.at(-1).outcome,'denied');assert.equal(records.at(-1).claims,undefined);
  fail=true;await assert.rejects(tool.execute(await signed()),{code:'audit_failed'});assert.equal(calls,1);
  let writes=0;const completion=new PolicyProtectedTool({verifier:s.verifier,authorise:s.policy.authorise,timeoutMs:1000,audit:async()=>{if(++writes===2)throw Error('PRIVATE');},operation:async()=>{calls++;return'PRIVATE_RESULT';}});
  await assert.rejects(completion.execute(await signed()),e=>e.code==='audit_failed'&&!String(e).includes('PRIVATE_RESULT'));assert.equal(calls,2);
 }finally{s.store.close();}
});
