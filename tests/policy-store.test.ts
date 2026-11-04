import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join,resolve,dirname,basename } from 'node:path';
import { PolicyStore } from '../src/policy/store.ts';

const capability={scope:'copilot.invoke',resource:'sharepoint:approved-research'};
const claims={iss:'https://pf-a.test',aud:'api://gateway-2',sub:'partner:user',act:{iss:'https://agents.test',sub:'partner:agent'},org_id:'partner',delegation_id:'grant-1',execution_mode:'autonomous',scope:'copilot.invoke'};
function initialise(store:PolicyStore){
  store.registerOrganisation('partner','admin');
  store.registerPrincipal({id:'human-1',kind:'human',issuer:'https://humans.test',subject:claims.sub,organisation:'partner',tokenIssuers:['https://pf-a.test','https://pf-b.test']},'admin');
  store.registerPrincipal({id:'agent-1',kind:'agent',issuer:claims.act.iss,subject:claims.act.sub,organisation:'partner'},'admin');
  store.createGrant({id:'grant-1',humanId:'human-1',agentId:'agent-1',organisation:'partner',modes:['interactive','autonomous'],scopes:[capability.scope],resources:[capability.resource],expiresAt:Date.now()+60000,consent:{reference:'approval-1',approvedAt:Date.now()-1000,expiresAt:Date.now()+120000}},'admin');
}
test('persisted grant permits both modes and revocation survives a new connection',()=>{
  const dir=mkdtempSync(join(tmpdir(),'copilot-policy-'));
  const path=join(dir,'policy.sqlite');
  let store=new PolicyStore(path,[capability]);
  try{
    initialise(store);
    assert.equal(store.decide(claims,capability,'gateway-2').permit,true);
    assert.equal(store.decide({...claims,execution_mode:'interactive'},capability,'gateway-2').permit,true);
    const reader=new PolicyStore(path,[capability]);
    try{store.revokeGrant('grant-1','admin');assert.equal(reader.decide(claims,capability,'gateway-2').permit,false);}finally{reader.close();}
    store.consumeAssertion('gateway','persistent-jti',Math.floor(Date.now()/1000)+60);
    store.close();store=new PolicyStore(path,[capability]);
    assert.throws(()=>store.consumeAssertion('gateway','persistent-jti',Math.floor(Date.now()/1000)+60));
    assert.equal(store.decide(claims,capability,'gateway-2').permit,false);
    assert.throws(()=>initialise(store));
  }finally{store.close();const absolute=resolve(dir);if(dirname(absolute)!==resolve(tmpdir())||!basename(absolute).startsWith('copilot-policy-'))throw Error('Refused test cleanup path');rmSync(absolute,{recursive:true,force:true});}
});
for(const [name,patch]of Object.entries({human:{sub:'other'},agent:{act:{...claims.act,sub:'other'}},agentIssuer:{act:{...claims.act,iss:'https://evil.test'}},organisation:{org_id:'other'},grant:{delegation_id:'unknown'},mode:{execution_mode:'other'},issuer:{iss:'https://evil.test'},scope:{scope:'copilot.invoke admin'}}))test(`persistent policy denies mismatched ${name}`,()=>{
  const store=new PolicyStore(':memory:',[capability]);try{initialise(store);assert.equal(store.decide({...claims,...patch},capability,'gateway-2').permit,false);}finally{store.close();}
});
for(const entity of ['organisation','human','agent']as const)test(`suspended ${entity} denies existing tokens`,()=>{
  const s=new PolicyStore(':memory:',[capability]);try{initialise(s);s.suspend(entity,entity==='organisation'?'partner':entity==='human'?'human-1':'agent-1','admin');assert.equal(s.decide(claims,capability,'gateway-2').permit,false);}finally{s.close();}
});
test('unknown resource and missing consent cannot grant authority',()=>{
  const s=new PolicyStore(':memory:',[capability]);try{initialise(s);assert.equal(s.decide(claims,{...capability,resource:'https://graph.microsoft.com/anything'},'gateway-2').permit,false);assert.throws(()=>s.createGrant({id:'bad'}as never,'admin'));}finally{s.close();}
});
test('client assertion replay is persisted and separated by workload',()=>{
  const s=new PolicyStore(':memory:',[capability]);try{s.consumeAssertion('gateway','jti-1',Math.floor(Date.now()/1000)+60);assert.throws(()=>s.consumeAssertion('gateway','jti-1',Math.floor(Date.now()/1000)+60));s.consumeAssertion('administrator','jti-1',Math.floor(Date.now()/1000)+60);}finally{s.close();}
});
test('decisions and governance changes have credential-free audit records',()=>{
  const s=new PolicyStore(':memory:',[capability]);try{initialise(s);const permit=s.decide(claims,capability,'gateway-2');s.revokeGrant('grant-1','admin');const denial=s.decide(claims,capability,'gateway-2');const events=s.audit();assert.ok(events.some(e=>e.id===permit.decisionId&&e.grant_version===1&&e.token_issuer===claims.iss&&e.actor_issuer===claims.act.iss&&e.audience===claims.aud));assert.ok(events.some(e=>e.id===denial.decisionId&&e.grant_version===2));assert.ok(events.some(e=>e.action==='grant.revoke'));assert.ok(events.some(e=>e.action==='decision'&&e.outcome==='deny'));assert.ok(events.some(e=>e.subject===claims.sub&&e.actor===claims.act.sub));assert.ok(!JSON.stringify(events).includes('access_token'));}finally{s.close();}
});
test('cross-organisation grants and expired consent fail atomically',()=>{
 const s=new PolicyStore(':memory:',[capability]);try{
  initialise(s);s.registerOrganisation('other','admin');s.registerPrincipal({id:'other-agent',kind:'agent',issuer:'https://other.test',subject:'other-agent',organisation:'other'},'admin');
  const g={id:'invalid-grant',humanId:'human-1',agentId:'other-agent',organisation:'partner',modes:['autonomous'],scopes:[capability.scope],resources:[capability.resource],expiresAt:Date.now()+60000,consent:{reference:'approval-2',approvedAt:Date.now(),expiresAt:Date.now()+120000}};
  const before=s.audit().length;assert.throws(()=>s.createGrant(g,'admin'));assert.equal(s.grant(g.id),undefined);assert.equal(s.audit().length,before);
  assert.throws(()=>s.createGrant({...g,agentId:'agent-1',consent:{...g.consent,expiresAt:Date.now()-1}},'admin'));
 }finally{s.close();}
});
test('expired persisted grants are denied without a stale permit cache',async()=>{
 const s=new PolicyStore(':memory:',[capability]);try{
  initialise(s);s.createGrant({id:'short-grant',humanId:'human-1',agentId:'agent-1',organisation:'partner',modes:['interactive'],scopes:[capability.scope],resources:[capability.resource],expiresAt:Date.now()+20,consent:{reference:'short-approval',approvedAt:Date.now(),expiresAt:Date.now()+1000}},'admin');
  await new Promise(r=>setTimeout(r,40));assert.equal(s.decide({...claims,delegation_id:'short-grant',execution_mode:'interactive'},capability,'gateway-2').permit,false);
 }finally{s.close();}
});
