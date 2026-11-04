import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { join,dirname } from 'node:path';
import { generateKeyPair, decodeJwt } from 'jose';
import { PingFederateExchange } from '../../src/adapters/pingfederate.ts';
import { load, nodes } from '../../scripts/pf/common.mjs';
import { profile } from '../../scripts/pf/config.mjs';
import { key, authorise, clientAssertion, exchangeA, exchangeB, signProof,policyClient } from '../../scripts/pf/harness.mjs';
import { startPolicy } from '../../scripts/pf/run-policy.mjs';
import { jwtPattern } from '../../scripts/pf/logging-config.mjs';

const logStart=new Date(Date.now()-5000).toISOString();

function accepted(r: { status: number; value: Record<string, unknown> }): string {
  assert.equal(r.status,200,'Real PF exchange must succeed (no tokens in assertion diagnostics)');
  assert.equal(typeof r.value?.access_token,'string');
  return r.value.access_token as string;
}
const denied = (r: { status: number }) => assert.ok(r.status >= 400 && r.status < 500,`PF must deny, HTTP ${r.status}`);
for (const mode of ['interactive','autonomous']) test(`real PF A → Gateway 2 → PF B: ${mode}`,async () => {
  const original = accepted(await exchangeA(mode));
  const adapter = new PingFederateExchange(load('exchange-config.json'),{clientKey:await key('gateway-2'),authorise});
  const result = await adapter.exchange(original);
  assert.equal(result.claims.iss,nodes.b.issuer);
  assert.equal(result.claims.aud,'api://copilot-broker');
  assert.equal(result.claims.sub,profile.human);
  assert.deepEqual(result.claims.act,{sub:profile.agent,iss:profile.agentIssuer});
  assert.equal(result.claims.org_id,profile.org);
  assert.equal(result.claims.delegation_id,profile.grant);
  assert.equal(result.claims.execution_mode,mode);
  assert.equal(result.claims.scope,profile.scope);
  assert.ok(result.claims.exp <= decodeJwt(original).exp!);
});
test('PF A refuses absent independent actor proof',async () => denied(await exchangeA('interactive',{form:{actor_token:'',actor_token_type:''}})));
test('local delegation authority refuses an agent outside the active grant',async () => {
  await assert.rejects(exchangeA('autonomous',{actorPatch:{sub:'partner-a:other-agent'}}));
});
test('PF A independently refuses a substituted signed agent credential',async () => {
  const actor=await signProof('agent',{sub:'partner-a:other-agent'},profile.agentIssuer,'api://pf-a/agent-proof');
  denied(await exchangeA('interactive',{form:{actor_token:actor}}));
});
for (const [name,patch] of Object.entries({
  'unknown human':{sub:'partner-a:other'},'wrong partner':{org_id:'partner-b'},'unbound agent':{actor_sub:'partner-a:other-agent'},
  'unknown grant':{delegation_id:'unknown'},'wrong mode':{execution_mode:'autonomous'},'wrong issuer':{iss:'https://evil.test'},
  'wrong audience':{aud:'api://other'},'expired subject':{exp:1},'future subject':{nbf:Math.floor(Date.now()/1000)+3600},
})) test(`PF A rejects ${name}`,async () => denied(await exchangeA('interactive',{subjectPatch:patch})));
test('PF A refuses a human proof substituted for autonomous delegation authority',async () => denied(await exchangeA('interactive',{form:{subject_token_type:'urn:example:token-type:delegation-proof'}})));
test('PF B refuses unsigned/modified upstream token',async () => {
  const parts = accepted(await exchangeA()).split('.');
  const payload = decodeJwt(parts.join('.'));
  parts[1]=Buffer.from(JSON.stringify({...payload,sub:'admin'})).toString('base64url');
  denied(await exchangeB(parts.join('.')));
});
for (const [name,patch] of Object.entries({ 'wrong client audience':{aud:'https://evil.test'},'wrong client subject':{sub:'other-client'},'expired client assertion':{exp:1} })) test(`PF B rejects ${name}`,async () => {
  const subject=accepted(await exchangeA());
  denied(await exchangeB(subject,{assertion:await clientAssertion('b',patch)}));
});
test('PF B refuses unregistered client key',async () => {
  const subject=accepted(await exchangeA());
  const rogue=await generateKeyPair('RS256');
  denied(await exchangeB(subject,{assertion:await clientAssertion('b',{},rogue.privateKey)}));
});
test('PF B rejects private_key_jwt replay',async () => {
  const subject=accepted(await exchangeA());
  const assertion=await clientAssertion('b');
  accepted(await exchangeB(subject,{assertion}));
  denied(await exchangeB(subject,{assertion}));
});
test('PF B refuses scope escalation',async () => denied(await exchangeB(accepted(await exchangeA()),{form:{scope:'copilot.invoke admin'}})));
test('PF B refuses cross-audience output request',async () => denied(await exchangeB(accepted(await exchangeA()),{form:{resource:'api://other'}})));
test('policy API outage fails closed before PF B issuance in both modes',async()=>{
  const isolated=await startPolicy();const client=await policyClient('gateway',isolated.origin);await isolated.stop();
  for(const mode of ['interactive','autonomous']){
    const original=accepted(await exchangeA(mode));let issuancePosts=0;
    const adapter=new PingFederateExchange(load('exchange-config.json'),{clientKey:await key('gateway-2'),authorise:client.authorise,fetch:async(url,init)=>{if(init?.method==='POST')issuancePosts++;return fetch(url,init);}});
    await assert.rejects(adapter.exchange(original),e=>String(e)==='ExchangeError: policy_denied');
    assert.equal(issuancePosts,0);
  }
});
for(const mode of ['interactive','autonomous'])test(`revocation during real PF B issuance prevents ${mode} token release`,async()=>{
  const original=accepted(await exchangeA(mode));
  const directory=mkdtempSync(join(dirname(process.env.POLICY_DATABASE!),'revocation-race-'));
  const isolated=await startPolicy({...process.env,POLICY_DATABASE:join(directory,'policy.sqlite')});
  try{
    const client=await policyClient('gateway',isolated.origin),admin=await policyClient('admin',isolated.origin);let issued=false;
    const adapter=new PingFederateExchange(load('exchange-config.json'),{clientKey:await key('gateway-2'),authorise:client.authorise,fetch:async(url,init)=>{
      const response=await fetch(url,init);
      if(init?.method==='POST'&&response.ok){issued=true;await admin.request(`/v1/grants/${profile.grant}/revoke`,{});}
      return response;
    }});
    await assert.rejects(adapter.exchange(original),e=>String(e)==='ExchangeError: policy_denied');
    assert.equal(issued,true,'The post-issuance policy check must deny a successfully issued token');
  }finally{await isolated.stop();}
});
test('authenticated persisted revocation blocks both modes and survives a new policy process',async () => {
  const originals=await Promise.all(['interactive','autonomous'].map(async mode=>accepted(await exchangeA(mode))));
  const admin=await policyClient('admin');
  assert.equal((await admin.request(`/v1/grants/${profile.grant}/revoke`,{})).revoked,true);
  const adapter=new PingFederateExchange(load('exchange-config.json'),{clientKey:await key('gateway-2'),authorise});
  for(const original of originals)await assert.rejects(adapter.exchange(original),e=>String(e)==='ExchangeError: policy_denied');
  await assert.rejects(exchangeA('autonomous'));
  await assert.rejects(exchangeA('interactive'));
  const restarted=await startPolicy();
  try{
    const client=await policyClient('gateway',restarted.origin);
    for(const original of originals)await assert.rejects(client.authorise({}as never,{accessToken:original}));
  }finally{await restarted.stop();}
});
test('live PF failure logs contain no compact JWT credentials',() => {
  for(const node of ['a','b']) {
    const result=spawnSync('docker',['logs','--since',logStart,`federated-copilot-pf-pf-${node}-1`],{encoding:'utf8',maxBuffer:20_000_000,timeout:15000});
    assert.equal(result.status,0,'Bounded PF log inspection must complete successfully');
    const logs=result.stdout+result.stderr;
    assert.equal((logs.match(new RegExp(jwtPattern,'g'))??[]).length,0,`PF ${node} must redact JWTs`);
    assert.equal(/PatternLayout contains an invalid element|Unable to locate plugin/.test(logs),false);
  }
});
