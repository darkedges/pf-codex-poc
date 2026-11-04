import test from 'node:test';
import assert from 'node:assert/strict';
import { copilotProfile, loginObjects, toolObjects } from '../scripts/pf/copilot-config.mjs';
const jwks={keys:[{kty:'RSA',kid:'copilot-sso-exchange',use:'sig',alg:'RS256',n:'test-public-modulus',e:'AQAB'}]};
test('Copilot login is disabled, callback-exact and cannot exchange or refresh tokens',()=>{
 const {client,manager}=loginObjects('disposable-unit-test-secret');
 assert.equal(client.enabled,false);assert.deepEqual(client.redirectUris,['https://token.botframework.com/.auth/web/redirect']);
 assert.deepEqual(client.grantTypes,['AUTHORIZATION_CODE']);assert.equal(client.clientAuth.type,'SECRET');
 assert.deepEqual(client.restrictedScopes,['copilot.login']);assert.equal(client.restrictToDefaultAccessTokenManager,true);
 assert.deepEqual(manager.accessControlSettings.allowedClients,[{id:client.clientId}]);
});
test('human login token has a separate audience and no fabricated delegation identity',()=>{
 const {manager,mapping}=loginObjects('disposable-unit-test-secret');
 assert.equal(manager.configuration.fields.find(f=>f.name==='Audience Claim Value').value,'api://copilot-login');
 assert.deepEqual(Object.keys(mapping.attributeContractFulfillment),['sub']);
 for(const claim of ['act','delegation_id','execution_mode','org_id'])assert.ok(!manager.attributeContract.extendedAttributes.some(a=>a.name===claim));
});

test('only the Copilot login manager uses the approved sixty-minute lifetime',()=>{
 const login=loginObjects('disposable-unit-test-secret'),tool=toolObjects(jwks,jwks);
 assert.equal(copilotProfile.loginLifetimeSeconds,3600);
 assert.equal(login.manager.configuration.fields.find(f=>f.name==='Token Lifetime').value,'60');
 assert.equal(tool.manager.configuration.fields.find(f=>f.name==='Token Lifetime').value,'1');
});
test('login secret must be supplied explicitly without fallback',()=>{
 for(const secret of ['',undefined,null])assert.throws(()=>loginObjects(secret));
});
test('tool client is independently signed, disabled and has no login or refresh grant',()=>{
 const {client,manager}=toolObjects(jwks,jwks);
 assert.equal(client.enabled,false);assert.equal(client.clientAuth.type,'PRIVATE_KEY_JWT');assert.equal(client.clientAuth.enforceReplayPrevention,true);
 assert.deepEqual(client.grantTypes,['TOKEN_EXCHANGE']);assert.deepEqual(client.restrictedScopes,['copilot.invoke']);
 assert.deepEqual(manager.accessControlSettings.allowedClients,[{id:'copilot-sso-exchange'}]);
 assert.notEqual(client.clientId,copilotProfile.loginClientId);
});
test('tool trust requires verified PF A gateway audience and its pinned signing keys',()=>{
 const {processor}=toolObjects(jwks,jwks);
 const tables=processor.configuration.tables;
 assert.equal(tables[0].rows[0].fields.find(f=>f.name==='Issuer').value,'https://localhost:9033');
 assert.equal(tables[1].rows[0].fields[0].value,'api://gateway-2');
 assert.throws(()=>toolObjects({keys:[]},jwks));assert.throws(()=>toolObjects(jwks,{keys:[]}));
});
test('tool lifetime derives from verified upstream expiry with a fail-closed minimum budget',()=>{
 const {processor,policy,manager,mapping}=toolObjects(jwks,jwks);
 assert.ok(processor.attributeContract.extendedAttributes.some(a=>a.name==='exp'));
 assert.deepEqual(policy.processorMappings[0].attributeContractFulfillment.upstream_exp,{source:{type:'SUBJECT_TOKEN'},value:'exp'});
 assert.ok(manager.attributeContract.extendedAttributes.some(a=>a.name==='exp'));
 assert.ok(mapping.attributeContractFulfillment.exp.value.includes('tepp.upstream_exp'));
 assert.ok(mapping.issuanceCriteria.expressionCriteria.length>0);
});
test('tool issuance preserves signed subject, actor, organisation, grant and mode',()=>{
 const {policy,mapping,manager}=toolObjects(jwks,jwks);
 const incoming=policy.processorMappings[0].attributeContractFulfillment;
 for(const claim of ['actor_sub','actor_iss','org_id','delegation_id','execution_mode'])assert.deepEqual(incoming[claim],{source:{type:'SUBJECT_TOKEN'},value:claim});
 assert.deepEqual(incoming.subject,{source:{type:'SUBJECT_TOKEN'},value:'sub'});
 assert.equal(mapping.context.contextRef.id,policy.id);assert.equal(mapping.accessTokenManagerRef.id,manager.id);
 assert.ok(mapping.attributeContractFulfillment.act.value.includes('tepp.actor_sub'));
 assert.ok(!policy.processorMappings[0].issuanceCriteria.conditionalCriteria.some(c=>c.attributeName==='delegation_id'),'Durable grant IDs must come from signed evidence, not a fixed fixture');
});
test('public issuer claims are isolated to new token managers',()=>{
 const login=loginObjects('disposable-unit-test-secret'),tool=toolObjects(jwks,jwks);
 assert.equal(login.manager.configuration.fields.find(f=>f.name==='Issuer Claim Value').value,'https://pf-a.copilot.darkedges.com');
 assert.equal(tool.manager.configuration.fields.find(f=>f.name==='Issuer Claim Value').value,'https://pf-b.copilot.darkedges.com');
 assert.equal(tool.manager.configuration.fields.find(f=>f.name==='Audience Claim Value').value,'api://copilot-tool');
 assert.equal(tool.manager.configuration.fields.find(f=>f.name==='Token Lifetime').value,'1');
});
test('tool trust rejects private key material and unexpected signing algorithms',()=>{
 for(const patch of [{d:'private-material'},{alg:'HS256'},{use:'enc'}])assert.throws(()=>toolObjects({keys:[{...jwks.keys[0],...patch}]},jwks));
});
