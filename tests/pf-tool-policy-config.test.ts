import test from 'node:test';
import assert from 'node:assert/strict';
import {toolTrust,toolExchangeConfig,toolPolicyEnabled} from '../scripts/pf/copilot-tool-profile.mjs';
test('tool policy is explicit opt-in and rejects ambiguous configuration',()=>{
 assert.equal(toolPolicyEnabled({}),false);assert.equal(toolPolicyEnabled({POLICY_COPILOT_TOOL_PROFILE:'local-verified',POLICY_DATABASE:'isolated.sqlite'}),true);
 for(const value of ['', 'true','mock','production'])assert.throws(()=>toolPolicyEnabled({POLICY_COPILOT_TOOL_PROFILE:value,POLICY_DATABASE:'isolated.sqlite'}));
 assert.throws(()=>toolPolicyEnabled({POLICY_COPILOT_TOOL_PROFILE:'local-verified'}));
});
test('tool trust pins public issuer and distinct audience to verified local PF keys',()=>{
 const trust=toolTrust();assert.equal(trust.issuer,'https://pf-b.copilot.darkedges.com');assert.equal(trust.audience,'api://copilot-tool');
 assert.equal(trust.jwksUri,'https://localhost:9034/pf/JWKS');assert.deepEqual(trust.algorithms,['RS256']);assert.deepEqual(trust.keyIds,['copilot-tool-signing']);assert.equal(trust.maxLifetimeSeconds,120);
});
test('tool exchange cannot reuse broker credentials, audience or input proof',()=>{
 const config=toolExchangeConfig();assert.equal(config.clientId,'copilot-sso-exchange');assert.equal(config.clientKeyId,'copilot-sso-exchange');
 assert.equal(config.upstream[0].issuer,'https://localhost:9033');assert.equal(config.upstream[0].audience,'api://gateway-2');assert.deepEqual(config.upstream[0].keyIds,['consent-a-signing']);
 assert.equal(config.downstream.audience,'api://copilot-tool');assert.equal(config.requestedResource,'urn:copilot:delegated:tool');assert.equal(config.targetParameter,'resource');assert.equal(config.tokenEndpoint,'https://localhost:9034/as/token.oauth2');
 config.downstream.keyIds.push('untrusted');assert.deepEqual(toolTrust().keyIds,['copilot-tool-signing']);
});
