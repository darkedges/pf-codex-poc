import test from 'node:test';import assert from 'node:assert/strict';
import {obtainProviderLogin,providerVerifier,bindLabProviderIdentity,providerSso} from '../../scripts/copilot/provider-login.ts';
import {localPublicRequest} from './public-origin.mjs';
import {JwksTokenVerifier} from '../../src/adapters/pingfederate.ts';
import {toolTrust} from '../../scripts/pf/copilot-tool-profile.mjs';
import {profile} from '../../scripts/pf/config.mjs';
import {admin} from '../../scripts/pf/common.mjs';
test('actual PF A configured-provider token is acquired without Microsoft callback or token POST',async()=>{
 let jwksCalls=0;const verifier=providerVerifier(async(url,init)=>{assert.equal(String(url),providerSso.issuer+'/pf/JWKS');assert.equal(init?.redirect,'error');jwksCalls++;const response=await localPublicRequest(String(url));return Response.json(response.value);});
 const result=await obtainProviderLogin(localPublicRequest,verifier);assert.ok(jwksCalls>0);assert.equal(result.claims.iss,providerSso.issuer);assert.equal(result.claims.aud,'api://copilot-login');assert.equal(result.claims.scope,'copilot.login');assert.equal(result.claims.sub,profile.human);
 assert.equal(result.claims.exp-result.claims.iat,3600);assert.equal(providerSso.maxLifetimeSeconds,3600);
 const broker={sub:profile.human,org_id:profile.org,act:{iss:profile.agentIssuer,sub:profile.agent},execution_mode:'interactive'};assert.doesNotThrow(()=>bindLabProviderIdentity(result.claims,broker as any));
 const tool=new JwksTokenVerifier([toolTrust()],'copilot.invoke',1000,async()=>{assert.fail('wrong-issuer user token must not select tool keys');});await assert.rejects(tool.verify(result.token));
 assert.equal((await admin('b','oauth/clients/copilot-sso-exchange')).enabled,false);
});
