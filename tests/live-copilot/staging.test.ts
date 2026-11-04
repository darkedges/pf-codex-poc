import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import {importPKCS8,SignJWT} from 'jose';
import {admin,call,nodes,root} from '../../scripts/pf/common.mjs';
import {copilotProfile} from '../../scripts/pf/copilot-config.mjs';
const privateRoot=resolve(root,'.local/copilot');
test('actual staged clients are disabled, separately scoped and callback-bound',async()=>{
 const login=await admin('a','oauth/clients/'+copilotProfile.loginClientId);
 assert.equal(login.enabled,false);assert.equal(login.clientAuth.type,'SECRET');
 assert.deepEqual(login.redirectUris,[copilotProfile.callback]);assert.deepEqual(login.grantTypes,['AUTHORIZATION_CODE']);
 assert.deepEqual(login.restrictedScopes,['copilot.login']);assert.equal(login.restrictToDefaultAccessTokenManager,true);
 const tool=await admin('b','oauth/clients/'+copilotProfile.toolClientId);
 assert.equal(tool.enabled,false);assert.equal(tool.clientAuth.type,'PRIVATE_KEY_JWT');assert.equal(tool.clientAuth.enforceReplayPrevention,true);
 assert.deepEqual(tool.grantTypes,['TOKEN_EXCHANGE']);assert.deepEqual(tool.restrictedScopes,['copilot.invoke']);
});
test('staged login cannot issue with its actual credential',async()=>{
 const secret=readFileSync(resolve(privateRoot,'pf-generic-oauth-client-secret.txt'),'utf8').trim();
 const response=await call(nodes.a.issuer+'/as/token.oauth2',{method:'POST',form:true,body:{client_id:copilotProfile.loginClientId,client_secret:secret,
  grant_type:'authorization_code',code:'deliberately-invalid-code',redirect_uri:copilotProfile.callback}});
 assert.equal(response.status,401);assert.equal(response.value?.error,'invalid_client');assert.equal(response.value?.access_token,undefined);
});
test('staged signed exchange cannot issue even with valid workload authentication',async()=>{
 const assertion=await new SignJWT({}).setProtectedHeader({alg:'RS256',kid:'copilot-sso-exchange',typ:'client-authentication+jwt'})
  .setIssuer(copilotProfile.toolClientId).setSubject(copilotProfile.toolClientId).setAudience(nodes.b.issuer).setIssuedAt().setExpirationTime('60s').setJti(randomUUID())
  .sign(await importPKCS8(readFileSync(resolve(privateRoot,'pf-sso-exchange.private.pem'),'utf8'),'RS256'));
 const response=await call(nodes.b.issuer+'/as/token.oauth2',{method:'POST',form:true,body:{client_id:copilotProfile.toolClientId,
  client_assertion:assertion,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',grant_type:'urn:ietf:params:oauth:grant-type:token-exchange',
  subject_token:'deliberately-invalid-subject',subject_token_type:'urn:ietf:params:oauth:token-type:access_token',resource:'urn:copilot:delegated:tool',scope:'copilot.invoke'}});
 assert.equal(response.status,401);assert.equal(response.value?.error,'invalid_client');assert.equal(response.value?.access_token,undefined);
});
test('existing local base URLs, consent clients and gateway clients remain active',async()=>{
 for(const node of ['a','b']){
  assert.equal((await admin(node,'serverSettings')).federationInfo.baseUrl,nodes[node].issuer);
  for(const id of node==='a'?['copilot-consent-portal','gateway-1-token-exchange','consent-gateway-1']:['gateway-2-token-exchange','consent-gateway-2'])assert.equal((await admin(node,'oauth/clients/'+id)).enabled,true);
 }
});

