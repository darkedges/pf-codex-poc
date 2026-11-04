// Local integration authority only. Not an application authentication service.
import { randomUUID } from 'node:crypto';
import { importPKCS8, importJWK, SignJWT, jwtVerify } from 'jose';
import { call, read, load, nodes } from './common.mjs';
import { local } from './common.mjs';
import { resolve } from 'node:path';
import { PolicyStore } from '../../src/policy/store.ts';
import { PolicyClient } from '../../src/policy/client.ts';
import { profile, tokenType } from './config.mjs';
export const key = name => importPKCS8(read(`${name}.private.pem`),'RS256');
export async function signProof(name, claims, issuer, audience, patch = {}) {
  const now = Math.floor(Date.now()/1000);
  return new SignJWT({ iss: issuer, aud: audience, iat: now, nbf: now, exp: now+(name === 'delegation' ? 60 : 240), jti: randomUUID(), ...claims, ...patch })
    .setProtectedHeader({ alg: 'RS256', kid: `copilot-${name}`, typ: 'JWT' }).sign(await key(name));
}
const capability={scope:profile.scope,resource:'sharepoint:approved-research'};
export async function policyClient(role='gateway',origin=process.env.POLICY_API_ORIGIN){
  if(!origin)throw Error('Authenticated policy API origin is required');
  return new PolicyClient({origin,clientId:`policy-${role}`,keyId:`copilot-policy-${role}`,key:await key(`policy-${role}`),capability,timeoutMs:5000});
}
export async function authorise(claims,evidence){await(await policyClient()).authorise(claims,evidence);}
async function authorityAuthorise(claims){
  const store=new PolicyStore(process.env.POLICY_DATABASE??resolve(local,'policy.sqlite'),[capability]);
  try{if(!store.decide({iss:nodes.a.issuer,...claims},capability,'lab-authority').permit)throw Error('Local authority grant policy denied');}
  finally{store.close();}
}
export async function clientAssertion(node, patch = {}, signer) {
  const name = node === 'a' ? 'gateway-1' : 'gateway-2';
  const clientId = node === 'a' ? 'gateway-1-token-exchange' : 'gateway-2-token-exchange';
  const now = Math.floor(Date.now()/1000);
  return new SignJWT({ iss: clientId, sub: clientId, aud: nodes[node].issuer, iat: now, exp: now+60, jti: randomUUID(), ...patch })
    .setProtectedHeader({ alg: 'RS256', kid: `copilot-${name}`, typ: 'client-authentication+jwt' }).sign(signer ?? await key(name));
}
export async function proofs(mode = 'interactive', subjectPatch = {}, actorPatch = {}) {
  if (!['interactive','autonomous'].includes(mode)) throw Error('Unsupported authority mode');
  const actor = await signProof('agent', { sub: profile.agent }, profile.agentIssuer, 'api://pf-a/agent-proof', actorPatch);
  // Independently validate the agent proof before a grant-backed subject assertion is signed.
  const publicKey = await importJWK(load('agent.jwks.json').keys[0], 'RS256');
  const { payload: agentIdentity } = await jwtVerify(actor,publicKey,{issuer:profile.agentIssuer,audience:'api://pf-a/agent-proof',algorithms:['RS256']});
  const claims = { sub: profile.human, actor_sub: profile.agent, actor_iss: profile.agentIssuer, org_id: profile.org, delegation_id: profile.grant, execution_mode: mode, scope: profile.scope };
  await authorityAuthorise({ ...claims, act: { sub: agentIdentity.sub, iss: agentIdentity.iss } });
  const autonomous = mode === 'autonomous';
  // Test patches deliberately construct signed invalid assertions for direct PF negative cases.
  const subject = await signProof(autonomous ? 'delegation' : 'human',claims,autonomous ? profile.delegationIssuer : profile.humanIssuer,autonomous ? 'api://pf-a/delegation-proof' : 'api://pf-a/human-proof',subjectPatch);
  return { subject, actor, subjectType: autonomous ? 'urn:example:token-type:delegation-proof' : 'urn:example:token-type:interactive-proof' };
}
export async function exchangeA(mode = 'interactive', options = {}) {
  const p = await proofs(mode,options.subjectPatch,options.actorPatch);
  return call(nodes.a.issuer+'/as/token.oauth2',{method:'POST',form:true,body:{
    grant_type:'urn:ietf:params:oauth:grant-type:token-exchange',subject_token:p.subject,subject_token_type:p.subjectType,
    actor_token:p.actor,actor_token_type:'urn:example:token-type:agent-proof',resource:'api://gateway-2',scope:profile.scope,
    requested_token_type:tokenType,client_id:'gateway-1-token-exchange',client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion:await clientAssertion('a'),...options.form,
  }});
}
export async function exchangeB(subject, options = {}) {
  return call(nodes.b.issuer+'/as/token.oauth2',{method:'POST',form:true,body:{
    grant_type:'urn:ietf:params:oauth:grant-type:token-exchange',subject_token:subject,subject_token_type:tokenType,
    resource:'api://copilot-broker',scope:profile.scope,requested_token_type:tokenType,client_id:'gateway-2-token-exchange',
    client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:options.assertion ?? await clientAssertion('b'),...options.form,
  }});
}
