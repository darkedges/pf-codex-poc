import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPair,exportJWK} from 'jose';
import {documentPfProfile} from '../../scripts/pf/document-profile.mjs';

const pair=await generateKeyPair('RS256',{extractable:true});
const jwks={keys:[{...await exportJWK(pair.publicKey),kid:'document-test',alg:'RS256',use:'sig'}]};
const material=()=>({authority:jwks,agent:jwks,upstream:jwks,clientA:jwks,clientB:jwks});
test('document PF profiles are disabled, isolated, interactive and signed-client-only',()=>{
 const p=documentPfProfile(material());
 for(const n of [p.a,p.b]){
  assert.equal(n.client.enabled,false);assert.equal(n.client.clientAuth.type,'PRIVATE_KEY_JWT');
  assert.equal(n.client.clientAuth.enforceReplayPrevention,true);
  assert.deepEqual(n.client.restrictedScopes,['m365.document.read']);
  assert.equal(n.policy.processorMappings.length,1);
  const conditions=n.policy.processorMappings[0].issuanceCriteria.conditionalCriteria;
  assert.ok(conditions.some(c=>c.attributeName==='execution_mode'&&c.value==='interactive'));
  assert.ok(conditions.some(c=>c.attributeName==='scope'&&c.value==='m365.document.read'));
  assert.ok(!conditions.some(c=>c.attributeName==='delegation_id'));
  assert.equal(n.tokenManager.configuration.fields.find(f=>f.name==='Token Lifetime').value,n===p.a?'2':'1');
  assert.equal(n.mapping.context.contextRef.id,n.policy.id);
  assert.equal(n.mapping.accessTokenManagerRef.id,n.tokenManager.id);
 }
 assert.equal(p.a.policy.processorMappings[0].actorTokenProcessor.id,'documentAgent');
 assert.equal(p.exchange.downstream.audience,'api://federated-copilot/documents');
 assert.equal(p.exchange.upstream[0].audience,'api://gateway-2/documents');
 assert.equal(p.exchange.clientId,p.b.client.clientId);
});
test('document lifetime ladder descends within the five-minute consent',()=>{const p=documentPfProfile(material());assert.equal(p.exchange.upstream[0].maxLifetimeSeconds,120);assert.equal(p.exchange.downstream.maxLifetimeSeconds,60);});
test('document processor pins the independent authority and actor audiences',()=>{
 const p=documentPfProfile(material());
 const audience=o=>o.configuration.tables.find(t=>t.name==='Allowed Audiences').rows[0].fields[0].value;
 assert.equal(audience(p.a.subjectProcessor),'api://pf-a/document-consent-proof');
 assert.equal(audience(p.a.actorProcessor),'api://pf-a/document-agent-proof');
 assert.equal(audience(p.b.subjectProcessor),'api://gateway-2/documents');
 assert.notEqual(p.authorityIssuer,'https://partner-a.test/consent-authority');
});
test('profile generation rejects private, remote, duplicate, weak or empty JWKS',()=>{
 for(const replacement of [{keys:[]},{keys:[{...jwks.keys[0],d:'private'}]}, {keys:[jwks.keys[0],jwks.keys[0]]},{keys:[{...jwks.keys[0],jku:'https://foreign.test'}]},{keys:[{...jwks.keys[0],n:'AQAB'}]}]){
  assert.throws(()=>documentPfProfile({...material(),authority:replacement}));
 }
});
test('generated profiles cannot be changed by mutating input or an earlier result',()=>{
 const m=structuredClone(material()),p=documentPfProfile(m);m.authority.keys[0].kid='changed';
 assert.ok(!JSON.stringify(p).includes('changed'));
 p.a.client.restrictedScopes.push('copilot.invoke');
 assert.deepEqual(documentPfProfile(material()).a.client.restrictedScopes,['m365.document.read']);
});
