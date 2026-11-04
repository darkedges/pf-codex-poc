import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {portalVaultPath,portalVaultPolicy,portalVaultRole,validatePortalRecord,fetchPortalRecord} from '../../src/consent/portal-vault.mjs';
const pair=generateKeyPairSync('rsa',{modulusLength:2048}),key=pair.privateKey.export({format:'pem',type:'pkcs8'}),jwk=pair.publicKey.export({format:'jwk'}),digest=v=>createHash('sha256').update(v).digest('hex');
const record={schemaVersion:1,purpose:'portal-controller',oidcClientKeyPem:key,policyConsentKeyPem:key,providerClientSecret:'synthetic-provider-secret',directLineSecret:'synthetic-channel-secret'};
const trust={oidcClientJwk:jwk,policyConsentJwk:jwk,providerClientSecretSha256:digest(record.providerClientSecret),directLineSecretSha256:digest(record.directLineSecret)};
test('portal Vault record contains only the selected controller credentials',()=>{
 assert.deepEqual(validatePortalRecord(record,trust),record);
 for(const patch of [{operatorToken:'secret'},{agentKeyPem:key},{schemaVersion:2},{purpose:'other'},{providerClientSecret:'wrong'},{directLineSecret:'wrong'},{oidcClientKeyPem:'invalid'}])assert.throws(()=>validatePortalRecord({...record,...patch},trust));
 assert.throws(()=>validatePortalRecord(record,{...trust,oidcClientJwk:{...jwk,n:'wrong'}}));
});
test('limited cert login reads one exact KV path and returns no Vault token',async()=>{
 const calls=[];const result=await fetchPortalRecord(async(path,options)=>{calls.push([path,options]);return path.endsWith('/login')?{status:200,value:{auth:{client_token:'synthetic-reader',policies:[portalVaultPolicy],num_uses:1,lease_duration:120}}}:{status:200,value:{data:{metadata:{version:1},data:record}}};},trust);
 assert.equal(calls[0][0],'/auth/tool-cert/login');assert.equal(calls[0][1].body.name,portalVaultRole);assert.equal(calls[1][0],portalVaultPath);assert.equal(calls[1][1].token,'synthetic-reader');assert.equal(result.version,1);assert.equal(result.client_token,undefined);
});
for(const patch of [{policies:['root']},{num_uses:2},{lease_duration:121},{client_token:''}])test('portal rejects broader or malformed Vault lease '+JSON.stringify(patch),async()=>{
 let reads=0;await assert.rejects(fetchPortalRecord(async(path)=>{if(path!== '/auth/tool-cert/login')reads++;return{status:200,value:{auth:{client_token:'synthetic-reader',policies:[portalVaultPolicy],num_uses:1,lease_duration:120,...patch}}};},trust),/^Error: Portal controller credentials unavailable$/);assert.equal(reads,0);
});
test('Vault failures and substituted records are sanitized with no local fallback',async()=>{
 await assert.rejects(fetchPortalRecord(async()=>{throw Error('synthetic-secret');},trust),/^Error: Portal controller credentials unavailable$/);
 await assert.rejects(fetchPortalRecord(async(path)=>path.endsWith('/login')?{status:200,value:{auth:{client_token:'synthetic-reader',policies:[portalVaultPolicy],num_uses:1,lease_duration:120}}}:{status:403,value:{secret:'synthetic-secret'}},trust));
});
