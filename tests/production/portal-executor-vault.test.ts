import test,{before,after} from 'node:test';import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';import {join} from 'node:path';import {tmpdir} from 'node:os';import {execFileSync} from 'node:child_process';import {createPrivateKey,createPublicKey,X509Certificate} from 'node:crypto';
import {validatePortalExecutor,fetchPortalExecutor,executorPath,executorPolicy} from '../../scripts/vault/portal-executor-profile.mjs';
const directory=mkdtempSync(join(tmpdir(),'portal-executor-'));let record:any,trust:any;
before(()=>{execFileSync('openssl',['req','-x509','-newkey','rsa:3072','-nodes','-keyout',join(directory,'key.pem'),'-out',join(directory,'cert.pem'),'-subj','/CN=executor-test','-addext','basicConstraints=critical,CA:FALSE','-addext','extendedKeyUsage=clientAuth','-days','1'],{stdio:'ignore',windowsHide:true,timeout:15000});const key=readFileSync(join(directory,'key.pem'),'utf8'),cert=readFileSync(join(directory,'cert.pem'),'utf8'),jwk=createPublicKey(createPrivateKey(key)).export({format:'jwk'}),authority=Object.fromEntries(['pfAClientKeyPem','pfBClientKeyPem','policyAgentKeyPem','policyGatewayKeyPem'].map(field=>[field,key]));record={schemaVersion:1,purpose:'portal-gateway-executor',...authority,agentKeyPem:key,gatewayKeyPem:key,gatewayCertificatePem:cert,gatewaySigningKeyPem:key};trust={authority:Object.fromEntries(Object.keys(authority).map(field=>[field,jwk])),agentJwk:jwk,gateway:{publicJwk:jwk,certificateSha256:new X509Certificate(cert).fingerprint256}};});
after(()=>rmSync(directory,{recursive:true,force:true}));
test('gateway Vault record validates every key against independent public trust',()=>{
 assert.deepEqual(validatePortalExecutor(record,trust),record);
 for(const patch of [{operatorToken:'synthetic'},{directLineSecret:'synthetic'},{purpose:'other'},{schemaVersion:2},{agentKeyPem:'invalid'},{gatewayKeyPem:'invalid'}])assert.throws(()=>validatePortalExecutor({...record,...patch},trust));
 assert.throws(()=>validatePortalExecutor(record,{...trust,agentJwk:{...trust.agentJwk,n:'other'}}));assert.throws(()=>validatePortalExecutor(record,{...trust,gateway:{...trust.gateway,certificateSha256:'other'}}));
});
test('gateway credential reader consumes an exact one-use lease and returns no operator authority',async()=>{
 const calls:string[]=[];const result=await fetchPortalExecutor(async(path)=>{calls.push(path);return path.endsWith('/login')?{status:200,value:{auth:{client_token:'synthetic-reader',policies:[executorPolicy],num_uses:1,lease_duration:120}}}:{status:200,value:{data:{metadata:{version:1},data:record}}};},trust);
 assert.deepEqual(calls,['/auth/tool-cert/login',executorPath]);assert.equal(result.version,1);assert.equal(result.client_token,undefined);
});
test('broader gateway Vault lease and unavailable records reject without fallback or secret output',async()=>{
 for(const patch of [{policies:['root']},{num_uses:2},{lease_duration:121}])await assert.rejects(fetchPortalExecutor(async()=>({status:200,value:{auth:{client_token:'synthetic-secret',policies:[executorPolicy],num_uses:1,lease_duration:120,...patch}}}),trust),/^Error: Portal gateway credentials unavailable$/);
 await assert.rejects(fetchPortalExecutor(async()=>{throw Error('synthetic-secret');},trust),/^Error: Portal gateway credentials unavailable$/);
});
