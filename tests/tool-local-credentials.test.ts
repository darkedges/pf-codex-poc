import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve} from 'node:path';
import {X509Certificate,createPrivateKey,createPublicKey} from 'node:crypto';
import {createLocalToolCredentials} from '../scripts/vault/local-tool-credentials.mjs';
import {validateRecord} from '../scripts/vault/tool-secrets.mjs';
test('local enrollment creates distinct named server/backend/client identities and a tool-only policy key',()=>{
 const dir=mkdtempSync(resolve(tmpdir(),'tool-local-credentials-'));
 try{
  const c=createLocalToolCredentials(dir);assert.equal(Object.keys(validateRecord(c.runtime)).length,6);
  const ca=new X509Certificate(c.maintenance.certificatePem),server=new X509Certificate(c.runtime.toolServerCertificatePem),backend=new X509Certificate(c.backend.certificatePem),monitor=new X509Certificate(c.monitor.certificatePem);
  assert.ok(ca.ca);for(const leaf of [server,backend,monitor]){assert.equal(leaf.ca,false);assert.ok(leaf.verify(ca.publicKey));}
  assert.equal(server.checkHost('localhost'),'localhost');assert.equal(server.checkHost('tool-api'),'tool-api');assert.equal(backend.checkHost('tool-backend'),'tool-backend');assert.equal(backend.checkHost('other'),undefined);
  assert.ok(server.keyUsage.includes('1.3.6.1.5.5.7.3.1'));assert.ok(monitor.keyUsage.includes('1.3.6.1.5.5.7.3.2'));
  assert.notEqual(server.fingerprint256,monitor.fingerprint256);assert.ok(monitor.checkPrivateKey(createPrivateKey(c.monitor.keyPem)));
  assert.equal(createPublicKey(c.runtime.policySigningKeyPem).export({format:'jwk'}).n,c.toolJwk.n);
  assert.throws(()=>createLocalToolCredentials(dir));
 }finally{rmSync(dir,{recursive:true,force:true});}
});
