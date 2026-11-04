import test,{before,after} from 'node:test';import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';import {execFileSync} from 'node:child_process';
import {validatePortalTls,fetchPortalTls,tlsPolicy,tlsPath} from '../../scripts/vault/portal-tls.mjs';
const directory=mkdtempSync(join(tmpdir(),'portal-tls-'));let record:any;
before(()=>{execFileSync('openssl',['req','-x509','-newkey','rsa:3072','-nodes','-keyout',join(directory,'key.pem'),'-out',join(directory,'cert.pem'),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-addext','basicConstraints=critical,CA:FALSE','-addext','extendedKeyUsage=serverAuth','-days','1'],{stdio:'ignore',windowsHide:true,timeout:15000});record={schemaVersion:1,purpose:'portal-web-tls',serverKeyPem:readFileSync(join(directory,'key.pem'),'utf8'),serverCertificatePem:readFileSync(join(directory,'cert.pem'),'utf8')};});
after(()=>rmSync(directory,{recursive:true,force:true}));
test('portal TLS accepts only its new server-only identity and pinned public certificate',()=>{
 assert.deepEqual(validatePortalTls(record,record.serverCertificatePem),{key:record.serverKeyPem,cert:record.serverCertificatePem});
 for(const patch of [{operatorToken:'synthetic'},{purpose:'other'},{serverKeyPem:'invalid'},{schemaVersion:2}])assert.throws(()=>validatePortalTls({...record,...patch},record.serverCertificatePem));assert.throws(()=>validatePortalTls(record,'other certificate'));
});
test('TLS reader uses a separate exact-path one-use lease',async()=>{
 const paths:string[]=[];const tls=await fetchPortalTls(async(path)=>{paths.push(path);return path.endsWith('/login')?{status:200,value:{auth:{client_token:'synthetic',policies:[tlsPolicy],num_uses:1,lease_duration:120}}}:{status:200,value:{data:{metadata:{version:1},data:record}}};},record.serverCertificatePem);assert.equal(tls.cert,record.serverCertificatePem);assert.deepEqual(paths,['/auth/tool-cert/login',tlsPath]);
});
test('TLS reader rejects broader leases and failed reads without local-file fallback',async()=>{
 await assert.rejects(fetchPortalTls(async()=>({status:200,value:{auth:{client_token:'synthetic',policies:['root'],num_uses:1,lease_duration:120}}}),record.serverCertificatePem),/^Error: Portal server TLS unavailable$/);
 await assert.rejects(fetchPortalTls(async()=>{throw Error('synthetic-private');},record.serverCertificatePem),/^Error: Portal server TLS unavailable$/);
 await assert.rejects(fetchPortalTls(async(path)=>path.endsWith('/login')?{status:200,value:{auth:{client_token:'synthetic',policies:[tlsPolicy],num_uses:1}}}:{status:200,value:{data:{metadata:{version:1},data:record}}},record.serverCertificatePem),/^Error: Portal server TLS unavailable$/);
});
