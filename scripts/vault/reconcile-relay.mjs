// Complete only the known interrupted first enrollment; never overwrite KV records.
import {existsSync,statSync,mkdirSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {resolve,sep} from 'node:path';
import {randomUUID,createHash,X509Certificate} from 'node:crypto';
import {protect,custody,rendererCertificate} from './tool-custody.mjs';
import {vault,operator,privateLoad} from './common.mjs';
import {relayPolicy,relayRole,relayMount,validateRelayRecord,fetchRelayRecord,relayRecordDigest} from './relay-secrets.mjs';
import {createLocalRelayRenderer} from './local-relay-credentials.mjs';
let stage;let checks=0;const check=v=>{if(!v)throw Error();checks++;};
const lock=resolve(custody,'relay-enrollment.lock');
try{
 if(process.argv.length!==2)throw Error();protect();
 check(existsSync(lock)&&!existsSync(resolve(custody,'relay-enrollment.json'))&&!existsSync(resolve(custody,'relay-renderer-key.pem'))&&!existsSync(resolve(custody,'relay-renderer-cert.pem')));
 const lockTime=statSync(lock).mtimeMs;check(Date.now()-lockTime<3600000);
 const token=privateLoad('bootstrap.json').root_token;
 for(const path of ['/sys/policies/acl/'+relayPolicy,'/auth/tool-cert/certs/'+relayRole])check((await vault(path,{token})).status===404);
 const runtime=(await operator('/'+relayMount+'/data/relay-runtime')).data,connection=(await operator('/'+relayMount+'/data/relay-connection')).data,tool=(await operator('/'+relayMount+'/data/runtime')).data;
 for(const r of [runtime,connection])check(r.metadata.version===1&&Date.parse(r.metadata.created_time)>=lockTime-2000&&Date.parse(r.metadata.created_time)<lockTime+120000);
 validateRelayRecord(runtime.data);check(connection.data.schemaVersion===1&&connection.data.purpose==='copilot-tool-relay-connector-credential'&&createHash('sha256').update(connection.data.connectionKey).digest('hex')===runtime.data.connectionKeySha256);
 check(runtime.data.toolServerCertificateSha256===new X509Certificate(tool.data.toolServerCertificatePem).fingerprint256);
 const audits=(await operator('/sys/audit')).data,tune=(await operator('/sys/mounts/'+relayMount+'/tune')).data;
 check(audits&&Object.keys(audits).length&&!Object.values(audits).some(a=>a.options?.log_raw==='true')&&!(tune.audit_non_hmac_request_keys??[]).length&&!(tune.audit_non_hmac_response_keys??[]).length);
 const ca=(await operator('/'+relayMount+'/data/local-pki')).data.data;check(runtime.data.outboundCaPem===ca.certificatePem);
 stage=resolve(custody,'relay-reconciliation-'+randomUUID());mkdirSync(stage,{mode:0o700});const renderer=createLocalRelayRenderer(stage,ca),identity={cert:renderer.certificatePem,key:renderer.keyPem};
 await operator('/sys/policies/acl/'+relayPolicy,{method:'PUT',body:{policy:readFileSync(new URL('../../infra/copilot/vault-relay-runtime-read.hcl',import.meta.url),'utf8')}});
 await operator('/auth/tool-cert/certs/'+relayRole,{method:'POST',body:{certificate:identity.cert,token_policies:[relayPolicy],token_no_default_policy:true,token_ttl:120,token_max_ttl:120,token_explicit_max_ttl:120,token_num_uses:1,token_type:'service'}});
 const fetched=await fetchRelayRecord((p,o)=>vault(p,{...o,...identity}));check(fetched.version===1&&relayRecordDigest(fetched.record)===relayRecordDigest(runtime.data));
 async function login(id,role,policy){const r=await vault('/auth/tool-cert/login',{method:'POST',body:{name:role},...id}),a=r.value?.auth;check(r.status===200&&typeof a?.client_token==='string'&&a.policies?.length===1&&a.policies[0]===policy&&a.num_uses===1&&a.lease_duration>0&&a.lease_duration<=120);return a.client_token;}
 for(const path of ['/'+relayMount+'/data/runtime','/'+relayMount+'/data/relay-connection','/'+relayMount+'/data/local-pki']){const access=await login(identity,relayRole,relayPolicy);check((await vault(path,{token:access})).status===403);}
 const signer=await login(identity,relayRole,relayPolicy);check((await vault('/transit/sign/consent-authority',{method:'POST',token:signer,body:{input:Buffer.from('synthetic').toString('base64')}})).status===403);
 const ordinary=await login(rendererCertificate(),'tool-runtime-renderer','tool-runtime-read');check((await vault('/'+relayMount+'/data/relay-runtime',{token:ordinary})).status===403);
 const snapshot='relay-snapshot-1-'+randomUUID();mkdirSync(resolve(custody,snapshot),{mode:0o700});
 for(const [name,value] of Object.entries(validateRelayRecord(runtime.data)))writeFileSync(resolve(custody,snapshot,name),value,{mode:0o600,flag:'wx'});
 for(const [name,value] of [['relay-renderer-cert.pem',identity.cert],['relay-renderer-key.pem',identity.key]])writeFileSync(resolve(custody,name),value,{mode:0o600,flag:'wx'});
 const current=(await operator('/'+relayMount+'/data/runtime')).data;check(current.metadata.version===tool.metadata.version&&relayRecordDigest(current.data)===relayRecordDigest(tool.data));
 const receipt={enrolledAt:new Date().toISOString(),reconciled:true,version:1,snapshot,runtimeRecord:'relay-runtime',connectionRecord:'relay-connection',rendererRole:relayRole,rendererPolicy:relayPolicy,outboundCertificateSha256:new X509Certificate(runtime.data.outboundCertificatePem).fingerprint256,runtimeFiles:8,checks,existingToolCredentialsUnchanged:true,existingToolTrustChanged:false,connectorConfigured:false,persistentRelayStarted:false,publicRoutesChanged:false};
 writeFileSync(resolve(custody,'relay-enrollment.json'),JSON.stringify(receipt,null,2),{mode:0o600,flag:'wx'});rmSync(lock);
 console.log(JSON.stringify({enrolled:true,reconciled:true,checks,runtimeFiles:8,existingToolCredentialsUnchanged:true,existingToolTrustChanged:false,persistentRelayStarted:false,rawValuesPrinted:false}));
}catch{console.error('Relay reconciliation incomplete; preserve custody records and lock');process.exitCode=1;}
finally{if(stage){if(!stage.startsWith(custody+sep))throw Error('Refused staging cleanup');rmSync(stage,{recursive:true,force:true});}}
