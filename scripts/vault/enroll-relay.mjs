import {readFileSync,writeFileSync,mkdirSync,existsSync,openSync,closeSync,rmSync} from 'node:fs';
import {resolve,sep} from 'node:path';
import {randomUUID,createHash,X509Certificate} from 'node:crypto';
import {protect,custody,rendererCertificate} from './tool-custody.mjs';
import {vault,operator,privateLoad} from './common.mjs';
import {relayPolicy,relayRole,relayMount,validateRelayRecord,fetchRelayRecord,relayRecordDigest as digest} from './relay-secrets.mjs';
import {createLocalRelayCredentials} from './local-relay-credentials.mjs';
const args=process.argv.slice(2);
if(args.length!==1||args[0]!=='--enroll')throw Error('Use --enroll for the approved separate local relay custody');
const lock=resolve(custody,'relay-enrollment.lock'),receiptPath=resolve(custody,'relay-enrollment.json');
const policyText=readFileSync(new URL('../../infra/copilot/vault-relay-runtime-read.hcl',import.meta.url),'utf8');
let fd,stage,snapshot,success=false,clean=true,roleWritten=false,policyWritten=false;const written=new Map(),files=[];
let checks=0;const check=v=>{if(!v)throw Error('Relay custody verification failed');checks++;};
try{
 protect();fd=openSync(lock,'wx',0o600);
 if(existsSync(receiptPath)||['relay-renderer-cert.pem','relay-renderer-key.pem'].some(n=>existsSync(resolve(custody,n))))throw Error('Existing relay enrollment must be reconciled');
 const token=privateLoad('bootstrap.json').root_token;
 const audits=(await operator('/sys/audit')).data,tune=(await operator('/sys/mounts/'+relayMount+'/tune')).data;
 check(audits&&Object.keys(audits).length&&!Object.values(audits).some(a=>a.options?.log_raw==='true')&&!(tune.audit_non_hmac_request_keys??[]).length&&!(tune.audit_non_hmac_response_keys??[]).length);
 for(const path of ['/'+relayMount+'/metadata/relay-runtime','/'+relayMount+'/metadata/relay-connection','/sys/policies/acl/'+relayPolicy,'/auth/tool-cert/certs/'+relayRole])check((await vault(path,{token})).status===404);
 const original=(await operator('/'+relayMount+'/data/runtime')).data,maintenance=(await operator('/'+relayMount+'/data/local-pki')).data.data;
 stage=resolve(custody,'relay-enrollment-'+randomUUID());mkdirSync(stage,{mode:0o700});
 const generated=createLocalRelayCredentials(stage,maintenance,original.data.toolServerCertificatePem);validateRelayRecord(generated.runtime);
 const connection={schemaVersion:1,purpose:'copilot-tool-relay-connector-credential',connectionKey:generated.connectionKey};
 for(const [name,data] of [['relay-connection',connection],['relay-runtime',generated.runtime]]){written.set(name,digest(data));await operator('/'+relayMount+'/data/'+name,{method:'POST',body:{options:{cas:0},data}});}
 policyWritten=true;await operator('/sys/policies/acl/'+relayPolicy,{method:'PUT',body:{policy:policyText}});
 roleWritten=true;await operator('/auth/tool-cert/certs/'+relayRole,{method:'POST',body:{certificate:generated.renderer.certificatePem,token_policies:[relayPolicy],token_no_default_policy:true,token_ttl:120,token_max_ttl:120,token_explicit_max_ttl:120,token_num_uses:1,token_type:'service'}});
 const identity={cert:generated.renderer.certificatePem,key:generated.renderer.keyPem};
 const fetched=await fetchRelayRecord((p,o)=>vault(p,{...o,...identity}));check(fetched.version===1&&digest(fetched.record)===digest(generated.runtime));
 async function login(id,role,policy){const r=await vault('/auth/tool-cert/login',{method:'POST',body:{name:role},...id}),a=r.value?.auth;check(r.status===200&&typeof a?.client_token==='string'&&a.policies?.length===1&&a.policies[0]===policy&&a.num_uses===1&&a.lease_duration<=120);return a.client_token;}
 for(const [path,method] of [['/'+relayMount+'/data/runtime','GET'],['/'+relayMount+'/data/relay-connection','GET'],['/'+relayMount+'/data/local-pki','GET'],['/transit/sign/consent-authority','POST']]){
  const access=await login(identity,relayRole,relayPolicy),r=await vault(path,{method,token:access,...(method==='POST'?{body:{input:Buffer.from('synthetic-permission-check').toString('base64')}}:{})});check(r.status===403);
 }
 const toolAccess=await login(rendererCertificate(),'tool-runtime-renderer','tool-runtime-read');check((await vault('/'+relayMount+'/data/relay-runtime',{token:toolAccess})).status===403);
 const raw=(await operator('/'+relayMount+'/data/relay-connection')).data;check(raw.metadata.version===1&&createHash('sha256').update(raw.data.connectionKey).digest('hex')===generated.runtime.connectionKeySha256);
 const current=(await operator('/'+relayMount+'/data/runtime')).data;check(current.metadata.version===original.metadata.version&&digest(current.data)===digest(original.data));
 snapshot='relay-snapshot-1-'+randomUUID();mkdirSync(resolve(custody,snapshot),{mode:0o700});
 for(const [name,value] of Object.entries(validateRelayRecord(fetched.record)))writeFileSync(resolve(custody,snapshot,name),value,{mode:0o600,flag:'wx'});
 for(const [name,value] of [['relay-renderer-cert.pem',identity.cert],['relay-renderer-key.pem',identity.key]]){const path=resolve(custody,name);files.push(path);writeFileSync(path,value,{mode:0o600,flag:'wx'});}
 const receipt={enrolledAt:new Date().toISOString(),version:1,snapshot,runtimeRecord:'relay-runtime',connectionRecord:'relay-connection',rendererRole:relayRole,rendererPolicy:relayPolicy,outboundCertificateSha256:new X509Certificate(generated.runtime.outboundCertificatePem).fingerprint256,runtimeFiles:8,checks,existingToolCredentialsUnchanged:true,existingToolTrustChanged:false,connectorConfigured:false,persistentRelayStarted:false,publicRoutesChanged:false};
 writeFileSync(receiptPath,JSON.stringify(receipt,null,2),{mode:0o600,flag:'wx'});success=true;console.log(JSON.stringify({enrolled:true,version:1,runtimeFiles:8,checks,existingToolCredentialsUnchanged:true,existingToolTrustChanged:false,persistentRelayStarted:false,rawValuesPrinted:false}));
}catch{console.error('Relay enrollment failed; existing tool was not reconfigured');process.exitCode=1;}
finally{
 if(!success&&fd!==undefined)try{
  const token=privateLoad('bootstrap.json').root_token;
  if(roleWritten){await operator('/auth/tool-cert/certs/'+relayRole,{method:'DELETE'});}
  if(policyWritten){await operator('/sys/policies/acl/'+relayPolicy,{method:'DELETE'});}
  for(const [name,hash] of written){const r=await vault('/'+relayMount+'/data/'+name,{token});if(r.status===404)continue;if(r.status!==200||r.value.data.metadata.version!==1||digest(r.value.data.data)!==hash)throw Error();await operator('/'+relayMount+'/metadata/'+name,{method:'DELETE'});}
  for(const path of files)if(existsSync(path))rmSync(path);
  if(snapshot){const target=resolve(custody,snapshot);if(!target.startsWith(custody+sep))throw Error();rmSync(target,{recursive:true,force:true});}
 }catch{clean=false;console.error('Relay enrollment cleanup requires review; lock retained');}
 if(stage){if(!stage.startsWith(custody+sep))throw Error('Refused relay staging cleanup');rmSync(stage,{recursive:true,force:true});}
 if(fd!==undefined){closeSync(fd);if(clean)rmSync(lock);}
}
