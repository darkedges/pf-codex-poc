import {mkdirSync,openSync,closeSync,existsSync,readFileSync,writeFileSync,renameSync,rmSync} from 'node:fs';
import {resolve} from 'node:path';
import {createHash,randomUUID,X509Certificate} from 'node:crypto';
import {protect,custody,rendererCertificate} from './tool-custody.mjs';
import {vault,operator,privateLoad} from './common.mjs';
import {mount,validateRecord,fetchRecord,publishRecord} from './tool-secrets.mjs';
import {createLocalToolCredentials} from './local-tool-credentials.mjs';
import {validatePersistentWorkloads} from '../pf/persistent-tool-policy.ts';
import {toolTrust} from '../pf/copilot-tool-profile.mjs';
import {loadToolRuntime} from '../../src/copilot/tool-runtime.ts';
const canonical=value=>JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a],[b])=>a.localeCompare(b))));
const hash=value=>createHash('sha256').update(canonical(value)).digest('hex');
let fd,staging,oldTrust,newTrust,snapshot,configText,success=false,clean=true;
const written=new Map(),lock=resolve(custody,'verification.lock'),trustFile=resolve(custody,'policy-workloads.json'),receiptFile=resolve(custody,'runtime-enrollment.json');
try{
 if(process.argv.length!==2)throw Error();protect();fd=openSync(lock,'wx',0o600);
 if(existsSync(resolve(custody,'policy-service.lock'))||existsSync(receiptFile)||existsSync(resolve(custody,'tool-runtime.json'))||existsSync(resolve(custody,'policy-workloads.next.json')))throw Error();
 oldTrust=readFileSync(trustFile,'utf8');const workload=validatePersistentWorkloads(JSON.parse(oldTrust));
 const rootToken=privateLoad('bootstrap.json').root_token;
 for(const name of ['runtime','local-pki','private-backend','monitoring']){const r=await vault('/'+mount+'/metadata/'+name,{token:rootToken});if(r.status!==404)throw Error();}
 staging=resolve(custody,'enrollment-'+randomUUID());mkdirSync(staging,{mode:0o700});
 const generated=createLocalToolCredentials(staging);validateRecord(generated.runtime);
 for(const [name,data] of [['local-pki',generated.maintenance],['private-backend',generated.backend],['monitoring',generated.monitor],['runtime',generated.runtime]]){
  written.set(name,hash(data));await operator('/'+mount+'/data/'+name,{method:'POST',body:{options:{cas:0},data}});
 }
 workload.tool={keys:[generated.toolJwk]};newTrust=JSON.stringify(validatePersistentWorkloads(workload));
 const next=resolve(custody,'policy-workloads.next.json');writeFileSync(next,newTrust,{mode:0o600,flag:'wx'});renameSync(next,trustFile);
 const fetched=await fetchRecord((p,o)=>vault(p,{...o,...rendererCertificate()}));if(hash(fetched.record)!==hash(generated.runtime)||fetched.version!==1)throw Error();
 const cert=new X509Certificate(generated.monitor.certificatePem),config={version:1,trust:{...toolTrust(),jwksUri:'https://tool-backend:7443/pf/JWKS'},policy:{origin:'https://tool-backend:7443',clientId:'policy-tool',keyId:'copilot-policy-tool'},clientCertificateSha256:[cert.fingerprint256],timeouts:{jwksMs:1500,policyMs:1500,toolMs:5000},admission:{maxConcurrentRequests:16,perWorkloadRequestsPerMinute:60,maxConnections:128}};
 snapshot='snapshot-1-'+randomUUID();publishRecord(fetched.record,resolve(custody,snapshot));
 configText=JSON.stringify(config,null,2);writeFileSync(resolve(custody,'tool-runtime.json'),configText,{mode:0o600,flag:'wx'});
 const audit=resolve(staging,'audit');mkdirSync(audit,{mode:0o700});const secrets=resolve(custody,snapshot);
 const loaded=await loadToolRuntime({TOOL_MODE:'verified',TOOL_CONFIG_FILE:resolve(custody,'tool-runtime.json'),TOOL_SECRETS_DIR:secrets,TOOL_AUDIT_DIR:audit,NODE_EXTRA_CA_CERTS:resolve(secrets,'tool-outbound-ca.pem')},{fetch:async()=>{throw Error('Not connected');}});
 if(loaded.server.listening)throw Error();
 const receipt={enrolledAt:new Date().toISOString(),version:1,snapshot,serverNames:['localhost','tool-api','tool'],backendName:'tool-backend',approvedCaller:'local-tool-monitor',runtimeConfigurationValidated:true,publicRoutesChanged:false,persistentToolStarted:false};
 writeFileSync(receiptFile,JSON.stringify(receipt,null,2),{mode:0o600,flag:'wx'});success=true;console.log(JSON.stringify({enrolled:true,version:1,runtimeFiles:6,privateRecords:3,persistentToolStarted:false}));
}catch{console.error('Local tool enrollment failed; no service activation attempted');process.exitCode=1;}
finally{
 if(!success&&fd!==undefined)try{
  if(newTrust&&readFileSync(trustFile,'utf8')===newTrust)writeFileSync(trustFile,oldTrust,{mode:0o600});
  for(const [name,digest] of written){const r=await vault('/'+mount+'/data/'+name,{token:privateLoad('bootstrap.json').root_token});if(r.status===404)continue;if(r.status!==200||r.value.data.metadata.version!==1||hash(r.value.data.data)!==digest)throw Error();await operator('/'+mount+'/metadata/'+name,{method:'DELETE'});}
  if(configText&&existsSync(resolve(custody,'tool-runtime.json'))&&readFileSync(resolve(custody,'tool-runtime.json'),'utf8')===configText)rmSync(resolve(custody,'tool-runtime.json'));
  if(snapshot){const target=resolve(custody,snapshot);if(!target.startsWith(custody+'\\'))throw Error();rmSync(target,{recursive:true,force:true});}
 }catch{clean=false;console.error('Enrollment cleanup requires review; custody lock retained');}
 if(staging){if(!staging.startsWith(custody+'\\'))throw Error('Refused staging cleanup');rmSync(staging,{recursive:true,force:true});}
 if(fd!==undefined){closeSync(fd);if(clean)rmSync(lock);}
}
