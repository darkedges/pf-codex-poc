import assert from 'node:assert/strict';
import {createPublicKey,X509Certificate} from 'node:crypto';
import {readFileSync,readdirSync,rmSync} from 'node:fs';
import {resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
import {root} from '../pf/common.mjs';
import {protect,custody,rendererCertificate} from './tool-custody.mjs';
import {vault,operator,privateSave} from './common.mjs';
import {mount,fetchRecord} from './tool-secrets.mjs';
const checks=[];const check=(name,value)=>{assert.ok(value,name);checks.push(name);};
let extraSnapshot;
try{
 protect();const {record,version}=await fetchRecord((p,o)=>vault(p,{...o,...rendererCertificate()}));check('enrolled tool record valid',version>=1);
 const workloads=JSON.parse(readFileSync(resolve(custody,'policy-workloads.json'),'utf8'));
 check('PDP trusts only the enrolled tool workload public key',workloads.tool.keys.length===1&&workloads.tool.keys[0].n===createPublicKey(record.policySigningKeyPem).export({format:'jwk'}).n);
 const config=JSON.parse(readFileSync(resolve(custody,'tool-runtime.json'),'utf8')),monitor=(await operator('/'+mount+'/data/monitoring')).data.data;
 check('monitor certificate pin matches runtime configuration',config.clientCertificateSha256.length===1&&config.clientCertificateSha256[0]===new X509Certificate(monitor.certificatePem).fingerprint256);
 check('server certificate names match local runtime',new X509Certificate(record.toolServerCertificatePem).checkHost('tool-api')==='tool-api');
 for(const name of ['local-pki','private-backend','monitoring']){
  const login=await vault('/auth/tool-cert/login',{method:'POST',body:{name:'tool-runtime-renderer'},...rendererCertificate()});
  check('reader denied '+name,(await vault('/'+mount+'/data/'+name,{token:login.value.auth.client_token})).status===403);
 }
 const out=execFileSync(process.execPath,[resolve(root,'scripts/vault/render-tool.mjs')],{encoding:'utf8',windowsHide:true,timeout:15000});const r=JSON.parse(out);
 if(!/^snapshot-[1-9][0-9]*-[a-f0-9-]+$/.test(r.snapshot))throw Error();extraSnapshot=resolve(custody,r.snapshot);check('actual enrolled record renders six files',r.rendered===true&&readdirSync(extraSnapshot).length===6);
}catch{process.exitCode=1;console.error(JSON.stringify({error:'Enrolled Vault credential verification failed',lastCompletedCheck:checks.at(-1)??'none'}));}
finally{
 if(extraSnapshot){if(!extraSnapshot.startsWith(custody+'\\'))throw Error('Refused snapshot cleanup');rmSync(extraSnapshot,{recursive:true,force:true});}
 const receipt={completedAt:new Date().toISOString(),checks:checks.length,passed:process.exitCode!==1,persistentCredentialsPreserved:true,persistentToolStarted:false};privateSave('tool-enrolled-validation.json',receipt);console.log(JSON.stringify(receipt));
}
