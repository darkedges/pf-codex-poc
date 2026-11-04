// Actual local Vault verification. Refuses to touch an existing runtime record.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {openSync,closeSync,readFileSync,writeFileSync,existsSync,rmSync,readdirSync,mkdirSync} from 'node:fs';
import {resolve} from 'node:path';
import {randomUUID,createHash} from 'node:crypto';
import {operator,vault,runtimeToken,privateSave} from './common.mjs';
import {setupTool} from './setup-tool.mjs';
import {protect,custody,rendererCertificate} from './tool-custody.mjs';
import {mount,role,validateRecord,fetchRecord,publishRecord} from './tool-secrets.mjs';
import {root} from '../pf/common.mjs';
const checks=[];const check=(name,value)=>{assert.ok(value,name);checks.push(name);};
const hash=value=>createHash('sha256').update(JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a],[b])=>a.localeCompare(b))))).digest('hex');
protect();const lock=resolve(custody,'verification.lock'),fd=openSync(lock,'wx',0o600);
const dir=resolve(custody,'verification-'+randomUUID());mkdirSync(dir,{mode:0o700});
let ownsRecord=false,expectedHash,lease,clean=false,ownVersion=0;
try{
 await setupTool();
 const metadata=await vault('/'+mount+'/metadata/runtime',{token:(await import('./common.mjs')).privateLoad('bootstrap.json').root_token});
 check('refuse existing runtime record',metadata.status===404);
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',resolve(dir,'key'),'-out',resolve(dir,'cert'),'-subj','/CN=synthetic-tool','-addext','basicConstraints=critical,CA:TRUE','-days','1'],{stdio:'ignore',windowsHide:true,timeout:20000});
 const record={toolServerKeyPem:readFileSync(resolve(dir,'key'),'utf8'),toolServerCertificatePem:readFileSync(resolve(dir,'cert'),'utf8'),workloadClientCaPem:readFileSync(resolve(dir,'cert'),'utf8'),outboundCaPem:readFileSync(resolve(dir,'cert'),'utf8'),policySigningKeyPem:readFileSync(resolve(dir,'key'),'utf8'),auditHmacKeyHex:'cd'.repeat(32)};
 validateRecord(record);expectedHash=hash(record);
 await operator('/'+mount+'/data/runtime',{method:'POST',body:{options:{cas:0},data:record}});ownsRecord=true;ownVersion=1;
 const identity=rendererCertificate(),call=(path,options)=>vault(path,{...options,...identity});
 const login=async()=>{const r=await call('/auth/tool-cert/login',{method:'POST',body:{name:role}});assert.equal(r.status,200);return r.value.auth;};
 const fetched=await fetchRecord(call);check('certificate login and exact six-field record read',hash(fetched.record)===expectedHash&&fetched.version===1);
 const auth=await login();check('single-use two-minute policy without default',auth.policies.length===1&&auth.policies[0]==='tool-runtime-read'&&auth.num_uses===1&&auth.lease_duration<=120);
 check('first read allowed',(await vault('/'+mount+'/data/runtime',{token:auth.client_token})).status===200);
 check('used token denied',(await vault('/'+mount+'/data/runtime',{token:auth.client_token})).status===403);
 for(const [name,path,method,body] of [
  ['list denied','/'+mount+'/metadata','LIST'],['other record denied','/'+mount+'/data/other','GET'],
  ['write denied','/'+mount+'/data/runtime','POST',{options:{cas:1},data:record}],
  ['delete denied','/'+mount+'/data/runtime','DELETE'],['transit denied','/transit/sign/consent-authority/sha2-256','POST',{input:'dGVzdA=='}],
  ['token creation denied','/auth/token/create','POST',{}],['administration denied','/sys/mounts','GET']
 ]){const a=await login();check(name,(await vault(path,{method,body,token:a.client_token})).status===403);}
 const revoked=await login();await operator('/auth/token/revoke',{method:'POST',body:{token:revoked.client_token}});
 check('revoked reader denied',(await vault('/'+mount+'/data/runtime',{token:revoked.client_token})).status===403);
 check('missing client certificate denied',(await vault('/auth/tool-cert/login',{method:'POST',body:{name:role}})).status===400);
 check('unregistered client certificate denied',(await vault('/auth/tool-cert/login',{method:'POST',body:{name:role},cert:record.toolServerCertificatePem,key:record.toolServerKeyPem})).status===400);
 lease=await runtimeToken('60s');check('authority signer cannot read tool credentials',(await vault('/'+mount+'/data/runtime',{token:lease.client_token})).status===403);
 const stale=await vault('/'+mount+'/data/runtime',{method:'POST',body:{options:{cas:0},data:record},token:(await import('./common.mjs')).privateLoad('bootstrap.json').root_token});check('stale CAS rejected',stale.status===400);
 await operator('/'+mount+'/data/runtime',{method:'POST',body:{options:{cas:1},data:record}});ownVersion=2;
 check('rotation reads new version',(await fetchRecord(call)).version===2);
 publishRecord(fetched.record,resolve(dir,'snapshot'));check('complete six-file atomic snapshot',readdirSync(resolve(dir,'snapshot')).length===6);
 const output=execFileSync(process.execPath,[resolve(root,'scripts/vault/render-tool.mjs')],{encoding:'utf8',windowsHide:true,timeout:15000});
 const receipt=JSON.parse(output);check('actual standalone renderer succeeds',receipt.rendered===true&&receipt.version===2&&/^snapshot-2-[a-f0-9-]+$/.test(receipt.snapshot));
 const rendered=resolve(custody,receipt.snapshot);check('renderer writes only six runtime files',readdirSync(rendered).length===6);rmSync(rendered,{recursive:true,force:true});
 await assert.rejects(fetchRecord(async()=>{throw Error('unavailable');}));check('outage fails closed',true);
}catch{console.error(JSON.stringify({error:'Actual tool Vault verification failed',lastCompletedCheck:checks.at(-1)??'none'}));process.exitCode=1;}
finally{
 try{
  if(lease)await operator('/auth/token/revoke',{method:'POST',body:{token:lease.client_token}});
  if(ownsRecord){const r=await operator('/'+mount+'/data/runtime');assert.equal(hash(r.data.data),expectedHash);assert.equal(r.data.metadata.version,ownVersion);await operator('/'+mount+'/metadata/runtime',{method:'DELETE'});const r2=await vault('/'+mount+'/data/runtime',{...rendererCertificate(),token:(await (async()=>{const r=await vault('/auth/tool-cert/login',{method:'POST',body:{name:role},...rendererCertificate()});return r.value.auth.client_token;})())});assert.equal(r2.status,404);}
  assert.ok(dir.startsWith(custody+ (process.platform==='win32'?'\\':'/')));rmSync(dir,{recursive:true,force:true});clean=true;
 }catch{console.error('Tool Vault cleanup requires review; verification lock retained');process.exitCode=1;}
 closeSync(fd);if(clean)rmSync(lock);
 const receipt={completedAt:new Date().toISOString(),checks:checks.length,passed:process.exitCode!==1,temporaryRecordRemoved:ownsRecord&&clean,syntheticFilesRemoved:clean,persistentToolStarted:false};
 privateSave('tool-validation.json',receipt);console.log(JSON.stringify(receipt));
}
