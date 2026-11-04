import {spawn} from 'node:child_process';
import {readFileSync,writeFileSync,openSync,closeSync,existsSync,rmSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomBytes,createPublicKey,verify} from 'node:crypto';
import {vault,runtimeToken,privateLoad} from './common.mjs';
import {retireRuntimeLease} from './retire-lease.mjs';
import {protect,custody} from './tool-custody.mjs';
import {root,local,load} from '../pf/common.mjs';
import {authoritySettings} from '../pf/authority-config.mjs';
import {validatePersistentWorkloads} from '../pf/persistent-tool-policy.ts';
import {onceAsync} from './service-lifecycle.mjs';
import {toolPolicyLease} from './policy-lease-options.mjs';

const lock=resolve(custody,'policy-service.lock'),tokenFile=resolve(custody,'policy-authority-token'),leaseFile=resolve(custody,'policy-authority-lease.json');
const save=(file,value)=>writeFileSync(file,value,{mode:0o600,flag:'wx'});
export async function startPersistentToolPolicy({ownerInstance,leaseSeconds}={}){
 const selectedLease=toolPolicyLease(leaseSeconds);
 if(ownerInstance!==undefined&&!/^[a-f0-9-]{36}$/.test(ownerInstance))throw Error('Invalid policy owner instance');
 protect();const fd=openSync(lock,'wx',0o600);writeFileSync(fd,JSON.stringify({pid:process.pid,ownerInstance}));let lease,child,timer;
 const cleanup=onceAsync(async()=>{
  clearTimeout(timer);
  if(child&&child.exitCode===null){await new Promise((done,reject)=>{const t=setTimeout(()=>reject(Error('Policy process did not stop; custody lock retained')),5000);child.once('exit',()=>{clearTimeout(t);done();});if(child.connected)child.disconnect();else child.kill();});}
  // Retire before removing the token or releasing the single-instance lock.
  if(existsSync(leaseFile)){
   const previous=JSON.parse(readFileSync(leaseFile,'utf8'));
   await retireRuntimeLease(vault,privateLoad('bootstrap.json').root_token,previous.accessor);
   rmSync(leaseFile);if(existsSync(tokenFile))rmSync(tokenFile);
  }else if(lease){await retireRuntimeLease(vault,privateLoad('bootstrap.json').root_token,lease.accessor);}
  closeSync(fd);rmSync(lock);
 });
 try{
  const settings=authoritySettings({AUTHORITY_SIGNER:'vault-transit'});
  if(existsSync(leaseFile)){const previous=JSON.parse(readFileSync(leaseFile,'utf8'));await retireRuntimeLease(vault,privateLoad('bootstrap.json').root_token,previous.accessor);rmSync(leaseFile);if(existsSync(tokenFile))rmSync(tokenFile);}
  else if(existsSync(tokenFile))throw Error('Untracked authority credential; custody review required');
  const trustFile=resolve(custody,'policy-workloads.json');
  if(!existsSync(trustFile))save(trustFile,JSON.stringify(validatePersistentWorkloads(Object.fromEntries(['gateway','admin','consent','agent','tool'].map(role=>[role,load('policy-'+role+'.jwks.json')])))));
  else validatePersistentWorkloads(JSON.parse(readFileSync(trustFile,'utf8')));
  lease=await runtimeToken(selectedLease);
  // Prove the actual lease signs with the selected pinned key before opening a listener.
  const config=JSON.parse(readFileSync(settings.AUTHORITY_TRANSIT_CONFIG_FILE,'utf8')),challenge=randomBytes(32);
  save(leaseFile,JSON.stringify({accessor:lease.accessor,expiresAt:Date.now()+lease.lease_duration*1000,ownerInstance}));save(tokenFile,lease.client_token);
  const signed=await vault('/transit/sign/consent-authority/sha2-256',{method:'POST',token:lease.client_token,body:{input:challenge.toString('base64'),key_version:config.version,signature_algorithm:'pkcs1v15'}});
  const signature=signed.value?.data?.signature;
  if(signed.status!==200||typeof signature!=='string'||!signature.startsWith('vault:v'+config.version+':')||!verify('sha256',challenge,createPublicKey({key:config.publicJwk,format:'jwk'}),Buffer.from(signature.split(':')[2],'base64')))throw Error('Selected authority signing lease unavailable');
  const env={...process.env,...settings,AUTHORITY_VAULT_TOKEN_FILE:tokenFile,NODE_EXTRA_CA_CERTS:resolve(local,'ca.pem'),POLICY_PERSISTENT_TOOL_PROFILE:'local-vault',POLICY_COPILOT_TOOL_PROFILE:'local-verified',POLICY_DATABASE:resolve(custody,'policy.sqlite'),POLICY_PORT:'9452',POLICY_TOOL_DECISION_ORIGIN:'https://tool-backend:7443'};
  child=spawn(process.execPath,['--experimental-strip-types',resolve(root,'scripts/pf/policy-service.ts')],{cwd:root,env,stdio:['ignore','ignore','ignore','ipc'],windowsHide:true});
  await new Promise((done,reject)=>{const t=setTimeout(()=>reject(Error('Persistent policy startup timed out')),15000);child.once('error',()=>{clearTimeout(t);reject(Error('Persistent policy process unavailable'));});child.once('exit',()=>{clearTimeout(t);reject(Error('Persistent policy exited before readiness'));});child.once('message',m=>{clearTimeout(t);if(m?.ready===true&&m.origin==='https://localhost:9452')done();else reject(Error('Invalid persistent policy readiness'));});});
  // A bounded lease requires an explicit restart, never privileged auto-renewal.
  timer=setTimeout(()=>{void cleanup().catch(()=>{console.error('Policy lease shutdown requires custody review');process.exitCode=1;});},Math.max(1,lease.lease_duration*1000-30000));
  return{origin:'https://localhost:9452',pid:child.pid,stop:cleanup,exited:new Promise(done=>child.once('exit',done))};
 }catch(error){await cleanup();throw error;}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 let service;
 try{
  if(process.argv.length!==2)throw Error();service=await startPersistentToolPolicy();
  console.log(JSON.stringify({ready:true,origin:service.origin,profile:'persistent-local-vault',fixtureGrantsCreated:false,automaticRenewal:false}));
  const stop=()=>{void service.stop().catch(()=>{console.error('Policy shutdown failed; custody lock retained');process.exitCode=1;});};
  process.once('SIGINT',stop);process.once('SIGTERM',stop);await service.exited;await service.stop();
 }catch{console.error('Persistent tool policy unavailable; no fallback enabled');process.exitCode=1;}
}
