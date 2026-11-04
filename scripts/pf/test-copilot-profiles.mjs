import {spawnSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {mkdirSync,writeFileSync,readFileSync,existsSync} from 'node:fs';
import {resolve} from 'node:path';
import {root,local,admin} from './common.mjs';
import {startPolicy} from './run-policy.mjs';
import {authoritySettings} from './authority-config.mjs';
const receipt=JSON.parse(readFileSync(resolve(root,'.local/copilot/pf-public-profile-receipt.json'),'utf8'));
const args=process.argv.slice(2);
if(args.length>1||args.some(a=>!['--policy','--browser'].includes(a)))throw Error('Use no arguments, --policy or --browser');
const policyMode=args[0]==='--policy';
const browserMode=args[0]==='--browser';
if(receipt.status!=='reconciled-disabled')throw Error('Completed disabled public-profile reconciliation required');
const runDirectory=resolve(local,'copilot-profile-tests',randomUUID());mkdirSync(runDirectory,{recursive:true});
const env={...process.env,...authoritySettings(),NODE_EXTRA_CA_CERTS:resolve(local,'ca.pem'),POLICY_DATABASE:resolve(runDirectory,'policy.sqlite'),POLICY_COPILOT_TOOL_PROFILE:policyMode?'local-verified':undefined};
const clients=[['a','copilot-studio-generic-oauth'],['b','copilot-sso-exchange']];
// Exclusive run lock: never enable the staged clients concurrently.
const lock=resolve(root,'.local/copilot/pf-live-verification.json');
if(existsSync(lock)){
 const previous=JSON.parse(readFileSync(lock,'utf8'));
 if(previous.status!=='completed-clients-disabled')throw Error('Verification lock exists; inspect/recover client state first');
 writeFileSync(resolve(runDirectory,'previous-verification.json'),JSON.stringify(previous),{flag:'wx',mode:0o600});
}
for(const [node,id]of clients)if((await admin(node,'oauth/clients/'+id)).enabled!==false)throw Error('Expected disabled staged client');
// Acquire exclusivity separately from the retained last-run receipt.
const lease=resolve(root,'.local/copilot/pf-live-verification.lock');
writeFileSync(lease,JSON.stringify({pid:process.pid}),{flag:'wx',mode:0o600});
writeFileSync(lock,JSON.stringify({status:'verification-active',startedAt:new Date().toISOString()}),{mode:0o600});
let policy;
try{
 policy=await startPolicy(env);
 for(const [node,id]of clients.filter(([node])=>policyMode?node==='b':browserMode?node==='a':true)){const c=await admin(node,'oauth/clients/'+id);await admin(node,'oauth/clients/'+id,'PUT',{...c,enabled:true});}
 const result=spawnSync(process.execPath,['--experimental-strip-types','--test',policyMode?'tests/live-copilot/tool-policy.integration.ts':browserMode?'tests/live-copilot/browser.integration.ts':'tests/live-copilot/profiles.integration.ts'],{cwd:root,env:{...env,POLICY_API_ORIGIN:policy.origin},stdio:'inherit',windowsHide:true,timeout:240000});
 process.exitCode=result.status??1;
}finally{
 const failures=[];
 for(const [node,id]of clients){
  let disabled=false;
  // Bounded retry only for the idempotent local disable/verification operation.
  for(let attempt=0;attempt<3&&!disabled;attempt++)try{const c=await admin(node,'oauth/clients/'+id);await admin(node,'oauth/clients/'+id,'PUT',{...c,enabled:false});disabled=(await admin(node,'oauth/clients/'+id)).enabled===false;}catch{if(attempt<2)await new Promise(done=>setTimeout(done,250));}
  if(!disabled)failures.push(id);
 }
 if(policy)await policy.stop();
 writeFileSync(lock,JSON.stringify({status:failures.length?'recovery-required':'completed-clients-disabled',completedAt:new Date().toISOString(),exitCode:process.exitCode??1,failedToDisable:failures}),{mode:0o600});
 if(failures.length)throw Error('Local client disable recovery required; inspect the protected receipt');
 // Fixed workspace-owned run lease only; preserve receipts and credentials.
 (await import('node:fs')).unlinkSync(lease);
}
