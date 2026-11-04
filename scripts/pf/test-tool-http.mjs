import {spawnSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {mkdirSync,writeFileSync,existsSync,unlinkSync,readdirSync} from 'node:fs';
import {resolve} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {root,local,admin} from './common.mjs';
import {startPolicy} from './run-policy.mjs';
import {authoritySettings} from './authority-config.mjs';
import {withToolClient} from './tool-client-lease.mjs';

const args=process.argv.slice(2);
if(!args.length){console.log(JSON.stringify({purpose:'local PF-to-tool HTTPS integration',modes:['interactive','autonomous'],temporarilyEnablesLocalToolClient:true,preservesHumanLogin:true,bind:'127.0.0.1 ephemeral',microsoftRequests:0,graphRequests:0}));process.exit(0);}
if(args.length!==1||args[0]!=='--run')throw Error('Use preview or --run');
const authority=authoritySettings();if(authority.AUTHORITY_SIGNER!=='vault-transit')throw Error('Selected Vault signer required');
if(existsSync(resolve(root,'.local/copilot/pf-live-verification.lock')))throw Error('Another PF verification is active');
// Shared with the Microsoft runner: never overlap local client mutations.
const lease=resolve(root,'.local/copilot/live-sso.lock');
writeFileSync(lease,JSON.stringify({pid:process.pid,purpose:'local-tool-http',startedAt:new Date().toISOString()}),{flag:'wx',mode:0o600});
const run=resolve(local,'tool-http-tests',randomUUID());mkdirSync(run,{recursive:true});
const receipt={status:'intent',startedAt:new Date().toISOString(),completedAt:null,clientsRestored:false,grantsRevoked:false,temporaryCredentialsRemoved:false,microsoftRequests:0,graphRequests:0,workerExitCode:null,workerSignal:null,failureCategory:null};
const record=()=>writeFileSync(resolve(run,'run.json'),JSON.stringify(receipt,null,2),{mode:0o600});record();
const env={...process.env,...authority,NODE_EXTRA_CA_CERTS:resolve(local,'ca.pem'),POLICY_DATABASE:resolve(run,'policy.sqlite'),POLICY_COPILOT_TOOL_PROFILE:'local-verified',TOOL_HTTP_RUN_DIR:run};
let policy;
try{
 policy=await startPolicy(env);
 await withToolClient(admin,async()=>{
  receipt.status='active';record();
  const result=spawnSync(process.execPath,['--experimental-strip-types','scripts/pf/test-tool-http-worker.ts'],{cwd:root,env:{...env,POLICY_API_ORIGIN:policy.origin},stdio:'inherit',windowsHide:true,timeout:180000});
  receipt.workerExitCode=result.status;receipt.workerSignal=result.signal;
  if(result.status!==0)throw Error('Local HTTP verification failed');
 });
 receipt.status='completed';
}catch(error){receipt.status='failed';receipt.failureCategory=error?.message==='Human client changed during verification; reconcile without overwriting'?'human-client-drift':error?.message==='Local HTTP verification failed'?'worker-failed':error?.message==='Tool client disable recovery required'?'client-cleanup':'startup-or-profile';process.exitCode=1;}
finally{
 if(policy)await policy.stop();
 try{receipt.clientsRestored=(await admin('a','oauth/clients/copilot-studio-generic-oauth')).enabled===true&&(await admin('b','oauth/clients/copilot-sso-exchange')).enabled===false;}catch{}
 try{
  const db=new DatabaseSync(resolve(run,'policy.sqlite'),{readOnly:true});
  try{const row=db.prepare("SELECT COUNT(*) AS total, SUM(CASE WHEN g.state='revoked' THEN 1 ELSE 0 END) AS revoked FROM consents c JOIN grants g ON g.id=c.grant_id").get();receipt.grantsRevoked=row.total===0||row.total===row.revoked;}finally{db.close();}
 }catch{}
 receipt.temporaryCredentialsRemoved=!readdirSync(run).some(name=>/\.(key|pem)$/.test(name));
 receipt.completedAt=new Date().toISOString();
 if(!receipt.clientsRestored||!receipt.grantsRevoked||!receipt.temporaryCredentialsRemoved){receipt.status='recovery-required';process.exitCode=1;}
 record();if(receipt.clientsRestored&&receipt.grantsRevoked&&receipt.temporaryCredentialsRemoved)unlinkSync(lease);
 console.log(JSON.stringify(receipt));
}
