import {spawnSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {mkdirSync,writeFileSync,readFileSync,existsSync,unlinkSync} from 'node:fs';
import {resolve} from 'node:path';
import {root,local,admin} from '../pf/common.mjs';
import {startPolicy} from '../pf/run-policy.mjs';
import {authoritySettings} from '../pf/authority-config.mjs';
import {withToolClient} from '../pf/tool-client-lease.mjs';
import {reserveTimingFollowup,reserveOperatorRetry} from './live-budget.mjs';
const args=process.argv.slice(2);
if(!args.length){console.log(JSON.stringify({purpose:'configured-provider user-token SSO diagnostic; Microsoft acceptance UNVERIFIED',supportedModes:['interactive'],autonomous:'UNVERIFIED_FAIL_CLOSED',providerIssuer:'https://pf-a.copilot.darkedges.com',providerAudience:'api://copilot-login',delegatedToolTokenPosted:false,existingAllowancesReusable:false,temporarilyEnablesLocalToolClient:true,preservesHumanLogin:true,maxConversations:1,newPublicRoutes:false,copilotToolAcceptanceVerified:false}));process.exit(0);}
if(args.length!==1||!['--run','--remaining','--timing-followup','--operator-retry'].includes(args[0]))throw Error('Use preview, --run, --remaining or --timing-followup');
if(['--run','--remaining'].includes(args[0]))throw Error('Legacy two-mode Generic OAuth diagnostic retired; autonomous provider sign-in is unverified');
const retry=args[0]==='--operator-retry';
const followup=retry||args[0]==='--timing-followup';
const authority=authoritySettings();if(authority.AUTHORITY_SIGNER!=='vault-transit')throw Error('Live diagnostic requires the selected Vault signer');
if(existsSync(resolve(root,'.local/copilot/pf-live-verification.lock')))throw Error('Another PF verification is active');
const budgetFile=resolve(root,'.local/copilot/live-sso-budget.json');
if(followup){
 const original=JSON.parse(readFileSync(budgetFile,'utf8')),file=resolve(root,retry?'.local/copilot/live-sso-operator-retry-1-budget.json':'.local/copilot/live-sso-timing-budget.json');
 const next=existsSync(file)?JSON.parse(readFileSync(file,'utf8')):{max:1,reserved:[]};if(retry)reserveOperatorRetry(original,JSON.parse(readFileSync(resolve(root,'.local/copilot/live-sso-timing-budget.json'),'utf8')),next);else reserveTimingFollowup(original,next);
 if(!existsSync(file))writeFileSync(file,JSON.stringify(next),{flag:'wx',mode:0o600});
}else if(existsSync(budgetFile)){const b=JSON.parse(readFileSync(budgetFile,'utf8'));if(b.max!==2||!Array.isArray(b.reserved)||b.reserved.some(m=>!['interactive','autonomous'].includes(m))||new Set(b.reserved).size!==b.reserved.length||b.reserved.length>=2||args[0]==='--run'&&b.reserved.length||args[0]==='--remaining'&&b.reserved.length!==1)throw Error('Approved conversation budget already used or invalid; reconcile without retry');}
else{if(args[0]==='--remaining')throw Error('No partial approved run');writeFileSync(budgetFile,JSON.stringify({max:2,reserved:[]}),{flag:'wx',mode:0o600});}
const lease=resolve(root,'.local/copilot/live-sso.lock');
writeFileSync(lease,JSON.stringify({pid:process.pid,startedAt:new Date().toISOString()}),{flag:'wx',mode:0o600});
const run=resolve(local,'copilot-live-sso',randomUUID());mkdirSync(run,{recursive:true});
const receipt={status:'intent',startedAt:new Date().toISOString(),approval:retry?'user-requested-single-interactive-retry':followup?'one-interactive-timing-followup':'original-two-modes',publicRoutesChanged:false,toolAcceptanceVerified:false};
const record=()=>writeFileSync(resolve(run,'run.json'),JSON.stringify(receipt,null,2),{mode:0o600});record();
const env={...process.env,...authority,NODE_EXTRA_CA_CERTS:resolve(local,'ca.pem'),POLICY_DATABASE:resolve(run,'policy.sqlite'),POLICY_COPILOT_TOOL_PROFILE:'local-verified',COPILOT_LIVE_SSO_RUN_DIR:run,COPILOT_LIVE_SSO_FOLLOWUP:retry?'operator-retry-1':followup?'interactive-timing':''};
let policy,safe=false;
try{
 policy=await startPolicy(env);
 await withToolClient(admin,async()=>{
  receipt.status='active';record();
  const result=spawnSync(process.execPath,['--experimental-strip-types','scripts/copilot/live-sso-worker.ts'],{cwd:root,env:{...env,POLICY_API_ORIGIN:policy.origin},stdio:'inherit',windowsHide:true,timeout:180000});
  if(result.status!==0)throw Error('Live worker did not complete');
 });
 receipt.status='completed-clients-restored';
}catch{
 receipt.status='failed';process.exitCode=1;
}finally{
 if(policy)await policy.stop();
 try{safe=(await admin('b','oauth/clients/copilot-sso-exchange')).enabled===false&&(await admin('a','oauth/clients/copilot-studio-generic-oauth')).enabled===true;}catch{}
 receipt.completedAt=new Date().toISOString();receipt.clientsRestored=safe;
 if(!safe){receipt.status='recovery-required';process.exitCode=1;}record();
 if(safe)unlinkSync(lease);
 console.log(JSON.stringify({status:receipt.status,clientsRestored:safe,toolAcceptanceVerified:false}));
}
