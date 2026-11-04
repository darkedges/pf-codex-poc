import {spawnSync} from 'node:child_process';
import {readFileSync,writeFileSync,mkdirSync,existsSync,rmSync} from 'node:fs';
import {resolve} from 'node:path';
import {randomUUID,createHash} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {root,local,admin} from '../pf/common.mjs';
import {startPolicy} from '../pf/run-policy.mjs';
import {startConsent} from '../pf/run-consent.mjs';
import {withToolClient} from '../pf/tool-client-lease.mjs';
import {authoritySettings} from '../pf/authority-config.mjs';
import {revokeOwnedToolConsent} from '../pf/revoke-owned-tool-consent.mjs';
import {revokeOwnedCanaryGrant} from '../vault/enrolled-canary-checks.mjs';
import {protect,custody} from '../vault/tool-custody.mjs';
import {runtimeToken,vault,privateLoad} from '../vault/common.mjs';
import {retireRuntimeLease} from '../vault/retire-lease.mjs';
import {reserveProviderCapture,reserveRetainedProviderCapture,reservePublishedProviderCapture,reserveLongerProviderCapture,reserveHourProviderCapture} from './live-budget.mjs';
import {prepareCaptureWriter,retireCaptureWriter,readPrivateCapture} from './vault-capture-access.mjs';
const args=process.argv.slice(2);if(!args.length){console.log(JSON.stringify({purpose:'one user-approved corrected PF A token POST with redacted curl evidence; --run-retained also stores originals in operator-only Vault',maxConversations:1,maxTokenPosts:1,postRetries:0,keepsHistoricalBudgets:true,changesMicrosoftSettings:false}));process.exit(0);}if(args.length!==1||!['--run','--run-retained','--run-published-1','--run-longer-1','--run-hour-1'].includes(args[0]))throw Error('Use preview, --run or --run-retained');
const hourMode=args[0]==='--run-hour-1',longerMode=args[0]==='--run-longer-1',publishedMode=args[0]==='--run-published-1',retainedMode=hourMode||longerMode||publishedMode||args[0]==='--run-retained';
if(process.env.NODE_EXTRA_CA_CERTS!==resolve(local,'ca.pem')){const child=spawnSync(process.execPath,['--experimental-strip-types',...process.argv.slice(1)],{cwd:root,env:{...process.env,NODE_EXTRA_CA_CERTS:resolve(local,'ca.pem')},stdio:'inherit',windowsHide:true,timeout:300000});process.exit(child.status??1);}
const directory=resolve(root,'.local/copilot'),budgetFile=resolve(directory,hourMode?'live-sso-hour-vault-capture-1-budget.json':longerMode?'live-sso-longer-vault-capture-1-budget.json':publishedMode?'live-sso-published-vault-capture-1-budget.json':retainedMode?'live-sso-provider-vault-capture-1-budget.json':'live-sso-provider-capture-1-budget.json'),historyNames=['live-sso-budget.json','live-sso-timing-budget.json','live-sso-operator-retry-1-budget.json'];
const previousFile=resolve(directory,'live-sso-provider-capture-1-budget.json');
const history=()=>historyNames.map(n=>JSON.parse(readFileSync(resolve(directory,n),'utf8'))),digests=()=>[...historyNames,...(retainedMode?['live-sso-provider-capture-1-budget.json']:[]),...((publishedMode||longerMode||hourMode)?['live-sso-provider-vault-capture-1-budget.json']:[]),...((longerMode||hourMode)?['live-sso-published-vault-capture-1-budget.json']:[]),...(hourMode?['live-sso-longer-vault-capture-1-budget.json']:[])].map(n=>createHash('sha256').update(readFileSync(resolve(directory,n))).digest('hex'));
const next=existsSync(budgetFile)?JSON.parse(readFileSync(budgetFile,'utf8')):{max:1,reserved:[],purpose:hourMode?'hour-provider-vault-capture':longerMode?'longer-provider-vault-capture':publishedMode?'published-provider-vault-capture':retainedMode?'configured-provider-vault-capture':'configured-provider-capture'};
if(hourMode)reserveHourProviderCapture(history(),JSON.parse(readFileSync(previousFile,'utf8')),JSON.parse(readFileSync(resolve(directory,'live-sso-provider-vault-capture-1-budget.json'),'utf8')),JSON.parse(readFileSync(resolve(directory,'live-sso-published-vault-capture-1-budget.json'),'utf8')),JSON.parse(readFileSync(resolve(directory,'live-sso-longer-vault-capture-1-budget.json'),'utf8')),next);else if(longerMode)reserveLongerProviderCapture(history(),JSON.parse(readFileSync(previousFile,'utf8')),JSON.parse(readFileSync(resolve(directory,'live-sso-provider-vault-capture-1-budget.json'),'utf8')),JSON.parse(readFileSync(resolve(directory,'live-sso-published-vault-capture-1-budget.json'),'utf8')),next);else if(publishedMode)reservePublishedProviderCapture(history(),JSON.parse(readFileSync(previousFile,'utf8')),JSON.parse(readFileSync(resolve(directory,'live-sso-provider-vault-capture-1-budget.json'),'utf8')),next);else if(retainedMode)reserveRetainedProviderCapture(history(),JSON.parse(readFileSync(previousFile,'utf8')),next);else reserveProviderCapture(history(),next);
if(existsSync(resolve(directory,'pf-live-verification.lock')))throw Error('PF verification already active');
const mutex=resolve(directory,'live-sso.lock');writeFileSync(mutex,JSON.stringify({pid:process.pid,purpose:'user-approved-provider-capture',startedAt:new Date().toISOString()}),{mode:0o600,flag:'wx'});
const id=randomUUID(),run=resolve(local,'copilot-live-sso',id),capture=resolve(custody,'provider-capture-'+id),initialDigests=digests();
let policy,signing,writer,safe=false;const record={status:'intent',startedAt:new Date().toISOString(),approval:hourMode?'user-approved-one-retained-test-with-sixty-minute-provider-token':longerMode?'user-approved-one-retained-test-with-five-minute-provider-token':publishedMode?'user-approved-one-retained-test-after-2026-10-31-0827-publication':retainedMode?'user-approved-one-test-retaining-original-values-in-vault':'user-requested-one-corrected-provider-test-and-real-data-capture',maxConversations:1,maxTokenPosts:1,captureDirectory:capture,clientsRestored:false,grantsRevoked:false,signingLeaseRetired:false,historicalBudgetsUnchanged:false,privateCaptureRetained:false,writerRetired:!retainedMode};
const save=()=>writeFileSync(resolve(run,'run.json'),JSON.stringify(record,null,2),{mode:0o600});
try{
 protect();mkdirSync(capture,{mode:0o700});mkdirSync(run,{recursive:true});save();if(!existsSync(budgetFile))writeFileSync(budgetFile,JSON.stringify(next),{mode:0o600,flag:'wx'});
 signing=await runtimeToken('5m');const tokenFile=resolve(capture,'authority-token');writeFileSync(tokenFile,signing.client_token,{mode:0o600,flag:'wx'});
 if(retainedMode){writer=await prepareCaptureWriter(id);writeFileSync(resolve(capture,'vault-writer-token'),writer.token,{mode:0o600,flag:'wx'});}
 const authority=authoritySettings({AUTHORITY_SIGNER:'vault-transit',AUTHORITY_VAULT_TOKEN_FILE:tokenFile});
 const env={...process.env,...authority,NODE_EXTRA_CA_CERTS:resolve(local,'ca.pem'),POLICY_DATABASE:resolve(run,'policy.sqlite'),POLICY_COPILOT_TOOL_PROFILE:'local-verified',COPILOT_LIVE_SSO_RUN_DIR:run,COPILOT_LIVE_SSO_FOLLOWUP:hourMode?'hour-vault-capture-1':longerMode?'longer-vault-capture-1':publishedMode?'published-vault-capture-1':retainedMode?'provider-vault-capture-1':'provider-capture-1',COPILOT_PROVIDER_CAPTURE_DIR:capture,...(retainedMode?{COPILOT_CAPTURE_WRITER_FILE:resolve(capture,'vault-writer-token')}:{})};
 policy=await startPolicy(env);
 await withToolClient(admin,async()=>{record.status='active';save();const result=spawnSync(process.execPath,['--experimental-strip-types',resolve(root,'scripts/copilot/live-sso-worker.ts')],{cwd:root,env:{...env,POLICY_API_ORIGIN:policy.origin},windowsHide:true,stdio:'inherit',timeout:180000});if(result.status!==0)throw Error('Provider capture worker stopped');});
 record.status='completed';
}catch{record.status='failed';process.exitCode=1;}
finally{
 try{
  if(policy){
   const db=new DatabaseSync(resolve(run,'policy.sqlite'),{readOnly:true});let active;try{active=db.prepare("SELECT g.id FROM grants g JOIN consents c ON c.grant_id=g.id WHERE g.state!='revoked'").all();}finally{db.close();}
   if(active.length){const portal=await startConsent({...process.env,NODE_EXTRA_CA_CERTS:resolve(local,'ca.pem'),POLICY_API_ORIGIN:policy.origin,CONSENT_PORT:'9461'});try{for(const g of active)await revokeOwnedCanaryGrant(()=>{const d=new DatabaseSync(resolve(run,'policy.sqlite'),{readOnly:true});try{return d.prepare('SELECT state FROM grants WHERE id=?').get(g.id)?.state;}finally{d.close();}},()=>revokeOwnedToolConsent(portal.origin,g.id));}finally{await portal.stop();}}
   const d=new DatabaseSync(resolve(run,'policy.sqlite'),{readOnly:true});try{record.grantsRevoked=Number(d.prepare("SELECT count(*) n FROM grants g JOIN consents c ON c.grant_id=g.id WHERE g.state!='revoked'").get().n)===0;}finally{d.close();}
  }else record.grantsRevoked=true;
 }catch{}
 if(policy)try{await policy.stop();}catch{}
 if(signing)try{await retireRuntimeLease(vault,privateLoad('bootstrap.json').root_token,signing.accessor);record.signingLeaseRetired=true;rmSync(resolve(capture,'authority-token'));}catch{}else record.signingLeaseRetired=true;
 if(writer){try{const stored=await readPrivateCapture(id);record.privateCaptureRetained=stored.metadata.version===2&&stored.data.state==='request-and-response-retained'&&typeof JSON.parse(stored.data.request.body).token==='string'&&typeof stored.data.rawResponse==='string';}catch{}try{await retireCaptureWriter(writer);rmSync(resolve(capture,'vault-writer-token'));record.writerRetired=true;}catch{}}
 try{record.clientsRestored=(await admin('a','oauth/clients/copilot-studio-generic-oauth')).enabled===true&&(await admin('b','oauth/clients/copilot-sso-exchange')).enabled===false;record.historicalBudgetsUnchanged=JSON.stringify(digests())===JSON.stringify(initialDigests);}catch{}
 record.completedAt=new Date().toISOString();safe=record.clientsRestored&&record.grantsRevoked&&record.signingLeaseRetired&&record.historicalBudgetsUnchanged&&record.writerRetired;if(!safe){record.status='recovery-required';process.exitCode=1;}
 if(existsSync(run))save();if(existsSync(capture))writeFileSync(resolve(capture,'run-cleanup.json'),JSON.stringify(record,null,2),{mode:0o600});if(safe)rmSync(mutex);
 console.log(JSON.stringify({status:record.status,captureDirectory:capture,clientsRestored:record.clientsRestored,grantsRevoked:record.grantsRevoked,signingLeaseRetired:record.signingLeaseRetired,historicalBudgetsUnchanged:record.historicalBudgetsUnchanged,privateCaptureRetained:record.privateCaptureRetained,writerRetired:record.writerRetired}));
}
