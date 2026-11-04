import {readFileSync,writeFileSync,existsSync,mkdirSync,openSync,closeSync,rmSync} from 'node:fs';import {resolve} from 'node:path';import {createHash,randomUUID,X509Certificate} from 'node:crypto';
import {custody,protect} from './tool-custody.mjs';import {portalOwnerSid as currentOwnerSid,portalProcessPresent as processPresent} from './portal-process-owner.mjs';
import {openPortalRuntime} from './portal-runtime.ts';import {startPortalWorker} from './portal-worker-host.ts';import {recoverPortalPolicyDatabase} from '../../src/consent/portal-policy-recovery.ts';import {capability} from '../pf/policy-setup.ts';
import {readPortalActivation,activationDirectory} from './portal-activation.mjs';import {portalActivationWindow} from '../../src/consent/portal-activation.ts';import {createPortalPfLease,clientFingerprint} from '../pf/portal-activation-policy.mjs';import {portalAdmin} from '../pf/portal-admin.mjs';
import {portalRunFiles} from '../../src/consent/portal-run.ts';
import {openPortalJournal} from '../../src/consent/portal-journal-profile.ts';
const directory=resolve(custody,'portal-service'),lockPath=resolve(custody,'portal-controller.lock'),instancePath=resolve(directory,'instance.json'),statusPath=resolve(directory,'status.json'),requestPath=resolve(directory,'stop-request.json');
const json=path=>JSON.parse(readFileSync(path,'utf8')),save=(path,value)=>writeFileSync(path,JSON.stringify(value,null,2),{mode:0o600});
const args=process.argv.slice(2);
const pfLeasePath=resolve(directory,'pf-client-lease.json'),leaseStore={get:()=>existsSync(pfLeasePath)?json(pfLeasePath):undefined,create:value=>writeFileSync(pfLeasePath,JSON.stringify(value),{mode:0o600,flag:'wx'}),remove:()=>rmSync(pfLeasePath)};
const makeLease=(owner,expiresAt,baselineHash,humanHash)=>createPortalPfLease({admin:portalAdmin,store:leaseStore,owner,expiresAt,baselineHash,humanHash});
async function serve(mode='staged'){
 const activation=mode==='live'?readPortalActivation({requireCandidate:true}):undefined;
 if(activation){const proof=json(resolve(activationDirectory,'public-stage-verified.json')),tenant=json(resolve(activationDirectory,'tenant-readback.json')),age=Date.now()-Date.parse(proof.verifiedAt),tenantAge=Date.now()-Date.parse(tenant.verifiedAt);if(leaseStore.get()||proof.stageVerified!==true||proof.hostname!==activation.manifest.hostname||!Number.isFinite(age)||age<0||age>900000||Date.parse(proof.verifiedAt)<activation.approval.approvedAt||tenant.connectionConnected!==true||tenant.publicationReceiptMatched!==true||!Number.isFinite(tenantAge)||tenantAge<0||tenantAge>900000||Date.parse(tenant.verifiedAt)<activation.approval.approvedAt)throw Error();for(const change of activation.manifest.callbacks)if(clientFingerprint(await portalAdmin('a','oauth/clients/'+change.clientId))!==change.afterHash)throw Error();}
 protect();mkdirSync(directory,{recursive:true,mode:0o700});const instance=randomUUID(),ownerSid=currentOwnerSid();let lock,runtime,worker,timer,stopping,completed,closed=false,pfLease,latestTrial=null;
 const done=new Promise(resolve=>{completed=resolve;});
 const snapshot=()=>{try{if(runtime)latestTrial=runtime.trialSnapshot();}catch{}return latestTrial;};
 const status=(state,reason)=>{if(runtime)save(resolve(directory,'diagnostic.json'),runtime.diagnostics());save(statusPath,{state,instance,at:new Date().toISOString(),mode,signInEnabled:state==='ready'&&!!runtime?.trialEnabled(),...(mode==='staged'?{microsoftRequests:0}:{trial:snapshot()}),publicRoutesChanged:mode==='live',...(reason?{reason}:{})});};
 const stop=reason=>stopping??=(async()=>{
  clearInterval(timer);status('draining',reason);runtime?.abort();
  let clean=true;
  try{if(worker)await worker.stop();}catch{clean=false;}
  snapshot();
  try{if(runtime)await runtime.stop();else if(existsSync(resolve(directory,portalRunFiles(json(instancePath).plan).journal))){
   const i=json(instancePath);if(i.instance!==instance)throw Error();const journal=openPortalJournal(directory,i.plan);
   try{const result=await recoverPortalPolicyDatabase({database:resolve(custody,'policy.sqlite'),journal,capability,workerStopped:true});if(result.pending!==0)throw Error();}finally{journal.close();}
  }}catch{clean=false;}
  try{if(pfLease)await pfLease.release();}catch{clean=false;}
  if(clean){status('stopped',reason);if(lock!==undefined){closeSync(lock);lock=undefined;rmSync(lockPath);}if(existsSync(requestPath)&&json(requestPath).instance===instance)rmSync(requestPath);closed=true;}
  else{status('recovery-required','cleanup-incomplete');process.exitCode=1;}
  completed();
 })();
 try{
  lock=openSync(lockPath,'wx',0o600);writeFileSync(lock,JSON.stringify({instance,pid:process.pid,ownerSid}));save(instancePath,{instance,pid:process.pid,ownerSid,plan:{mode,reviewSha256:activation?.manifest.reviewSha256??createHash('sha256').update('portal-staged-no-microsoft-v1').digest('hex'),...(activation?.manifest.runId?{runId:activation.manifest.runId,runReviewSha256:activation.manifest.runReviewSha256,...(activation.manifest.sessionPolicy?{sessionPolicy:activation.manifest.sessionPolicy}:{})}:{})}});status('starting');
  const relay=json(resolve(custody,'relay-service/instance.json')),tool=json(resolve(custody,'service/instance.json'));
  if(activation&&relay.plan.expiresAt<=Date.now()+600000)throw Error();
  let window;
  if(activation){
   const path=resolve(activationDirectory,portalRunFiles(activation.manifest).window);window=portalActivationWindow(activation.approval,existsSync(path)?json(path):undefined);if(!existsSync(path))writeFileSync(path,JSON.stringify(window),{mode:0o600,flag:'wx'});
  }
  const plan={schemaVersion:1,mode,reviewSha256:activation?.manifest.reviewSha256??createHash('sha256').update('portal-staged-no-microsoft-v1').digest('hex'),...(activation?{activationManifestSha256:activation.approval.manifestSha256,...(activation.manifest.runId?{runId:activation.manifest.runId,runReviewSha256:activation.manifest.runReviewSha256,...(activation.manifest.sessionPolicy?{sessionPolicy:activation.manifest.sessionPolicy}:{})}:{})}:{}),expiresAt:Math.min(relay.plan.expiresAt-30000,window?.expiresAt??Date.now()+8*3600000-30000),toolInstance:tool.instance,relayInstance:relay.plan.instance};
  save(instancePath,{instance,pid:process.pid,ownerSid,plan,automaticRestart:false,automaticRenewal:false,port:9466,host:'127.0.0.1'});
  if(activation){
   const journal=openPortalJournal(directory,plan);
   try{const trial=journal.trialSnapshot();if(trial&&(trial.reviewSha256!==portalRunFiles(plan).reviewSha256||trial.state!=='approved'||trial.expiresAt<=Date.now()))throw Error();if(!trial)journal.authorizeTrial({reviewSha256:portalRunFiles(plan).reviewSha256,approved:true,expiresAt:plan.expiresAt,maxConversations:1,maxTokenPosts:1,maxSuccessfulToolOperations:1});}finally{journal.close();}
   pfLease=makeLease({instance,pid:process.pid},plan.expiresAt,activation.manifest.toolClientHash,activation.manifest.callbacks.find(c=>c.clientId==='copilot-studio-generic-oauth').afterHash);await pfLease.acquire();
  }
  runtime=await openPortalRuntime(directory,plan);if(!await runtime.ready())throw Error();
  worker=await startPortalWorker({tls:runtime.tls,public:runtime.public,expiresAt:plan.expiresAt,port:9466,methods:runtime.methods,afterCall:()=>worker?.budget(runtime.trialEnabled()),onSpawn:workerPid=>save(instancePath,{instance,pid:process.pid,workerPid,ownerSid,plan,automaticRestart:false,automaticRenewal:false,port:9466,host:'127.0.0.1'}),onExit:()=>{void stop('worker-exited');}});
  save(instancePath,{instance,pid:process.pid,workerPid:worker.pid,ownerSid,plan,automaticRestart:false,automaticRenewal:false,port:9466,host:'127.0.0.1',serverCertificateSha256:new X509Certificate(runtime.tls.cert).fingerprint256});
  worker.heartbeat(true,runtime.trialEnabled());status('ready');console.log(JSON.stringify({state:'ready',mode,host:'127.0.0.1',port:9466,signInEnabled:runtime.trialEnabled(),publicRoutesChanged:mode==='live'}));
  let polling=false;
  timer=setInterval(()=>{if(polling||stopping)return;polling=true;void(async()=>{
   try{if(existsSync(requestPath)&&json(requestPath).instance===instance){await stop('operator-stop');return;}if(!await runtime.ready())throw Error();await runtime.sweep();if(stopping)return;if(pfLease&&leaseStore.get()){if(snapshot()?.state==='finished')await pfLease.release();else await pfLease.check();}if(stopping)return;worker.heartbeat(true,runtime.trialEnabled());status('ready');}
   catch{await stop('dependency-unavailable');}finally{polling=false;}
  })();},5000);
  process.once('SIGINT',()=>{void stop('signal');});process.once('SIGTERM',()=>{void stop('signal');});await done;
 }catch{if(lock!==undefined)await stop('startup-failed');throw Error();}
 finally{clearInterval(timer);if(!closed&&lock!==undefined)process.exitCode=1;}
}
try{
 if(args.length===0)console.log(JSON.stringify({action:'preview',mode:'staged',host:'127.0.0.1',port:9466,signInEnabled:false,automaticRestart:false,microsoftRequests:0,publicRoutesChanged:false}));
 else if(args.join()==='--serve')await serve();
 else if(args.join()==='--serve-live')await serve('live');
 else if(args.join()==='--status'){
  const s=json(statusPath),age=Math.max(0,Math.floor((Date.now()-Date.parse(s.at))/1000));console.log(JSON.stringify({state:s.state==='ready'&&age>35?'unknown':s.state,mode:s.mode,observedSecondsAgo:age,signInEnabled:s.signInEnabled,controllerLockPresent:existsSync(lockPath),publicRoutesChanged:s.publicRoutesChanged,...(s.mode==='live'?{trial:s.trial}:{})}));
 }else if(args.join()==='--stop'){
  const i=json(instancePath);if(i.ownerSid!==currentOwnerSid()||!existsSync(lockPath)||!processPresent(i.pid))throw Error();save(requestPath,{instance:i.instance});
  const deadline=Date.now()+20000;while(existsSync(lockPath)&&Date.now()<deadline)await new Promise(done=>setTimeout(done,250));if(existsSync(lockPath))throw Error();console.log(JSON.stringify({stopped:true}));
 }else if(args.join()==='--recover'){
  protect();const i=json(instancePath),record=json(lockPath);if(i.instance!==record.instance||i.pid!==record.pid||i.ownerSid!==currentOwnerSid()||processPresent(i.pid)||i.workerPid&&processPresent(i.workerPid)||!['staged','live'].includes(i.plan.mode))throw Error();
  const lease=leaseStore.get();if(lease)await makeLease({instance:i.instance,pid:i.pid},lease.expiresAt,lease.baselineHash,lease.humanHash).release();
  const journal=openPortalJournal(directory,i.plan);try{const result=await recoverPortalPolicyDatabase({database:resolve(custody,'policy.sqlite'),journal,capability,workerStopped:true});if(result.pending!==0)throw Error();}finally{journal.close();}
  save(statusPath,{state:'stopped',mode:i.plan.mode,instance:i.instance,at:new Date().toISOString(),reason:'owned-recovery',signInEnabled:false,publicRoutesChanged:i.plan.mode==='live'});rmSync(lockPath);console.log(JSON.stringify({recovered:true,stopped:true}));
 }else throw Error();
}catch{console.error('Managed portal action failed; inspect the restricted status. No automatic retry.');process.exitCode=1;}
