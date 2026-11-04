import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {readFileSync,writeFileSync,mkdirSync,openSync,closeSync,existsSync,rmSync,readdirSync,renameSync} from 'node:fs';
import {resolve} from 'node:path';
import {randomUUID,X509Certificate,createPrivateKey,createHash} from 'node:crypto';
import {protect,custody,rendererCertificate,readProtected} from './tool-custody.mjs';
import {root,read} from '../pf/common.mjs';
import {vault,operator} from './common.mjs';
import {fetchRecord,validateRecord,mount} from './tool-secrets.mjs';
import {startPersistentToolPolicy} from './run-tool-policy.mjs';
import {servicePlan,ownedResource,onceAsync,inspectRecordedContainer} from './service-lifecycle.mjs';
import {inspectServiceAudit,pruneStoppedAudit} from './service-audit-retention.mjs';
import {validateServiceCallerTrust} from './relay-activation.mjs';
import {fetchRelayRecord} from './relay-secrets.mjs';
export const serviceDirectory=resolve(custody,'service');
export const serviceLock=resolve(custody,'service-controller.lock'),networkLock=resolve(custody,'network-verification.lock');
export function currentOwnerSid(){return execFileSync('pwsh',['-NoProfile','-Command','[Security.Principal.WindowsIdentity]::GetCurrent().User.Value'],{encoding:'utf8',windowsHide:true,timeout:10000}).trim();}
export const docker=(args,input)=>execFileSync('docker',args,{encoding:'utf8',input,windowsHide:true,timeout:20000,stdio:['pipe','pipe','pipe']}).trim();
export function saveServiceJson(name,value){if(!/^[a-z-]+\.json$/.test(name))throw Error();const path=resolve(serviceDirectory,name),next=path+'.next';writeFileSync(next,JSON.stringify(value,null,2),{mode:0o600,flag:'wx'});renameSync(next,path);}
export function inspectOwnedContainer(name,plan){
 return inspectRecordedContainer(name,plan,docker);
}
export async function startLocalToolService(operations){
 if(!operations||Object.keys(operations).sort().join()!=='ownerSid,retentionDays')throw Error('Explicit service operations required');
 protect();if(operations?.ownerSid!==currentOwnerSid())throw Error('Current Windows owner required');
 const image=JSON.parse(readFileSync(resolve(root,'infra/tool-api/deployment.review.json'),'utf8')).hostingProposal.localImageId;
 const plan=servicePlan({instance:randomUUID(),image,...operations});
 let fd,networkFd,policy,timer,poll,createdNetwork=false,doneResolve;
 const exited=new Promise(done=>doneResolve=done),created=new Set();let last='starting',finished=false;
 const instanceDirectory=resolve(serviceDirectory,'instances',plan.instance),audit=resolve(serviceDirectory,'audit'),bridge=resolve(instanceDirectory,'bridge'),probe=resolve(instanceDirectory,'probe');
 const status=(state,reason)=>{last=state;saveServiceJson('status.json',{state,reason,instance:plan.instance,at:new Date().toISOString(),opensHostPorts:false,automaticRestart:false});};
 const stop=onceAsync(async(reason='requested')=>{
  clearInterval(timer);clearInterval(poll);status('draining',reason);let safe=true;const problems=[];
  for(const name of [plan.tool,plan.backend])if(created.has(name))try{const c=inspectOwnedContainer(name,plan);if(c)try{docker(['stop','--time','7',c.Id]);}catch{if(inspectOwnedContainer(name,plan))throw Error();}const remaining=inspectOwnedContainer(name,plan);if(remaining)docker(['rm','-f',remaining.Id]);}catch{safe=false;problems.push(name===plan.tool?'tool-stop':'backend-stop');}
  if(createdNetwork)try{const n=JSON.parse(docker(['network','inspect',plan.network]))[0];if(!ownedResource({name:n.Name,labels:n.Labels},plan))throw Error();docker(['network','rm',plan.network]);}catch{safe=false;problems.push('network-stop');}
  if(policy)try{await policy.stop();}catch{safe=false;problems.push('lease-retirement');}
  if(safe){try{for(const dir of [bridge,probe]){if(!dir.startsWith(resolve(serviceDirectory,'instances')+'\\'))throw Error();if(existsSync(dir))rmSync(dir,{recursive:true,force:true});}if(plan.retentionDays!==null)pruneStoppedAudit(audit,plan.retentionDays,true);}catch{safe=false;problems.push('credential-or-audit-maintenance');}}
  if(safe){if(networkFd!==undefined){closeSync(networkFd);rmSync(networkLock);}if(fd!==undefined){closeSync(fd);rmSync(serviceLock);}if(existsSync(resolve(serviceDirectory,'stop-request.json')))rmSync(resolve(serviceDirectory,'stop-request.json'));status('stopped',reason);finished=true;doneResolve({stopped:true,reason});}
  else{status('recovery-required',problems.join(','));doneResolve({stopped:false,reason:'cleanup-uncertain'});throw Error('Service cleanup uncertain; locks retained');}
 });
 const restrictions=['--user','1000:1000','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','256m','--cpus','0.5','--pids-limit','64','--init','--log-opt','max-size=5m','--log-opt','max-file=2'];
 let call;
 try{
  mkdirSync(serviceDirectory,{recursive:true,mode:0o700});fd=openSync(serviceLock,'wx',0o600);writeFileSync(fd,JSON.stringify({pid:process.pid,instance:plan.instance}));networkFd=openSync(networkLock,'wx',0o600);writeFileSync(networkFd,JSON.stringify({pid:process.pid,instance:plan.instance}));
  for(const name of [plan.tool,plan.backend])if(docker(['ps','-aq','--filter','name=^/'+name+'$']))throw Error('Existing named service resource');
  if(docker(['network','ls','-q','--filter','name=^'+plan.network+'$']))throw Error('Existing named service network');
  mkdirSync(instanceDirectory,{recursive:true,mode:0o700});for(const d of [bridge,probe,audit])mkdirSync(d,{recursive:true,mode:0o700});if(plan.retentionDays!==null)pruneStoppedAudit(audit,plan.retentionDays,true);else inspectServiceAudit(audit);
  saveServiceJson('instance.json',{...plan,pid:process.pid,startedAt:new Date().toISOString()});status('starting','preflight');
  const receipt=JSON.parse(readFileSync(resolve(custody,'runtime-enrollment.json'),'utf8'));if(!/^snapshot-[1-9][0-9]*-[a-f0-9-]+$/.test(receipt.snapshot))throw Error();
  const {record,version}=await fetchRecord((p,o)=>vault(p,{...o,...rendererCertificate()}));assert.equal(version,receipt.version);const snapshot=resolve(custody,receipt.snapshot);assert.equal(readdirSync(snapshot).length,6);for(const [name,value] of Object.entries(validateRecord(record)))assert.equal(readFileSync(resolve(snapshot,name),'utf8'),value);
  const configPath=resolve(custody,'tool-runtime.json'),configText=readFileSync(configPath,'utf8'),config=JSON.parse(configText);
  const backend=(await operator('/'+mount+'/data/private-backend')).data.data,monitor=(await operator('/'+mount+'/data/monitoring')).data.data,ca=new X509Certificate(record.outboundCaPem);
  for(const material of [backend,monitor]){const cert=new X509Certificate(material.certificatePem);assert.ok(cert.verify(ca.publicKey)&&cert.checkPrivateKey(createPrivateKey(material.keyPem))&&Date.parse(cert.validTo)>Date.now()+300000);}
  assert.equal(new X509Certificate(backend.certificatePem).checkHost('tool-backend'),'tool-backend');
  let activation,relayEvidence;const activationPath=resolve(custody,'relay-tool-activation.json');
  if(existsSync(activationPath)){
   activation=JSON.parse(readFileSync(activationPath,'utf8'));
   const identity={cert:readProtected('relay-renderer-cert.pem'),key:readProtected('relay-renderer-key.pem')},renderer=new X509Certificate(identity.cert);
   assert.ok(renderer.checkPrivateKey(createPrivateKey(identity.key))&&Date.parse(renderer.validTo)>Date.now()+300000);
   const enrolled=await fetchRelayRecord((p,o)=>vault(p,{...o,...identity}));
   relayEvidence={version:enrolled.version,pin:new X509Certificate(enrolled.record.outboundCertificatePem).fingerprint256,configurationSha256:createHash('sha256').update(configText).digest('hex')};
  }
  validateServiceCallerTrust(config.clientCertificateSha256,new X509Certificate(monitor.certificatePem).fingerprint256,activation,relayEvidence);
  const save=(dir,name,value)=>writeFileSync(resolve(dir,name),value,{mode:0o600,flag:'wx'});
  save(bridge,'server-key.pem',backend.keyPem);save(bridge,'server-cert.pem',backend.certificatePem);save(bridge,'pf-ca.pem',read('ca.pem'));save(bridge,'config.json',JSON.stringify({policyPort:9452}));save(probe,'client-key.pem',monitor.keyPem);save(probe,'client-cert.pem',monitor.certificatePem);save(probe,'server-ca.pem',record.outboundCaPem);
  policy=await startPersistentToolPolicy({ownerInstance:plan.instance});saveServiceJson('instance.json',{...plan,pid:process.pid,policyPid:policy.pid,startedAt:new Date().toISOString()});
  assert.equal(docker(['image','inspect',image,'--format','{{.Id}}']),image);
  const label='federated-copilot.local-service='+plan.instance;
  docker(['network','create','--internal','--subnet',plan.subnet,'--label',label,plan.network]);createdNetwork=true;
  created.add(plan.backend);docker(['run','--detach','--rm','--name',plan.backend,'--label',label,'--network','bridge',...restrictions,'--mount',`type=bind,source=${bridge},target=/run/bridge,readonly`,'--mount',`type=bind,source=${resolve(root,'scripts/pf/tool-backend-bridge.mjs')},target=/bridge/main.mjs,readonly`,'--mount',`type=bind,source=${resolve(root,'scripts/pf/tool-backend-route.mjs')},target=/bridge/tool-backend-route.mjs,readonly`,'--entrypoint','node','node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32','/bridge/main.mjs']);docker(['network','connect','--alias','tool-backend',plan.network,plan.backend]);
  created.add(plan.tool);docker(['run','--detach','--rm','--name',plan.tool,'--label',label,'--network',plan.network,'--network-alias','tool-api',...restrictions,'--mount',`type=bind,source=${snapshot},target=/run/secrets,readonly`,'--mount',`type=bind,source=${configPath},target=/run/config/tool-runtime.json,readonly`,'--mount',`type=bind,source=${audit},target=/var/lib/tool-audit`,image]);
  call=input=>JSON.parse(docker(['run','--rm','-i','--label',label,'--network',plan.network,...restrictions,'--mount',`type=bind,source=${probe},target=/run/probe,readonly`,'--mount',`type=bind,source=${resolve(root,'scripts/vault/enrolled-tool-probe.mjs')},target=/probe.mjs,readonly`,'--entrypoint','node',image,'/probe.mjs'],JSON.stringify(input)));
  let ready=false;for(let i=0;i<8;i++){if(call({health:'ready'}).ready){ready=true;break;}await new Promise(done=>setTimeout(done,500));}assert.ok(ready);status('ready','startup-verified');
  const check=async()=>{
   if(finished)return{ready:false};
   for(const name of [plan.tool,plan.backend])if(!inspectOwnedContainer(name,plan)?.State.Running){await stop('container-exited');return{ready:false};}
   const a=inspectServiceAudit(audit);if(plan.retentionDays!==null&&a.oldest+plan.retentionDays*86400000<=Date.now()){await stop('audit-retention-due');return{ready:false};}
   const result=call({health:'ready'});status(result.ready?'ready':'unready',result.ready?'health-verified':'dependency-unavailable');return result;
  };
  let checking=false;timer=setInterval(()=>{if(checking||finished)return;checking=true;void check().catch(()=>stop('health-check-failed')).catch(()=>{}).finally(()=>{checking=false;});},30000);
  poll=setInterval(()=>{if(existsSync(resolve(serviceDirectory,'stop-request.json'))){try{const request=JSON.parse(readFileSync(resolve(serviceDirectory,'stop-request.json'),'utf8'));if(request.instance===plan.instance)void stop('requested').catch(()=>{});}catch{}}},2000);
  void policy.exited.then(()=>stop('policy-exited')).catch(()=>{});
  return{plan,call,check,stop,exited,state:()=>last};
 }catch{
  if(fd!==undefined&&existsSync(instanceDirectory))await stop('startup-failed');
  else{if(networkFd!==undefined){closeSync(networkFd);rmSync(networkLock);}if(fd!==undefined){closeSync(fd);rmSync(serviceLock);}}
  throw Error('Local tool service startup failed; no fallback enabled');
 }
}
