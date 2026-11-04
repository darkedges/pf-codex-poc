import {readFileSync,writeFileSync,mkdirSync,existsSync,readdirSync,openSync,closeSync,rmSync,renameSync} from 'node:fs';import {resolve,sep} from 'node:path';import {execFileSync} from 'node:child_process';import {randomUUID,createHash,X509Certificate,createPrivateKey} from 'node:crypto';import {isDeepStrictEqual} from 'node:util';
import {root} from '../pf/common.mjs';import {protect,custody,readProtected} from './tool-custody.mjs';import {vault,operator} from './common.mjs';import {fetchRelayRecord} from './relay-secrets.mjs';import {validateServiceCallerTrust} from './relay-activation.mjs';
const args=process.argv.slice(2),hash=s=>createHash('sha256').update(s).digest('hex'),configFile=resolve(custody,'tool-runtime.json'),activationFile=resolve(custody,'relay-tool-activation.json');
const command=(program,args)=>execFileSync(program,args,{cwd:root,encoding:'utf8',windowsHide:true,timeout:40000,stdio:['pipe','pipe','pipe']}).trim();
const save=(path,text)=>{const next=path+'.next';writeFileSync(next,text,{mode:0o600,flag:'wx'});renameSync(next,path);};
if(!args.length){console.log(JSON.stringify({actions:['prepare','apply'],purpose:'activate only the enrolled local relay tool caller',controlledServiceRestart:true,hostPorts:[],changesVaultCredentials:false}));process.exit(0);}
let fd,run,phase='preflight',plan,changed=false,newPid,stopped=false,complete=false;
const lock=resolve(custody,'relay-activation.lock');
try{
 protect();fd=openSync(lock,'wx',0o600);
 if(args.length===1&&args[0]==='--prepare'){
  if(existsSync(activationFile)||!existsSync(resolve(custody,'service-controller.lock')))throw Error();
  const source=readFileSync(configFile,'utf8'),old=JSON.parse(source),monitor=(await operator('/federated-copilot-tool-secrets/data/monitoring')).data.data;
  const monitorPin=new X509Certificate(monitor.certificatePem).fingerprint256;validateServiceCallerTrust(old.clientCertificateSha256,monitorPin);
  const identity={cert:readProtected('relay-renderer-cert.pem'),key:readProtected('relay-renderer-key.pem')},cert=new X509Certificate(identity.cert);if(!cert.checkPrivateKey(createPrivateKey(identity.key))||Date.parse(cert.validTo)<=Date.now()+300000)throw Error();
  const relay=await fetchRelayRecord((p,o)=>vault(p,{...o,...identity})),enrollment=JSON.parse(readFileSync(resolve(custody,'relay-enrollment.json'),'utf8'));if(relay.version!==enrollment.version)throw Error();
  const pin=new X509Certificate(relay.record.outboundCertificatePem).fingerprint256;
  const expected={...old,clientCertificateSha256:[monitorPin,pin]};let verification;
  for(const dir of readdirSync(custody).filter(n=>/^relay-network-[a-f0-9-]{36}$/.test(n))){const path=resolve(custody,dir,'verification.json');if(!existsSync(path))continue;const r=JSON.parse(readFileSync(path,'utf8'));if(r.passed===true&&r.checks>=14&&r.ownedResourcesRemoved&&r.temporaryCredentialsRemoved&&r.existingServicePreserved&&r.existingToolTrustChanged===false&&r.microsoftRequests===0&&r.grantsCreated===0&&r.pendingToolConfiguration===resolve(custody,dir,'pending-tool-runtime.json')&&isDeepStrictEqual(JSON.parse(readFileSync(r.pendingToolConfiguration,'utf8')),expected))verification=path;}
  if(!verification)throw Error();
  const id=randomUUID();run=resolve(custody,'relay-activation-'+id);mkdirSync(run,{mode:0o700});const active=JSON.stringify(expected,null,2);
  plan={id,preparedAt:new Date().toISOString(),sourceConfigurationSha256:hash(source),activeConfigurationSha256:hash(active),activation:{version:1,relayVaultVersion:relay.version,relayCertificateSha256:pin,configurationSha256:hash(active)},verification,serviceRestartRequired:true,hostPorts:[]};
  writeFileSync(resolve(run,'previous-tool-runtime.json'),source,{mode:0o600,flag:'wx'});writeFileSync(resolve(run,'active-tool-runtime.json'),active,{mode:0o600,flag:'wx'});writeFileSync(resolve(run,'plan.json'),JSON.stringify(plan,null,2),{mode:0o600,flag:'wx'});
  console.log(JSON.stringify({prepared:true,id,serviceRestartRequired:true,hostPorts:[],selectedConfigurationChanged:false}));complete=true;
 }else if(args.length===2&&args[0]==='--apply'&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(args[1])){
  run=resolve(custody,'relay-activation-'+args[1]);plan=JSON.parse(readFileSync(resolve(run,'plan.json'),'utf8'));const previous=readFileSync(resolve(run,'previous-tool-runtime.json'),'utf8'),active=readFileSync(resolve(run,'active-tool-runtime.json'),'utf8');
  if(plan.id!==args[1]||Date.now()-Date.parse(plan.preparedAt)>3600000||hash(previous)!==plan.sourceConfigurationSha256||hash(active)!==plan.activeConfigurationSha256||hash(readFileSync(configFile,'utf8'))!==plan.sourceConfigurationSha256||existsSync(activationFile))throw Error();
  phase='stopping';command(process.execPath,['--experimental-strip-types','scripts/vault/service.mjs','--stop']);if(existsSync(resolve(custody,'service-controller.lock')))throw Error();stopped=true;
  if(hash(readFileSync(configFile,'utf8'))!==plan.sourceConfigurationSha256)throw Error();
  phase='installing';writeFileSync(activationFile,JSON.stringify(plan.activation,null,2),{mode:0o600,flag:'wx'});changed=true;save(configFile,active);
  phase='starting';newPid=JSON.parse(command('pwsh',['-NoProfile','-File','scripts/vault/start-tool-hidden.ps1'])).pid;
  const until=Date.now()+120000;let ready=false;
  while(Date.now()<until){await new Promise(done=>setTimeout(done,500));const instance=JSON.parse(readFileSync(resolve(custody,'service/instance.json'),'utf8')),status=JSON.parse(readFileSync(resolve(custody,'service/status.json'),'utf8'));if(instance.pid===newPid&&status.instance===instance.instance&&status.state==='ready'&&Date.now()-Date.parse(status.at)<10000){ready=true;break;}}
  if(!ready||hash(readFileSync(configFile,'utf8'))!==plan.activeConfigurationSha256)throw Error();
  phase='ready';complete=true;writeFileSync(resolve(run,'result.json'),JSON.stringify({completedAt:new Date().toISOString(),activated:true,controllerPid:newPid,monitorPreserved:true,relayVaultVersion:plan.activation.relayVaultVersion,hostPorts:[],microsoftRequests:0},null,2),{mode:0o600,flag:'wx'});console.log(JSON.stringify({activated:true,id:plan.id,controllerReady:true,monitorPreserved:true,hostPorts:[],microsoftRequests:0}));
 }else throw Error();
}catch{
 let rolledBack=false;
 if(run&&plan&&stopped)try{
  if(newPid&&existsSync(resolve(custody,'service-controller.lock'))){const instance=JSON.parse(readFileSync(resolve(custody,'service/instance.json'),'utf8'));if(instance.pid!==newPid)throw Error();command(process.execPath,['--experimental-strip-types','scripts/vault/service.mjs','--stop']);}
  if(existsSync(resolve(custody,'service-controller.lock')))throw Error();
  const currentHash=hash(readFileSync(configFile,'utf8'));
  if(changed){if(currentHash!==plan.activeConfigurationSha256&&currentHash!==plan.sourceConfigurationSha256||!isDeepStrictEqual(JSON.parse(readFileSync(activationFile,'utf8')),plan.activation))throw Error();save(configFile,readFileSync(resolve(run,'previous-tool-runtime.json'),'utf8'));rmSync(activationFile);}
  command('pwsh',['-NoProfile','-File','scripts/vault/start-tool-hidden.ps1']);rolledBack=true;
 }catch{}
 if(run)writeFileSync(resolve(run,'failure.json'),JSON.stringify({at:new Date().toISOString(),phase,newControllerPid:newPid??null,rolledBack,activationComplete:false},null,2),{mode:0o600});console.error(JSON.stringify({activationComplete:false,phase,rolledBack,recoveryRequired:stopped&&!rolledBack}));process.exitCode=1;
}finally{if(fd!==undefined){closeSync(fd);if(complete||!stopped)rmSync(lock);}}
