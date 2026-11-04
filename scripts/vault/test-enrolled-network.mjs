import assert from 'node:assert/strict';
import {execFileSync,spawnSync} from 'node:child_process';
import {readFileSync,writeFileSync,mkdirSync,openSync,closeSync,existsSync,rmSync,readdirSync} from 'node:fs';
import {resolve} from 'node:path';
import {randomUUID,X509Certificate,createPrivateKey} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {root,local,read,admin} from '../pf/common.mjs';
import {protect,custody,rendererCertificate} from './tool-custody.mjs';
import {operator,vault,privateSave} from './common.mjs';
import {fetchRecord,validateRecord,mount} from './tool-secrets.mjs';
import {startPersistentToolPolicy} from './run-tool-policy.mjs';
import {enrolledNetworkPlan} from './enrolled-network-plan.mjs';
import {enrolledCanary,canaryGrantState} from './enrolled-canary.ts';
import {canaryTerminalState} from './enrolled-canary-checks.mjs';
const args=process.argv.slice(2);
if(!args.length){console.log(JSON.stringify({purpose:'verify enrolled Vault credentials through private Docker backend',opensHostPorts:false,changesPfClients:false,createsGrants:false,microsoftRequests:0,graphRequests:0,leavesServicesRunning:false}));process.exit(0);}
if(args.length!==1||!['--run','--canary'].includes(args[0]))throw Error('Use preview, --run or --canary');
const canary=args[0]==='--canary';
// Browser fetch must load the pinned lab CA at Node startup, never bypass TLS.
if(canary&&process.env.NODE_EXTRA_CA_CERTS!==resolve(local,'ca.pem')){
 const child=spawnSync(process.execPath,['--experimental-strip-types',...process.argv.slice(1)],{cwd:root,env:{...process.env,NODE_EXTRA_CA_CERTS:resolve(local,'ca.pem')},stdio:'inherit',windowsHide:true,timeout:600000});
 process.exit(child.status??1);
}
const invoke=(args,input)=>execFileSync('docker',args,{input,encoding:'utf8',windowsHide:true,timeout:20000,stdio:['pipe','pipe','pipe']}).trim();
const id=randomUUID(),image=JSON.parse(readFileSync(resolve(root,'infra/tool-api/deployment.review.json'),'utf8')).hostingProposal.localImageId;
const plan=enrolledNetworkPlan({id,image}),run=resolve(custody,'network-check-'+id),lock=resolve(custody,'network-verification.lock');
const checks=[];const check=(name,value)=>{assert.ok(value,name);checks.push(name);console.log(JSON.stringify({check:name,passed:true}));};
const restrictions=['--user',plan.runAsUser,'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','256m','--cpus','0.5','--pids-limit','64','--init','--log-opt','max-size=5m','--log-opt','max-file=2'];
let fd,policy,networkCreated=false,cleanup=true,firstCounts,clientLeaseFd;
const clientLease=resolve(root,'.local/copilot/live-sso.lock');
const containers=new Set();
const counts=()=>{const d=new DatabaseSync(resolve(custody,'policy.sqlite'),{readOnly:true});try{return JSON.stringify(d.prepare('SELECT (SELECT count(*) FROM grants) grants,(SELECT count(*) FROM consents) consents').get());}finally{d.close();}};
const save=(dir,name,data)=>writeFileSync(resolve(dir,name),data,{mode:0o600,flag:'wx'});
try{
 protect();fd=openSync(lock,'wx',0o600);mkdirSync(run,{mode:0o700});
 if(canary){if(existsSync(resolve(root,'.local/copilot/pf-live-verification.lock')))throw Error();clientLeaseFd=openSync(clientLease,'wx',0o600);writeFileSync(clientLeaseFd,JSON.stringify({purpose:'enrolled-tool-canary',startedAt:new Date().toISOString(),pid:process.pid}));}
 const receipt=JSON.parse(readFileSync(resolve(custody,'runtime-enrollment.json'),'utf8'));if(!/^snapshot-[1-9][0-9]*-[a-f0-9-]+$/.test(receipt.snapshot))throw Error();
 const {record,version}=await fetchRecord((p,o)=>vault(p,{...o,...rendererCertificate()}));assert.equal(version,receipt.version);
 const snapshot=resolve(custody,receipt.snapshot),expected=validateRecord(record);assert.equal(readdirSync(snapshot).length,6);for(const [name,value] of Object.entries(expected))assert.equal(readFileSync(resolve(snapshot,name),'utf8'),value);
 check('selected six-file snapshot matches current Vault version',true);
 const configPath=resolve(custody,'tool-runtime.json'),config=JSON.parse(readFileSync(configPath,'utf8'));
 const backend=(await operator('/'+mount+'/data/private-backend')).data.data,monitor=(await operator('/'+mount+'/data/monitoring')).data.data;
 const ca=new X509Certificate(record.outboundCaPem),bc=new X509Certificate(backend.certificatePem),mc=new X509Certificate(monitor.certificatePem);
 for(const [cert,key] of [[bc,backend.keyPem],[mc,monitor.keyPem]])assert.ok(cert.checkPrivateKey(createPrivateKey(key))&&cert.verify(ca.publicKey)&&Date.parse(cert.validTo)>Date.now()+300000);
 assert.equal(bc.checkHost('tool-backend'),'tool-backend');assert.deepEqual(config.clientCertificateSha256,[mc.fingerprint256]);
 const bridge=resolve(run,'bridge'),probe=resolve(run,'probe'),audit=resolve(run,'audit');for(const d of [bridge,probe,audit])mkdirSync(d,{mode:0o700});
 save(bridge,'server-key.pem',backend.keyPem);save(bridge,'server-cert.pem',backend.certificatePem);save(bridge,'pf-ca.pem',read('ca.pem'));save(bridge,'config.json',JSON.stringify({policyPort:9452}));
 save(probe,'client-key.pem',monitor.keyPem);save(probe,'client-cert.pem',monitor.certificatePem);save(probe,'server-ca.pem',record.outboundCaPem);
 policy=await startPersistentToolPolicy();firstCounts=counts();check('persistent Vault policy profile started without granting access',true);
 assert.equal(invoke(['image','inspect',image,'--format','{{.Id}}']),image);
 invoke(['network','create','--internal','--subnet',plan.internalSubnet,'--label',plan.label,plan.network]);networkCreated=true;
 const bridgeArgs=['run','--detach','--rm','--name',plan.bridgeName,'--label',plan.label,'--network','bridge',...restrictions,'--mount',`type=bind,source=${bridge},target=/run/bridge,readonly`,'--mount',`type=bind,source=${resolve(root,'scripts/pf/tool-backend-bridge.mjs')},target=/bridge/main.mjs,readonly`,'--mount',`type=bind,source=${resolve(root,'scripts/pf/tool-backend-route.mjs')},target=/bridge/tool-backend-route.mjs,readonly`,'--entrypoint','node','node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32','/bridge/main.mjs'];
 const startBridge=()=>{containers.add(plan.bridgeName);invoke(bridgeArgs);invoke(['network','connect','--alias','tool-backend',plan.network,plan.bridgeName]);};startBridge();
 containers.add(plan.toolName);invoke(['run','--detach','--rm','--name',plan.toolName,'--label',plan.label,'--network',plan.network,'--network-alias','tool-api',...restrictions,'--mount',`type=bind,source=${snapshot},target=/run/secrets,readonly`,'--mount',`type=bind,source=${configPath},target=/run/config/tool-runtime.json,readonly`,'--mount',`type=bind,source=${audit},target=/var/lib/tool-audit`,image]);
 const call=input=>JSON.parse(invoke(['run','--rm','-i','--label',plan.label,'--network',plan.network,...restrictions,'--mount',`type=bind,source=${probe},target=/run/probe,readonly`,'--mount',`type=bind,source=${resolve(root,'scripts/vault/enrolled-tool-probe.mjs')},target=/probe.mjs,readonly`,'--entrypoint','node',image,'/probe.mjs'],JSON.stringify(input)));
 const ready=async(expected)=>{for(let i=0;i<8;i++){const r=call({health:'ready'});if(r.status===(expected?200:503)&&r.ready===expected)return true;await new Promise(done=>setTimeout(done,500));}return false;};
 check('enrolled tool reaches signed PDP and pinned actual PF JWKS',await ready(true));
 check('authenticated liveness',(call({health:'live'})).live);
 check('actual PF public-only JWKS through enrolled backend',(call({target:'backend'})).publicJwks);
 for(const path of ['/pf-admin-api/v1/version','/as/token.oauth2','/v1/grants','/v1/assertions','/pf/JWKS?target=admin'])check('backend denies '+path,call({target:'backend',path}).status===404);
 check('readiness requires client certificate',call({health:'ready',client:'none'}).error==='transport_denied');
 check('missing delegated token denied',call({}).status===401);check('malformed delegated token denied',call({bearer:true}).status===401);
 const state=JSON.parse(invoke(['inspect',plan.toolName]))[0];check('tool is non-root with private network and no host ports',state.Config.User===plan.runAsUser&&state.HostConfig.ReadonlyRootfs&&Object.keys(state.HostConfig.PortBindings??{}).length===0&&Object.keys(state.NetworkSettings.Networks).length===1&&!!state.NetworkSettings.Networks[plan.network]);
 check('tool mounts only selected credentials config and audit',state.Mounts.length===3&&state.Mounts.every(m=>['/run/secrets','/run/config/tool-runtime.json','/var/lib/tool-audit'].includes(m.Destination)&&m.RW===(m.Destination==='/var/lib/tool-audit')));
 await policy.stop();policy=undefined;check('policy outage makes tool unready',await ready(false));check('policy outage preserves liveness',call({health:'live'}).live);
 policy=await startPersistentToolPolicy();check('policy restart restores signed readiness',await ready(true));
 invoke(['stop','--time','5',plan.bridgeName]);check('backend outage makes tool unready',await ready(false));check('backend outage preserves liveness',call({health:'live'}).live);
 startBridge();check('backend recovery restores readiness',await ready(true));
 check('authenticated metrics available',call({health:'metrics'}).metrics);
 check('verification creates no grants or consents',counts()===firstCounts);
 if(canary)await enrolledCanary({run,origin:policy.origin,call,check});
}catch{process.exitCode=1;console.error(JSON.stringify({error:'Enrolled private network verification failed',lastCompletedCheck:checks.at(-1)??'none'}));}
finally{
 for(const name of [...containers].reverse())try{if(invoke(['ps','-aq','--filter','name=^/'+name+'$']))invoke(['rm','-f',name]);}catch{cleanup=false;}
 if(networkCreated)try{invoke(['network','rm',plan.network]);}catch{cleanup=false;}
 if(policy)try{await policy.stop();}catch{cleanup=false;}
 if(fd!==undefined){
  try{assert.equal(invoke(['ps','-aq','--filter','label='+plan.label]),'');assert.equal(invoke(['network','ls','-q','--filter','label='+plan.label]),'');for(const name of ['bridge','probe']){const path=resolve(run,name);if(!path.startsWith(custody+'\\network-check-'))throw Error();if(existsSync(path))rmSync(path,{recursive:true,force:true});}if(firstCounts){if(canary&&existsSync(resolve(run,'canary-grants.json'))){const c=JSON.parse(readFileSync(resolve(run,'canary-grants.json'),'utf8'));assert.ok(canaryTerminalState(c.before,canaryGrantState(),c.owned));}else assert.equal(counts(),firstCounts);}assert.equal(existsSync(resolve(custody,'policy-authority-token')),false);if(clientLeaseFd!==undefined)assert.ok((await admin('a','oauth/clients/copilot-studio-generic-oauth')).enabled===true&&(await admin('b','oauth/clients/copilot-sso-exchange')).enabled===false);}catch{cleanup=false;}
  closeSync(fd);if(cleanup)rmSync(lock);
 }
 if(clientLeaseFd!==undefined){closeSync(clientLeaseFd);if(cleanup)rmSync(clientLease);}
 if(!cleanup)process.exitCode=1;
 const receipt={completedAt:new Date().toISOString(),passed:process.exitCode!==1,checks:checks.length,canary,canaryGrantsRevoked:canary&&cleanup,clientsRestored:canary&&cleanup,containersRemoved:cleanup,temporaryCredentialsRemoved:cleanup,policyStopped:cleanup,credentialsPreserved:true,opensHostPorts:false,persistentToolStarted:false};
 if(existsSync(run))writeFileSync(resolve(run,'verification.json'),JSON.stringify(receipt,null,2),{mode:0o600});privateSave('tool-network-validation.json',receipt);console.log(JSON.stringify(receipt));
}
