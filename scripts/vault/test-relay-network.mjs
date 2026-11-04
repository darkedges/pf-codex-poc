import {execFileSync} from 'node:child_process';import {existsSync,readFileSync,writeFileSync,mkdirSync,openSync,closeSync,rmSync,readdirSync} from 'node:fs';import {resolve,sep} from 'node:path';
import {randomUUID,X509Certificate,createPrivateKey} from 'node:crypto';
import {protect,custody,rendererCertificate,readProtected} from './tool-custody.mjs';
import {vault,operator} from './common.mjs';import {fetchRecord,validateRecord} from './tool-secrets.mjs';
import {fetchRelayRecord,validateRelayRecord,relayRecordDigest,relayCandidatePlan} from './relay-secrets.mjs';
import {createRelayCandidateServer} from './local-relay-credentials.mjs';import {root,read} from '../pf/common.mjs';
const args=process.argv.slice(2);if(!args.length){console.log(JSON.stringify({purpose:'isolated Docker relay-identity candidate',hostPorts:[],changesExistingTool:false,microsoftRequests:0,createsGrants:false}));process.exit(0);}if(args.length!==1||args[0]!=='--run')throw Error('Use preview or --run');
const docker=(args,input)=>execFileSync('docker',args,{encoding:'utf8',input,windowsHide:true,timeout:20000,stdio:['pipe','pipe','pipe']}).trim();
const id=randomUUID(),image=JSON.parse(readFileSync(resolve(root,'infra/tool-api/deployment.review.json'),'utf8')).hostingProposal.localImageId,plan=relayCandidatePlan({id,image});
const lock=resolve(custody,'relay-network.lock'),run=resolve(custody,'relay-network-'+id),dirs=['tool','bridge','probe','candidate-ca'],checks=[];let fd,networkId,existing,passed=false,clean=true;
const created=new Map(),check=(name,v)=>{if(!v)throw Error('Relay network verification failed');checks.push(name);console.log(JSON.stringify({check:name,status:'passed'}));};
const save=(dir,name,value)=>writeFileSync(resolve(run,dir,name),value,{mode:0o600,flag:'wx'});
const inspect=name=>JSON.parse(docker(['inspect',name]))[0];
const existingState=()=>['federated-copilot-local-tool','federated-copilot-local-backend'].map(name=>{const c=inspect(name);if(!c.State.Running||Object.keys(c.HostConfig.PortBindings??{}).length)throw Error();return{id:c.Id,name,networks:Object.keys(c.NetworkSettings.Networks).sort()};});
try{
 protect();fd=openSync(lock,'wx',0o600);mkdirSync(run,{mode:0o700});for(const d of [...dirs,'audit'])mkdirSync(resolve(run,d),{mode:0o700});existing=existingState();
 check('selected immutable tool image',docker(['image','inspect',image,'--format','{{.Id}}'])===image);
 const tool=await fetchRecord((p,o)=>vault(p,{...o,...rendererCertificate()})),enrollment=JSON.parse(readFileSync(resolve(custody,'relay-enrollment.json'),'utf8'));
 const identity={cert:readProtected('relay-renderer-cert.pem'),key:readProtected('relay-renderer-key.pem')},renderer=new X509Certificate(identity.cert);check('relay renderer identity valid',renderer.checkPrivateKey(createPrivateKey(identity.key))&&Date.parse(renderer.validTo)>Date.now()+300000);
 const relay=await fetchRelayRecord((p,o)=>vault(p,{...o,...identity}));
 check('selected relay snapshot matches current Vault',relay.version===enrollment.version&&/^relay-snapshot-1-[a-f0-9-]{36}$/.test(enrollment.snapshot)&&readdirSync(resolve(custody,enrollment.snapshot)).length===8&&Object.entries(validateRelayRecord(relay.record)).every(([name,value])=>readFileSync(resolve(custody,enrollment.snapshot,name),'utf8')===value));
 const maintenance=(await operator('/federated-copilot-tool-secrets/data/local-pki')).data.data,backend=(await operator('/federated-copilot-tool-secrets/data/private-backend')).data.data;
 const candidate=createRelayCandidateServer(resolve(run,'candidate-ca'),maintenance,plan.hostname);
 const toolFiles=validateRecord(tool.record);toolFiles['tool-server-key.pem']=candidate.keyPem;toolFiles['tool-server-cert.pem']=candidate.certificatePem;
 for(const [name,value] of Object.entries(toolFiles))save('tool',name,value);
 const sourceConfig=readFileSync(resolve(custody,'tool-runtime.json'),'utf8'),config=JSON.parse(sourceConfig),pending=structuredClone(config),relayPin=new X509Certificate(relay.record.outboundCertificatePem).fingerprint256;
 check('relay identity is separate from current tool callers',!config.clientCertificateSha256.includes(relayPin));pending.clientCertificateSha256=[...config.clientCertificateSha256,relayPin];
 writeFileSync(resolve(run,'pending-tool-runtime.json'),JSON.stringify(pending,null,2),{mode:0o600,flag:'wx'});writeFileSync(resolve(run,'candidate-tool-runtime.json'),JSON.stringify(pending),{mode:0o600,flag:'wx'});
 save('bridge','server-key.pem',backend.keyPem);save('bridge','server-cert.pem',backend.certificatePem);save('bridge','pf-ca.pem',read('ca.pem'));save('bridge','config.json',JSON.stringify({policyPort:9452}));
 save('probe','key.pem',relay.record.outboundKeyPem);save('probe','cert.pem',relay.record.outboundCertificatePem);save('probe','ca.pem',relay.record.outboundCaPem);save('probe','config.json',JSON.stringify({hostname:plan.hostname,toolPin:new X509Certificate(candidate.certificatePem).fingerprint256,backendPin:new X509Certificate(backend.certificatePem).fingerprint256}));
 const restrictions=['--user','1000:1000','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','256m','--cpus','0.5','--pids-limit','64','--init','--log-opt','max-size=1m','--log-opt','max-file=1'];
 networkId=docker(['network','create','--internal','--subnet',plan.subnet,'--label',plan.label,plan.network]);
 created.set(plan.backend,docker(['run','--detach','--rm','--name',plan.backend,'--label',plan.label,'--network','bridge',...restrictions,'--mount',`type=bind,source=${resolve(run,'bridge')},target=/run/bridge,readonly`,'--mount',`type=bind,source=${resolve(root,'scripts/pf/tool-backend-bridge.mjs')},target=/bridge/main.mjs,readonly`,'--mount',`type=bind,source=${resolve(root,'scripts/pf/tool-backend-route.mjs')},target=/bridge/tool-backend-route.mjs,readonly`,'--entrypoint','node','node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32','/bridge/main.mjs']));
 docker(['network','connect','--alias','tool-backend',plan.network,plan.backend]);
 created.set(plan.tool,docker(['run','--detach','--rm','--name',plan.tool,'--label',plan.label,'--network',plan.network,'--network-alias',plan.hostname,...restrictions,'--mount',`type=bind,source=${resolve(run,'tool')},target=/run/secrets,readonly`,'--mount',`type=bind,source=${resolve(run,'candidate-tool-runtime.json')},target=/run/config/tool-runtime.json,readonly`,'--mount',`type=bind,source=${resolve(run,'audit')},target=/var/lib/tool-audit`,image]));
 const call=operation=>JSON.parse(docker(['run','--rm','-i','--label',plan.label,'--network',plan.network,...restrictions,'--mount',`type=bind,source=${resolve(run,'probe')},target=/run/probe,readonly`,'--mount',`type=bind,source=${resolve(root,'scripts/vault/relay-network-probe.mjs')},target=/probe.mjs,readonly`,'--entrypoint','node',image,'/probe.mjs'],JSON.stringify({operation})));
 let ready=false;for(let i=0;i<10;i++){if(call('ready').ready){ready=true;break;}await new Promise(done=>setTimeout(done,500));}
 check('new relay workload reaches signed candidate readiness over pinned mTLS',ready);
 check('missing workload certificate denied',call('missing-client').error==='transport_denied');
 check('invalid tool proof denied after caller authentication',call('missing-proof').status===401);
 check('human and resource override rejected',call('override').status===400);
 check('private backend returns public pinned PF JWKS',call('backend-jwks').publicJwks);
 check('private backend cannot reach PF admin API',call('backend-admin').status===404);
 const c=inspect(plan.tool),n=JSON.parse(docker(['network','inspect',plan.network]))[0];
 check('candidate is internal non-root read-only and publishes no ports',n.Internal&&Object.keys(c.HostConfig.PortBindings??{}).length===0&&Object.keys(c.NetworkSettings.Networks).length===1&&c.Config.User==='1000:1000'&&c.HostConfig.ReadonlyRootfs);
 check('existing selected tool configuration unchanged',readFileSync(resolve(custody,'tool-runtime.json'),'utf8')===sourceConfig);
 check('existing tool and backend identities/networks unchanged',JSON.stringify(existingState())===JSON.stringify(existing));
 check('existing tool Vault record unchanged',(await operator('/federated-copilot-tool-secrets/data/runtime')).data.metadata.version===tool.version&&relayRecordDigest((await operator('/federated-copilot-tool-secrets/data/runtime')).data.data)===relayRecordDigest(tool.record));
 passed=true;
}catch{console.error('Relay candidate verification failed; cleaning only owned resources');process.exitCode=1;}
finally{
 for(const name of [plan.tool,plan.backend])if(created.has(name))try{const containerId=created.get(name);if(!/^[a-f0-9]{64}$/.test(containerId))throw Error();if(docker(['ps','-aq','--filter','id='+containerId])){const c=inspect(containerId);if(c.Config.Labels?.['federated-copilot.relay-candidate']!==id||c.Name!=='/'+name)throw Error();docker(['stop','--time','5',containerId]);}if(docker(['ps','-aq','--filter','id='+containerId]))throw Error();}catch{clean=false;}
 if(networkId)try{const n=JSON.parse(docker(['network','inspect',networkId]))[0];if(n.Name!==plan.network||n.Labels?.['federated-copilot.relay-candidate']!==id)throw Error();docker(['network','rm',networkId]);}catch{clean=false;}
 if(clean)try{for(const dir of dirs){const target=resolve(run,dir);if(!target.startsWith(custody+sep)||!target.startsWith(run+sep))throw Error();if(existsSync(target))rmSync(target,{recursive:true,force:true});}}catch{clean=false;}
 let existingPreserved=false;try{existingPreserved=JSON.stringify(existingState())===JSON.stringify(existing);}catch{}
 const receipt={completedAt:new Date().toISOString(),passed:passed&&clean&&existingPreserved,checks:checks.length,ownedResourcesRemoved:clean,temporaryCredentialsRemoved:clean,existingServicePreserved:existingPreserved,existingToolTrustChanged:false,hostPorts:[],microsoftRequests:0,grantsCreated:0,pendingToolConfiguration:resolve(run,'pending-tool-runtime.json')};
 if(existsSync(run))writeFileSync(resolve(run,'verification.json'),JSON.stringify(receipt,null,2),{mode:0o600});if(fd!==undefined){closeSync(fd);if(clean)rmSync(lock);}if(!receipt.passed)process.exitCode=1;console.log(JSON.stringify(receipt));
}
