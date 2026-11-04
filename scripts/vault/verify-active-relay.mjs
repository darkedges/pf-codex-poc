import {readFileSync,writeFileSync,mkdirSync,rmSync} from 'node:fs';import {resolve,sep} from 'node:path';import {execFileSync} from 'node:child_process';import {randomUUID,X509Certificate} from 'node:crypto';
import {root} from '../pf/common.mjs';import {protect,custody,readProtected} from './tool-custody.mjs';import {vault} from './common.mjs';import {fetchRelayRecord} from './relay-secrets.mjs';
if(process.argv.length!==2)throw Error('No arguments accepted');
const id=randomUUID(),run=resolve(custody,'active-relay-check-'+id),probe=resolve(run,'probe'),label='federated-copilot.relay-active-check='+id;
const docker=(args,input)=>execFileSync('docker',args,{encoding:'utf8',input,windowsHide:true,timeout:20000,stdio:['pipe','pipe','pipe']}).trim();
const checks=[];const check=(name,v)=>{if(!v)throw Error();checks.push(name);};let clean=true,passed=false;
try{
 protect();mkdirSync(run,{mode:0o700});mkdirSync(probe,{mode:0o700});
 const activation=JSON.parse(readFileSync(resolve(custody,'relay-tool-activation.json'),'utf8')),instance=JSON.parse(readFileSync(resolve(custody,'service/instance.json'),'utf8')),config=JSON.parse(readFileSync(resolve(custody,'tool-runtime.json'),'utf8'));
 const relay=await fetchRelayRecord((p,o)=>vault(p,{...o,cert:readProtected('relay-renderer-cert.pem'),key:readProtected('relay-renderer-key.pem')}));
 check('selected relay identity is active at its pinned Vault version',activation.relayVaultVersion===relay.version&&activation.relayCertificateSha256===new X509Certificate(relay.record.outboundCertificatePem).fingerprint256&&config.clientCertificateSha256.length===2&&config.clientCertificateSha256[1]===activation.relayCertificateSha256);
 const c=JSON.parse(docker(['inspect','federated-copilot-local-tool']))[0];
 check('target is the owned private running tool',c.State.Running&&c.Config.Labels?.['federated-copilot.local-service']===instance.instance&&Object.keys(c.HostConfig.PortBindings??{}).length===0&&instance.network==='federated-copilot-local-private');
 for(const [name,value] of [['key.pem',relay.record.outboundKeyPem],['cert.pem',relay.record.outboundCertificatePem],['ca.pem',relay.record.outboundCaPem],['config.json',JSON.stringify({hostname:'tool-api',toolPin:relay.record.toolServerCertificateSha256})]])writeFileSync(resolve(probe,name),value,{mode:0o600,flag:'wx'});
 const call=operation=>JSON.parse(docker(['run','--rm','-i','--label',label,'--network',instance.network,'--user','1000:1000','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','128m','--pids-limit','32','--mount',`type=bind,source=${probe},target=/run/probe,readonly`,'--mount',`type=bind,source=${resolve(root,'scripts/vault/relay-network-probe.mjs')},target=/probe.mjs,readonly`,'--entrypoint','node',instance.image,'/probe.mjs'],JSON.stringify({operation})));
 check('active relay certificate passes pinned mTLS readiness',call('ready').ready===true);
 check('missing sender certificate is denied',call('missing-client').error==='transport_denied');
 check('invalid tool proof is denied after relay authentication',call('missing-proof').status===401);
 check('body-supplied human/resource is denied',call('override').status===400);
 const current=JSON.parse(docker(['inspect','federated-copilot-local-tool']))[0];check('verification preserved running tool identity and ports',current.Id===c.Id&&current.State.Running&&Object.keys(current.HostConfig.PortBindings??{}).length===0);passed=true;
}catch{console.error('Active relay workload verification failed');process.exitCode=1;}
finally{
 try{const ids=docker(['ps','-aq','--filter','label='+label]).split(/\s+/).filter(Boolean);for(const containerId of ids){if(!/^[a-f0-9]{12,64}$/.test(containerId))throw Error();const c=JSON.parse(docker(['inspect',containerId]))[0];if(c.Config.Labels?.['federated-copilot.relay-active-check']!==id)throw Error();docker(['stop','--time','5',c.Id]);}if(docker(['ps','-aq','--filter','label='+label]))throw Error();}catch{clean=false;}
 if(clean){if(!probe.startsWith(custody+sep)||!probe.startsWith(run+sep))throw Error('Refused cleanup');rmSync(probe,{recursive:true,force:true});}
 const receipt={completedAt:new Date().toISOString(),passed:passed&&clean,checks:checks.length,temporaryCredentialsRemoved:clean,hostPorts:[],microsoftRequests:0,grantsCreated:0};writeFileSync(resolve(run,'verification.json'),JSON.stringify(receipt,null,2),{mode:0o600});console.log(JSON.stringify(receipt));if(!receipt.passed)process.exitCode=1;
}
