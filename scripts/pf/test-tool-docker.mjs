import {execFileSync} from 'node:child_process';
import {mkdirSync,readFileSync,writeFileSync,unlinkSync} from 'node:fs';
import {resolve} from 'node:path';
import {randomUUID,randomBytes,X509Certificate} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const root=resolve(fileURLToPath(new URL('../../',import.meta.url))),run=resolve(root,'.local/copilot/tool-docker-tests',randomUUID());
mkdirSync(run,{recursive:true});
const name='federated-tool-smoke-'+randomUUID(),files=[],checks=[];
const invoke=(cmd,args,timeout=15000)=>execFileSync(cmd,args,{encoding:'utf8',timeout,windowsHide:true,stdio:['ignore','pipe','pipe']}).trim();
const check=(value,label)=>{if(!value)throw Error('Docker smoke failed');checks.push(label);};
const image='federated-copilot-tool:local';let started=false,cleanup=true;
try{
 // No network, ports or mounts for the missing-configuration rejection.
 let rejected=false;
 try{invoke('docker',['run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',image]);}
 catch(error){rejected=error.status===1&&String(error.stderr).includes('Tool runtime configuration rejected');}
 check(rejected,'missing-configuration-rejected');
 const path=name=>{const p=resolve(run,name);files.push(p);return p;};
 const key=path('tool-server-key.pem'),cert=path('tool-server-cert.pem');
 invoke('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-days','1']);
 for(const name of ['tool-client-ca.pem','tool-outbound-ca.pem'])writeFileSync(path(name),readFileSync(cert));
 invoke('openssl',['genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',path('tool-policy-key.pem')]);
 const audit=resolve(run,'audit');mkdirSync(audit);writeFileSync(path('tool-audit-key'),randomBytes(32).toString('hex'));
 const config=JSON.parse(readFileSync(resolve(root,'infra/tool-api/runtime.example.json'),'utf8'));
 config.trust={issuer:'https://pf-smoke.invalid',jwksUri:'https://pf-smoke.invalid/pf/JWKS',audience:'api://copilot-tool',algorithms:['RS256'],keyIds:['synthetic-smoke'],organisations:['synthetic'],actorIssuers:['https://agents-smoke.invalid'],maxLifetimeSeconds:120};
 config.policy={origin:'https://policy-smoke.invalid',clientId:'synthetic-smoke',keyId:'synthetic-smoke'};
 config.clientCertificateSha256=[new X509Certificate(readFileSync(cert)).fingerprint256];
 const configPath=path('runtime.json');writeFileSync(configPath,JSON.stringify(config),{mode:0o600});
 const admission=config.admission;config.admission=null;writeFileSync(configPath,JSON.stringify(config));
 let unsafeRejected=false;
 try{invoke('docker',['run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--mount',`type=bind,source=${run},target=/run/secrets,readonly`,'--mount',`type=bind,source=${audit},target=/var/lib/tool-audit`,'--mount',`type=bind,source=${configPath},target=/run/config/tool-runtime.json,readonly`,image]);}
 catch(error){unsafeRejected=error.status===1&&String(error.stderr).includes('Tool runtime configuration rejected');}
 check(unsafeRejected,'null-admission-config-rejected');config.admission=admission;writeFileSync(configPath,JSON.stringify(config));
 invoke('docker',['run','--detach','--rm','--name',name,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64','--memory','256m','--cpus','0.5','--mount',`type=bind,source=${run},target=/run/secrets,readonly`,'--mount',`type=bind,source=${audit},target=/var/lib/tool-audit`,'--mount',`type=bind,source=${configPath},target=/run/config/tool-runtime.json,readonly`,image]);started=true;
 let ready=false;
 for(let i=0;i<15;i++){const logs=invoke('docker',['logs',name]);if(logs.includes('"event":"tool_runtime_started"')){ready=true;break;}await new Promise(r=>setTimeout(r,500));}
 check(ready,'synthetic-startup-only-not-readiness');
 check(invoke('docker',['exec',name,'id','-u'])==='1000','non-root-runtime');
 const state=JSON.parse(invoke('docker',['inspect',name]))[0];
 check(state.HostConfig.NetworkMode==='none'&&!Object.keys(state.HostConfig.PortBindings??{}).length,'no-network-or-host-port');
 check(state.HostConfig.ReadonlyRootfs===true&&state.HostConfig.CapDrop.includes('ALL'),'read-only-and-capability-dropped');
 const inventory=invoke('docker',['exec',name,'node','-e',"const f=require('node:fs');process.stdout.write(String(!f.existsSync('/app/.local')&&!f.existsSync('/app/src/services/mock-pf-a.ts')&&!f.existsSync('/app/scripts')))"]);
 check(inventory==='true','no-lab-files-or-mock-services-in-image');
}catch{console.error('Docker runtime smoke failed; no raw credential/configuration output retained.');process.exitCode=1;}
finally{
 if(started)try{invoke('docker',['stop','--time','7',name]);}catch{cleanup=false;}
 for(const path of files)try{unlinkSync(path);}catch{cleanup=false;}
 const result={status:process.exitCode?'failed':'passed',checks,cleanupComplete:cleanup,network:'none',hostPorts:0,usesLiveCredentials:false,productionReadinessVerified:false};
 if(!cleanup){result.status='recovery-required';process.exitCode=1;}
 writeFileSync(resolve(run,'result.json'),JSON.stringify(result,null,2));console.log(JSON.stringify(result));
}
