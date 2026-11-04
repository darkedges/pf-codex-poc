import {readFileSync,writeFileSync,mkdirSync,unlinkSync} from 'node:fs';
import {resolve,sep,basename} from 'node:path';
import {execFileSync} from 'node:child_process';
import {randomBytes,X509Certificate} from 'node:crypto';
import {importPKCS8} from 'jose';
import {OidcClient} from '../../src/identity/oidc.ts';
import {PolicyStore} from '../../src/policy/store.ts';
import {startConsent} from './run-consent.mjs';
import {localToolAuthority} from './consent-tool-exchange.ts';
import {issueConsentedUpstream} from './consent-exchange.ts';
import {LocalBrowser,forms} from '../../tests/live/local-browser.mjs';
import {root,local,read,load} from './common.mjs';
import {profile} from './config.mjs';
import {capability} from './policy-setup.ts';
import {DatabaseSync} from 'node:sqlite';
import {revokeOwnedToolConsent} from './revoke-owned-tool-consent.mjs';

const run=resolve(process.env.TOOL_CONTAINER_RUN_DIR??'');
if(!run.startsWith(resolve(local,'tool-container-tests')+sep)||process.env.POLICY_DATABASE!==resolve(run,'policy.sqlite')||process.env.AUTHORITY_SIGNER!=='vault-transit'||process.env.POLICY_TOOL_DECISION_ORIGIN!=='https://tool-backend:7443')throw Error('Isolated private container run required');
const id=basename(run),label='federated-copilot.tool-integration='+id,network='fc-tool-'+id;
const bridgeName='fc-backend-'+id,toolName='fc-runtime-'+id,containers:string[]=[],files:string[]=[],grants:any[]=[],checks:string[]=[];
let portal:any,networkCreated=false,stage='prepare',loadEvidence:any;
const check=(value:unknown)=>{if(!value)throw Error('Private tool integration failed');};
const passed=(name:string)=>{checks.push(name);console.log(JSON.stringify({check:name,status:'passed'}));};
const invoke=(cmd:string,args:string[],input?:string)=>execFileSync(cmd,args,{encoding:'utf8',input,timeout:20000,windowsHide:true,stdio:['pipe','pipe','pipe']}).trim();
const docker=(args:string[],input?:string)=>invoke('docker',args,input);
const directory=(name:string)=>{const d=resolve(run,name);mkdirSync(d);return d;};
const save=(d:string,name:string,value:string|Buffer)=>{const path=resolve(d,name);files.push(path);writeFileSync(path,value,{mode:0o600});return path;};
function certificate(d:string,name:string,dns:string){
 const key=resolve(d,name+'-key.pem'),cert=resolve(d,name+'-cert.pem');files.push(key,cert);
 invoke('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-subj','/CN='+dns,'-addext','subjectAltName=DNS:'+dns,'-days','1']);
 return{key:readFileSync(key),cert:readFileSync(cert)};
}
async function grant(){
 const b=new LocalBrowser(portal.origin),home=await b.request(portal.origin+'/');
 const login=await b.submit(forms(home.html).find(f=>f.action==='/login'));
 const approval=await b.submit(forms(login.html).find(f=>'pf.pass'in f.fields),{'pf.username':profile.human,'pf.pass':read('login-password'),'pf.ok':'clicked'});
 const review=await b.submit(forms(approval.html).find(f=>'pf.oauth.authz.consent'in f.fields),{'pf.oauth.authz.consent':'allow'});
 const result=await b.submit(forms(review.html).find(f=>f.action==='/approve'),{duration:'3600',autonomous:'on'});
 const revoke=forms(result.html).find(f=>f.action==='/revoke');check(revoke);let revoked=false;
 const state=()=>{const db=new DatabaseSync(process.env.POLICY_DATABASE!,{readOnly:true});try{return db.prepare('SELECT state FROM grants WHERE id=?').get(revoke.fields.grantId)?.state;}finally{db.close();}};
 const g={id:revoke.fields.grantId,revoke:async()=>{
  if(revoked||state()==='revoked'){revoked=true;return;}
  try{await b.submit(revoke,{},{noRedirect:true});}catch{}
  if(state()!=='revoked')await revokeOwnedToolConsent(portal.origin,revoke.fields.grantId);
  check(state()==='revoked');revoked=true;
 }};
 grants.push(g);return g;
}
async function loginProof(){
 const c=new OidcClient({...load('oidc-config.json'),redirectUri:portal.origin+'/callback',clientKey:await importPKCS8(read('consent-oidc.private.pem'),'RS256')});
 const nonce=randomBytes(24).toString('hex'),verifier=randomBytes(32).toString('base64url'),b=new LocalBrowser(portal.origin);
 const login=await b.request(await c.start(randomBytes(24).toString('hex'),nonce,verifier));
 const approval=await b.submit(forms(login.html).find(f=>'pf.pass'in f.fields),{'pf.username':profile.human,'pf.pass':read('login-password'),'pf.ok':'clicked'});
 await b.submit(forms(approval.html).find(f=>'pf.oauth.authz.consent'in f.fields),{'pf.oauth.authz.consent':'allow'},{captureCallback:true});
 const result=await c.redeem(new URL(b.callback).searchParams.get('code')!,verifier,nonce);return{idToken:result.idToken,nonce};
}
try{
 stage='certificate-preparation';
 const bridge=directory('bridge'),secrets=directory('secrets'),probe=directory('probe'),auditDir=directory('audit');
 const backendCert=certificate(bridge,'server','tool-backend'),toolCert=certificate(secrets,'tool-server','tool-runtime');
 const approved=certificate(probe,'approved','approved-workload'),other=certificate(probe,'other','unapproved-workload');
 save(bridge,'pf-ca.pem',read('ca.pem'));save(bridge,'config.json',JSON.stringify({policyPort:Number(new URL(process.env.POLICY_API_ORIGIN!).port)}));
 save(secrets,'tool-client-ca.pem',Buffer.concat([approved.cert,other.cert]));save(secrets,'tool-outbound-ca.pem',backendCert.cert);
 // Dedicated decision-only lab workload credential; never mounted in the bridge.
 save(secrets,'tool-policy-key.pem',read('policy-tool.private.pem'));save(secrets,'tool-audit-key',randomBytes(32).toString('hex'));
 save(probe,'server-ca.pem',Buffer.concat([toolCert.cert,backendCert.cert]));
 const config={version:1,admission:{maxConcurrentRequests:16,perWorkloadRequestsPerMinute:60,maxConnections:128},trust:{issuer:'https://pf-b.copilot.darkedges.com',jwksUri:'https://tool-backend:7443/pf/JWKS',audience:'api://copilot-tool',algorithms:['RS256'],keyIds:['copilot-tool-signing'],organisations:[profile.org],actorIssuers:[profile.agentIssuer],maxLifetimeSeconds:120},policy:{origin:'https://tool-backend:7443',clientId:'policy-tool',keyId:'copilot-policy-tool'},clientCertificateSha256:[new X509Certificate(approved.cert).fingerprint256],timeouts:{jwksMs:1500,policyMs:1500,toolMs:5000}};
 const configPath=save(run,'runtime.json',JSON.stringify(config));
 stage='runtime-image-inspection';const image=docker(['image','inspect','federated-copilot-tool:local','--format','{{.Id}}']);check(/^sha256:[a-f0-9]{64}$/.test(image));
 stage='private-network-create';
 // The host's default Docker pools are exhausted; this lab-only /28 was
 // checked against existing networks/routes. Docker rejects any collision.
 docker(['network','create','--internal','--subnet','10.236.250.0/28','--label',label,network]);networkCreated=true;
 const restrictions=['--user','1000:1000','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64','--memory','256m','--cpus','0.5'];
 stage='backend-start';containers.push(bridgeName);
 const backendArgs=['run','--detach','--rm','--name',bridgeName,'--label',label,'--network','bridge',...restrictions,'--mount',`type=bind,source=${bridge},target=/run/bridge,readonly`,'--mount',`type=bind,source=${resolve(root,'scripts/pf/tool-backend-bridge.mjs')},target=/bridge/main.mjs,readonly`,'--mount',`type=bind,source=${resolve(root,'scripts/pf/tool-backend-route.mjs')},target=/bridge/tool-backend-route.mjs,readonly`,'--entrypoint','node','node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32','/bridge/main.mjs'];
 docker(backendArgs);
 docker(['network','connect','--alias','tool-backend',network,bridgeName]);
 stage='runtime-start';containers.push(toolName);
 const runtimeArgs=['run','--detach','--rm','--name',toolName,'--label',label,'--network',network,'--network-alias','tool-runtime',...restrictions,'--mount',`type=bind,source=${secrets},target=/run/secrets,readonly`,'--mount',`type=bind,source=${auditDir},target=/var/lib/tool-audit`,'--mount',`type=bind,source=${configPath},target=/run/config/tool-runtime.json,readonly`,image];
 docker(runtimeArgs);
 let started=false;for(let i=0;i<15;i++){if(docker(['logs',toolName]).includes('tool_runtime_started')){started=true;break;}await new Promise(r=>setTimeout(r,500));}check(started);passed('private-container-runtime-started');
 const call=(input:Record<string,unknown>)=>JSON.parse(docker(['run','--rm','-i','--label',label,'--network',network,...restrictions,'--env','NODE_EXTRA_CA_CERTS=/run/probe/server-ca.pem','--mount',`type=bind,source=${probe},target=/run/probe,readonly`,'--mount',`type=bind,source=${resolve(root,'scripts/pf/tool-docker-probe.mjs')},target=/probe.mjs,readonly`,'--mount',`type=bind,source=${resolve(root,'scripts/pf/bounded-probe-batch.mjs')},target=/bounded-probe-batch.mjs,readonly`,'--entrypoint','node',image,'/probe.mjs'],JSON.stringify(input)));
 check(call({health:'live'}).live);passed('mTLS-liveness-without-human-token');
 check(call({health:'ready'}).ready);passed('signed-PDP-and-pinned-JWKS-readiness');
 check(call({health:'ready',client:'none'}).error==='tls_denied');passed('unauthenticated-readiness-denied');
 check(call({target:'backend'}).publicJwks);passed('actual-PF-JWKS-through-private-TLS-bridge');
 for(const path of ['/pf-admin-api/v1/version','/as/token.oauth2','/v1/grants','/pf/JWKS?target=admin'])check(call({target:'backend',path}).status===404);passed('backend-admin-token-arbitrary-paths-denied');
 const state=JSON.parse(docker(['inspect',toolName]))[0];check(Object.keys(state.NetworkSettings.Networks).length===1&&!!state.NetworkSettings.Networks[network]&&!Object.keys(state.HostConfig.PortBindings??{}).length);passed('tool-attached-only-to-internal-network-with-no-host-ports');
 portal=await startConsent();const authority=await localToolAuthority(process.env.POLICY_API_ORIGIN!,'gateway');
 const aging:any[]=[];
 for(const mode of ['interactive','autonomous']){
  stage=mode;const g=await grant(),login=mode==='interactive'?await loginProof():undefined,issued=await authority.issue(g.id,mode,login);
  check(issued.claims.sub===profile.human&&issued.claims.act.sub===profile.agent&&issued.claims.act.iss===profile.agentIssuer&&issued.claims.delegation_id===g.id&&issued.claims.execution_mode===mode);
  check(call({token:issued.accessToken}).authorized);passed(mode+':actual-PF-token-accepted-inside-Docker');
  check(call({token:issued.accessToken,client:'unapproved'}).status===403);passed(mode+':unapproved-certificate-denied');
  check(call({token:issued.accessToken,client:'none'}).error==='tls_denied');passed(mode+':missing-certificate-denied');
  check(call({token:'unsigned'}).status===401);passed(mode+':invalid-token-denied');
  check(call({token:issued.accessToken,body:{sub:'forged',resource:'sharepoint:unapproved'}}).status===400);passed(mode+':identity-resource-override-denied');
  check(call({token:await issueConsentedUpstream(g.id,mode,login)}).status===401);passed(mode+':upstream-audience-denied');
  await g.revoke();check(call({token:issued.accessToken}).status===403);passed(mode+':revoked-grant-denied');
  const freshGrant=await grant(),freshLogin=mode==='interactive'?await loginProof():undefined,fresh=await authority.issue(freshGrant.id,mode,freshLogin);
  check(call({token:fresh.accessToken}).authorized);aging.push({g:freshGrant,token:fresh,mode,login:freshLogin});
 }
 stage='real-token-aging';const until=Math.max(...aging.map(a=>a.token.claims.exp))*1000+1000;check(until-Date.now()>0&&until-Date.now()<=122000);let progress=Date.now();
 while(Date.now()<until){await new Promise(r=>setTimeout(r,Math.min(1000,until-Date.now())));if(Date.now()-progress>=30000){console.log(JSON.stringify({phase:'Docker-token-aging',remainingSeconds:Math.max(0,Math.ceil((until-Date.now())/1000))}));progress=Date.now();}}
 for(const a of aging){
  check(call({token:a.token.accessToken}).status===401);passed(a.mode+':expired-token-denied-inside-Docker');
  const fresh=await authority.issue(a.g.id,a.mode,a.login);check(call({token:fresh.accessToken}).authorized);passed(a.mode+':fresh-token-under-active-grant-accepted');await a.g.revoke();
 }
 stage='backend-outage';const g=await grant(),issued=await authority.issue(g.id,'autonomous');check(call({token:issued.accessToken}).authorized);
 docker(['stop','--time','5',bridgeName]);check(call({token:issued.accessToken}).status===403);passed('private-backend-outage-denies-cached-JWKS-token');
 await new Promise(r=>setTimeout(r,1100));check(call({health:'ready'}).status===503);passed('backend-outage-readiness-fails-closed');
 check(call({health:'live'}).live);passed('backend-outage-process-stays-live');
 docker(backendArgs);docker(['network','connect','--alias','tool-backend',network,bridgeName]);
 await new Promise(r=>setTimeout(r,1100));check(call({health:'ready'}).ready);passed('backend-recovery-readiness-restored');
 check(call({token:issued.accessToken}).authorized);passed('backend-recovery-protected-operation-restored');
 const metrics=call({health:'metrics'}).metrics;check(metrics.auditHealthy&&metrics.counters.policyDenied>0&&metrics.counters.toolSuccess>0&&metrics.certificateExpiring);passed('authenticated-metrics-contains-only-health-and-counters');
 check(call({health:'metrics',client:'none'}).error==='tls_denied');passed('unauthenticated-metrics-denied');
 docker(['exec',toolName,'node','-e',"const f=require('node:fs');f.renameSync('/var/lib/tool-audit/tool-access.jsonl','/var/lib/tool-audit/held.jsonl');f.mkdirSync('/var/lib/tool-audit/tool-access.jsonl');"]);
 check(call({token:issued.accessToken}).status===503);passed('audit-failure-blocks-protected-operation');
 await new Promise(r=>setTimeout(r,1100));check(call({health:'ready'}).status===503);passed('audit-failure-readiness-denied');
 docker(['exec',toolName,'node','-e',"const f=require('node:fs');f.rmdirSync('/var/lib/tool-audit/tool-access.jsonl');f.renameSync('/var/lib/tool-audit/held.jsonl','/var/lib/tool-audit/tool-access.jsonl');"]);
 await new Promise(r=>setTimeout(r,1100));check(call({health:'ready'}).ready&&call({token:issued.accessToken}).authorized);passed('audit-recovery-restores-readiness-and-operation');
 const journal=readFileSync(resolve(auditDir,'tool-access.jsonl'),'utf8');const rows=journal.trim().split('\n').map(line=>JSON.parse(line));
 check(rows.some(r=>r.outcome==='success')&&rows.some(r=>r.outcome==='denied')&&!journal.includes(issued.accessToken)&&!journal.includes(profile.human)&&!journal.includes(profile.agent));passed('restricted-audit-projects-identities-and-excludes-tokens');
 if(process.env.TOOL_LOAD_CHECK==='bounded-burst'){
  stage='bounded-burst-load';
  docker(['stop','--time','7',toolName]);
  config.admission.maxConcurrentRequests=4;config.admission.perWorkloadRequestsPerMinute=8;
  writeFileSync(configPath,JSON.stringify(config));docker(runtimeArgs);
  let ready=false;for(let i=0;i<15;i++){if(docker(['logs',toolName]).includes('tool_runtime_started')){ready=true;break;}await new Promise(r=>setTimeout(r,500));}check(ready);
  const live=await authority.issue(g.id,'autonomous');
  loadEvidence=call({token:live.accessToken,batch:{requests:64,concurrency:32}}).batch;
  check(loadEvidence?.completed===64&&loadEvidence.accepted>0&&loadEvidence.rateLimited+loadEvidence.overloaded>0&&loadEvidence.unexpected===0&&loadEvidence.networkErrors===0);passed('bounded-load-accepts-and-rejects-without-queueing');
  await new Promise(r=>setTimeout(r,8000));const metrics=call({health:'metrics'});
  check(metrics.status===200&&metrics.metrics.counters.rateLimited+metrics.metrics.counters.overloaded>0&&metrics.metrics.auditHealthy);passed('load-rejections-visible-in-authenticated-metrics');
  await new Promise(r=>setTimeout(r,8000));check(call({token:live.accessToken}).authorized);passed('capacity-recovers-after-burst');
 }
 const auditStore=new PolicyStore(process.env.POLICY_DATABASE!,[capability]);
 try{
  const permits=auditStore.audit().filter(r=>r.action==='decision'&&r.workload==='policy-tool'&&r.outcome==='permit');
  check(['interactive','autonomous'].every(mode=>permits.some(r=>r.mode===mode))&&permits.every(r=>r.subject===profile.human&&r.actor===profile.agent&&r.actor_issuer===profile.agentIssuer&&r.organisation===profile.org&&r.audience==='api://copilot-tool'&&r.token_issuer==='https://pf-b.copilot.darkedges.com'&&r.scope===capability.scope&&r.resource===capability.resource&&grants.some(g=>g.id===r.grant_id)));
  passed('independent-PDP-audit-preserves-human-actor-grant-mode-and-audience');
 }finally{auditStore.close();}
 writeFileSync(resolve(run,'result.json'),JSON.stringify({status:'passed',checks,...(loadEvidence?{loadEvidence}:{}),microsoftRequests:0,graphRequests:0},null,2));
}catch(error){
 const category=/non-overlapping|address pool|overlaps with other/i.test(String((error as any)?.stderr??''))?'address-pool':/no such image/i.test(String((error as any)?.stderr??''))?'image-unavailable':'verification-failed';
 writeFileSync(resolve(run,'result.json'),JSON.stringify({status:'failed',stage,category,checks,microsoftRequests:0,graphRequests:0},null,2));console.error(JSON.stringify({status:'failed',stage,category}));process.exitCode=1;
}finally{
 let safe=true;
 // The parent performs a fresh owner-authenticated sweep before releasing its
 // lease; old browser/CSRF state is never the sole cleanup guarantee.
 let deferred=false;for(const g of grants)try{await g.revoke();}catch{deferred=true;}
 if(deferred)console.log(JSON.stringify({event:'fresh-owner-cleanup-required'}));
 if(portal)await portal.stop();
 for(const container of containers.reverse())try{if(docker(['ps','-aq','--filter','name=^/'+container+'$']))docker(['rm','-f',container]);}catch{safe=false;}
 if(networkCreated)try{docker(['network','rm',network]);}catch{safe=false;}
 for(const file of files)try{unlinkSync(file);}catch{safe=false;}
 if(!safe){console.error('Private container integration cleanup requires review');process.exitCode=1;}
}
