import {readFileSync,writeFileSync,unlinkSync} from 'node:fs';
import {resolve,sep} from 'node:path';
import {execFileSync} from 'node:child_process';
import {request} from 'node:https';
import {randomBytes,X509Certificate} from 'node:crypto';
import {importPKCS8} from 'jose';
import {ToolApi} from '../../src/copilot/tool-api.ts';
import {createToolServer} from '../../src/copilot/tool-server.ts';
import {OidcClient} from '../../src/identity/oidc.ts';
import {PolicyStore} from '../../src/policy/store.ts';
import {startConsent} from './run-consent.mjs';
import {startPolicy} from './run-policy.mjs';
import {localToolAuthority} from './consent-tool-exchange.ts';
import {issueConsentedUpstream} from './consent-exchange.ts';
import {LocalBrowser,forms} from '../../tests/live/local-browser.mjs';
import {local,load,read} from './common.mjs';
import {profile} from './config.mjs';
import {capability} from './policy-setup.ts';

const run=resolve(process.env.TOOL_HTTP_RUN_DIR??'');
if(!run.startsWith(resolve(local,'tool-http-tests')+sep)||process.env.POLICY_DATABASE!==resolve(run,'policy.sqlite')||process.env.AUTHORITY_SIGNER!=='vault-transit')throw Error('Explicit isolated Vault-backed local run required');
const checks:string[]=[],grants:any[]=[],certFiles:string[]=[];let portal:any,server:any;
const check=(ok:unknown)=>{if(!ok)throw Error('Local HTTP verification failed');};
const passed=(name:string)=>{checks.push(name);console.log(JSON.stringify({check:name,status:'passed'}));};
function certificate(name:string){
 const key=resolve(run,name+'.key'),cert=resolve(run,name+'.pem');certFiles.push(key,cert);
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-days','1'],{stdio:'ignore',windowsHide:true,timeout:15000});
 return{key:readFileSync(key),cert:readFileSync(cert)};
}
async function grant(){
 const b=new LocalBrowser(portal.origin),home=await b.request(portal.origin+'/');
 const login=await b.submit(forms(home.html).find(f=>f.action==='/login'));
 const approval=await b.submit(forms(login.html).find(f=>'pf.pass'in f.fields),{'pf.username':profile.human,'pf.pass':read('login-password'),'pf.ok':'clicked'});
 const review=await b.submit(forms(approval.html).find(f=>'pf.oauth.authz.consent'in f.fields),{'pf.oauth.authz.consent':'allow'});
 const result=await b.submit(forms(review.html).find(f=>f.action==='/approve'),{duration:'3600',autonomous:'on'});
 const revoke=forms(result.html).find(f=>f.action==='/revoke');check(revoke);let revoked=false;
 const g={id:revoke.fields.grantId,revoke:async()=>{if(revoked)return;check((await b.submit(revoke,{},{noRedirect:true})).status===303);const store=new PolicyStore(process.env.POLICY_DATABASE!,[capability]);try{check(store.grant(revoke.fields.grantId)?.state==='revoked');}finally{store.close();}revoked=true;}};
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
 const approved=certificate('approved'),other=certificate('unapproved');
 portal=await startConsent();const authority=await localToolAuthority(process.env.POLICY_API_ORIGIN!);
 let operations=0,expected:any,revokeDuringOperation=false;
 const api=new ToolApi(authority.tool(async claims=>{
  check(claims.sub===profile.human&&claims.act.sub===profile.agent&&claims.act.iss===profile.agentIssuer&&claims.org_id===profile.org&&claims.delegation_id===expected.id&&claims.execution_mode===expected.mode&&claims.aud==='api://copilot-tool'&&claims.scope===capability.scope);
  operations++;if(revokeDuringOperation)await expected.revoke();return{authorized:true};
 }));
 server=createToolServer({...approved,ca:[approved.cert,other.cert]},api,{certificateSha256:[new X509Certificate(approved.cert).fingerprint256]});
 await new Promise<void>(done=>server.listen(0,'127.0.0.1',done));let port=server.address().port;
 const call=(token:string,client:typeof approved|null=approved,body='{}')=>new Promise<any>((done,reject)=>{
  const req=request({host:'127.0.0.1',port,servername:'localhost',method:'POST',path:'/v1/tools/verify-access',ca:approved.cert,...client,agent:false,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},timeout:15000},res=>{
   let text='';res.on('data',c=>{text+=c;if(text.length>1024)req.destroy();});res.on('end',()=>{try{done({status:res.statusCode,body:JSON.parse(text)});}catch{reject(Error('Invalid local response'));}});
  });req.on('error',reject);req.on('timeout',()=>req.destroy(Error('Local HTTP deadline')));req.end(body);
 });
 for(const mode of ['interactive','autonomous']){
  const g=await grant();expected={...g,mode};const login=mode==='interactive'?await loginProof():undefined;
  const issued=await authority.issue(g.id,mode,login),before=operations;
  const ok=await call(issued.accessToken);check(ok.status===200&&JSON.stringify(ok.body)==='{"authorized":true}'&&operations===before+1);passed(mode+':actual-PF-token-over-mTLS');
  check((await call(issued.accessToken,other)).status===403&&operations===before+1);passed(mode+':unapproved-workload-denied');
  let tlsDenied=false;try{await call(issued.accessToken,null);}catch(e){tlsDenied=/TLS|SSL/.test((e as any)?.code??'');}check(tlsDenied&&operations===before+1);passed(mode+':missing-certificate-denied');
  check((await call(issued.accessToken,approved,JSON.stringify({resource:'sharepoint:unapproved',sub:'forged'}))).status===400&&operations===before+1);passed(mode+':resource-and-human-override-denied');
  check((await call('unsigned')).status===401&&operations===before+1);passed(mode+':invalid-token-denied');
  const upstream=await issueConsentedUpstream(g.id,mode,login);check((await call(upstream)).status===401&&operations===before+1);passed(mode+':upstream-audience-denied');
  await g.revoke();check((await call(issued.accessToken)).status===403&&operations===before+1);passed(mode+':revocation-denied');
 }
 const g=await grant();expected={...g,mode:'autonomous'};const issued=await authority.issue(g.id,'autonomous');
 revokeDuringOperation=true;check((await call(issued.accessToken)).status===403);passed('revocation-during-operation-withholds-result');revokeDuringOperation=false;
 // Fresh grants remain active while actual PF tokens age under the real clock.
 const aging:any[]=[];
 for(const mode of ['interactive','autonomous']){
  const owned=await grant(),login=mode==='interactive'?await loginProof():undefined;
  const token=await authority.issue(owned.id,mode,login);expected={...owned,mode};
  check(token.claims.exp*1000>Date.now()+1000&&token.claims.exp*1000<=Date.now()+120000);
  check((await call(token.accessToken)).status===200);passed(mode+':pre-expiry-HTTPS-accepted');
  aging.push({owned,mode,login,token});
 }
 const replaceListener=async(pins:string[])=>{
  await new Promise<void>(done=>{server.close(()=>done());server.closeAllConnections();});
  server=createToolServer({...approved,ca:[approved.cert,other.cert]},api,{certificateSha256:pins});
  // Reuse the endpoint after draining the old listener; no hot trust mutation.
  await new Promise<void>((done,reject)=>{server.once('error',()=>reject(Error('Local rollover listener failed')));server.listen(port,'127.0.0.1',done);});
 };
 const oldPin=new X509Certificate(approved.cert).fingerprint256,nextPin=new X509Certificate(other.cert).fingerprint256;
 expected={...aging[1].owned,mode:'autonomous'};const rotationToken=aging[1].token.accessToken;
 await replaceListener([oldPin,nextPin]);
 check((await call(rotationToken,approved)).status===200);passed('certificate-overlap-old-accepted');
 check((await call(rotationToken,other)).status===200);passed('certificate-overlap-successor-accepted');
 await replaceListener([nextPin]);const beforeRetired=operations;
 check((await call(rotationToken,approved)).status===403&&operations===beforeRetired);passed('retired-workload-certificate-denied');
 check((await call(rotationToken,other)).status===200);passed('successor-certificate-after-retirement-accepted');
 // Restore the harness's original isolated trust profile for the aging checks.
 await replaceListener([oldPin]);
 check((await call(rotationToken,other)).status===403);passed('removed-successor-certificate-denied-after-restoration');
 const waitUntil=Math.max(...aging.map(a=>a.token.claims.exp))*1000+1000;
 check(waitUntil-Date.now()>0&&waitUntil-Date.now()<=122000);
 let lastProgress=Date.now();
 while(Date.now()<waitUntil){
  await new Promise(done=>setTimeout(done,Math.min(1000,waitUntil-Date.now())));
  if(Date.now()-lastProgress>=30000){console.log(JSON.stringify({phase:'waiting-for-actual-PF-token-expiry',remainingSeconds:Math.max(0,Math.ceil((waitUntil-Date.now())/1000))}));lastProgress=Date.now();}
 }
 for(const entry of aging){
  expected={...entry.owned,mode:entry.mode};const before=operations;
  const store=new PolicyStore(process.env.POLICY_DATABASE!,[capability]);try{check(store.grant(entry.owned.id)?.state==='active');}finally{store.close();}
  check((await call(entry.token.accessToken)).status===401&&operations===before);passed(entry.mode+':actually-expired-token-denied-over-HTTPS');
  const fresh=await authority.issue(entry.owned.id,entry.mode,entry.login);
  check((await call(fresh.accessToken)).status===200&&operations===before+1);passed(entry.mode+':fresh-token-under-same-active-grant-accepted');
  await entry.owned.revoke();
 }
 // A separate real service is stopped to exercise fail-closed dependency behavior.
 const activeGrant=await grant(),activeToken=await authority.issue(activeGrant.id,'autonomous');
 const otherPolicy=await startPolicy();let outageCalls=0;
 try{
  const unavailable=await localToolAuthority(otherPolicy.origin);
  const outage=new ToolApi(unavailable.tool(async()=>{outageCalls++;return{authorized:true};}));
  await new Promise<void>(done=>{server.close(()=>done());server.closeAllConnections();});
  server=createToolServer({...approved,ca:approved.cert},outage,{certificateSha256:[new X509Certificate(approved.cert).fingerprint256]});
  await new Promise<void>(done=>server.listen(0,'127.0.0.1',done));port=server.address().port;
  check((await call(activeToken.accessToken)).status===200&&outageCalls===1);
  await otherPolicy.stop();
  check((await call(activeToken.accessToken)).status===403&&outageCalls===1);passed('stopped-independent-policy-denied-over-HTTPS');
 }finally{await otherPolicy.stop();}
 writeFileSync(resolve(run,'result.json'),JSON.stringify({status:'passed',checks,microsoftRequests:0,graphRequests:0},null,2),{mode:0o600});
}catch{
 writeFileSync(resolve(run,'result.json'),JSON.stringify({status:'failed',checks,microsoftRequests:0,graphRequests:0},null,2),{mode:0o600});
 console.error('Local tool HTTP verification failed; only sanitized evidence retained.');process.exitCode=1;
}finally{
 let cleanupFailed=false;
 for(const g of grants)try{await g.revoke();}catch{cleanupFailed=true;}
 if(server)await new Promise<void>(done=>{server.close(()=>done());server.closeAllConnections();});
 if(portal)await portal.stop();
 for(const path of certFiles)try{unlinkSync(path);}catch{cleanupFailed=true;}
 if(cleanupFailed){console.error('Local verification cleanup requires review.');process.exitCode=1;}
}
