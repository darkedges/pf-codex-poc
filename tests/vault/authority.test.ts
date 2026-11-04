import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync,writeFileSync,readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { request as httpsRequest } from 'node:https';
import { randomUUID } from 'node:crypto';
import { importJWK,importPKCS8,SignJWT,jwtVerify,decodeJwt } from 'jose';
import { VaultTransitSigner } from '../../src/identity/assertion-signer.ts';
import { PolicyClient } from '../../src/policy/client.ts';
import { startPolicy } from '../../scripts/pf/run-policy.mjs';
import { startConsent } from '../../scripts/pf/run-consent.mjs';
import { runConsentedExchange } from '../../scripts/pf/consent-exchange.ts';
import { capability } from '../../scripts/pf/policy-setup.ts';
import { local,load,read,nodes,call } from '../../scripts/pf/common.mjs';
import { profile } from '../../scripts/pf/config.mjs';
import { LocalBrowser,forms } from '../live/local-browser.mjs';
import { vault,operator,privateLoad,keyName,runtimeToken } from '../../scripts/vault/common.mjs';
import { rotateAuthority,retirePrevious } from '../../scripts/vault/rotate.mjs';

const container='federated-copilot-authority-vault-1',run=resolve(local,'vault-tests',randomUUID());
mkdirSync(run,{recursive:true});
const tokenFile=resolve(run,'runtime-token'),seenTokens:string[]=[];
const env={...process.env,POLICY_DATABASE:resolve(run,'policy.sqlite'),AUTHORITY_SIGNER:'vault-transit',AUTHORITY_VAULT_TOKEN_FILE:tokenFile};
let policy:Awaited<ReturnType<typeof startPolicy>>,portal:Awaited<ReturnType<typeof startConsent>>,browser:LocalBrowser,grantId:string,lease;
const key=(name:string)=>importPKCS8(read(`${name}.private.pem`),'RS256');
async function credential(ttl='15m'){
 lease=await runtimeToken(ttl);seenTokens.push(lease.client_token);writeFileSync(tokenFile,lease.client_token,{mode:0o600});return lease;
}
async function signer(config=load('authority-transit-config.json')){return new VaultTransitSigner({...config,publicKey:await importJWK(config.publicJwk,'RS256'),token:()=>readFileSync(tokenFile,'utf8')});}
async function startAndApprove(){
 policy=await startPolicy(env);portal=await startConsent({...env,POLICY_API_ORIGIN:policy.origin});browser=new LocalBrowser(portal.origin);
 let page=await browser.request(portal.origin+'/');let form=forms(page.html).find(f=>f.action==='/login');assert.ok(form);
 page=await browser.submit(form);form=forms(page.html).find(f=>'pf.pass'in f.fields);assert.ok(form);
 page=await browser.submit(form,{'pf.username':profile.human,'pf.pass':read('login-password'),'pf.ok':'clicked'});form=forms(page.html).find(f=>'pf.oauth.authz.consent'in f.fields);assert.ok(form);
 page=await browser.submit(form,{'pf.oauth.authz.consent':'allow'});assert.equal(page.status,200);form=forms(page.html).find(f=>f.action==='/approve');assert.ok(form);
 page=await browser.submit(form,{duration:'3600',autonomous:'on'});assert.equal(page.status,200);form=forms(page.html).find(f=>f.action==='/revoke');assert.ok(form);grantId=form.fields.grantId;
}
async function stopServices(){if(portal)await portal.stop();if(policy)await policy.stop();}
async function both(expected:number){for(const mode of ['interactive','autonomous']){const home=await browser.request(portal.origin+'/');assert.equal(home.status,200);const form=forms(home.html).find(f=>f.action==='/execute'&&f.fields.mode===mode&&f.fields.grantId===grantId);assert.ok(form);const result=await browser.submit(form);assert.equal(result.status,expected,`${mode} result`);if(expected===200)assert.ok(result.html.includes('Access check passed'));}}
async function unseal(){
 let status;for(let n=0;n<40;n++){try{status=await vault('/sys/seal-status');if(status.status===200)break;}catch{}await new Promise(r=>setTimeout(r,250));}
 assert.equal(status?.status,200,'Vault must restart with verified TLS');
 if(status.value.sealed){const result=await vault('/sys/unseal',{method:'POST',body:{key:privateLoad('bootstrap.json').keys_base64[0]}});assert.equal(result.status,200);assert.equal(result.value.sealed,false);}
}
function docker(...args:string[]){const r=spawnSync('docker',args,{encoding:'utf8',windowsHide:true,maxBuffer:8*1024*1024,timeout:20000});assert.equal(r.status,0,'Dedicated Vault container operation failed');return r.stdout;}
async function actorProof(){return new SignJWT({sub:profile.agent}).setProtectedHeader({alg:'RS256',kid:'copilot-agent'}).setIssuer(profile.agentIssuer).setAudience('api://pf-a/agent-proof').setIssuedAt().setNotBefore('0s').setExpirationTime('120s').setJti(randomUUID()).sign(await key('agent'));}
async function pfA(subject:string,actor:string){
 const authentication=await new SignJWT({}).setProtectedHeader({alg:'RS256',kid:'copilot-consent-gateway-1',typ:'client-authentication+jwt'}).setIssuer('consent-gateway-1').setSubject('consent-gateway-1').setAudience(nodes.a.issuer).setIssuedAt().setExpirationTime('60s').setJti(randomUUID()).sign(await key('consent-gateway-1'));
 return call(nodes.a.issuer+'/as/token.oauth2',{method:'POST',form:true,body:{grant_type:'urn:ietf:params:oauth:grant-type:token-exchange',client_id:'consent-gateway-1',client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:authentication,subject_token:subject,subject_token_type:'urn:example:token-type:consented-autonomous',actor_token:actor,actor_token_type:'urn:example:token-type:agent-proof',resource:'urn:copilot:consent:gateway-2',scope:profile.scope,requested_token_type:'urn:ietf:params:oauth:token-type:access_token'}});
}
before(async()=>{await credential();await startAndApprove();});
after(async()=>{await stopServices();if(lease)await operator('/auth/token/revoke-accessor',{method:'POST',body:{accessor:lease.accessor}});});

test('real Vault key is non-exportable, audited, and runtime credential has only signing permission',async()=>{
 const metadata=(await operator('/transit/keys/'+keyName)).data;assert.equal(metadata.exportable,false);assert.equal(metadata.allow_plaintext_backup,false);
 const root=privateLoad('bootstrap.json').root_token;
 for(const path of [`/transit/export/signing-key/${keyName}`,`/transit/backup/${keyName}`]){const r=await vault(path,{token:root});assert.ok(r.status>=400&&!r.value?.data&&r.value?.errors?.some(e=>/export|backup|disallowed/i.test(e)),'Even operator must receive an explicit export/backup refusal');}
 const token=readFileSync(tokenFile,'utf8');
 for(const path of [`/transit/keys/${keyName}`,`/transit/export/signing-key/${keyName}`,`/transit/backup/${keyName}`,'/sys/mounts'])assert.equal((await vault(path,{token})).status,403);
 for(const path of [`/transit/keys/${keyName}/rotate`,'/transit/keys/unapproved'])assert.equal((await vault(path,{method:'POST',token,body:{}})).status,403);
 assert.equal((await vault(`/transit/sign/${keyName}/sha2-256`,{method:'POST',token:'unregistered-agent-credential',body:{input:'dGVzdA=='}})).status,403);
 const s=await signer(),raw=await s.sign({sub:'signature-check',exp:Math.floor(Date.now()/1000)+60});assert.equal((await jwtVerify(raw,await importJWK(load('authority-transit-config.json').publicJwk,'RS256'))).payload.sub,'signature-check');
});
test('both execution modes preserve human and actor through live Vault and PF A/B',async()=>{
 await both(200);const output=await runConsentedExchange(grantId,'autonomous',undefined,policy.origin);assert.equal(output.subject,profile.human);assert.equal(output.actor,profile.agent);
});
test('revoked Vault credential blocks both modes; replacing the lease recovers without fallback',async()=>{
 await operator('/auth/token/revoke-accessor',{method:'POST',body:{accessor:lease.accessor}});lease=undefined;
 try{await both(503);}finally{await credential();}await both(200);
});
test('expired Vault credential blocks both modes',async()=>{
 const valid=readFileSync(tokenFile,'utf8'),expired=await runtimeToken('1s');seenTokens.push(expired.client_token);writeFileSync(tokenFile,expired.client_token,{mode:0o600});
 try{await new Promise(r=>setTimeout(r,1500));await both(503);}finally{writeFileSync(tokenFile,valid,{mode:0o600});}
});
test('sealed Vault blocks both modes until explicitly unsealed',async()=>{
 await operator('/sys/seal',{method:'POST',body:{}});try{await both(503);}finally{await unseal();}await both(200);
});
test('stopped Vault blocks both modes and persistent keys survive container restart',async()=>{
 const version=load('authority-transit-config.json').version;docker('stop',container);
 try{await both(503);}finally{docker('start',container);await unseal();}
 assert.equal((await operator('/transit/keys/'+keyName)).data.latest_version,version);await both(200);
});
test('real Vault TLS rejects an empty CA trust store',async()=>{
 await assert.rejects(new Promise((done,reject)=>{const req=httpsRequest('https://localhost:9470/v1/sys/health',{ca:[],rejectUnauthorized:true},()=>done(undefined));req.setTimeout(3000,()=>req.destroy());req.on('error',reject);req.end();}));
});
test('PF overlap accepts old/new signing versions; explicit retirement rejects the old key',async()=>{
 const oldConfig=load('authority-transit-config.json'),oldSigner=await signer(oldConfig),staged=await rotateAuthority();assert.equal(staged.config.version,oldConfig.version+1);
 await both(200); // Existing authority process still signs with the previous pinned version.
 await stopServices();await startAndApprove();await both(200); // New process selects the staged key.
 const actor=await actorProof(),client=new PolicyClient({origin:policy.origin,clientId:'policy-agent',keyId:load('policy-agent.jwks.json').keys[0].kid,key:await key('policy-agent'),capability,timeoutMs:5000});
 const issued=await client.request('/v1/assertions',{grantId,mode:'autonomous',operation:capability.scope,agentToken:actor});
 const old=await oldSigner.sign({...decodeJwt(String(issued.assertion)),jti:randomUUID()});
 await jwtVerify(old,await importJWK(oldConfig.publicJwk,'RS256'));assert.equal((await pfA(old,actor)).status,200);
 await retirePrevious();await assert.rejects(oldSigner.sign({sub:'retired',exp:Math.floor(Date.now()/1000)+60}));
 assert.equal((await pfA(old,actor)).status,400,'PF must reject even an otherwise valid unexpired retired-key assertion');
 await both(200);
 const wrong=await signer({...staged.config,publicJwk:oldConfig.publicJwk});await assert.rejects(wrong.sign({sub:'substitution'}));
});
test('Vault audit/server logs and authority telemetry contain no JWTs, operator or runtime credentials',()=>{
 const audit=docker('exec',container,'cat','/vault/file/audit.jsonl'),logs=docker('logs',container),telemetry=readFileSync(resolve(run,'policy-telemetry.jsonl'),'utf8');
 assert.ok(audit.length>0);const combined=audit+logs+telemetry;assert.ok(!/eyJ[A-Za-z0-9_-]{7,}(?:\.[A-Za-z0-9_-]+){2,4}/.test(combined),'Logs must not contain compact JWTs');
 const bootstrap=privateLoad('bootstrap.json');for(const secret of [bootstrap.root_token,...bootstrap.keys_base64,...seenTokens])assert.ok(!combined.includes(secret),'Logs must not contain operator/runtime credentials');
});
