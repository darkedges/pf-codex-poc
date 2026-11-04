import assert from 'node:assert/strict';
import {request} from 'node:https';
import {readFileSync,existsSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {SignJWT,importPKCS8} from 'jose';
import {startPersistentToolPolicy} from './run-tool-policy.mjs';
import {custody,rendererCertificate} from './tool-custody.mjs';
import {fetchRecord} from './tool-secrets.mjs';
import {vault,privateSave} from './common.mjs';
import {read} from '../pf/common.mjs';
const checks=[];const check=(name,value)=>{assert.ok(value,name);checks.push(name);};
let enrolledToolKey;
async function assertion(role,path,body,origin='https://localhost:9452'){
 return new SignJWT({method:'POST',body_sha256:createHash('sha256').update(JSON.stringify(body)).digest('base64url')}).setProtectedHeader({alg:'RS256',kid:'copilot-policy-'+role,typ:'policy-request+jwt'}).setIssuer('policy-'+role).setSubject('policy-'+role).setAudience(origin+path).setIssuedAt().setExpirationTime('60s').setJti(randomUUID()).sign(await importPKCS8(role==='tool'&&enrolledToolKey?enrolledToolKey:read('policy-'+role+'.private.pem'),'RS256'));
}
function post(path,body,token){return new Promise((done,reject)=>{const raw=JSON.stringify(body);const req=request('https://localhost:9452'+path,{method:'POST',ca:read('ca.pem'),rejectUnauthorized:true,headers:{'Content-Type':'application/json',Authorization:'Policy '+token,'Content-Length':Buffer.byteLength(raw)}},res=>{let text='';res.on('data',c=>{text+=c;if(text.length>32768)req.destroy(Error());});res.on('end',()=>{try{done({status:res.statusCode,body:JSON.parse(text)});}catch{reject(Error('Policy response unavailable'));}});res.on('error',reject);});const timer=setTimeout(()=>req.destroy(Error('Policy deadline')),3000);req.on('close',()=>clearTimeout(timer));req.on('error',()=>reject(Error('Policy unavailable')));req.end(raw);});}
function state(){const db=new DatabaseSync(resolve(custody,'policy.sqlite'),{readOnly:true});try{return{grants:Number(db.prepare('SELECT count(*) AS n FROM grants').get().n),consents:Number(db.prepare('SELECT count(*) AS n FROM consents').get().n),fixtures:Number(db.prepare("SELECT count(*) AS n FROM grants WHERE id='grant-container'").get().n),replays:Number(db.prepare('SELECT count(*) AS n FROM assertions').get().n)}}finally{db.close();}}
let service,clean=false;
try{
 if(existsSync(resolve(custody,'runtime-enrollment.json')))enrolledToolKey=(await fetchRecord((p,o)=>vault(p,{...o,...rendererCertificate()}))).record.policySigningKeyPem;
 service=await startPersistentToolPolicy();
 const first=state();check('persistent database has no fixture grant',first.fixtures===0);
 const lease=readFileSync(resolve(custody,'policy-authority-token'),'utf8');
 const health=await assertion('gateway','/v1/health',{});
 check('authenticated health succeeds',(await post('/v1/health',{},health)).status===200);
 check('unsigned request denied',(await post('/v1/health',{},'invalid')).status===401);
 check('wrong tool decision audience denied',(await post('/v1/health',{},await assertion('tool','/v1/health',{}))).status===401);
 check('fixed backend tool audience accepted',(await post('/v1/health',{},await assertion('tool','/v1/health',{},'https://tool-backend:7443'))).status===200);
 check('tool cannot call administration',(await post('/v1/grants',{},await assertion('tool','/v1/grants',{},'https://tool-backend:7443'))).status===401);
 const body={token:'invalid',capability:{scope:'copilot.invoke',resource:'sharepoint:approved-research'}};
 check('unverified delegated token denied',(await post('/v1/decisions',body,await assertion('tool','/v1/decisions',body,'https://tool-backend:7443'))).status===403);
 await service.stop();service=undefined;
 check('shutdown removes own credential and lock',!existsSync(resolve(custody,'policy-authority-token'))&&!existsSync(resolve(custody,'policy-authority-lease.json'))&&!existsSync(resolve(custody,'policy-service.lock')));
 check('shutdown revokes own Vault lease',(await vault('/transit/sign/consent-authority/sha2-256',{method:'POST',body:{input:'dGVzdA=='},token:lease})).status===403);
 service=await startPersistentToolPolicy();
 const second=state();check('restart preserves grants and consent counts',second.grants===first.grants&&second.consents===first.consents&&second.fixtures===0);
 check('replay is denied across actual process restart',(await post('/v1/health',{},health)).status===401);
 check('fresh proof succeeds after restart',(await post('/v1/health',{},await assertion('gateway','/v1/health',{}))).status===200);
 check('replay ledger persisted',second.replays>=2);
 await service.stop();service=undefined;
 await assert.rejects(post('/v1/health',{},'invalid'));check('stopped service unavailable',true);
 clean=!existsSync(resolve(custody,'policy-service.lock'))&&!existsSync(resolve(custody,'policy-authority-token'));
}catch{console.error(JSON.stringify({error:'Persistent local policy verification failed',lastCompletedCheck:checks.at(-1)??'none'}));process.exitCode=1;}
finally{
 if(service)try{await service.stop();clean=true;}catch{process.exitCode=1;console.error('Policy cleanup requires custody review');}
 const receipt={completedAt:new Date().toISOString(),passed:process.exitCode!==1,checks:checks.length,serviceStopped:clean,publicRoutesChanged:false,persistentToolStarted:false};privateSave('tool-policy-validation.json',receipt);console.log(JSON.stringify(receipt));
}
