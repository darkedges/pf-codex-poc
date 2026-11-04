import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve,sep} from 'node:path';
import {execFileSync} from 'node:child_process';
import {X509Certificate,randomBytes} from 'node:crypto';
import {generateKeyPair,exportPKCS8,exportJWK,SignJWT,jwtVerify} from 'jose';
import {request} from 'node:https';
import {loadToolRuntime} from '../../src/copilot/tool-runtime.ts';
const directory=mkdtempSync(resolve(tmpdir(),'tool-runtime-test-')),path=resolve(directory,'runtime.json');
const signing=await generateKeyPair('RS256'),workload=await generateKeyPair('RS256',{extractable:true});
let cert:Buffer,key:Buffer;
const config=()=>({version:1,admission:{maxConcurrentRequests:16,perWorkloadRequestsPerMinute:60,maxConnections:128},trust:{issuer:'https://pf.test',jwksUri:'https://pf.test/pf/JWKS',audience:'api://copilot-tool',algorithms:['RS256'],keyIds:['tool-key'],organisations:['partner'],actorIssuers:['https://agents.test'],maxLifetimeSeconds:120},policy:{origin:'https://policy.test',clientId:'tool-workload',keyId:'policy-key'},clientCertificateSha256:[new X509Certificate(cert).fingerprint256],timeouts:{jwksMs:1500,policyMs:1500,toolMs:5000}});
before(async()=>{
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',resolve(directory,'tool-server-key.pem'),'-out',resolve(directory,'tool-server-cert.pem'),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-days','1'],{stdio:'ignore',windowsHide:true,timeout:15000});
 mkdirSync(resolve(directory,'audit'));writeFileSync(resolve(directory,'tool-audit-key'),randomBytes(32).toString('hex'));
 cert=readFileSync(resolve(directory,'tool-server-cert.pem'));key=readFileSync(resolve(directory,'tool-server-key.pem'));
 for(const name of ['tool-client-ca.pem','tool-outbound-ca.pem'])writeFileSync(resolve(directory,name),cert);
 writeFileSync(resolve(directory,'tool-policy-key.pem'),await exportPKCS8(workload.privateKey));
});
after(()=>{if(!directory.startsWith(resolve(tmpdir())+sep)||!directory.includes('tool-runtime-test-'))throw Error('Unsafe test cleanup');rmSync(directory,{recursive:true,force:true});});
const env=()=>({TOOL_MODE:'verified',TOOL_CONFIG_FILE:path,TOOL_SECRETS_DIR:directory,TOOL_AUDIT_DIR:resolve(directory,'audit'),NODE_EXTRA_CA_CERTS:resolve(directory,'tool-outbound-ca.pem')});
const save=(value:any)=>writeFileSync(path,JSON.stringify(value));
test('runtime composes real JOSE, signed PDP and mTLS with a fixed diagnostic',async()=>{
 save(config());let decisions=0;
 const transport=async(url:unknown,init?:RequestInit)=>{
  if(String(url)==='https://pf.test/pf/JWKS')return Response.json({keys:[{...await exportJWK(signing.publicKey),kid:'tool-key',alg:'RS256',use:'sig'}]});
  assert.equal(String(url),'https://policy.test/v1/decisions');decisions++;
  const proof=new Headers(init?.headers).get('authorization')!.slice('Policy '.length);
  await jwtVerify(proof,workload.publicKey,{issuer:'tool-workload',audience:'https://policy.test/v1/decisions'});
  const body=JSON.parse(String(init?.body));assert.deepEqual(body.capability,{scope:'copilot.invoke',resource:'sharepoint:approved-research'});
  return Response.json({permit:true,decisionId:'approved',grantVersion:1});
 };
 const runtime=await loadToolRuntime(env(),{fetch:transport});
 assert.equal(runtime.server.listening,false);
 await new Promise<void>(done=>runtime.server.listen(0,'127.0.0.1',done));
 try{
  const now=Math.floor(Date.now()/1000),token=await new SignJWT({sub:'human',act:{iss:'https://agents.test',sub:'agent'},org_id:'partner',delegation_id:'grant',execution_mode:'autonomous',scope:'copilot.invoke',iat:now,nbf:now,exp:now+60,jti:'test-proof'}).setIssuer('https://pf.test').setAudience('api://copilot-tool').setProtectedHeader({alg:'RS256',kid:'tool-key'}).sign(signing.privateKey);
  const result=await new Promise<any>((done,reject)=>{const req=request({host:'127.0.0.1',port:(runtime.server.address() as any).port,servername:'localhost',path:'/v1/tools/verify-access',method:'POST',ca:cert,cert,key,agent:false,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'}},res=>{let body='';res.on('data',c=>body+=c);res.on('end',()=>done({status:res.statusCode,body:JSON.parse(body)}));});req.on('error',reject);req.end('{}');});
  assert.deepEqual(result,{status:200,body:{authorized:true}});assert.equal(decisions,2);
 }finally{await new Promise<void>(done=>{runtime.server.close(()=>done());runtime.server.closeAllConnections();});}
});
for(const mutate of [p=>p.mode='mock',p=>p.admission=null,p=>p.admission.perWorkloadRequestsPerMinute=0,p=>p.trust.audience='api://copilot-broker',p=>p.trust.jwksUri='http://pf.test/keys',p=>p.trust.keyIds=[],p=>p.trust.secret='PRIVATE',p=>p.policy.origin='https://policy.test/other',p=>p.clientCertificateSha256=[],p=>p.timeouts.toolMs=999999])test('unsafe or ambiguous runtime config fails before a listener opens',async()=>{
 const p=config();mutate(p);save(p);await assert.rejects(loadToolRuntime(env()),{message:'configuration'});
});
test('runtime rejects missing authority and TLS bypass environment without exposing inputs',async()=>{
 save(config());for(const change of [{TOOL_MODE:'mock'},{TOOL_AUDIT_DIR:''},{TOOL_CONFIG_FILE:'relative.json'},{TOOL_SECRETS_DIR:''},{NODE_EXTRA_CA_CERTS:''},{NODE_TLS_REJECT_UNAUTHORIZED:'0'}])await assert.rejects(loadToolRuntime({...env(),...change}),{message:'configuration'});
});
test('runtime refuses mismatched TLS key and certificate',async()=>{
 save(config());const original=readFileSync(resolve(directory,'tool-server-key.pem'));
 try{writeFileSync(resolve(directory,'tool-server-key.pem'),await exportPKCS8(workload.privateKey));await assert.rejects(loadToolRuntime(env()),{message:'configuration'});}finally{writeFileSync(resolve(directory,'tool-server-key.pem'),original);}
});
test('runtime readiness verifies credentials, pinned public JWKS and signed policy health without granting tool authority',async()=>{
 save(config());let healthy=true,approvedKid=true,healthCalls=0;
 const transport=async(url:unknown,init?:RequestInit)=>{
  if(String(url)==='https://pf.test/pf/JWKS')return Response.json({keys:[{...await exportJWK(signing.publicKey),kid:approvedKid?'tool-key':'unapproved-key',use:'sig',alg:'RS256'}]});
  assert.equal(String(url),'https://policy.test/v1/health');healthCalls++;
  assert.deepEqual(JSON.parse(String(init?.body)),{});
  await jwtVerify(new Headers(init?.headers).get('authorization')!.slice(7),workload.publicKey,{audience:'https://policy.test/v1/health'});
  return Response.json({ready:healthy});
 };
 const one=await loadToolRuntime(env(),{fetch:transport});assert.equal(await one.ready(),true);assert.equal(healthCalls,1);
 healthy=false;assert.equal(await(await loadToolRuntime(env(),{fetch:transport})).ready(),false);
 healthy=true;approvedKid=false;assert.equal(await(await loadToolRuntime(env(),{fetch:transport})).ready(),false);
 approvedKid=true;const missing=await loadToolRuntime(env(),{fetch:transport});
 const file=resolve(directory,'tool-policy-key.pem'),original=readFileSync(file);try{writeFileSync(file,'CHANGED');assert.equal(await missing.ready(),false);}finally{writeFileSync(file,original);}
 assert.equal(one.server.listening,false);
});
