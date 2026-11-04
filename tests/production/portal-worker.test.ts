import test,{before,after} from 'node:test';import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';import {execFileSync} from 'node:child_process';import {request} from 'node:https';
import {startPortalWorker} from '../../scripts/vault/portal-worker-host.ts';
const directory=mkdtempSync(join(tmpdir(),'portal-worker-'));let tls:any;
before(()=>{execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(directory,'key.pem'),'-out',join(directory,'cert.pem'),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-days','1'],{stdio:'ignore',windowsHide:true,timeout:15000});tls={key:readFileSync(join(directory,'key.pem'),'utf8'),cert:readFileSync(join(directory,'cert.pem'),'utf8')};});
after(()=>rmSync(directory,{recursive:true,force:true}));
const publicConfig={origin:'https://agent.copilot.darkedges.com',capability:{scope:'copilot.invoke',resource:'sharepoint:approved-research'},agent:{issuer:'https://agents.test',subject:'partner:agent'}};
const get=(port:number)=>new Promise<any>((done,reject)=>{const req=request({hostname:'localhost',servername:'localhost',port,path:'/',ca:tls.cert,headers:{Host:'agent.copilot.darkedges.com'}},res=>{let body='';res.on('data',c=>body+=c);res.on('end',()=>done({status:res.statusCode,body,headers:res.headers}));});req.on('error',reject);req.end();});
test('actual child worker stages a loopback page without any credential RPC or sign-in enabled',async()=>{
 let calls=0;const worker=await startPortalWorker({tls,public:publicConfig,expiresAt:Date.now()+120000,port:0,methods:{'oidc.start':async()=>{calls++;throw Error('PRIVATE');}}});
 try{const page=await get(worker.port);assert.equal(page.status,200);assert.match(page.body,/Live testing is not enabled/);assert.equal(calls,0);assert.ok(!page.body.includes('PRIVATE'));}finally{await worker.stop();}
 await assert.rejects(get(worker.port));
});
test('dependency failure heartbeat closes the owned worker and its listener',async()=>{
 const worker=await startPortalWorker({tls,public:publicConfig,expiresAt:Date.now()+120000,port:0,methods:{}});worker.heartbeat(false,false);await worker.exited;await assert.rejects(get(worker.port));
});
test('repeatable presentation flag does not enable authentication without controller authority',async()=>{let calls=0;const worker=await startPortalWorker({tls,public:{...publicConfig,repeatableSessions:true},expiresAt:Date.now()+120000,port:0,methods:{'oidc.start':async()=>{calls++;throw Error('PRIVATE');}}});try{const page=await get(worker.port);assert.equal(page.status,200);assert.match(page.body,/Live testing is not enabled/);assert.equal(calls,0);}finally{await worker.stop();}});
test('controller availability update reaches the next page without renewing dependency health',async()=>{const worker=await startPortalWorker({tls,public:{...publicConfig,repeatableSessions:true},expiresAt:Date.now()+120000,port:0,methods:{}});try{assert.match((await get(worker.port)).body,/Live testing is not enabled/);worker.budget(true);assert.match((await get(worker.port)).body,/Start with sign-in/);worker.budget(false);assert.match((await get(worker.port)).body,/Live testing is not enabled/);worker.heartbeat(false,false);await worker.exited;worker.budget(true);await assert.rejects(get(worker.port));}finally{await worker.stop();}});
test('enabled worker forwards only its cookie-bound sign-in transaction over controller RPC',async()=>{
 let calls=0,settled=0;const worker=await startPortalWorker({tls,public:publicConfig,expiresAt:Date.now()+120000,port:0,afterCall:()=>{settled++;throw Error('PRIVATE');},methods:{'oidc.start':async(...args)=>{calls++;assert.ok(args.every((v:string)=>/^[A-Za-z0-9_-]{43}$/.test(v)));return'https://pf-a.copilot.darkedges.com/as/authorization.oauth2';}}});
 try{worker.heartbeat(true,true);const home=await get(worker.port),csrf=home.body.match(/name="csrf" value="([^"]+)"/)[1],cookie=home.headers['set-cookie'][0].split(';')[0];
  const result=await new Promise<any>((done,reject)=>{const req=request({hostname:'localhost',servername:'localhost',port:worker.port,path:'/login',method:'POST',ca:tls.cert,headers:{Host:'agent.copilot.darkedges.com',Origin:'https://agent.copilot.darkedges.com',Cookie:cookie,'Content-Type':'application/x-www-form-urlencoded'}},res=>{res.resume();res.on('end',()=>done({status:res.statusCode,location:res.headers.location}));});req.on('error',reject);req.end('csrf='+csrf);});assert.equal(result.status,302);assert.equal(result.location,'https://pf-a.copilot.darkedges.com/as/authorization.oauth2');assert.equal(calls,1);assert.equal(settled,1);
 }finally{await worker.stop();}
});
