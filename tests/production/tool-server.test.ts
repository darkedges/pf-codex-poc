import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve,sep} from 'node:path';
import {X509Certificate} from 'node:crypto';
import {request} from 'node:https';
import {ToolApi} from '../../src/copilot/tool-api.ts';
import {PolicyProtectedTool} from '../../src/copilot/tool-authority.ts';
import {createToolServer} from '../../src/copilot/tool-server.ts';

// Ephemeral test certificates only; no local PF/operator credentials are read.
const directory=mkdtempSync(resolve(tmpdir(),'federated-tool-test-'));
let approved:{key:Buffer;cert:Buffer},other:{key:Buffer;cert:Buffer};
before(()=>{
 const generate=(name:string)=>{
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',resolve(directory,name+'.key'),'-out',resolve(directory,name+'.pem'),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-days','1'],{stdio:'ignore',timeout:15000,windowsHide:true});
  return{key:readFileSync(resolve(directory,name+'.key')),cert:readFileSync(resolve(directory,name+'.pem'))};
 };
 approved=generate('approved');other=generate('other');
});
after(()=>{if(!directory.startsWith(resolve(tmpdir())+sep)||!directory.includes('federated-tool-test-'))throw Error('Unsafe test cleanup');rmSync(directory,{recursive:true,force:true});});
async function fixture(pins?:string[],controls:any={},operation?:()=>Promise<void>){
 let allow=true,calls=0;
 const tool=new PolicyProtectedTool({timeoutMs:500,verifier:{verify:async(raw:string)=>{if(raw!=='test-tool-proof')throw Error('private');return{exp:Math.floor(Date.now()/1000)+60} as any;}},authorise:async()=>{if(!allow)throw Error('private');},operation:async()=>{calls++;if(operation)await operation();return{authorized:true,privateField:'MUST_NOT_ESCAPE'};}});
 const api=new ToolApi(tool),pin=new X509Certificate(approved.cert).fingerprint256;
 const server=createToolServer({...approved,ca:[approved.cert,other.cert]},api,{certificateSha256:pins??[pin]},controls);
 await new Promise<void>(done=>server.listen(0,'127.0.0.1',done));
 const port=(server.address() as any).port;
 const call=(client:typeof approved|null=approved,headers:Record<string,string|string[]>={},body='{}',path='/v1/tools/verify-access')=>new Promise<{status:number;body:any;headers:any}>((done,reject)=>{
  const req=request({host:'127.0.0.1',port,servername:'localhost',method:path.startsWith('/health/')?'GET':'POST',path,ca:approved.cert,...client,agent:false,headers:{...(path.startsWith('/health/')?{}:{Authorization:'Bearer test-tool-proof','Content-Type':'application/json'}),...headers},timeout:2000},res=>{let text='';res.on('data',c=>text+=c);res.on('end',()=>done({status:res.statusCode!,body:JSON.parse(text),headers:res.headers}));});
  req.on('error',reject);req.on('timeout',()=>req.destroy(Error('Test deadline')));req.end(path.startsWith('/health/')?undefined:body);
 });
 return{call,calls:()=>calls,deny:()=>{allow=false;},stop:()=>new Promise<void>(done=>{server.close(()=>done());server.closeAllConnections();})};
}
test('HTTPS tool requires certificate and token independently, strips callback data, and enforces revocation',async()=>{
 const s=await fixture();try{
  const ok=await s.call();assert.equal(ok.status,200);assert.deepEqual(ok.body,{authorized:true});assert.equal(ok.headers['cache-control'],'no-store');
  const bad=await s.call(approved,{Authorization:'Bearer invalid'});assert.equal(bad.status,401);assert.equal(s.calls(),1);
  s.deny();assert.equal((await s.call()).status,403);assert.equal(s.calls(),1);
 }finally{await s.stop();}
});
test('TLS-valid but unapproved workload certificate is denied before operation',async()=>{
 const s=await fixture();try{assert.equal((await s.call(other)).status,403);assert.equal(s.calls(),0);}finally{await s.stop();}
});
test('missing client certificate fails TLS even with a valid bearer',async()=>{
 const s=await fixture();try{await assert.rejects(s.call(null),(error:any)=>/TLS|SSL/.test(error.code));assert.equal(s.calls(),0);}finally{await s.stop();}
});
test('duplicate credentials, wrong media type and oversized body never invoke operation',async()=>{
 const s=await fixture();try{
  assert.equal((await s.call(approved,{Authorization:['Bearer test-tool-proof','Bearer other']})).status,401);
  assert.equal((await s.call(approved,{'Content-Type':'text/plain'})).status,400);
  assert.equal((await s.call(approved,{},' '.repeat(1025))).status,413);assert.equal(s.calls(),0);
 }finally{await s.stop();}
});
test('tool HTTPS refuses missing CA, empty or malformed workload pins',()=>{
 const api=new ToolApi(new PolicyProtectedTool({verifier:{verify:async()=>({exp:1} as any)},authorise:async()=>{},operation:async()=>({authorized:true}),timeoutMs:500}));
 for(const pins of [[],['invalid'],['AA:BB']])assert.throws(()=>createToolServer({...approved,ca:approved.cert},api,{certificateSha256:pins}));
 assert.throws(()=>createToolServer(approved,api,{certificateSha256:[new X509Certificate(approved.cert).fingerprint256]}));
});
test('certificate rollover accepts overlap then rejects retired certificate on replacement listener',async()=>{
 const oldPin=new X509Certificate(approved.cert).fingerprint256,newPin=new X509Certificate(other.cert).fingerprint256;
 const pins=[oldPin,newPin],overlap=await fixture(pins);
 try{
  pins.length=0; // Caller mutation cannot alter a running server's trust snapshot.
  assert.equal((await overlap.call(approved)).status,200);assert.equal((await overlap.call(other)).status,200);
 }finally{await overlap.stop();}
 const retired=await fixture([newPin]);try{
  assert.equal((await retired.call(approved)).status,403);assert.equal((await retired.call(other)).status,200);assert.equal(retired.calls(),1);
 }finally{await retired.stop();}
});
test('mTLS health separates liveness from dependency readiness without a human bearer',async()=>{
 let ready=false,probes=0;const s=await fixture(undefined,{ready:async()=>{probes++;return ready;}});
 try{
  assert.deepEqual((await s.call(approved,{},'','/health/live')).body,{live:true});
  assert.equal((await s.call(approved,{},'','/health/ready')).status,503);ready=true;
  assert.deepEqual((await s.call(approved,{},'','/health/ready')).body,{ready:true});
  assert.equal((await s.call(other,{},'','/health/ready')).status,403);assert.equal(probes,2);assert.equal(s.calls(),0);
 }finally{await s.stop();}
});
test('HTTPS admission rejects saturation without queueing, restores capacity, and applies per-certificate rates',async()=>{
 let entered:()=>void,release:()=>void;const started=new Promise<void>(done=>entered=done),blocked=new Promise<void>(done=>release=done);let first=true;
 const pins=[new X509Certificate(approved.cert).fingerprint256,new X509Certificate(other.cert).fingerprint256];
 const s=await fixture(pins,{admission:{maxConcurrentRequests:1,perWorkloadRequestsPerMinute:2,maxConnections:8}},async()=>{if(first){first=false;entered();await blocked;}});
 try{
  const pending=s.call();await started;
  const denied=await s.call(other);assert.equal(denied.status,503);assert.equal(denied.body.error,'overloaded');assert.equal(denied.headers['retry-after'],'1');assert.equal(s.calls(),1);
  release();assert.equal((await pending).status,200);
  assert.equal((await s.call()).status,200);assert.equal((await s.call()).status,429);
  assert.equal((await s.call(other)).status,200);assert.equal(s.calls(),3);
 }finally{release();await s.stop();}
});
