import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {request} from 'node:https';
import {createAgentPortalServer} from '../../src/consent/agent-server.ts';
const directory=mkdtempSync(join(tmpdir(),'agent-http-'));let tls:any;
before(()=>{execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(directory,'key.pem'),'-out',join(directory,'cert.pem'),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-days','1'],{stdio:'ignore',windowsHide:true,timeout:15000});tls={key:readFileSync(join(directory,'key.pem')),cert:readFileSync(join(directory,'cert.pem'))};});
after(()=>rmSync(directory,{recursive:true,force:true}));
async function fixture(options:any={}){
 let calls=0,ready=true;const observations:any[]=[];
 const server=createAgentPortalServer(tls,{handle:async()=>{calls++;if(options.pause)await options.pause;return{status:200,headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'},html:'<h1>Portal</h1>'};}},{origin:'https://agent.test',maxConcurrent:2,maxConnections:8,requestsPerMinute:60,ready:()=>ready,observe:e=>observations.push(e),...options.controls});
 await new Promise<void>(done=>server.listen(0,'127.0.0.1',done));const port=(server.address() as any).port;
 const call=(method='GET',path='/',headers:any={},body='')=>new Promise<any>((done,reject)=>{const req=request({hostname:'localhost',servername:'localhost',port,method,path,ca:tls.cert,headers:{Host:'agent.test',...headers}},res=>{let body='';res.on('data',c=>body+=c);res.on('end',()=>done({status:res.statusCode,headers:res.headers,body}));});req.on('error',reject);req.end(body);});
 return{server,call,calls:()=>calls,observations,unready:()=>{ready=false;},close:async()=>{server.closeAllConnections();await new Promise<void>(done=>server.close(()=>done()));}};
}
test('portal HTTPS serves the approved host with no-store and no cross-origin access',async()=>{
 const f=await fixture();try{const r=await f.call();assert.equal(r.status,200);assert.equal(r.headers['cache-control'],'no-store');assert.equal(r.headers['access-control-allow-origin'],undefined);assert.equal(f.calls(),1);}finally{await f.close();}
});
test('form pages preserve same-origin browser POST Origin while suppressing cross-origin referrers',async()=>{
 const f=await fixture();try{
  assert.equal((await f.call()).headers['referrer-policy'],'same-origin');
  for(const Origin of ['null','https://evil.test'])assert.equal((await f.call('POST','/login',{Origin,'Content-Type':'application/x-www-form-urlencoded'},'csrf=synthetic')).status,403);
  assert.equal(f.calls(),1);
 }finally{await f.close();}
});
test('host, origin, authority headers, methods and route substitutions never reach portal',async()=>{
 const f=await fixture();try{
  for(const headers of [{Host:'evil.test'},{Authorization:'Bearer synthetic'},{'X-User-Id':'forged'},{Origin:['https://agent.test','https://evil.test']}])assert.ok((await f.call('GET','/',headers)).status>=400);
  assert.equal((await f.call('POST','/approve',{'Content-Type':'application/x-www-form-urlencoded',Origin:'https://evil.test'},'csrf=value')).status,403);
  assert.equal((await f.call('GET','/admin')).status,404);assert.equal((await f.call('GET','/check')).status,404);assert.equal((await f.call('PUT','/')).status,404);assert.equal((await f.call('GET','/?prompt=hello')).status,404);assert.equal(f.calls(),0);
 }finally{await f.close();}
});
test('unexpected media, encoding and oversized bodies are rejected before portal execution',async()=>{
 const f=await fixture();try{
  assert.equal((await f.call('POST','/approve',{Origin:'https://agent.test','Content-Type':'application/json'},'{}')).status,400);
  assert.equal((await f.call('POST','/approve',{Origin:'https://agent.test','Content-Type':'application/x-www-form-urlencoded','Content-Encoding':'gzip'},'data')).status,400);
  assert.equal((await f.call('POST','/approve',{Origin:'https://agent.test','Content-Type':'application/x-www-form-urlencoded'},'x'.repeat(1025))).status,413);assert.equal(f.calls(),0);
 }finally{await f.close();}
});
test('dependency failure and draining deny requests without exposing private status',async()=>{
 const f=await fixture();try{f.unready();assert.equal((await f.call()).status,503);assert.equal(f.calls(),0);f.server.beginDrain();assert.equal((await f.call()).status,503);}finally{await f.close();}
});
test('global admission rate cannot be bypassed by spoofing forwarded addresses',async()=>{
 const f=await fixture({controls:{requestsPerMinute:1}});try{assert.equal((await f.call()).status,200);const r=await f.call('GET','/',{'X-Forwarded-For':'different'});assert.equal(r.status,429);assert.equal(f.calls(),1);assert.ok(f.observations.every(e=>Object.keys(e).sort().join()==='event,status'));}finally{await f.close();}
});
