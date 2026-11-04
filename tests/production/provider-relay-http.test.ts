import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve,sep} from 'node:path';
import {request,createServer} from 'node:https';
import {X509Certificate,createHash} from 'node:crypto';
import {ProviderToolRelay,ProviderToolRelayApi,connectionKeyAuthenticator} from '../../src/copilot/provider-tool-relay.ts';
import {createProviderRelayServer,createPrivateToolInvoker,providerRelayLifecycle,composeProviderToolConnection} from '../../src/copilot/provider-relay-http.ts';
import {createToolServer} from '../../src/copilot/tool-server.ts';
import {ToolApi} from '../../src/copilot/tool-api.ts';
import {PolicyProtectedTool} from '../../src/copilot/tool-authority.ts';
const directory=mkdtempSync(resolve(tmpdir(),'provider-relay-http-'));let approved:any,other:any;
before(()=>{const generate=(name:string)=>{execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',resolve(directory,name+'.key'),'-out',resolve(directory,name+'.pem'),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-days','1'],{stdio:'ignore',timeout:15000,windowsHide:true});return{key:readFileSync(resolve(directory,name+'.key')),cert:readFileSync(resolve(directory,name+'.pem'))};};approved=generate('approved');other=generate('other');});
after(()=>{if(!directory.startsWith(resolve(tmpdir())+sep)||!directory.includes('provider-relay-http-'))throw Error('Unsafe cleanup');rmSync(directory,{recursive:true,force:true});});
const listen=async(s:any)=>{await new Promise<void>(done=>s.listen(0,'127.0.0.1',done));return s.address().port;};
const stop=async(s:any)=>{await new Promise<void>(done=>{s.close(()=>done());s.closeAllConnections();});};
async function fixture(options:any={}){
 const now=Math.floor(Date.now()/1000),broker={iss:'https://broker.test',aud:'api://broker',sub:'human',act:{iss:'https://agents.test',sub:'agent'},org_id:'partner',delegation_id:'grant',execution_mode:'interactive',scope:'copilot.invoke',iat:now,nbf:now,exp:now+100,jti:'broker'};
 const provider={iss:'https://provider.test',aud:'api://copilot-login',sub:'human',scope:'copilot.login',iat:now,nbf:now,exp:now+3600,jti:'provider'},tool={...broker,aud:'api://copilot-tool',jti:'tool'};
 let calls=0;const events:any[]=[];
 const downstream=createToolServer({...approved,ca:[approved.cert,other.cert]},new ToolApi(new PolicyProtectedTool({verifier:{verify:async raw=>{assert.equal(raw,'synthetic-tool-token');return tool as any;}},authorise:async()=>{},operation:async()=>{calls++;if(options.pause)await options.pause();return{authorized:true};},timeoutMs:1000})),{certificateSha256:[new X509Certificate(approved.cert).fingerprint256]});
 const downstreamPort=await listen(downstream);
 const privateTool={origin:'https://localhost:'+downstreamPort,...approved,ca:approved.cert,serverCertificateSha256:options.badPin?new X509Certificate(other.cert).fingerprint256:new X509Certificate(approved.cert).fingerprint256,timeoutMs:1000,...(options.wrongClient?other:{})};const invoke=createPrivateToolInvoker(privateTool);
 const relayConfig={brokerAudience:broker.aud,toolAudience:tool.aud,scope:broker.scope,callerId:'copilot-connection',provider:{issuer:provider.iss,audience:provider.aud,scope:provider.scope},bindingLifetimeSeconds:120,maxBindings:5,timeoutMs:2000};const relayDependencies={brokerVerifier:{verify:async raw=>{assert.equal(raw,'synthetic-broker-token');return broker as any;}},providerVerifier:{verify:async raw=>{assert.equal(raw,'synthetic-provider-token');return provider;}},authenticateCaller:connectionKeyAuthenticator({callerId:'copilot-connection',sha256:createHash('sha256').update('synthetic-connection-key').digest('hex')}),bindProviderIdentity:async(p,b)=>{assert.equal(p.sub,b.sub);},authoriseBroker:async()=>{},issueToolToken:async()=> 'synthetic-tool-token',toolVerifier:{verify:async()=>tool as any},invokeTool:invoke,audit:async()=>{}};const relay=new ProviderToolRelay(relayConfig,relayDependencies);
 const ingress=createProviderRelayServer(approved,new ProviderToolRelayApi(relay),{maxConcurrent:options.maxConcurrent??2,maxConnections:8,requestsPerMinute:options.requestsPerMinute??100,...(options.providerHeader?{providerHeader:options.providerHeader}:{}),observe:e=>events.push(e)}),port=await listen(ingress);
 const call=(headers:any={},body='{}',path='/v1/copilot-tools/verify-access',targetPort=port)=>new Promise<any>((done,reject)=>{const req=request({host:'127.0.0.1',port:targetPort,servername:'localhost',ca:approved.cert,agent:false,method:'POST',path,headers:{'Content-Type':'application/json','X-PF-User-Access-Token':'synthetic-provider-token','X-Copilot-Connection-Key':'synthetic-connection-key',...headers}},res=>{let body='';res.on('data',c=>{body+=c;});res.on('end',()=>done({status:res.statusCode,body:JSON.parse(body),headers:res.headers}));});req.on('error',reject);req.end(body);});
 return{relay,call,privateTool,relayConfig,relayDependencies,ingress,calls:()=>calls,events,stop:async()=>{await stop(ingress);await stop(downstream);}};
}
test('loopback HTTPS relay authenticates both credentials and invokes only the pinned mTLS tool',async()=>{const f=await fixture();try{await f.relay.bind('synthetic-broker-token','synthetic-provider-token');const result=await f.call();assert.equal(result.status,200);assert.deepEqual(result.body,{authorized:true});assert.equal(result.headers['cache-control'],'no-store');assert.equal(f.calls(),1);assert.equal((await f.call()).status,403);assert.ok(!JSON.stringify(f.events).includes('synthetic-'));}finally{await f.stop();}});

test('relay diagnostics distinguish missing, malformed and present credential headers without exposing values',async()=>{
 const f=await fixture();try{
  assert.equal((await f.call({'X-PF-User-Access-Token':[]})).status,401);
  assert.deepEqual(f.events.at(-1),{event:'provider_relay_http',status:401,credentials:{provider:'missing',caller:'present'}});
  assert.equal((await f.call({'X-Copilot-Connection-Key':'synthetic-rejected-key'})).status,401);
  assert.deepEqual(f.events.at(-1).credentials,{provider:'present',caller:'present'});
  assert.equal((await f.call({'X-PF-User-Access-Token':'synthetic malformed value'})).status,401);
  assert.deepEqual(f.events.at(-1).credentials,{provider:'malformed',caller:'present'});
  assert.equal((await f.call({'X-Copilot-Connection-Key':['a','b']})).status,401);
  assert.deepEqual(f.events.at(-1).credentials,{provider:'present',caller:'multiple'});
  assert.equal((await f.call()).status,403);
  assert.equal(f.calls(),0);
  assert.ok(!JSON.stringify(f.events).includes('synthetic'));
 }finally{await f.stop();}
});

test('explicit simple provider header preserves binding and refuses legacy or mixed headers',async()=>{
 const f=await fixture({providerHeader:'PfUserAccessToken'});try{
  await f.relay.bind('synthetic-broker-token','synthetic-provider-token');
  assert.equal((await f.call()).status,400);
  assert.equal((await f.call({PfUserAccessToken:'synthetic-provider-token'})).status,400);
  assert.equal(f.calls(),0);
  const headers={'X-PF-User-Access-Token':[],PfUserAccessToken:'synthetic-provider-token'};
  assert.equal((await f.call({...headers,'X-Copilot-Connection-Key':'synthetic-wrong'})).status,401);
  assert.equal((await f.call({...headers,PfUserAccessToken:['a','b']})).status,401);
  assert.equal((await f.call(headers)).status,200);assert.equal(f.calls(),1);
  assert.equal((await f.call(headers)).status,403);assert.equal(f.calls(),1);
 }finally{await f.stop();}
});
test('duplicate credentials and request authority never reach the private tool',async()=>{const f=await fixture();try{await f.relay.bind('synthetic-broker-token','synthetic-provider-token');for(const [headers,body,path,status] of [[{'X-PF-User-Access-Token':['a','b']},'{}',undefined,401],[{'X-Copilot-Connection-Key':['a','b']},'{}',undefined,401],[{Authorization:'Bearer other'},'{}',undefined,400],[{'Content-Type':'text/plain'},'{}',undefined,400],[{},'x'.repeat(1025),undefined,413],[{},'{"grant":"chosen"}',undefined,400],[{},'{}','/v1/copilot-tools/verify-access?grant=chosen',400],[{'X-Agent-Id':'chosen'},'{}',undefined,400],[{'X-Copilot-Connection-Key':'wrong'},'{}',undefined,401]]as any[])assert.equal((await f.call(headers,body,path)).status,status);assert.equal(f.calls(),0);assert.equal((await f.call()).status,200);}finally{await f.stop();}});
for(const option of [{badPin:true},{wrongClient:true}])test('downstream server or workload identity mismatch suppresses result and consumes binding',async()=>{const f=await fixture(option);try{await f.relay.bind('synthetic-broker-token','synthetic-provider-token');assert.equal((await f.call()).status,503);assert.equal(f.calls(),0);assert.equal((await f.call()).status,403);}finally{await f.stop();}});
test('private client refuses redirects and unexpected response data',async()=>{for(const [status,body] of [[302,''],[200,'{"authorized":true,"secret":"private"}'],[200,'x'.repeat(1025)]]as const){const server=createServer(approved,(_req,res)=>{res.writeHead(status,{'Content-Type':'application/json',Location:'https://unapproved.invalid'});res.end(body);});const port=await listen(server);try{const invoke=createPrivateToolInvoker({origin:'https://localhost:'+port,...approved,ca:approved.cert,serverCertificateSha256:new X509Certificate(approved.cert).fingerprint256,timeoutMs:1000});await assert.rejects(invoke('synthetic-tool-token',AbortSignal.timeout(2000)),e=>!String(e).includes('private'));}finally{await stop(server);}}});
test('relay lifecycle adapter passes cancellation and exact credentials to trusted methods',async()=>{const f=await fixture();try{const hooks=providerRelayLifecycle(f.relay);await hooks.bind('synthetic-broker-token','synthetic-provider-token',AbortSignal.timeout(1000));hooks.invalidate('synthetic-provider-token');assert.equal((await f.call()).status,403);}finally{await f.stop();}});

for(const closeBeforeCall of [true,false])test('composed Direct Line lifecycle prepares the HTTP relay and closes it with the session',async()=>{
 const f=await fixture();let server:any;
 try{
  const config={endpoint:'https://directline.botframework.com/v3/directline',brokerAudience:'api://broker',ssoAudience:'api://copilot-login',scope:'copilot.invoke',providerSso:{...f.relayConfig.provider,maxLifetimeSeconds:3600},botId:'bot',trustedOrigins:['https://client.test'],tokenPostRules:[{origin:'https://token.botframework.com',pathExact:'/api/sas/postToken',requiredQueryParameters:['sig']}],timeoutMs:1000,maxSessions:1,sessionLifetimeSeconds:120,maxActivities:100};
  const options={relayConfig:f.relayConfig,relayDependencies:f.relayDependencies,directLineConfig:config,directLineDependencies:{secret:async()=> 'synthetic-channel-secret',issueSsoToken:async()=> 'synthetic-provider-token',authorise:async()=>{},fetch:async(url:any,init:any)=>{
   if(String(url).startsWith('https://token.botframework.com'))return new Response(null,{status:200});
   if(String(url).endsWith('/tokens/generate')||String(url).endsWith('/conversations'))return Response.json({conversationId:'c1',token:'synthetic-channel-token',expires_in:120});
   return Response.json({activities:[{type:'message',id:'card',channelId:'directline',conversation:{id:'c1'},from:{id:'bot'},attachments:[{contentType:'application/vnd.microsoft.card.oauth',content:{tokenPostResource:{sasUrl:'https://token.botframework.com/api/sas/postToken?sig=synthetic'}}}]}]});
  }},privateTool:f.privateTool,tls:approved,controls:{maxConcurrent:2,maxConnections:8,requestsPerMinute:100}};
  const composition=composeProviderToolConnection(options as any);server=composition.server;const port=await listen(server);
  const session=await composition.adapter.open('synthetic-broker-token');await composition.adapter.poll(session.handle,'synthetic-broker-token');
  if(!closeBeforeCall){assert.equal((await f.call({},'{}',undefined,port)).status,200);assert.equal(f.calls(),1);}
  await composition.adapter.close(session.handle,'synthetic-broker-token');assert.equal((await f.call({},'{}',undefined,port)).status,403);assert.equal(f.calls(),closeBeforeCall?0:1);
  assert.throws(()=>composeProviderToolConnection({...options,relayConfig:{...f.relayConfig,brokerAudience:'wrong'}}as any));
 }finally{if(server)await stop(server);await f.stop();}
});
test('draining relay refuses new work without consuming or invoking a binding',async()=>{const f=await fixture();try{await f.relay.bind('synthetic-broker-token','synthetic-provider-token');f.ingress.beginDrain();assert.equal((await f.call()).status,503);assert.equal(f.calls(),0);}finally{await f.stop();}});

test('relay rate ceiling rejects excess calls before authority is consumed',async()=>{const f=await fixture({requestsPerMinute:1});try{await f.relay.bind('synthetic-broker-token','synthetic-provider-token');assert.equal((await f.call({'X-Copilot-Connection-Key':'wrong'})).status,401);assert.equal((await f.call()).status,429);assert.equal(f.calls(),0);}finally{await f.stop();}});
test('global concurrency limit refuses extra work while the private tool is busy',async()=>{let release!:()=>void,start!:()=>void;const started=new Promise<void>(done=>{start=done;}),hold=new Promise<void>(done=>{release=done;});const f=await fixture({maxConcurrent:1,pause:async()=>{start();await hold;}});try{await f.relay.bind('synthetic-broker-token','synthetic-provider-token');const first=f.call();await started;assert.equal((await f.call()).status,503);release();assert.equal((await first).status,200);assert.equal(f.calls(),1);}finally{release();await f.stop();}});
test('private tool configuration cannot select plaintext, path overrides or missing TLS identity',async()=>{const f=await fixture();try{for(const patch of [{origin:'http://localhost'},{origin:f.privateTool.origin+'/other'},{origin:f.privateTool.origin+'?resource=chosen'},{ca:undefined},{key:undefined},{serverCertificateSha256:'invalid'}])assert.throws(()=>createPrivateToolInvoker({...f.privateTool,...patch}));}finally{await f.stop();}});
