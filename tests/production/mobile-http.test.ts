import test from 'node:test';import assert from 'node:assert/strict';
import {MobileHttpApi} from '../../src/mobile/http-api.ts';
import {androidAssociation} from '../../src/mobile/android-links.ts';
import {MobileChatJobs} from '../../src/mobile/chat-jobs.ts';
import {bodyHash} from '../../src/policy/protocol.ts';
const origin='https://agent.example.test';
function fixture(){let calls=0;const authority={termsHash:'reviewed-terms',beginResume:async()=>{calls++;return{challengeId:'fixture',challenge:'resume:fixture',expiresAt:Date.now()+60000};},completeEnrollment:async()=>{calls++;return{};},completeResume:async()=>{calls++;return{};},authorize:async()=>{calls++;throw Error('private-credential-detail');}};
 const handoff={start:async()=>{calls++;return{authorizationUrl:'https://pf.example.test/auth',expiresAt:Date.now()+60000};},claim:async()=>{calls++;return{};},callback:async()=>{calls++;return{returnUrl:origin+'/mobile/return?handoff='+'a'.repeat(43)};}};
 const api=new MobileHttpApi({origin,authority,handoff});
 const post=(path,body='{}',headers={})=>new Request(origin+path,{method:'POST',headers:{Origin:'https://localhost','Content-Type':'application/json',...headers},body});
 return{api,post,authority,handoff,calls:()=>calls};
}
test('fixed routes accept only the Android origin and reject arbitrary host, path and body authority',async()=>{const f=fixture();assert.equal((await f.api.handle(f.post('/v1/mobile/session/challenge','{"enrollmentId":"x","sessionPublicKeySpki":"y"}'))).status,200);assert.equal(f.calls(),1);
 for(const request of [f.post('/admin'),f.post('/v1/mobile/session/challenge','{}',{Origin:'https://evil.test'}),new Request('https://evil.test/v1/mobile/config'),f.post('/v1/mobile/session/challenge','{"subject":"admin"}')])assert.ok((await f.api.handle(request)).status>=400);assert.equal(f.calls(),1);
});
test('duplicate escaped JSON keys, nested values, oversized bodies and non-JSON requests fail before adapters',async()=>{const f=fixture();for(const body of ['{"enrollmentId":"a","enrollment\\u0049d":"b","sessionPublicKeySpki":"c"}','{"enrollmentId":{}}','{"enrollmentId":"'+'x'.repeat(17000)+'"}'])assert.ok((await f.api.handle(f.post('/v1/mobile/session/challenge',body))).status>=400);assert.equal((await f.api.handle(f.post('/v1/mobile/session/challenge','{}',{'Content-Type':'text/plain'}))).status,415);assert.equal(f.calls(),0);});
test('callback redirects only to fixed app return URL and never reflects incoming code/state',async()=>{const f=fixture();const response=await f.api.handle(new Request(origin+'/mobile/callback?code=server-secret-code&state=server-state'));assert.equal(response.status,303);assert.ok(response.headers.get('location').startsWith(origin+'/mobile/return?handoff='));assert.equal(await response.text(),'');assert.equal(response.headers.get('cache-control'),'no-store');assert.equal(response.headers.get('referrer-policy'),'no-referrer');assert.equal((await f.api.handle(new Request(origin+'/mobile/callback?code=a&code=b&state=c'))).status,400);});
test('missing proof or failed authority never invokes a chat executor or leaks error details',async()=>{const f=fixture();const missing=await f.api.handle(f.post('/v1/mobile/chat/messages','{"question":"hello"}'));assert.equal(missing.status,401);const failed=await f.api.handle(f.post('/v1/mobile/chat/messages','{"question":"hello"}',{'X-Mobile-Session':'session','X-Mobile-Proof':'proof'}));assert.equal(failed.status,401);assert.ok(!(await failed.text()).includes('private'));});
test('preflight is fixed and responses never allow credentials or arbitrary origin reflection',async()=>{const f=fixture();const r=await f.api.handle(new Request(origin+'/v1/mobile/session/challenge',{method:'OPTIONS',headers:{Origin:'https://localhost','Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'content-type'}}));assert.equal(r.status,204);assert.equal(r.headers.get('access-control-allow-origin'),'https://localhost');assert.equal(r.headers.get('access-control-allow-credentials'),null);assert.equal((await f.api.handle(new Request(origin+'/v1/mobile/config',{headers:{Origin:'https://evil.test'}}))).status,403);});

test('an enrolled session cannot turn missing delegated execution into a simulated answer',async()=>{const f=fixture();f.authority.authorize=async()=>({type:'registered-device-key'});const r=await f.api.handle(f.post('/v1/mobile/chat/messages','{"question":"hello"}',{'X-Mobile-Session':'session','X-Mobile-Proof':'proof'}));assert.equal(r.status,503);assert.deepEqual(await r.json(),{error:'mobile_chat_not_configured'});});
test('configuring an executor cannot bypass the independent resource-consent gate',async()=>{const f=fixture();f.authority.authorize=async()=>({type:'registered-device-key'});let calls=0;const api=new MobileHttpApi({origin,authority:f.authority,handoff:f.handoff,execute:async()=>{calls++;return{answer:'must not execute'};}});const r=await api.handle(f.post('/v1/mobile/chat/messages','{"question":"hello"}',{'X-Mobile-Session':'session','X-Mobile-Proof':'proof'}));assert.equal(r.status,503);assert.equal(calls,0);});
test('revocation during execution prevents releasing the answer even if the client did not abort',async()=>{const f=fixture();f.authority.authorize=async()=>({type:'registered-device-key'});let revoked=false,checks=0;const resourceConsent={terms:()=>({}),approve:async()=>({}),status:async()=>({}),revoke:async()=>({}),authoriseChat:async()=>{checks++;if(revoked)throw Error('revoked');}};const api=new MobileHttpApi({origin,authority:f.authority,handoff:f.handoff,resourceConsent,execute:async()=>{revoked=true;return{answer:'must not be released'};}});const response=await api.handle(f.post('/v1/mobile/chat/messages','{"question":"hello"}',{'X-Mobile-Session':'session','X-Mobile-Proof':'proof'}));assert.equal(response.status,401);assert.equal(checks,2);assert.ok(!(await response.text()).includes('must not be released'));});

test('aborting during authorization prevents execution even if verification eventually succeeds',async()=>{
 const f=fixture();let started,release,executions=0;const barrier=new Promise(resolve=>release=resolve),entered=new Promise<void>(resolve=>started=resolve);
 f.authority.authorize=async()=>{started();await barrier;return{type:'registered-device-key'};};
 const api=new MobileHttpApi({origin,authority:f.authority,handoff:f.handoff,execute:async()=>{executions++;return{answer:'must not execute'};}}),controller=new AbortController();
 const request=new Request(f.post('/v1/mobile/chat/messages','{"question":"hello"}',{'X-Mobile-Session':'session','X-Mobile-Proof':'proof'}),{signal:controller.signal});
 const response=api.handle(request);await entered;controller.abort();release();assert.equal((await response).status,408);assert.equal(executions,0);
});

test('Android association pins only the reviewed package and exact public signing fingerprint',()=>{const certificate='01'.repeat(32),r=androidAssociation(certificate);assert.equal(r[0].target.package_name,'com.darkedges.federatedcopilot.demo');assert.deepEqual(r[0].target.sha256_cert_fingerprints,[Array(32).fill('01').join(':')]);for(const value of ['',certificate+'00','*','https://evil.test'])assert.throws(()=>androidAssociation(value));});

test('opt-in async API starts one job and authenticates separate result and cancel requests',async()=>{
 const f=fixture(),valid=new WeakSet(),consent={terms:()=>({}),approve:async()=>({}),status:async()=>({}),revoke:async()=>({}),authoriseChat:async e=>{if(!valid.has(e))throw Error();}};
 f.authority.authorize=async(session,proof,request)=>{if(proof!=='fixture-proof')throw Error();const e={sessionId:session,enrollmentId:'device',consentId:'consent',human:{issuer:'fixture',subject:'human',audience:'mobile'},agent:{issuer:'fixture',subject:'agent'},organisation:'org',requestPath:request.path,requestBodyHash:bodyHash(request.body),expiresAt:Date.now()+60000};valid.add(e);return e;};
 const jobs=new MobileChatJobs({timeoutMs:1000,capacity:2,revalidate:async e=>{if(!valid.has(e))throw Error();return e;},authorise:consent.authoriseChat,execute:async()=>({answer:'fixture only'})});
 const api=new MobileHttpApi({origin,authority:f.authority,handoff:f.handoff,resourceConsent:consent,jobs}),headers={'X-Mobile-Session':'foreground','X-Mobile-Proof':'fixture-proof'};
 try{
  const started=await api.handle(f.post('/v1/mobile/chat/messages','{"question":"Hello"}',headers));assert.equal(started.status,202);const job=await started.json();assert.equal(job.status,'pending');
  const raw=JSON.stringify({jobId:job.jobId});assert.equal((await api.handle(f.post('/v1/mobile/chat/result',raw))).status,401);
  assert.equal((await api.handle(f.post('/v1/mobile/chat/result',raw,{...headers,'X-Mobile-Session':'other'}))).status,401);
  await new Promise(r=>setTimeout(r,5));const done=await api.handle(f.post('/v1/mobile/chat/result',raw,headers));assert.deepEqual(await done.json(),{status:'complete',answer:'fixture only'});
  assert.equal((await api.handle(f.post('/v1/mobile/chat/result',raw,headers))).status,401);
  const second=await(await api.handle(f.post('/v1/mobile/chat/messages','{"question":"Hello"}',headers))).json();
  assert.equal((await api.handle(f.post('/v1/mobile/chat/cancel',JSON.stringify({jobId:second.jobId}),headers))).status,200);
 }finally{jobs.close();}
});
