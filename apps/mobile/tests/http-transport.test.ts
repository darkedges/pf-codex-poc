import test from 'node:test';import assert from 'node:assert/strict';
import {MobileHttpsTransport,parseMobileReturn,MobileTransportError} from '../src/http-transport.ts';

test('HTTP failure exposes only a bounded status, never response body, URL or raw fetch error',async()=>{const t=new MobileHttpsTransport('https://agent.example.test','https://pf.example.test/as/authorization.oauth2',async()=>new Response('PRIVATE_RESPONSE_TOKEN',{status:403}));await assert.rejects(t.startLogin({devicePublicKeySpki:'fixture',claimHash:'fixture'}),error=>error instanceof MobileTransportError&&error.httpStatus===403&&!String(error).includes('PRIVATE_RESPONSE'));const failed=new MobileHttpsTransport('https://agent.example.test','https://pf.example.test/as/authorization.oauth2',async()=>{throw Error('PRIVATE_NETWORK_URL');});await assert.rejects(failed.config(),error=>error instanceof MobileTransportError&&error.httpStatus===undefined&&!String(error).includes('PRIVATE_NETWORK'));});
test('browser fetch is called with its global receiver rather than the transport instance',async()=>{let called=0;const browserFetch=async function(this:unknown){assert.equal(this,globalThis,'browser fetch receiver');called++;return Response.json({termsHash:'a'.repeat(43)});};const t=new MobileHttpsTransport('https://agent.example.test','https://pf.example.test/as/authorization.oauth2',browserFetch as typeof fetch);assert.deepEqual(await t.config(),{termsHash:'a'.repeat(43)});assert.equal(called,1);});
const origin='https://agent.example.test',provider='https://pf.example.test/as/authorization.oauth2';
test('transport fixes destination and refuses redirects, cookies and unbounded responses',async()=>{
 let count=0;const t=new MobileHttpsTransport(origin,provider,async(url,init)=>{count++;assert.equal(url,origin+'/v1/mobile/session/challenge');assert.equal(init.redirect,'error');assert.equal(init.credentials,'omit');assert.equal(init.method,'POST');assert.ok(!new Headers(init.headers).has('Authorization'));return Response.json({challengeId:'fixture',challenge:'resume:fixture',expiresAt:1});});
 await t.beginResume({enrollmentId:'device',sessionPublicKeySpki:'key'});assert.equal(count,1);
 for(const response of [new Response('x'.repeat(17000)),Response.json({error:'credential-detail'},{status:401}),new Response('{}',{status:302,headers:{Location:'https://evil.test'}})]){
  const denied=new MobileHttpsTransport(origin,provider,async()=>response);await assert.rejects(denied.beginResume({enrollmentId:'device',sessionPublicKeySpki:'key'}),e=>!e.message.includes('credential-detail'));
 }
});
test('provider URL and return link require exact configured origin, path and single opaque handoff',async()=>{
 const handoff='a'.repeat(42)+'A';assert.equal(parseMobileReturn(origin+'/mobile/return?handoff='+handoff,origin),handoff);
 for(const url of ['https://evil.test/mobile/return?handoff='+handoff,origin+'/mobile/return?handoff='+handoff+'&handoff='+handoff,origin+'/mobile/return?handoff='+handoff+'#x',origin+'/other?handoff='+handoff,'http://agent.example.test/mobile/return?handoff='+handoff])assert.throws(()=>parseMobileReturn(url,origin));
 const t=new MobileHttpsTransport(origin,provider,async()=>Response.json({authorizationUrl:'https://evil.test/login',expiresAt:Date.now()+10000}));await assert.rejects(t.startLogin({devicePublicKeySpki:'key',claimHash:handoff}));
});
test('transport makes one attempt and preserves the exact signed request bytes',async()=>{
 let calls=0;const body='{"question":"Hello"}';const t=new MobileHttpsTransport(origin,provider,async(url,init)=>{calls++;assert.equal(url,origin+'/v1/mobile/chat/messages');assert.equal(init.body,body);assert.equal(new Headers(init.headers).get('X-Mobile-Proof'),'proof');throw Error('network-secret');});
 await assert.rejects(t.chat({sessionId:'session',proof:'proof',body}),e=>!e.message.includes('network-secret'));assert.equal(calls,1);
});

test('async chat submits once then signs a separate fixed result request',async()=>{
 const jobId='a'.repeat(43),body=JSON.stringify({question:'Hello'}),seen=[];let signed=0;
 const t=new MobileHttpsTransport(origin,provider,async(url,init)=>{seen.push(String(url));if(seen.length===1)return Response.json({status:'pending',jobId},{status:202});assert.equal(init.body,JSON.stringify({jobId}));assert.equal(new Headers(init.headers).get('X-Mobile-Proof'),'fresh-result-proof');return Response.json({status:'complete',answer:'fixture answer'});});
 const answer=await t.chat({sessionId:'session',proof:'start-proof',body},async(raw,path)=>{signed++;assert.equal(path,'/v1/mobile/chat/result');return{sessionId:'session',proof:'fresh-result-proof',body:raw};});
 assert.deepEqual(answer,{answer:'fixture answer'});assert.equal(signed,1);assert.deepEqual(seen,[origin+'/v1/mobile/chat/messages',origin+'/v1/mobile/chat/result']);
});
test('async chat rejects malformed jobs and cancellation during polling never resubmits',async()=>{
 for(const value of [{status:'pending',jobId:'bad'},{status:'pending',jobId:'a'.repeat(43),token:'unexpected'}]){
  let calls=0;const t=new MobileHttpsTransport(origin,provider,async()=>{calls++;return Response.json(value,{status:202});});await assert.rejects(t.chat({sessionId:'session',proof:'proof',body:'{}'},async()=>{throw Error('must not sign');}));assert.equal(calls,1);
 }
 let calls=0;const t=new MobileHttpsTransport(origin,provider,async()=>{calls++;return Response.json({status:'pending',jobId:'a'.repeat(43)},{status:202});});
 const running=t.chat({sessionId:'session',proof:'proof',body:'{}'},async body=>({sessionId:'session',proof:'new',body}));setTimeout(()=>t.cancelPending(),20);await assert.rejects(running);assert.equal(calls,1);
});
