import test from 'node:test';import assert from 'node:assert/strict';
import {createVaultCaptureWriter,executeRetainedPost} from '../scripts/copilot/vault-capture.mjs';
import {reserveRetainedProviderCapture,reservePublishedProviderCapture,reserveLongerProviderCapture,reserveHourProviderCapture} from '../scripts/copilot/live-budget.mjs';
import {retainedHttpPacket} from '../scripts/copilot/retained-packet.mjs';
const id='12345678-1234-4234-9234-123456789abc',url='https://token.botframework.com/api/sas/postToken?expiry=1800000000&id=PRIVATE_ID&state=PRIVATE_STATE&hmac=PRIVATE_SIG';
const request={url,init:{method:'POST',headers:{Accept:'application/json','Content-Type':'application/json'},body:'{"token":"PRIVATE_PROVIDER_TOKEN"}'}};
test('raw request is stored with CAS before transmission; exact raw response follows under CAS 1',async()=>{const calls=[];const writer=createVaultCaptureWriter(id,()=> 'PRIVATE_WRITER',async(path,o)=>{calls.push({path,...o});return{status:200,value:{data:{version:calls.length}}};});let sent=false;const result=await executeRetainedPost(writer,request.url,request.init,()=>{assert.equal(calls.length,1);sent=true;return{parsed:{status:400},rawResponse:'HTTP/1.1 400 Bad Request\r\n\r\n"Token is expired"'};});assert.ok(sent);assert.equal(result.parsed.status,400);assert.equal(calls[0].body.options.cas,0);assert.equal(calls[1].body.options.cas,1);assert.equal(calls[1].body.data.request.url,url);assert.equal(calls[1].body.data.request.body,request.init.body);assert.equal(calls[1].body.data.rawResponse,'HTTP/1.1 400 Bad Request\r\n\r\n"Token is expired"');assert.equal(calls[0].token,'PRIVATE_WRITER');});
test('Vault failure prevents any token POST and does not fall back to plaintext',async()=>{const writer=createVaultCaptureWriter(id,()=> 'PRIVATE',async()=>({status:403}));let sent=false;await assert.rejects(executeRetainedPost(writer,url,request.init,()=>{sent=true;}),/^Error: Private capture unavailable$/);assert.equal(sent,false);});
test('retained capture refuses foreign paths, credential headers and extra request fields',async()=>{assert.throws(()=>createVaultCaptureWriter('../runtime',()=> 'x',async()=>({})));const writer=createVaultCaptureWriter(id,()=> 'x',async()=>({status:200,value:{data:{version:1}}}));await assert.rejects(writer.request(url,{...request.init,headers:{Authorization:'PRIVATE','Content-Type':'application/json'}}));});
test('new retained-capture allowance cannot reuse consumed earlier capture',()=>{const history=[{max:2,reserved:['interactive','autonomous']},{max:1,reserved:['interactive']},{max:1,reserved:['interactive']}],previous={max:1,reserved:['interactive'],purpose:'configured-provider-capture'},fresh={max:1,reserved:[],purpose:'configured-provider-vault-capture'};assert.equal(reserveRetainedProviderCapture(history,previous,fresh).reserved.length,1);assert.throws(()=>reserveRetainedProviderCapture(history,previous,{...fresh,reserved:['interactive']}));assert.throws(()=>reserveRetainedProviderCapture(history,{...previous,reserved:[]},fresh));});
test('explicit private retrieval reconstructs retained values without substituting new tokens',()=>{const d={state:'request-and-response-retained',request:{method:'POST',url,headers:request.init.headers,body:request.init.body},rawResponse:'HTTP/1.1 400\r\n\r\n"Original response"'};const p=retainedHttpPacket(d);assert.ok(p.includes(url));assert.ok(p.includes('PRIVATE_PROVIDER_TOKEN'));assert.ok(p.endsWith(d.rawResponse));assert.throws(()=>retainedHttpPacket({...d,state:'request-retained-before-send'}));});

test('post-publication allowance preserves all consumed history and permits exactly one new conversation',()=>{
 const history=[{max:2,reserved:['interactive','autonomous']},{max:1,reserved:['interactive']},{max:1,reserved:['interactive']}],previous={max:1,reserved:['interactive'],purpose:'configured-provider-capture'},retained={max:1,reserved:['interactive'],purpose:'configured-provider-vault-capture'},fresh={max:1,reserved:[],purpose:'published-provider-vault-capture'};
 const before=JSON.stringify({history,previous,retained});
 const used=reservePublishedProviderCapture(history,previous,retained,fresh);
 assert.deepEqual(used,{max:1,reserved:['interactive'],purpose:'published-provider-vault-capture'});
 assert.equal(JSON.stringify({history,previous,retained}),before);
 assert.throws(()=>reservePublishedProviderCapture(history,previous,retained,used));
 assert.throws(()=>reservePublishedProviderCapture(history,previous,{...retained,reserved:[]},fresh));
 assert.throws(()=>reservePublishedProviderCapture(history,previous,retained,{...fresh,purpose:'configured-provider-vault-capture'}));
});

test('five-minute test has one independent allowance after consumed publication test',()=>{
 const history=[{max:2,reserved:['interactive','autonomous']},{max:1,reserved:['interactive']},{max:1,reserved:['interactive']}],previous={max:1,reserved:['interactive'],purpose:'configured-provider-capture'},retained={max:1,reserved:['interactive'],purpose:'configured-provider-vault-capture'},published={max:1,reserved:['interactive'],purpose:'published-provider-vault-capture'},fresh={max:1,reserved:[],purpose:'longer-provider-vault-capture'};
 const before=JSON.stringify([history,previous,retained,published]);
 const used=reserveLongerProviderCapture(history,previous,retained,published,fresh);
 assert.equal(used.purpose,fresh.purpose);assert.deepEqual(used.reserved,['interactive']);
 assert.equal(JSON.stringify([history,previous,retained,published]),before);
 assert.throws(()=>reserveLongerProviderCapture(history,previous,retained,published,used));
 assert.throws(()=>reserveLongerProviderCapture(history,previous,retained,{...published,reserved:[]},fresh));
 assert.throws(()=>reserveLongerProviderCapture(history,previous,retained,published,{...fresh,max:2}));
});

test('one-hour test cannot reuse the consumed five-minute allowance',()=>{
 const history=[{max:2,reserved:['interactive','autonomous']},{max:1,reserved:['interactive']},{max:1,reserved:['interactive']}],previous={max:1,reserved:['interactive'],purpose:'configured-provider-capture'},retained={max:1,reserved:['interactive'],purpose:'configured-provider-vault-capture'},published={max:1,reserved:['interactive'],purpose:'published-provider-vault-capture'},longer={max:1,reserved:['interactive'],purpose:'longer-provider-vault-capture'},fresh={max:1,reserved:[],purpose:'hour-provider-vault-capture'};
 const before=JSON.stringify([history,previous,retained,published,longer]);
 const used=reserveHourProviderCapture(history,previous,retained,published,longer,fresh);
 assert.deepEqual(used,{max:1,reserved:['interactive'],purpose:fresh.purpose});assert.equal(JSON.stringify([history,previous,retained,published,longer]),before);
 assert.throws(()=>reserveHourProviderCapture(history,previous,retained,published,longer,used));
 assert.throws(()=>reserveHourProviderCapture(history,previous,retained,published,{...longer,reserved:[]},fresh));
 assert.throws(()=>reserveHourProviderCapture(history,previous,retained,published,longer,{...fresh,max:2}));
});
