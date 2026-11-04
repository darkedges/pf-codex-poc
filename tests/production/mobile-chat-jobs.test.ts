import test from 'node:test';
import assert from 'node:assert/strict';
import {MobileChatJobs} from '../../src/mobile/chat-jobs.ts';
import {bodyHash} from '../../src/policy/protocol.ts';

// Explicit authority/execution fixtures; these tests do not establish live PF or Copilot acceptance.
function fixture(execute=async()=>({answer:'fixture answer'}),timeoutMs=1000){
 const valid=new WeakSet<object>();let revoked=false;
 const evidence=(sessionId='foreground-1',question='Question?')=>{const e={sessionId,enrollmentId:'device-1',consentId:'consent-1',human:{issuer:'https://login.example.test',subject:'human',audience:'mobile',authTime:1},agent:{issuer:'https://agent.example.test',subject:'agent'},organisation:'org',requestPath:'/v1/mobile/chat/messages',requestBodyHash:bodyHash(JSON.stringify({question})),expiresAt:Date.now()+60000};valid.add(e);return e;};
 const jobs=new MobileChatJobs({timeoutMs,capacity:2,revalidate:async e=>{if(!valid.has(e)||revoked||e.expiresAt<=Date.now())throw Error('secret detail');return e;},authorise:async()=>{if(revoked)throw Error('private grant');},execute});
 return{jobs,evidence,revoke:()=>{revoked=true;}};
}
async function finish(jobs,e,id){for(let i=0;i<30;i++){const r=await jobs.result(e,id);if(r.status!=='pending')return r;await new Promise(r=>setTimeout(r,5));}throw Error('fixture did not finish');}

test('bounded chat job returns only to original foreground and consumes its answer once',async()=>{
 const f=fixture(),e=f.evidence(),r=await f.jobs.start(e,'Question?');
 assert.match(r.jobId,/^[\w-]{43}$/);assert.equal(r.status,'pending');
 await assert.rejects(f.jobs.result(f.evidence('foreground-2'),r.jobId),/mobile_chat_job_denied/);
 assert.deepEqual(await finish(f.jobs,e,r.jobId),{status:'complete',answer:'fixture answer'});
 await assert.rejects(f.jobs.result(e,r.jobId),/mobile_chat_job_denied/);await assert.rejects(f.jobs.start(e,'Question?'),/mobile_chat_job_denied/);f.jobs.close();
});
test('question substitution, copied evidence, duplicate foreground execution and capacity fail closed',async()=>{
 let release;const f=fixture(()=>new Promise(r=>{release=r;})),e=f.evidence();
 await assert.rejects(f.jobs.start(e,'Different question'),/mobile_chat_job_denied/);
 await assert.rejects(f.jobs.start({...e},'Question?'),/mobile_chat_job_denied/);
 const one=await f.jobs.start(e,'Question?');
 await assert.rejects(f.jobs.start(e,'Question?'),/mobile_chat_job_denied/);
 await f.jobs.start(f.evidence('foreground-2'),'Question?');
 await assert.rejects(f.jobs.start(f.evidence('foreground-3'),'Question?'),/mobile_chat_job_denied/);
 f.jobs.close();release?.({answer:'late answer'});await assert.rejects(f.jobs.result(e,one.jobId));
});
test('revocation while execution is pending suppresses its answer',async()=>{
 let release;const f=fixture(()=>new Promise(r=>{release=r;})),e=f.evidence(),r=await f.jobs.start(e,'Question?');
 await new Promise(r=>setTimeout(r,0));f.revoke();release({answer:'must not escape'});
 await assert.rejects(f.jobs.result(e,r.jobId),/mobile_chat_job_denied/);f.jobs.close();
});
test('deadline and cancellation discard late results without automatic retry',async()=>{
 let calls=0;const f=fixture(async({signal})=>{calls++;await new Promise(r=>setTimeout(r,70));return{answer:signal.aborted?'late':'unexpected'};},25),e=f.evidence();
 const r=await f.jobs.start(e,'Question?');await new Promise(r=>setTimeout(r,40));
 await assert.rejects(f.jobs.result(e,r.jobId),/mobile_chat_job_denied/);assert.equal(calls,1);f.jobs.close();
 const g=fixture(),p=g.evidence(),s=await g.jobs.start(p,'Question?');await g.jobs.cancel(p,s.jobId);
 await assert.rejects(g.jobs.result(p,s.jobId),/mobile_chat_job_denied/);g.jobs.close();
});
test('concurrent readers cannot consume the same completed answer twice',async()=>{
 const f=fixture(),e=f.evidence(),r=await f.jobs.start(e,'Question?');await new Promise(r=>setTimeout(r,5));
 const results=await Promise.allSettled([f.jobs.result(e,r.jobId),f.jobs.result(e,r.jobId)]);
 assert.equal(results.filter(r=>r.status==='fulfilled'&&r.value.status==='complete').length,1);
 assert.equal(results.filter(r=>r.status==='rejected').length,1);f.jobs.close();
});
test('an uncooperative timed-out executor still occupies bounded capacity',async()=>{
 const f=fixture(()=>new Promise(()=>{}),25),a=f.evidence(),b=f.evidence('foreground-2');
 await f.jobs.start(a,'Question?');await f.jobs.start(b,'Question?');await new Promise(r=>setTimeout(r,40));
 await assert.rejects(f.jobs.start(f.evidence('foreground-3'),'Question?'),/mobile_chat_job_denied/);f.jobs.close();
});
test('aborted admission cannot start downstream execution',async()=>{
 let calls=0;const f=fixture(async()=>{calls++;return{answer:'must not execute'};}),controller=new AbortController();controller.abort();
 await assert.rejects(f.jobs.start(f.evidence(),'Question?',controller.signal));assert.equal(calls,0);f.jobs.close();
});
