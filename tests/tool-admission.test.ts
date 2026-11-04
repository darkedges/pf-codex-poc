import test from 'node:test';import assert from 'node:assert/strict';
import {ToolAdmission} from '../src/copilot/tool-admission.ts';
const limits={maxConcurrentRequests:1,perWorkloadRequestsPerMinute:2,maxConnections:8};
test('concurrency saturation rejects without queueing and release is idempotent',()=>{
 const gate=new ToolAdmission(limits,['one','two']);const first=gate.enter('one');assert.equal(first.allowed,true);
 assert.deepEqual(gate.enter('two'),{allowed:false,status:503,code:'overloaded',retryAfter:1});
 first.release();first.release();const next=gate.enter('two');assert.equal(next.allowed,true);next.release();
});
test('workload rate buckets refill monotonically and cannot be bypassed with another token',()=>{
 let now=0;const gate=new ToolAdmission(limits,['one'],()=>now);
 for(let i=0;i<2;i++){const slot=gate.enter('one');assert.equal(slot.allowed,true);slot.release();}
 assert.equal(gate.enter('one').status,429);now=30000;const slot=gate.enter('one');assert.equal(slot.allowed,true);slot.release();
});
test('unknown workloads do not allocate buckets and draining denies new work',()=>{
 const gate=new ToolAdmission(limits,['one']);assert.equal(gate.enter('unknown').status,403);gate.drain();assert.equal(gate.enter('one').status,503);
});
for(const patch of [{maxConcurrentRequests:0},{maxConcurrentRequests:257},{perWorkloadRequestsPerMinute:0},{maxConnections:0}])test('unsafe admission configuration fails closed',()=>assert.throws(()=>new ToolAdmission({...limits,...patch},['one'])));
