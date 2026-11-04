import test from 'node:test';import assert from 'node:assert/strict';
import {runBoundedProbeBatch} from '../scripts/pf/bounded-probe-batch.mjs';
test('load probe caps concurrency and projects counts instead of response bodies',async()=>{
 let active=0,peak=0,calls=0;
 const result=await runBoundedProbeBatch({requests:12,concurrency:3},async()=>{active++;peak=Math.max(peak,active);const n=calls++;await new Promise(r=>setTimeout(r,1));active--;return{status:n<3?200:n<8?429:503,token:'PRIVATE'};});
 assert.equal(peak,3);assert.equal(result.completed,12);assert.equal(result.accepted,3);assert.equal(result.rateLimited,5);assert.equal(result.overloaded,4);assert.ok(!JSON.stringify(result).includes('PRIVATE'));
});
test('load probe reports errors without leaking exceptions',async()=>{const result=await runBoundedProbeBatch({requests:1,concurrency:1},async()=>{throw Error('PRIVATE');});assert.equal(result.networkErrors,1);assert.ok(!JSON.stringify(result).includes('PRIVATE'));});
for(const options of [{requests:129,concurrency:1},{requests:1,concurrency:33},{requests:0,concurrency:1},{requests:1,concurrency:0}])test('load probe refuses unbounded or malformed workloads',async()=>{await assert.rejects(runBoundedProbeBatch(options,async()=>({status:200})));});
