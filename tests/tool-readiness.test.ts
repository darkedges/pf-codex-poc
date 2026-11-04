import test from 'node:test';import assert from 'node:assert/strict';
import {ToolReadiness} from '../src/copilot/tool-readiness.ts';
test('readiness requires every independent check and recovers after failure',async()=>{
 let dependency=true,now=0,calls=0;
 const health=new ToolReadiness({timeoutMs:100,cacheMs:1000,now:()=>now,checks:[async()=>true,async()=>{calls++;return dependency;}]});
 assert.equal(await health.check(),true);dependency=false;now=1001;assert.equal(await health.check(),false);dependency=true;now=2002;assert.equal(await health.check(),true);assert.equal(calls,3);
});
test('concurrent probes coalesce without granting authority or hiding a later outage',async()=>{
 let calls=0;const health=new ToolReadiness({timeoutMs:100,cacheMs:0,checks:[async()=>{calls++;await new Promise(r=>setTimeout(r,10));return true;}]});
 assert.deepEqual(await Promise.all([health.check(),health.check(),health.check()]),[true,true,true]);assert.equal(calls,1);
});
test('hung and throwing dependency checks fail closed with cancellation',async()=>{
 let aborted=false;const health=new ToolReadiness({timeoutMs:100,cacheMs:0,checks:[async signal=>{signal.addEventListener('abort',()=>{aborted=true;});return new Promise(()=>{});}]});
 assert.equal(await health.check(),false);assert.equal(aborted,true);
 assert.equal(await new ToolReadiness({timeoutMs:100,cacheMs:0,checks:[async()=>{throw Error('PRIVATE');}]}).check(),false);
});
