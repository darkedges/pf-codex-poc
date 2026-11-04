import test from 'node:test';import assert from 'node:assert/strict';
import {assertPortalActivation,portalActivationWindow} from '../../src/consent/portal-activation.ts';
const hash='a'.repeat(64),review='b'.repeat(64),scope='portal-browser-first-live-v1';
function fixture(){const now=Date.now(),manifest={schemaVersion:1,scope,hostname:'agent.copilot.darkedges.com',tunnelId:'a979d27b-f2cd-45cf-aada-b44c850e3a0e',dns:{type:'CNAME',name:'agent.copilot.darkedges.com',content:'a979d27b-f2cd-45cf-aada-b44c850e3a0e.cfargotunnel.com',proxied:true},limits:{grants:1,conversations:1,tokenPosts:1,successfulTools:1,windowSeconds:3600},reviewSha256:review,sourceTunnelSha256:hash,candidateTunnelSha256:'c'.repeat(64),toolClientHash:hash,files:{'docs/portal-live-activation-review.md':review},callbacks:[{clientId:'copilot-consent-portal',beforeHash:hash,afterHash:hash},{clientId:'copilot-studio-generic-oauth',beforeHash:hash,afterHash:hash}]};const approval={schemaVersion:1,approved:true,scope,reviewSha256:review,manifestSha256:hash,approvedAt:now};return{now,manifest,approval};}
test('activation requires explicit approval of the exact bounded manifest and all current file hashes',()=>{
 const f=fixture();assert.doesNotThrow(()=>assertPortalActivation(f.manifest,f.approval,{manifestSha256:hash,files:f.manifest.files},f.now));
 for(const patch of [{approved:false},{scope:'other'},{reviewSha256:hash},{manifestSha256:review},{approvedAt:f.now-86400001}])assert.throws(()=>assertPortalActivation(f.manifest,{...f.approval,...patch},{manifestSha256:hash,files:f.manifest.files},f.now));
 assert.throws(()=>assertPortalActivation(f.manifest,f.approval,{manifestSha256:hash,files:{'docs/portal-live-activation-review.md':hash}},f.now));
});
test('public origin, tunnel, DNS target, limits and PF client substitutions fail closed',()=>{
 const f=fixture();for(const patch of [{hostname:'other.test'},{tunnelId:'other'},{dns:{...f.manifest.dns,proxied:false}},{limits:{...f.manifest.limits,conversations:2}},{limits:{...f.manifest.limits,windowSeconds:7200}},{callbacks:[{clientId:'foreign',beforeHash:hash,afterHash:hash}]}])assert.throws(()=>assertPortalActivation({...f.manifest,...patch},f.approval,{manifestSha256:hash,files:f.manifest.files},f.now));
});
test('activation window is fixed at first intent and cannot be extended by restart or another approval',()=>{
 const f=fixture(),first=portalActivationWindow(f.approval,undefined,f.now);assert.equal(first.expiresAt,f.now+3600000);assert.deepEqual(portalActivationWindow(f.approval,first,f.now+10000),first);
 assert.throws(()=>portalActivationWindow(f.approval,{...first,expiresAt:first.expiresAt+1},f.now+10000));assert.throws(()=>portalActivationWindow({...f.approval,manifestSha256:review},first,f.now+10000));assert.throws(()=>portalActivationWindow(f.approval,first,first.expiresAt));
});
test('a new run needs its own bound approval, review and preserved predecessor evidence',()=>{
 const f=fixture(),run={runId:'10e7b629-a404-4f67-9a70-7ee4e4778974',runReviewSha256:'d'.repeat(64),predecessorSha256:'e'.repeat(64),predecessorJournalSha256:'f'.repeat(64),predecessorWindowSha256:'1'.repeat(64)},manifest={...f.manifest,...run,files:{...f.manifest.files,'docs/portal-relay-retry-review.md':run.runReviewSha256}},approval={...f.approval,...run},current={manifestSha256:hash,files:manifest.files};
 assert.doesNotThrow(()=>assertPortalActivation(manifest,approval,current,f.now));assert.throws(()=>assertPortalActivation(manifest,f.approval,current,f.now));
 for(const patch of [{runId:'20e7b629-a404-4f67-9a70-7ee4e4778974'},{runReviewSha256:hash},{predecessorSha256:hash},{predecessorJournalSha256:hash},{predecessorWindowSha256:hash}])assert.throws(()=>assertPortalActivation(manifest,{...approval,...patch},current,f.now));
});
test('repeatable sessions require an explicitly matching cap, dedicated review and new run',()=>{
 const f=fixture(),run={runId:'10e7b629-a404-4f67-9a70-7ee4e4778974',runReviewSha256:'d'.repeat(64),runReviewPath:'docs/portal-repeatable-session-review.md',successfulPredecessor:{runId:'20e7b629-a404-4f67-9a70-7ee4e4778974',journalSha256:'2'.repeat(64),windowSha256:'3'.repeat(64),resultSha256:'4'.repeat(64)},predecessorSha256:'e'.repeat(64),predecessorJournalSha256:'f'.repeat(64),predecessorWindowSha256:'1'.repeat(64),sessionPolicy:{maxSessions:5,maxConcurrent:1}},manifest={...f.manifest,...run,files:{...f.manifest.files,[run.runReviewPath]:run.runReviewSha256}},approval={...f.approval,...run},current={manifestSha256:hash,files:manifest.files};
 assert.doesNotThrow(()=>assertPortalActivation(manifest,approval,current,f.now));assert.throws(()=>assertPortalActivation(manifest,f.approval,current,f.now));
 for(const sessionPolicy of [undefined,{maxSessions:6,maxConcurrent:1},{maxSessions:5,maxConcurrent:2},{maxSessions:26,maxConcurrent:1},{maxSessions:5,maxConcurrent:1,allowReset:true}])assert.throws(()=>assertPortalActivation(manifest,{...approval,sessionPolicy},current,f.now));
 for(const successfulPredecessor of [undefined,{...run.successfulPredecessor,runId:'../journal'},{...run.successfulPredecessor,resultSha256:hash}])assert.throws(()=>assertPortalActivation(manifest,{...approval,successfulPredecessor},current,f.now));
 assert.throws(()=>assertPortalActivation({...manifest,successfulPredecessor:{...run.successfulPredecessor,runId:run.runId}},{...approval,successfulPredecessor:{...run.successfulPredecessor,runId:run.runId}},current,f.now));
 assert.throws(()=>assertPortalActivation({...manifest,runReviewPath:'docs/portal-relay-retry-review.md'},{...approval,runReviewPath:'docs/portal-relay-retry-review.md'},current,f.now));
 const window=portalActivationWindow(approval,undefined,f.now);assert.throws(()=>portalActivationWindow({...approval,sessionPolicy:{maxSessions:6,maxConcurrent:1}},window,f.now+1000));
});
