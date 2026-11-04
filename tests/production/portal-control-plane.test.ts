import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {PortalJournal} from '../../src/consent/portal-journal.ts';
import {createPortalControlPlane} from '../../src/consent/portal-control-plane.ts';
const review='a'.repeat(64),proof={idToken:'synthetic-id-token',nonce:'synthetic-nonce'};
function fixture(options:{lostResponse?:boolean;omitCounts?:boolean}={}){
 const directory=mkdtempSync(join(tmpdir(),'portal-control-')),journal=new PortalJournal(join(directory,'state.sqlite'),review);let approvals=0,operations=0;
 journal.authorizeTrial({reviewSha256:review,approved:true,expiresAt:Date.now()+600000,maxConversations:1,maxTokenPosts:1,maxSuccessfulToolOperations:1});
 const control=createPortalControlPlane({journal,verifier:{verify:async(token,nonce)=>{assert.equal(token,proof.idToken);assert.equal(nonce,proof.nonce);return{tokenHash:'h'.repeat(43)} as any;}},policy:{request:async(path)=>{if(path.endsWith('approve')){assert.equal(journal.recoveryIntents().length,1);approvals++;if(options.lostResponse)throw Error('lost response');return{grantId:'owned-grant'};}return{revoked:true};}},perform:async(_proof,controls)=>{if(!options.omitCounts){controls.beforeConversation();controls.beforeTokenPost();}operations++;return{authorized:true};}});
 return{control,journal,approvals:()=>approvals,operations:()=>operations,close:()=>{journal.close();rmSync(directory,{recursive:true,force:true});}};
}
const approve=(f:ReturnType<typeof fixture>)=>f.control.policy.request('/v1/consents/approve',{...proof,termsHash:'terms',modes:['interactive'],durationSeconds:3600});
const execute=(f:ReturnType<typeof fixture>,grantId='owned-grant')=>f.control.execute({grantId,providerToken:'synthetic-provider',login:proof});
test('control plane reserves before grant creation and permits only one measured diagnostic',async()=>{
 const f=fixture();try{await approve(f);assert.deepEqual(await execute(f),{authorized:true});await assert.rejects(execute(f));assert.equal(f.operations(),1);assert.equal(f.approvals(),1);}finally{f.close();}
});
test('lost approval response preserves the ownership intent and consumes allowance',async()=>{
 const f=fixture({lostResponse:true});try{await assert.rejects(approve(f));assert.equal(f.journal.recoveryIntents().length,1);await assert.rejects(approve(f));assert.equal(f.approvals(),1);}finally{f.close();}
});
test('authority, endpoint and grant substitutions never reach operation',async()=>{
 const f=fixture();try{await assert.rejects(execute(f));await assert.rejects(f.control.policy.request('/v1/grants',proof));await assert.rejects(f.control.policy.request('/v1/consents/approve',{...proof,modes:['autonomous'],durationSeconds:3600}));await approve(f);await assert.rejects(execute(f,'foreign'));assert.equal(f.operations(),0);}finally{f.close();}
});
test('success without measured conversation and token POST is not verification',async()=>{
 const f=fixture({omitCounts:true});try{await approve(f);await assert.rejects(execute(f));await assert.rejects(execute(f));assert.equal(f.operations(),1);}finally{f.close();}
});
test('explicit revocation finishes the trial and makes recovery immediately eligible',async()=>{
 const f=fixture();try{await approve(f);await f.control.policy.request('/v1/consents/revoke',{...proof,grantId:'owned-grant'});assert.equal(f.journal.trialSnapshot()?.state,'finished');assert.ok(f.journal.recoveryIntents()[0].recoverAfter<=Date.now());await assert.rejects(execute(f));assert.equal(f.operations(),0);}finally{f.close();}
});
