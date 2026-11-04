import test from 'node:test';
import assert from 'node:assert/strict';
import {recoverPortalGrants} from '../../src/consent/portal-recovery.ts';
const intent={attempt:'attempt',tokenHash:'h'.repeat(43),grantId:null,createdAt:1000,recoverAfter:2000};
function fixture(patch={},grantPatch={}){let revoked=0,marked=0,state='active';return{revoked:()=>revoked,marked:()=>marked,
 journal:{recoveryIntents:()=>[intent],markRecovered:()=>{marked++;}},
 authority:{findByTokenHash:async()=>[{tokenHash:intent.tokenHash,grantId:'owned-grant',recordedBy:'policy-consent',approvedAt:1100,...patch}],grant:async()=>({id:'owned-grant',state,recordedBy:'policy-consent',...grantPatch}),revoke:async()=>{revoked++;state='revoked';}}};}
test('recovery finds a committed grant after its HTTP response was lost and verifies revocation',async()=>{
 const f=fixture();assert.deepEqual(await recoverPortalGrants(f.journal,f.authority,{recordedBy:'policy-consent',now:3000}),{recovered:1,pending:0});assert.equal(f.revoked(),1);assert.equal(f.marked(),1);
});
for(const patch of [{tokenHash:'foreign'},{recordedBy:'other-workload'},{approvedAt:999},{approvedAt:3001}])test('recovery rejects substituted ownership metadata '+JSON.stringify(patch),async()=>{
 const f=fixture(patch);await assert.rejects(recoverPortalGrants(f.journal,f.authority,{recordedBy:'policy-consent',now:3000}));assert.equal(f.revoked(),0);assert.equal(f.marked(),0);
});
test('an uncommitted or not-yet-visible grant remains pending rather than being forgotten',async()=>{
 const f=fixture();f.authority.findByTokenHash=async()=>[];assert.deepEqual(await recoverPortalGrants(f.journal,f.authority,{recordedBy:'policy-consent',now:3000}),{recovered:0,pending:1});assert.equal(f.marked(),0);
});
test('active browser lease is not revoked by a periodic sweep',async()=>{
 const f=fixture();assert.deepEqual(await recoverPortalGrants(f.journal,f.authority,{recordedBy:'policy-consent',now:1500}),{recovered:0,pending:1});assert.equal(f.revoked(),0);
});
test('stopped-worker recovery can close an owned grant before its lease deadline',async()=>{
 const f=fixture();await recoverPortalGrants(f.journal,f.authority,{recordedBy:'policy-consent',now:1500,workerStopped:true});assert.equal(f.revoked(),1);
});
test('attached grant substitution and ambiguous authority lookup are rejected',async()=>{
 const f=fixture();f.journal.recoveryIntents=()=>[{...intent,grantId:'foreign'} as any];await assert.rejects(recoverPortalGrants(f.journal,f.authority,{recordedBy:'policy-consent',now:3000}));assert.equal(f.revoked(),0);
 const other=fixture(),lookup=other.authority.findByTokenHash;other.authority.findByTokenHash=async()=>[...(await lookup()),...(await lookup())];await assert.rejects(recoverPortalGrants(other.journal,other.authority,{recordedBy:'policy-consent',now:3000}));
});
test('failed revoke or read-back preserves recovery obligation',async()=>{
 const f=fixture();f.authority.revoke=async()=>{throw Error('unavailable');};await assert.rejects(recoverPortalGrants(f.journal,f.authority,{recordedBy:'policy-consent',now:3000}));assert.equal(f.marked(),0);
 const other=fixture();other.authority.revoke=async()=>{};await assert.rejects(recoverPortalGrants(other.journal,other.authority,{recordedBy:'policy-consent',now:3000}));assert.equal(other.marked(),0);
});
