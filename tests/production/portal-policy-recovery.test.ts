import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {PolicyStore} from '../../src/policy/store.ts';
import {PortalJournal} from '../../src/consent/portal-journal.ts';
import {recoverPortalPolicyDatabase} from '../../src/consent/portal-policy-recovery.ts';
const capability={scope:'copilot.invoke',resource:'sharepoint:approved-research'},review='a'.repeat(64);
function fixture(){
 const directory=mkdtempSync(join(tmpdir(),'portal-policy-')),database=join(directory,'policy.sqlite'),store=new PolicyStore(database,[capability]),journal=new PortalJournal(join(directory,'portal.sqlite'),review);
 store.registerOrganisation('partner','admin');store.registerPrincipal({id:'human',kind:'human',issuer:'https://pf.test',subject:'partner:user',organisation:'partner',tokenIssuers:['https://pf.test']},'admin');store.registerPrincipal({id:'agent',kind:'agent',issuer:'https://agent.test',subject:'partner:agent',organisation:'partner'},'admin');
 const now=Date.now(),login={issuer:'https://pf.test',subject:'partner:user',audience:'portal',issuedAt:now,authTime:now,expiresAt:now+300000,tokenHash:'h'.repeat(43),nonceHash:'n'.repeat(43)};
 journal.authorizeTrial({reviewSha256:review,approved:true,expiresAt:now+600000,maxConversations:1,maxTokenPosts:1,maxSuccessfulToolOperations:1});journal.beginConsent(login.tokenHash);
 const owned=store.createConsentedGrant(login,'agent',['interactive'],3600,capability,'policy-consent');
 const foreign=store.createConsentedGrant({...login,tokenHash:'f'.repeat(43)},'agent',['interactive'],3600,capability,'policy-consent');
 return{directory,database,store,journal,owned,foreign,close:()=>{store.close();journal.close();rmSync(directory,{recursive:true,force:true});}};
}
test('actual policy SQLite recovery revokes only the journal-owned consent after lost response',async()=>{
 const f=fixture();try{const result=await recoverPortalPolicyDatabase({database:f.database,journal:f.journal,capability,workerStopped:true});assert.deepEqual(result,{recovered:1,pending:0});assert.equal(f.store.grant(f.owned.grantId)?.state,'revoked');assert.equal(f.store.grant(f.foreign.grantId)?.state,'active');assert.equal(f.store.grant(f.foreign.grantId)?.version,1);assert.deepEqual(f.journal.recoveryIntents(),[]);
  assert.deepEqual(await recoverPortalPolicyDatabase({database:f.database,journal:f.journal,capability,workerStopped:true}),{recovered:0,pending:0});
 }finally{f.close();}
});
test('live session lease prevents actual policy database cleanup',async()=>{
 const f=fixture();try{assert.deepEqual(await recoverPortalPolicyDatabase({database:f.database,journal:f.journal,capability}),{recovered:0,pending:1});assert.equal(f.store.grant(f.owned.grantId)?.state,'active');}finally{f.close();}
});
test('missing policy database is never created as a fallback',async()=>{
 const f=fixture();try{await assert.rejects(recoverPortalPolicyDatabase({database:join(f.directory,'missing.sqlite'),journal:f.journal,capability,workerStopped:true}));assert.equal(f.store.grant(f.owned.grantId)?.state,'active');}finally{f.close();}
});
