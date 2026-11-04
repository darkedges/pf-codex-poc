import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,readFileSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {PortalJournal} from '../../src/consent/portal-journal.ts';
const review='a'.repeat(64),hash='b'.repeat(43);
const approval=()=>({reviewSha256:review,approved:true as const,expiresAt:Date.now()+600000,maxConversations:1,maxTokenPosts:1,maxSuccessfulToolOperations:1});
function fixture(){const directory=mkdtempSync(join(tmpdir(),'portal-journal-')),path=join(directory,'portal.sqlite');return{directory,path,close:()=>rmSync(directory,{recursive:true,force:true})};}
test('no approval means no grant intent or Microsoft reservation',()=>{
 const f=fixture(),j=new PortalJournal(f.path,review);try{assert.throws(()=>j.beginConsent(hash));assert.deepEqual(j.recoveryIntents(),[]);}finally{j.close();f.close();}
});
test('consent intent precedes remote creation and allowance persists across new processes',()=>{
 const f=fixture();let j=new PortalJournal(f.path,review);try{
  j.authorizeTrial(approval());const attempt=j.beginConsent(hash);assert.equal(j.recoveryIntents().length,1);
  j.attachGrant(attempt,'owned-grant');j.beginExecution(attempt);j.consume(attempt,'conversation');j.consume(attempt,'tokenPost');
  assert.throws(()=>j.consume(attempt,'conversation'));assert.throws(()=>j.consume(attempt,'tokenPost'));assert.throws(()=>j.beginConsent('c'.repeat(43)));
  j.close();j=new PortalJournal(f.path,review);assert.throws(()=>j.beginConsent(hash));assert.throws(()=>j.authorizeTrial(approval()));
  assert.throws(()=>j.consume(attempt,'conversation'));assert.equal(j.recoveryIntents()[0].grantId,'owned-grant');
 }finally{j.close();f.close();}
});
test('a fresh process may recover but never resume an interrupted Microsoft attempt',()=>{
 const f=fixture();let j=new PortalJournal(f.path,review);try{j.authorizeTrial(approval());const attempt=j.beginConsent(hash);j.close();j=new PortalJournal(f.path,review);
  assert.throws(()=>j.consume(attempt,'conversation'));assert.equal(j.recoveryIntents()[0].tokenHash,hash);
 }finally{j.close();f.close();}
});
test('recovery is idempotent and does not reset the spent trial',()=>{
 const f=fixture(),j=new PortalJournal(f.path,review);try{j.authorizeTrial(approval());const attempt=j.beginConsent(hash);j.markRecovered(attempt);j.markRecovered(attempt);
  assert.deepEqual(j.recoveryIntents(),[]);assert.throws(()=>j.beginConsent(hash));assert.throws(()=>j.consume(attempt,'conversation'));
 }finally{j.close();f.close();}
});
test('approval, ownership and event substitutions fail closed',()=>{
 const f=fixture(),j=new PortalJournal(f.path,review);try{
  for(const patch of [{approved:false},{reviewSha256:'c'.repeat(64)},{expiresAt:1},{maxConversations:2},{maxTokenPosts:2},{maxSuccessfulToolOperations:2}])assert.throws(()=>j.authorizeTrial({...approval(),...patch} as any));
  j.authorizeTrial(approval());assert.throws(()=>j.beginConsent('raw-token'));const attempt=j.beginConsent(hash);j.attachGrant(attempt,'owned-grant');assert.throws(()=>j.attachGrant(attempt,'foreign-grant'));
  assert.throws(()=>j.consume('foreign','conversation'));assert.throws(()=>j.consume(attempt,'arbitrary' as any));assert.throws(()=>j.consume(attempt,'tokenPost'));
 }finally{j.close();f.close();}
});
test('another journal handle cannot reserve a second allowance and historical files stay unchanged',()=>{
 const f=fixture(),history=join(f.directory,'historical-budget.json');writeFileSync(history,'historical-consumed');const j=new PortalJournal(f.path,review),other=new PortalJournal(f.path,review);
 try{j.authorizeTrial(approval());j.beginConsent(hash);assert.throws(()=>other.beginConsent('c'.repeat(43)));assert.equal(readFileSync(history,'utf8'),'historical-consumed');}finally{j.close();other.close();f.close();}
});
test('finished execution makes its owned grant eligible for immediate scheduled recovery',()=>{
 const f=fixture(),j=new PortalJournal(f.path,review);try{j.authorizeTrial(approval());const attempt=j.beginConsent(hash);j.attachGrant(attempt,'owned-grant');j.beginExecution(attempt);j.finish(attempt);assert.ok(j.recoveryIntents()[0].recoverAfter<=Date.now());assert.equal(j.trialEnabled(),false);}finally{j.close();f.close();}
});
test('one-day metadata pruning preserves the spent trial and cannot rearm consent',()=>{
 const f=fixture(),j=new PortalJournal(f.path,review),original=Date.now;try{j.authorizeTrial(approval());assert.equal(j.canStartSignIn(),true);const attempt=j.beginConsent(hash);assert.equal(j.canStartSignIn(),false);j.markRecovered(attempt);const future=original()+25*3600000;Date.now=()=>future;j.pruneRecovered();assert.equal(j.trialSnapshot()?.state,'finished');assert.equal(j.canStartSignIn(),false);assert.throws(()=>j.authorizeTrial(approval()));assert.throws(()=>j.beginConsent(hash));}finally{Date.now=original;j.close();f.close();}
});
