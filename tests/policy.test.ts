import test from 'node:test';
import assert from 'node:assert/strict';
import {authorise,operationScope} from '../src/lib/policy.ts';
const good={grantId:'grant-demo',user:'partner-a:user-123',agent:'partner-a:agent-research',mode:'autonomous' as const,scope:'m365.document.read',resource:'sharepoint:approved-research'};
test('approved grant authorizes external user+agent+resource intersection',()=>{
  assert.equal(authorise(good).org,'partner-a');
});
test('wrong user rejected',()=>assert.throws(()=>authorise({...good,user:'partner-a:someone-else'})));
test('wrong agent rejected',()=>assert.throws(()=>authorise({...good,agent:'partner-a:other-agent'})));
test('revoked grant rejected',()=>assert.throws(()=>authorise({...good,grantId:'grant-revoked'})));
test('unapproved site rejected',()=>assert.throws(()=>authorise({...good,resource:'sharepoint:finance'})));
test('unknown operation rejected',()=>assert.throws(()=>operationScope('documents.delete','sharepoint:approved-research')));
