import test from 'node:test';import assert from 'node:assert/strict';
import {consumeToolAttempt,toolAttemptFiles} from '../scripts/copilot/tool-diagnostic-budget.mjs';
test('header repair attempt has independent approval/publication/ledger and preserves both consumed predecessors',()=>{
 const first=toolAttemptFiles('--run'),second=toolAttemptFiles('--run-followup-1'),third=toolAttemptFiles('--run-simple-header-1');
 assert.equal(new Set([first.budget,second.budget,third.budget]).size,3);
 assert.equal(new Set([first.approval,second.approval,third.approval]).size,3);
 assert.deepEqual(third.previous,[first.budget,second.budget]);
 assert.equal(third.publication,'publication-simple-header-1-confirmation.json');
 for(const unknown of ['--run-simple-header-2','../budget','--run-followup-2'])assert.throws(()=>toolAttemptFiles(unknown));
});
test('one tool attempt admits one conversation and one token post',()=>{
 const initial={conversations:0,tokenPosts:0};const opened=consumeToolAttempt(initial,'conversation');
 assert.deepEqual(initial,{conversations:0,tokenPosts:0});
 assert.deepEqual(consumeToolAttempt(opened,'tokenPost'),{conversations:1,tokenPosts:1});
});
for(const [state,event] of [[{conversations:0,tokenPosts:0},'tokenPost'],[{conversations:1,tokenPosts:0},'conversation'],[{conversations:1,tokenPosts:1},'tokenPost'],[{conversations:2,tokenPosts:0},'tokenPost'],[{conversations:0,tokenPosts:0},'other']])test('tool allowance rejects invalid transition '+JSON.stringify([state,event]),()=>assert.throws(()=>consumeToolAttempt(state,event)));
