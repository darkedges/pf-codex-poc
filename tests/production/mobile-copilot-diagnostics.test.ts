import test from 'node:test';import assert from 'node:assert/strict';
import {mobileCopilotDiagnostics} from '../../src/mobile/copilot-diagnostics.ts';
test('Copilot diagnostics reconstruct fixed categories without credentials, identities or arbitrary errors',()=>{
 let saved:unknown;const observe=mobileCopilotDiagnostics(events=>{saved=events;},()=>1000);
 observe({event:'copilot_directline',operation:'poll',outcome:'oauth_invalid',durationMs:7,token:'secret',url:'signed-url'});
 assert.deepEqual(saved,[{at:1000,operation:'poll',outcome:'oauth_invalid',durationMs:7}]);
 for(const field of [{operation:'secret'},{outcome:'raw exception secret'},{durationMs:Infinity},{durationMs:-1}])observe({event:'copilot_directline',operation:'poll',outcome:'ok',durationMs:1,...field});
 assert.equal((saved as unknown[]).length,1);
});
test('Copilot diagnostics bound history, expire after one day and cannot break execution',()=>{
 let at=1,saved:unknown[]=[];const observe=mobileCopilotDiagnostics(events=>{saved=events;},()=>at);
 const e={event:'copilot_directline',operation:'poll',outcome:'ok',durationMs:1};
 for(let i=0;i<200;i++)observe(e);assert.equal(saved.length,128);
 at+=86400000;observe.maintain();assert.equal(saved.length,0);observe(e);assert.equal(saved.length,1);
 assert.doesNotThrow(()=>mobileCopilotDiagnostics(()=>{throw Error('disk');})(e));
});
