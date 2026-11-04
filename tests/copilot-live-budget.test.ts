import test from 'node:test';import assert from 'node:assert/strict';
import {reserveConversation,reserveTimingFollowup,reserveOperatorRetry} from '../scripts/copilot/live-budget.mjs';

test('operator retry preserves spent history and permits exactly one interactive attempt',()=>{
 const original={max:2,reserved:['interactive','autonomous']},timing={max:1,reserved:['interactive']};
 const before=JSON.stringify([original,timing]);
 assert.deepEqual(reserveOperatorRetry(original,timing,{max:1,reserved:[]}),{max:1,reserved:['interactive']});
 assert.equal(JSON.stringify([original,timing]),before);
 assert.throws(()=>reserveOperatorRetry(original,timing,{max:1,reserved:['interactive']}));
 assert.throws(()=>reserveOperatorRetry(original,{max:1,reserved:[]},{max:1,reserved:[]}));
});
test('approved budget allows one interactive and one autonomous reservation',()=>{const a=reserveConversation({max:2,reserved:[]},'interactive');assert.deepEqual(reserveConversation(a,'autonomous'),{max:2,reserved:['interactive','autonomous']});});
for(const [budget,mode]of [[{max:2,reserved:['interactive']},'interactive'],[{max:2,reserved:['interactive','autonomous']},'autonomous'],[{max:3,reserved:[]},'interactive'],[{max:2,reserved:[]},'unknown'],[{max:2,reserved:['unknown']},'interactive']])test('ambiguous or reused reservation cannot create an extra conversation',()=>{assert.throws(()=>reserveConversation(budget,mode));});
test('explicit timing extension reserves only one interactive attempt without resetting original history',()=>{const original={max:2,reserved:['interactive','autonomous']};const before=JSON.stringify(original);assert.deepEqual(reserveTimingFollowup(original,{max:1,reserved:[]}),{max:1,reserved:['interactive']});assert.equal(JSON.stringify(original),before);});
for(const [original,followup]of [[{max:2,reserved:['interactive']},{max:1,reserved:[]}],[{max:2,reserved:['interactive','autonomous']},{max:1,reserved:['interactive']}],[{max:2,reserved:['interactive','autonomous']},{max:2,reserved:[]}],[{max:2,reserved:['interactive','interactive']},{max:1,reserved:[]}]])test('invalid history or used timing extension fails closed',()=>{assert.throws(()=>reserveTimingFollowup(original,followup));});
