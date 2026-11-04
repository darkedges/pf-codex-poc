import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
test('tool transcript lookup uses timestamp comparisons rather than calendar-date filters',()=>{
 const script=readFileSync(new URL('../scripts/copilot/inspect-tool-transcript.mjs',import.meta.url),'utf8');
 assert.match(script,/attribute="conversationstarttime" operator="ge" value="2026-10-31T14:24:00Z"/);
 assert.match(script,/attribute="conversationstarttime" operator="le" value="2026-10-31T14:27:00Z"/);
 assert.doesNotMatch(script,/operator="on-or-after"|operator="on-or-before"/);
 assert.match(script,/attribute="bot_conversationtranscriptid" operator="eq"/);
});
