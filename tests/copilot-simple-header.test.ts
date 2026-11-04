import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
test('simple provider-header candidate preserves the reviewed operation and caller authentication',()=>{
 const read=(name:string)=>JSON.parse(readFileSync(new URL('../infra/copilot/'+name,import.meta.url),'utf8'));
 const original=read('microsoft-tool-test.openapi.json'),candidate=read('microsoft-tool-test.simple-header.openapi.json');
 const expected=structuredClone(original);expected.info=candidate.info;expected.paths['/v1/copilot-tools/verify-access'].post.parameters[0].name='PfUserAccessToken';
 assert.deepEqual(candidate,expected);
 assert.equal(candidate.paths['/v1/copilot-tools/verify-access'].post.parameters[0].in,'header');
 assert.equal(candidate.securityDefinitions.connectionKey.name,'X-Copilot-Connection-Key');
});
