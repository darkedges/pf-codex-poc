import test from 'node:test';import assert from 'node:assert/strict';
import {tokenPostErrorMetadata} from '../scripts/copilot/token-post-error.mjs';
test('vendor error metadata reports fixed categories without echoing messages or credentials',()=>{const metadata=tokenPostErrorMetadata('{"error":{"code":"BadRequest","message":"Invalid token PRIVATE_TOKEN?state=PRIVATE_STATE"}}');assert.deepEqual(metadata,{category:'invalid_token',jsonError:true});assert.ok(!JSON.stringify(metadata).includes('PRIVATE'));});
for(const input of ['PRIVATE_TOKEN',{error:'PRIVATE'}.toString(),'x'.repeat(17000)])test('unknown or oversized vendor errors stay generic',()=>{assert.deepEqual(tokenPostErrorMetadata(input),{category:'unclassified',jsonError:false});});
