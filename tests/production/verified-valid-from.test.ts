import test from 'node:test';import assert from 'node:assert/strict';
import {waitForVerifiedValidFrom} from '../../src/identity/verified-valid-from.ts';
test('verified PF proof is not released before its actual validity start',async()=>{const target=Math.floor(Date.now()/1000)+1;await waitForVerifiedValidFrom({iat:target,nbf:target},new AbortController().signal);assert.ok(Date.now()>=target*1000);});
test('far-future or malformed validity cannot create an unbounded wait',async()=>{for(const input of [{iat:1,nbf:Math.floor(Date.now()/1000)+10},{iat:1.5,nbf:1},{iat:NaN,nbf:1}])await assert.rejects(waitForVerifiedValidFrom(input,new AbortController().signal));});
test('cancellation immediately ends the bounded validity wait',async()=>{const c=new AbortController(),target=Math.floor(Date.now()/1000)+4,pending=waitForVerifiedValidFrom({iat:target,nbf:target},c.signal);c.abort();await assert.rejects(pending);await assert.rejects(waitForVerifiedValidFrom({iat:1,nbf:1},c.signal));});
