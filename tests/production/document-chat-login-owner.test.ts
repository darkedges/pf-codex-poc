import test from 'node:test';import assert from 'node:assert/strict';
import {createDocumentChatLoginOwner} from '../../src/consent/document-chat-login-owner.ts';
test('only the two login proofs returned by this controller can be used',async()=>{
 const calls:string[]=[];const owner=createDocumentChatLoginOwner({verify:async(token:string,nonce:string)=>{calls.push(token);return{token,nonce};}});
 await assert.rejects(owner.verify('foreign-token','nonce'));assert.deepEqual(calls,[]);
 owner.remember('first-token','first-nonce');assert.deepEqual(await owner.verify('first-token','first-nonce'),{token:'first-token',nonce:'first-nonce'});
 await assert.rejects(owner.verify('first-token','other-nonce'));owner.remember('second-token','second-nonce');
 assert.throws(()=>owner.remember('third-token','nonce'));assert.throws(()=>owner.remember('first-token','first-nonce'));
 owner.close();await assert.rejects(owner.verify('first-token','first-nonce'));assert.throws(()=>owner.remember('token','nonce'));
});
