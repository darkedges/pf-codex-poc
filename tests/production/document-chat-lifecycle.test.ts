import test from 'node:test';import assert from 'node:assert/strict';
import {createDocumentChatLifecycle} from '../../scripts/vault/document-chat-lifecycle.mjs';
test('closing the question retires authority while leaving the answer worker available',async()=>{
 const calls:string[]=[];const d={abort:()=>calls.push('abort'),stopWorker:async()=>{calls.push('worker');},stopRuntime:async()=>{calls.push('runtime');},releasePf:async()=>{calls.push('pf');},stopDocumentPolicy:async()=>{calls.push('document');},stopOwnedChatPolicy:async()=>{calls.push('chat');}};
 const life=createDocumentChatLifecycle(d);await life.retireAuthority();assert.deepEqual(calls,['pf','document','chat']);await life.retireAuthority();await life.stop();await life.stop();assert.deepEqual(calls,['pf','document','chat','abort','worker','runtime']);
});
test('cleanup attempts all owned resources, retains failures and never silently retries mutations',async()=>{
 const calls:string[]=[];const life=createDocumentChatLifecycle({abort:()=>calls.push('abort'),stopWorker:async()=>{calls.push('worker');throw Error('private');},stopRuntime:async()=>{calls.push('runtime');throw Error('private');},releasePf:async()=>{calls.push('pf');throw Error('private');},stopDocumentPolicy:async()=>{calls.push('document');},stopOwnedChatPolicy:async()=>{calls.push('chat');}});
 await assert.rejects(life.stop(),/document_chat_cleanup_required/);assert.deepEqual(calls,['abort','worker','runtime','pf','document','chat']);await assert.rejects(life.stop());assert.equal(calls.length,6);
});
