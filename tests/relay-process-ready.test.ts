import test from 'node:test';import assert from 'node:assert/strict';import {EventEmitter} from 'node:events';import {waitForRelayReady} from '../scripts/vault/relay-process-ready.mjs';
test('diagnostic messages and foreign instances cannot complete or fail readiness',async()=>{
 const child=new EventEmitter();let completed=false;const ready=waitForRelayReady(child,'selected',1000).then(()=>{completed=true;});
 child.emit('message',{diagnostic:'relay-http',status:401});child.emit('message',{ready:true,instance:'foreign'});await Promise.resolve();assert.equal(completed,false);
 child.emit('message',{ready:true,instance:'selected'});await ready;assert.equal(child.listenerCount('message'),0);assert.equal(child.listenerCount('exit'),0);
});
test('readiness fails with a sanitized error on child failure or deadline',async()=>{
 for(const kind of ['failed','exit','timeout']){const child=new EventEmitter(),ready=waitForRelayReady(child,'selected',10);if(kind==='failed')child.emit('message',{failed:true,secret:'synthetic-private'});if(kind==='exit')child.emit('exit',1);await assert.rejects(ready,e=>String(e)==='Error: Managed relay readiness unavailable');assert.equal(child.listenerCount('message'),0);}
});
