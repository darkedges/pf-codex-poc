import test from 'node:test';import assert from 'node:assert/strict';import {EventEmitter} from 'node:events';import {randomUUID} from 'node:crypto';
import {attachPortalRpcServer,createPortalRpcClient} from '../../src/consent/portal-rpc.ts';
function pair(){const parent=new EventEmitter() as any,child=new EventEmitter() as any;parent.send=(m:any)=>{queueMicrotask(()=>child.emit('message',structuredClone(m)));};child.send=(m:any)=>{queueMicrotask(()=>parent.emit('message',structuredClone(m)));};return{parent,child};}
test('finite RPC dispatch returns only the method result and drains outstanding work',async()=>{
 const p=pair(),server=attachPortalRpcServer(p.parent,{execute:async()=>({authorized:true})}),client=createPortalRpcClient(p.child);
 try{const args=[{grantId:'owned',providerToken:'synthetic',login:{idToken:'synthetic-id',nonce:'synthetic'}}];assert.deepEqual(await client.call('execute',args),{authorized:true});await server.drain();await assert.rejects(client.call('execute',args));}finally{client.close();server.close();}
});
test('unknown methods, malformed input, replay IDs and extra metadata never reach handlers',async()=>{
 const p=pair();let calls=0;const results:any[]=[];p.child.on('message',(m:any)=>results.push(m));const server=attachPortalRpcServer(p.parent,{'provider.start':async()=>{calls++;return'https://provider.test/authorize';}});
 try{const id=randomUUID();p.child.send({kind:'call',id,method:'provider.start',args:['s'.repeat(43),'v'.repeat(43)]});await new Promise(done=>setImmediate(done));
  for(const message of [{kind:'call',id,method:'provider.start',args:['s'.repeat(43),'v'.repeat(43)]},{kind:'call',id:randomUUID(),method:'vault.read',args:['/secret']},{kind:'call',id:randomUUID(),method:'provider.start',args:[],token:'private'},{kind:'call',id:randomUUID(),method:'execute',args:[{grantId:'owned',providerToken:'synthetic',login:{idToken:'synthetic-id',nonce:'synthetic'},scope:'admin'}]}])p.child.send(message);
  await new Promise(done=>setImmediate(done));assert.equal(calls,1);assert.ok(!JSON.stringify(results).includes('private'));
 }finally{server.close();}
});
test('private handler exceptions and private-key response fields are never forwarded',async()=>{
 const p=pair(),server=attachPortalRpcServer(p.parent,{'provider.start':async()=>{throw Error('PRIVATE-KEY');},execute:async()=>({authorized:true,privateKey:'PRIVATE-KEY'})}),client=createPortalRpcClient(p.child);
 try{await assert.rejects(client.call('provider.start',['s'.repeat(43),'v'.repeat(43)]),/^PolicyError: unavailable$/);await assert.rejects(client.call('execute',[{grantId:'owned',providerToken:'synthetic',login:{idToken:'id',nonce:'nonce'}}]),/^PolicyError: unavailable$/);}finally{server.close();client.close();}
});
test('disconnect rejects pending calls and removes client listeners',async()=>{
 const p=pair(),server=attachPortalRpcServer(p.parent,{'provider.start':async()=>new Promise(()=>{})}),client=createPortalRpcClient(p.child),pending=client.call('provider.start',['s'.repeat(43),'v'.repeat(43)]);
 p.child.emit('disconnect');await assert.rejects(pending,/unavailable/);assert.equal(p.child.listenerCount('message'),0);server.close();
});
