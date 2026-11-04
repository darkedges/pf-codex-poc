import test from 'node:test';
import assert from 'node:assert/strict';
import {importSPKI,jwtVerify} from 'jose';
import {ForegroundProof} from '../src/foreground-proof.ts';
const origin='https://agent.example.test';
test('foreground key signs exact requests and matches the server protocol',async()=>{
 const proof=new ForegroundProof(origin),spki=await proof.create();
 const sessionId=crypto.randomUUID();proof.bind({sessionId,serverTime:Date.now(),sessionExpiresAt:Date.now()+60000});
 const token=await proof.sign('{"question":"hello"}');
 const key=await importSPKI(`-----BEGIN PUBLIC KEY-----\n${Buffer.from(spki,'base64url').toString('base64')}\n-----END PUBLIC KEY-----`,'ES256');
 const {payload,protectedHeader}=await jwtVerify(token,key,{algorithms:['ES256'],typ:'fc-mobile-request+jwt',issuer:sessionId,subject:sessionId,audience:origin});
 assert.equal(protectedHeader.alg,'ES256');assert.equal(payload.htm,'POST');assert.equal(payload.htu,origin+'/v1/mobile/chat/messages');
 assert.equal(payload.body_hash,Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode('{"question":"hello"}'))).toString('base64url'));
 assert.notEqual((await proof.sign('{}')),token);assert.ok(Number(payload.exp)-Number(payload.iat)<=60);
});
test('locked, unbound, expired and invalid configurations never produce a request proof',async()=>{
 for(const value of ['http://agent.example.test','https://other.test/path','https://agent.example.test/','https://user@agent.example.test'])assert.throws(()=>new ForegroundProof(value));
 const p=new ForegroundProof(origin);await assert.rejects(p.sign('{}'));await p.create();await assert.rejects(p.sign('{}'));
 assert.throws(()=>p.bind({sessionId:'not-a-session',serverTime:Date.now(),sessionExpiresAt:Date.now()+10000}));
 p.bind({sessionId:crypto.randomUUID(),serverTime:Date.now(),sessionExpiresAt:Date.now()+30000});
 await assert.rejects(p.sign('x'.repeat(16001)));p.lock();await assert.rejects(p.sign('{}'));
 await p.create();assert.throws(()=>p.bind({sessionId:crypto.randomUUID(),serverTime:Date.now(),sessionExpiresAt:Date.now()-1}));
});
test('background cancellation rejects in-flight proof creation and destroys the old session',async()=>{
 let release;const gate=new Promise<void>(resolve=>release=resolve);
 const p=new ForegroundProof(origin,()=>Date.now(),async()=>gate);
 const pending=p.create();p.lock();release();await assert.rejects(pending);
 await p.create();p.bind({sessionId:crypto.randomUUID(),serverTime:Date.now(),sessionExpiresAt:Date.now()+30000});p.lock();await assert.rejects(p.sign('{}'));
});
test('resource-consent requests have their own signed path and arbitrary paths stay forbidden',async()=>{
 const p=new ForegroundProof(origin);await p.create();p.bind({sessionId:crypto.randomUUID(),serverTime:Date.now(),sessionExpiresAt:Date.now()+60000});
 const proof=await p.sign('{}','/v1/mobile/access/status');const payload=JSON.parse(Buffer.from(proof.split('.')[1],'base64url').toString());assert.equal(payload.htu,origin+'/v1/mobile/access/status');
 await assert.rejects(p.sign('{}','/admin'));
});
test('server clock anchor permits an ahead phone without relaxing JWT checks and ignores wall clock changes',async()=>{const server=Date.now();let wall=server+6500,elapsed=0;const p=new ForegroundProof(origin,()=>wall,async()=>{},()=>elapsed),spki=await p.create(),sessionId=crypto.randomUUID();p.bind({sessionId,sessionExpiresAt:server+900000,serverTime:server});wall+=3600000;elapsed=2000;const token=await p.sign('{}','/v1/mobile/access/status'),key=await importSPKI(`-----BEGIN PUBLIC KEY-----\n${Buffer.from(spki,'base64url').toString('base64')}\n-----END PUBLIC KEY-----`,'ES256');const {payload}=await jwtVerify(token,key,{currentDate:new Date(server+2000),clockTolerance:0,audience:origin});assert.equal(payload.iat,Math.floor((server+2000)/1000));elapsed=900001;await assert.rejects(p.sign('{}'));});
test('missing or implausible server anchors and oversized sessions fail closed',async()=>{const now=Date.now(),p=new ForegroundProof(origin);await p.create();const session={sessionId:crypto.randomUUID(),sessionExpiresAt:now+60000,serverTime:now};for(const patch of [{serverTime:undefined},{serverTime:NaN},{serverTime:now+600000},{serverTime:0},{sessionExpiresAt:now+900001}])assert.throws(()=>p.bind({...session,...patch}));await assert.rejects(p.sign('{}'));});
