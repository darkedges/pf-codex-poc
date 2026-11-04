import test from 'node:test';import assert from 'node:assert/strict';
import {withToolClient} from '../scripts/pf/tool-client-lease.mjs';
function fixture(a=true,b=false){const clients={a:{clientId:'copilot-studio-generic-oauth',enabled:a,marker:'preserve'},b:{clientId:'copilot-sso-exchange',enabled:b,clientAuth:{type:'PRIVATE_KEY_JWT',enforceReplayPrevention:true},grantTypes:['TOKEN_EXCHANGE'],defaultAccessTokenManagerRef:{id:'copilotToolJWT'}}};const writes:string[]=[];return{clients,writes,admin:async(node:'a'|'b',_path:string,method='GET',body?:any)=>{if(method==='PUT'){writes.push(node);clients[node]=structuredClone(body);}return structuredClone(clients[node]);}};}
test('tool lease enables only B and restores it while preserving the active human client',async()=>{const f=fixture();assert.equal(await withToolClient(f.admin,async()=>{assert.equal(f.clients.b.enabled,true);return'ok';}),'ok');assert.equal(f.clients.a.enabled,true);assert.equal(f.clients.a.marker,'preserve');assert.equal(f.clients.b.enabled,false);assert.deepEqual(f.writes,['b','b']);});
test('tool lease restores B on verification failure',async()=>{const f=fixture();await assert.rejects(withToolClient(f.admin,async()=>{throw Error('test');}));assert.equal(f.clients.b.enabled,false);assert.equal(f.clients.a.enabled,true);});
for(const state of [[false,false],[true,true]])test('unexpected client lifecycle refuses changes',async()=>{const f=fixture(...state);let called=false;await assert.rejects(withToolClient(f.admin,async()=>{called=true;}));assert.equal(called,false);assert.equal(f.writes.length,0);});
test('client authentication/profile drift refuses enablement',async()=>{const f=fixture();f.clients.b.clientAuth.type='SECRET';await assert.rejects(withToolClient(f.admin,async()=>{}));assert.equal(f.writes.length,0);});
test('an ambiguous enable response still attempts and verifies disable',async()=>{const f=fixture();let first=true;await assert.rejects(withToolClient(async(...args:any[])=>{const value=await f.admin(...args);if(args[2]==='PUT'&&first){first=false;throw Error('ambiguous');}return value;},async()=>{}));assert.equal(f.clients.b.enabled,false);assert.equal(f.clients.a.enabled,true);});
test('PF randomized encryptedSecret representation is not configuration drift',async()=>{
 const f=fixture();let reads=0;
 const admin=async(...args:any[])=>{const value=await f.admin(...args);if(args[0]==='a')value.clientAuth={type:'SECRET',encryptedSecret:'encrypted-representation-'+(++reads),secondarySecrets:[]};return value;};
 await withToolClient(admin,async()=>{});assert.deepEqual(f.writes,['b','b']);
});
test('human client authentication configuration drift still fails after B cleanup',async()=>{
 const f=fixture();await assert.rejects(withToolClient(f.admin,async()=>{f.clients.a.marker='changed';}),/Human client changed/);assert.equal(f.clients.b.enabled,false);assert.deepEqual(f.writes,['b','b']);
});
