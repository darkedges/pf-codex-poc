import test from 'node:test';import assert from 'node:assert/strict';
import {clientFingerprint,callbackChange,applyPortalCallbacks,createPortalPfLease,assertPortalToolKey} from '../../scripts/pf/portal-activation-policy.mjs';
const consent={clientId:'copilot-consent-portal',enabled:true,clientAuth:{type:'PRIVATE_KEY_JWT',enforceReplayPrevention:true,tokenEndpointAuthSigningAlgorithm:'RS256'},grantTypes:['AUTHORIZATION_CODE'],redirectUris:['https://localhost:9460/callback','https://localhost:9461/callback'],restrictedScopes:['openid'],restrictScopes:true,requirePushedAuthorizationRequests:true,requireProofKeyForCodeExchange:true};
const login={clientId:'copilot-studio-generic-oauth',enabled:true,clientAuth:{type:'SECRET',encryptedSecret:'synthetic-encrypted'},grantTypes:['AUTHORIZATION_CODE'],redirectUris:['https://token.botframework.com/.auth/web/redirect'],restrictedScopes:['copilot.login'],restrictScopes:true,defaultAccessTokenManagerRef:{id:'copilotLoginJWT'},restrictToDefaultAccessTokenManager:true};
const tool={clientId:'copilot-sso-exchange',enabled:false,clientAuth:{type:'PRIVATE_KEY_JWT',enforceReplayPrevention:true,tokenEndpointAuthSigningAlgorithm:'RS256'},grantTypes:['TOKEN_EXCHANGE'],defaultAccessTokenManagerRef:{id:'copilotToolJWT'}};
function fixture(){const clients:any={...Object.fromEntries([consent,login,tool].map(c=>[c.clientId,structuredClone(c)]))};const writes:any[]=[];let stored:any;
 const admin=async(node:string,path:string,method='GET',body?:any)=>{const id=path.split('/').pop()!;assert.equal(node,id===tool.clientId?'b':'a');if(method==='PUT'){writes.push({id,body:structuredClone(body)});clients[id]=structuredClone(body);}return structuredClone(clients[id]);};
 const store={get:()=>stored,create:(v:any)=>{if(stored)throw Error();stored=structuredClone(v);},remove:()=>{if(!stored)throw Error('Already removed');stored=undefined;}};
 return{clients,writes,admin,store,stored:()=>stored};}
test('callback changes add exactly the two approved URLs and preserve client authentication',async()=>{
 const f=fixture(),changes=[callbackChange(consent),callbackChange(login)];await applyPortalCallbacks(f.admin,changes);assert.deepEqual(f.clients[login.clientId].clientAuth,login.clientAuth);assert.equal(f.writes.length,2);
 assert.ok(f.clients[consent.clientId].redirectUris.includes('https://agent.copilot.darkedges.com/callback'));assert.ok(f.clients[login.clientId].redirectUris.includes('https://agent.copilot.darkedges.com/provider-callback'));
 await applyPortalCallbacks(f.admin,changes);assert.equal(f.writes.length,2);
});
test('callback drift, unknown clients and broader original redirects are rejected',async()=>{
 assert.throws(()=>callbackChange({...login,redirectUris:['https://evil.test']}));assert.throws(()=>callbackChange({...consent,clientId:'foreign'}));
 assert.throws(()=>callbackChange({...consent,requirePushedAuthorizationRequests:false}));assert.throws(()=>callbackChange({...consent,requireProofKeyForCodeExchange:false}));assert.throws(()=>callbackChange({...login,defaultAccessTokenManagerRef:{id:'other'}}));
 const f=fixture(),changes=[callbackChange(consent),callbackChange(login)];f.clients[login.clientId].restrictedScopes=['admin'];await assert.rejects(applyPortalCallbacks(f.admin,changes));assert.equal(f.writes.length,0);
});
test('lost enable response and failed disable never discard recovery ownership',async()=>{
 const f=fixture(),base={store:f.store,owner:{instance:'owned-instance',pid:123},baselineHash:clientFingerprint(tool),humanHash:clientFingerprint(login),expiresAt:Date.now()+60000};
 const lost={...base,admin:async(...args:any[])=>{const result=await (f.admin as any)(...args);if(args[2]==='PUT'&&args[3]?.enabled===true)throw Error('lost response');return result;}};
 await assert.rejects(createPortalPfLease(lost).acquire());assert.ok(f.stored());assert.equal(f.clients[tool.clientId].enabled,true);
 const failed={...base,admin:async(...args:any[])=>{if(args[2]==='PUT'&&args[3]?.enabled===false)throw Error('offline');return (f.admin as any)(...args);}};
 await assert.rejects(createPortalPfLease(failed).release());assert.ok(f.stored());await createPortalPfLease({...base,admin:f.admin}).release();assert.equal(f.clients[tool.clientId].enabled,false);assert.equal(f.stored(),undefined);
});
test('callback rollback removes only the approved addition and refuses unrelated drift',async()=>{
 const f=fixture(),changes=[callbackChange(consent),callbackChange(login)];await applyPortalCallbacks(f.admin,changes);await applyPortalCallbacks(f.admin,changes,true);assert.deepEqual(f.clients[consent.clientId],consent);assert.deepEqual(f.clients[login.clientId],login);
});
test('lease writes ownership before enabling and restores the dedicated client only',async()=>{
 const f=fixture(),lease=createPortalPfLease({admin:f.admin,store:f.store,owner:{instance:'owned-instance',pid:123},baselineHash:clientFingerprint(tool),humanHash:clientFingerprint(login),expiresAt:Date.now()+60000});
 await lease.acquire();assert.ok(f.stored());assert.equal(f.clients[tool.clientId].enabled,true);assert.equal(f.writes.length,1);await lease.release();assert.equal(f.clients[tool.clientId].enabled,false);assert.equal(f.stored(),undefined);assert.deepEqual(f.clients[login.clientId],login);await lease.release();assert.equal(f.writes.length,2);
});
test('a retained lease can recover an interrupted enable without restarting execution',async()=>{
 const f=fixture(),options={admin:f.admin,store:f.store,owner:{instance:'owned-instance',pid:123},baselineHash:clientFingerprint(tool),humanHash:clientFingerprint(login),expiresAt:Date.now()+60000};await createPortalPfLease(options).acquire();await createPortalPfLease(options).release();assert.equal(f.clients[tool.clientId].enabled,false);
});
test('foreign ownership, existing enabled clients, config drift and failed disable retain fail-closed ownership',async()=>{
 const f=fixture(),options={admin:f.admin,store:f.store,owner:{instance:'owned-instance',pid:123},baselineHash:clientFingerprint(tool),humanHash:clientFingerprint(login),expiresAt:Date.now()+60000};
 f.clients[tool.clientId].enabled=true;await assert.rejects(createPortalPfLease(options).acquire());assert.equal(f.writes.length,0);f.clients[tool.clientId].enabled=false;
 await createPortalPfLease(options).acquire();await assert.rejects(createPortalPfLease({...options,owner:{instance:'foreign',pid:456}}).release());assert.equal(f.clients[tool.clientId].enabled,true);
 f.clients[tool.clientId].grantTypes=['CLIENT_CREDENTIALS'];await assert.rejects(createPortalPfLease(options).release());assert.ok(f.stored());
});
test('an expired lease still permits recovery and cannot enable again',async()=>{
 const f=fixture(),options={admin:f.admin,store:f.store,owner:{instance:'owned-instance',pid:123},baselineHash:clientFingerprint(tool),humanHash:clientFingerprint(login),expiresAt:Date.now()+60000};await createPortalPfLease(options).acquire();
 const original=Date.now;try{const future=original()+61000;Date.now=()=>future;await createPortalPfLease(options).release();assert.equal(f.clients[tool.clientId].enabled,false);await assert.rejects(createPortalPfLease(options).acquire());}finally{Date.now=original;}
});
test('server-managed modification dates and re-encrypted secrets do not masquerade as settings drift',()=>{
 const original={...login,modificationDate:'old',creationDate:'fixed'},changed={...login,modificationDate:'new',creationDate:'fixed',clientAuth:{...login.clientAuth,encryptedSecret:'new-synthetic-cipher'}};
 assert.equal(clientFingerprint(original),clientFingerprint(changed));assert.notEqual(clientFingerprint(original),clientFingerprint({...changed,restrictedScopes:['admin']}));assert.notEqual(clientFingerprint(original),clientFingerprint({...changed,creationDate:'recreated'}));
});
test('shutdown and completion racing to release the same lease share one restore',async()=>{
 const f=fixture(),lease=createPortalPfLease({admin:f.admin,store:f.store,owner:{instance:'owned-instance',pid:123},baselineHash:clientFingerprint(tool),humanHash:clientFingerprint(login),expiresAt:Date.now()+60000});await lease.acquire();await Promise.all([lease.release(),lease.release()]);assert.equal(f.writes.length,2);assert.equal(f.stored(),undefined);
});
test('the tool client key must match independently enrolled public trust',()=>{
 const pinned={keys:[{kty:'RSA',kid:'tool',alg:'RS256',use:'sig',n:'synthetic-public-modulus',e:'AQAB'}]},client={jwksSettings:{jwks:JSON.stringify(pinned)}};assert.doesNotThrow(()=>assertPortalToolKey(client,pinned));assert.throws(()=>assertPortalToolKey(client,{keys:[{...pinned.keys[0],n:'other'}]}));assert.throws(()=>assertPortalToolKey({jwksSettings:{jwks:JSON.stringify({keys:[{...pinned.keys[0],d:'synthetic-private'}]})}},pinned));assert.throws(()=>assertPortalToolKey({jwksSettings:{...client.jwksSettings,jwksUrl:'https://other.test/keys'}},pinned));
});
