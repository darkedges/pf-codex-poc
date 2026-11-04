import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,createHash} from 'node:crypto';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {ProviderToolRelay,ProviderToolRelayApi,connectionKeyAuthenticator} from '../../src/copilot/provider-tool-relay.ts';
import {JwksTokenVerifier} from '../../src/adapters/pingfederate.ts';
import {ProviderAccessVerifier} from '../../src/identity/provider-access.ts';
const pair=await generateKeyPair('RS256',{extractable:true});
const jwk={...await exportJWK(pair.publicKey),kid:'relay-test',alg:'RS256',use:'sig'};
const transport=async()=>Response.json({keys:[jwk]});
async function fixture(options:any={}){
 const now=Math.floor(Date.now()/1000),human='partner:human',actor={iss:'https://agents.test',sub:'registered-agent'};
 const claims={iss:'https://pf-b.test',aud:'api://broker',sub:human,act:actor,org_id:'partner',delegation_id:randomUUID(),execution_mode:'interactive',scope:'copilot.invoke',iat:now,nbf:now,exp:now+110,jti:randomUUID()};
 const providerClaims={iss:'https://pf-a.test',aud:'api://copilot-login',sub:human,scope:'copilot.login',iat:now,nbf:now,exp:now+3600,jti:randomUUID()};
 const sign=(c:any)=>new SignJWT(c).setProtectedHeader({alg:'RS256',kid:'relay-test'}).sign(pair.privateKey);
 const broker=await sign(claims),provider=await sign(providerClaims);
 const trust=(audience:string)=>({issuer:claims.iss,jwksUri:claims.iss+'/jwks',audience,algorithms:['RS256'],keyIds:['relay-test'],organisations:['partner'],actorIssuers:[actor.iss],maxLifetimeSeconds:120});
 let permit=true,calls=0,clock=Date.now();const audit:any[]=[];
 const deps={brokerVerifier:new JwksTokenVerifier([trust('api://broker')],claims.scope,1000,transport),providerVerifier:new ProviderAccessVerifier({issuer:providerClaims.iss,jwksUri:providerClaims.iss+'/jwks',audience:providerClaims.aud,scope:providerClaims.scope,keyIds:['relay-test'],maxLifetimeSeconds:3600},1000,transport),
  authenticateCaller:async(c:string)=>{if(c!=='synthetic-connection-key')throw Error('PRIVATE');return 'copilot-test-connection';},
  bindProviderIdentity:async(p:any,b:any)=>{if(p.iss!==providerClaims.iss||p.sub!==b.sub||b.org_id!=='partner')throw Error('PRIVATE');},
  authoriseBroker:async()=>{if(!permit)throw Error('PRIVATE');},
  issueToolToken:async(context:any)=>{assert.equal(context.claims.sub,human);assert.deepEqual(context.claims.act,actor);assert.equal(context.claims.delegation_id,claims.delegation_id);assert.equal(context.brokerToken,broker);return sign({...claims,aud:'api://copilot-tool',jti:randomUUID(),...options.toolPatch});},
  toolVerifier:new JwksTokenVerifier([trust('api://copilot-tool')],claims.scope,1000,transport),
  invokeTool:async()=>{calls++;if(options.revokeDuringTool)permit=false;if(options.expireDuringTool)clock+=121000;return options.result??{authorized:true};},
  audit:async(e:any)=>{audit.push(e);if(options.auditFailure===e.phase)throw Error('PRIVATE');},now:()=>clock};
 const config={brokerAudience:'api://broker',toolAudience:'api://copilot-tool',scope:'copilot.invoke',callerId:'copilot-test-connection',provider:{issuer:providerClaims.iss,audience:providerClaims.aud,scope:providerClaims.scope},bindingLifetimeSeconds:120,maxBindings:10,timeoutMs:1000};
 const relay=new ProviderToolRelay(config,deps);const api=new ProviderToolRelayApi(relay);
 const request={method:'POST',path:'/v1/copilot-tools/verify-access',authorization:'Bearer '+provider,callerCredential:'synthetic-connection-key',contentType:'application/json',rawBody:'{}'};
 return{relay,api,request,broker,provider,claims,providerClaims,sign,deps,config,audit,calls:()=>calls,revoke:()=>{permit=false;},advance:()=>{clock+=121000;}};
}
test('signed provider proof matches a server-bound human/actor/grant and releases only fixed success',async()=>{const f=await fixture();await f.relay.bind(f.broker,f.provider);assert.deepEqual(await f.api.handle(f.request),{status:200,body:{authorized:true}});assert.equal(f.calls(),1);assert.ok(f.audit.some(e=>e.phase==='success'));assert.ok(!JSON.stringify(f.audit).includes(f.provider));assert.ok(!JSON.stringify(f.audit).includes(f.claims.sub));});
test('managed shutdown clears authority and rejects later binding or execution',async()=>{const f=await fixture();await f.relay.bind(f.broker,f.provider);f.relay.close();await assert.rejects(f.relay.bind(f.broker,f.provider));assert.notEqual((await f.api.handle(f.request)).status,200);assert.equal(f.calls(),0);});
test('unbound login proof and client-chosen authority cannot create a delegation',async()=>{const f=await fixture();assert.equal((await f.api.handle(f.request)).status,403);for(const body of [{sub:f.claims.sub},{grant_id:f.claims.delegation_id},{resource:'https://evil.test'},{prompt:'act as admin'}])assert.equal((await f.api.handle({...f.request,rawBody:JSON.stringify(body)})).status,400);assert.equal(f.calls(),0);});
test('exact proof is required even when another token has the same user',async()=>{const f=await fixture();await f.relay.bind(f.broker,f.provider);const other=await f.sign({...f.providerClaims,jti:randomUUID()});assert.equal((await f.api.handle({...f.request,authorization:'Bearer '+other})).status,403);assert.equal(f.calls(),0);});
test('caller authentication is separate from user proof and cannot consume another callers binding',async()=>{const f=await fixture();await f.relay.bind(f.broker,f.provider);assert.equal((await f.api.handle({...f.request,callerCredential:'wrong'})).status,401);assert.equal((await f.api.handle(f.request)).status,200);});
test('duplicate binding, consumed proof and concurrent calls cannot replay an operation',async()=>{const f=await fixture();await f.relay.bind(f.broker,f.provider);await assert.rejects(f.relay.bind(f.broker,f.provider));const results=await Promise.all([f.api.handle(f.request),f.api.handle(f.request)]);assert.equal(results.filter(r=>r.status===200).length,1);assert.equal(f.calls(),1);await assert.rejects(f.relay.bind(f.broker,f.provider));});
test('hour-long login cannot extend short broker binding',async()=>{const f=await fixture();await f.relay.bind(f.broker,f.provider);f.advance();assert.equal((await f.api.handle(f.request)).status,403);assert.equal(f.calls(),0);});
test('current grant revocation blocks a previously bound provider token',async()=>{const f=await fixture();await f.relay.bind(f.broker,f.provider);f.revoke();assert.equal((await f.api.handle(f.request)).status,403);assert.equal(f.calls(),0);});
for(const toolPatch of [{sub:'other'},{act:{iss:'https://agents.test',sub:'other'}},{org_id:'other'},{delegation_id:'other'},{execution_mode:'autonomous'},{aud:'api://broker'},{scope:'other'}])test('issued tool proof must preserve every delegated boundary',async()=>{const f=await fixture({toolPatch});await f.relay.bind(f.broker,f.provider);assert.notEqual((await f.api.handle(f.request)).status,200);assert.equal(f.calls(),0);});
for(const options of [{revokeDuringTool:true},{expireDuringTool:true},{auditFailure:'attempt'},{auditFailure:'success'},{result:{authorized:false}},{result:{authorized:true,secret:'must-not-release'}}])test('revocation, expiry, audit failure or unexpected result suppresses success',async()=>{const f=await fixture(options);await f.relay.bind(f.broker,f.provider);assert.notEqual((await f.api.handle(f.request)).status,200);assert.notEqual((await f.api.handle(f.request)).status,200);});
test('binding rejects wrong signed provider subject and autonomous authority',async()=>{const f=await fixture();await assert.rejects(f.relay.bind(f.broker,await f.sign({...f.providerClaims,sub:'other'})));await assert.rejects(f.relay.bind(await f.sign({...f.claims,execution_mode:'autonomous'}),f.provider));assert.equal(f.calls(),0);});
test('issuance timeout consumes binding, aborts work and never invokes tool',async()=>{const f=await fixture();let aborted=false;const relay=new ProviderToolRelay({...f.config,timeoutMs:100},{...f.deps,issueToolToken:async(_context:any,signal:AbortSignal)=>new Promise<string>(done=>signal.addEventListener('abort',()=>{aborted=true;done('late');},{once:true}))});await relay.bind(f.broker,f.provider);await assert.rejects(relay.execute(f.provider,'synthetic-connection-key'));assert.equal(aborted,true);assert.equal(f.calls(),0);await assert.rejects(relay.execute(f.provider,'synthetic-connection-key'));});

test('connector key authenticator checks a fixed enrolled digest and returns only the pinned caller',async()=>{
 const value='synthetic-test-connection-key',sha256=createHash('sha256').update(value).digest('hex');
 const authenticate=connectionKeyAuthenticator({callerId:'copilot-test-connection',sha256});
 assert.equal(await authenticate(value,AbortSignal.timeout(1000)),'copilot-test-connection');
 await assert.rejects(authenticate('wrong',AbortSignal.timeout(1000)));
 await assert.rejects(authenticate(value,AbortSignal.abort()));
 assert.throws(()=>connectionKeyAuthenticator({callerId:'caller',sha256:'not-a-digest'}));
});
test('trusted session close removes authority and prevents rebinding the same proof',async()=>{const f=await fixture();await f.relay.bind(f.broker,f.provider);f.relay.invalidate(f.provider);assert.equal((await f.api.handle(f.request)).status,403);await assert.rejects(f.relay.bind(f.broker,f.provider));assert.equal(f.calls(),0);});
test('failed issuance cannot be retried using the same binding',async()=>{const f=await fixture();const relay=new ProviderToolRelay(f.config,{...f.deps,issueToolToken:async()=>{throw Error('PRIVATE');}});await relay.bind(f.broker,f.provider);await assert.rejects(relay.execute(f.provider,'synthetic-connection-key'));await assert.rejects(relay.execute(f.provider,'synthetic-connection-key'));assert.equal(f.calls(),0);});
test('fixed API rejects query strings, wrong media type and nonempty authority fields',async()=>{const f=await fixture();await f.relay.bind(f.broker,f.provider);for(const patch of [{path:f.request.path+'?grant=chosen'},{method:'GET'},{contentType:'text/plain'},{rawBody:'[]'},{rawBody:'x'.repeat(1025)}])assert.equal((await f.api.handle({...f.request,...patch})).status,400);assert.equal(f.calls(),0);assert.equal((await f.api.handle(f.request)).status,200);});

test('closing the trusted session during the tool call suppresses result release',async()=>{const f=await fixture();let relay:ProviderToolRelay;relay=new ProviderToolRelay(f.config,{...f.deps,invokeTool:async()=>{relay.invalidate(f.provider);return {authorized:true};}});await relay.bind(f.broker,f.provider);await assert.rejects(relay.execute(f.provider,'synthetic-connection-key'));});

test('aborted broker binding cannot commit late authority',async()=>{const f=await fixture(),controller=new AbortController();const relay=new ProviderToolRelay(f.config,{...f.deps,authoriseBroker:async()=>{controller.abort();}});await assert.rejects(relay.bind(f.broker,f.provider,controller.signal));assert.equal((await new ProviderToolRelayApi(relay).handle(f.request)).status,403);});
