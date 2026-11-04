import test from 'node:test';import assert from 'node:assert/strict';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';import {randomUUID} from 'node:crypto';
import {ProviderAccessVerifier} from '../../src/identity/provider-access.ts';
const pair=await generateKeyPair('RS256',{extractable:true}),issuer='https://pf-a.test',audience='api://copilot-login';
const config={issuer,jwksUri:issuer+'/pf/JWKS',audience,scope:'copilot.login',keyIds:['login-key'],maxLifetimeSeconds:180};
const publicKey={...await exportJWK(pair.publicKey),kid:'login-key',alg:'RS256',use:'sig'};
const token=(patch={},header={})=>{const now=Math.floor(Date.now()/1000);return new SignJWT({iss:issuer,aud:audience,sub:'partner:human',scope:'copilot.login',iat:now,nbf:now,exp:now+180,jti:randomUUID(),...patch}).setProtectedHeader({alg:'RS256',kid:'login-key',...header}).sign(pair.privateKey);};
const verifier=()=>new ProviderAccessVerifier(config,1000,async()=>Response.json({keys:[publicKey]}));
test('configured provider user access token verifies without inventing delegation claims',async()=>{const c=await verifier().verify(await token());assert.equal(c.sub,'partner:human');assert.equal(c.iss,issuer);assert.equal(c.aud,audience);assert.equal(c.scope,'copilot.login');assert.equal(c.act,undefined);assert.equal(c.delegation_id,undefined);});
for(const patch of [{iss:'https://pf-b.test'},{aud:'api://copilot-tool'},{aud:[audience,'extra']},{scope:'copilot.invoke'},{scope:undefined},{act:{sub:'agent'}},{delegation_id:'grant'},{org_id:'partner'},{execution_mode:'autonomous'},{sub:''},{exp:1},{exp:Math.floor(Date.now()/1000)+3600}])test('provider verifier rejects substituted, delegated, expired or overlong proof',async()=>{await assert.rejects(verifier().verify(await token(patch)),/^CopilotError: invalid_token$/);});
test('provider JWT cannot select an embedded or remote signing key',async()=>{for(const h of [{kid:'other'},{jku:'https://evil.test/keys'},{jwk:publicKey},{x5u:'https://evil.test/cert'}])await assert.rejects(verifier().verify(await token({},h)));});
test('provider JWKS outage has no cached fixture or development fallback',async()=>{const v=new ProviderAccessVerifier(config,100,async()=>{throw Error('PRIVATE');});await assert.rejects(v.verify(await token()),e=>String(e)==='CopilotError: invalid_token');});

test('explicit five-minute profile accepts its boundary and rejects longer or wrong-audience tokens',async()=>{
 const v=new ProviderAccessVerifier({...config,maxLifetimeSeconds:300},1000,async()=>Response.json({keys:[publicKey]}));
 const now=Math.floor(Date.now()/1000);
 assert.equal((await v.verify(await token({iat:now,nbf:now,exp:now+300}))).exp,now+300);
 for(const patch of [{iat:now,exp:now+301},{aud:'api://copilot-tool'},{exp:now-1},{nbf:now+60}])await assert.rejects(v.verify(await token(patch)));
});

test('explicit one-hour provider trust accepts its boundary without widening shorter trust',async()=>{
 const hour=new ProviderAccessVerifier({...config,maxLifetimeSeconds:3600},1000,async()=>Response.json({keys:[publicKey]}));
 const now=Math.floor(Date.now()/1000),proof=await token({iat:now,nbf:now,exp:now+3600});
 assert.equal((await hour.verify(proof)).exp,now+3600);
 await assert.rejects(verifier().verify(proof));
 for(const patch of [{iat:now,exp:now+3601},{aud:'api://copilot-tool'},{exp:now-1},{nbf:now+60}])await assert.rejects(hour.verify(await token(patch)));
 assert.throws(()=>new ProviderAccessVerifier({...config,maxLifetimeSeconds:3601},1000));
});
