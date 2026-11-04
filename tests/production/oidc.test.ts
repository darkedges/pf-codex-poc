import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair,exportJWK,SignJWT } from 'jose';
import { OidcVerifier } from '../../src/identity/oidc.ts';
const keys=await generateKeyPair('RS256');
const trust={issuer:'https://pf-a.test',jwksUri:'https://pf-a.test/pf/JWKS',clientId:'consent-portal',keyIds:['oidc-1']};
const nonce='random-browser-nonce-0123456789';
async function signed(patch={},header={}){const now=Math.floor(Date.now()/1000);return new SignJWT({iss:trust.issuer,aud:trust.clientId,sub:'partner:user',iat:now,auth_time:now,exp:now+120,nonce,...patch}).setProtectedHeader({alg:'RS256',kid:'oidc-1',...header}).sign(keys.privateKey);}
function verifier(){return new OidcVerifier({...trust,fetch:async()=>Response.json({keys:[{...await exportJWK(keys.publicKey),kid:'oidc-1',use:'sig',alg:'RS256'}]})});}
test('OIDC verifier returns bound human evidence without token values',async()=>{const token=await signed();const result=await verifier().verify(token,nonce);assert.equal(result.subject,'partner:user');assert.ok(result.tokenHash);assert.ok(!JSON.stringify(result).includes(token));});
for(const [name,patch]of Object.entries({issuer:{iss:'https://evil.test'},audience:{aud:'other'},nonce:{nonce:'other'},expiry:{exp:1},authentication:{auth_time:1},party:{azp:'other'},multipleAudiences:{aud:[trust.clientId,'other']}}))test(`OIDC ${name} substitution is rejected`,async()=>{await assert.rejects(verifier().verify(await signed(patch),nonce));});
test('unknown signing key and token-provided key URL reject',async()=>{for(const header of [{kid:'unknown'},{jku:'https://evil.test/jwks'}])await assert.rejects(verifier().verify(await signed({},header),nonce));});
test('an explicit virtual issuer preserves its verified issuer while unknown issuers still reject',async()=>{
 const v=new OidcVerifier({...trust,additionalIssuers:['https://public-pf.test'],fetch:async()=>Response.json({keys:[{...await exportJWK(keys.publicKey),kid:'oidc-1',use:'sig',alg:'RS256'}]})});
 assert.equal((await v.verify(await signed({iss:'https://public-pf.test'}),nonce)).issuer,'https://public-pf.test');
 assert.equal((await v.verify(await signed(),nonce)).issuer,trust.issuer);
 await assert.rejects(v.verify(await signed({iss:'https://unknown.test'}),nonce));
 await assert.rejects(v.verify(await signed({iss:'https://public-pf.test',aud:'other'}),nonce));
});
test('virtual issuer trust rejects insecure, duplicate and malformed issuer configuration',()=>{
 for(const additionalIssuers of [['http://public.test'],[trust.issuer],['https://public.test','https://public.test'],['https://user@public.test'],['https://public.test?x=y']])assert.throws(()=>new OidcVerifier({...trust,additionalIssuers}));
});
test('OIDC diagnostics identify a fixed validation stage and claim without credential values',async()=>{
 const events:any[]=[];const v=new OidcVerifier({...trust,observe:(e:any)=>events.push(e),fetch:async()=>Response.json({keys:[{...await exportJWK(keys.publicKey),kid:'oidc-1',use:'sig',alg:'RS256'}]})});
 const token=await signed({iss:'https://evil.test'});await assert.rejects(v.verify(token,nonce));
 assert.equal(events.length,1);assert.equal(events[0].outcome,'rejected');assert.equal(events[0].claim,'iss');assert.equal(events[0].stage,'jwt');
 assert.ok(!JSON.stringify(events).includes(token));assert.ok(!JSON.stringify(events).includes('evil.test'));assert.ok(!JSON.stringify(events).includes(nonce));
 events.length=0;await assert.rejects(v.verify(await signed({nonce:'other'}),nonce));assert.equal(events[0].stage,'binding');
 events.length=0;await assert.rejects(v.verify(await signed({}, {kid:'unknown'}),nonce));assert.equal(events[0].stage,'key');
});
test('diagnostic observer failure does not affect successful OIDC validation',async()=>{
 const v=new OidcVerifier({...trust,observe:()=>{throw Error('PRIVATE');},fetch:async()=>Response.json({keys:[{...await exportJWK(keys.publicKey),kid:'oidc-1',use:'sig',alg:'RS256'}]})});
 assert.equal((await v.verify(await signed(),nonce)).subject,'partner:user');
});
test('a rotated signing key requires an explicit pin refresh and keeps issuer and signature checks',async()=>{
 const rotated=await generateKeyPair('RS256'),attacker=await generateKeyPair('RS256'),now=Math.floor(Date.now()/1000);
 const make=(key:CryptoKey,iss=trust.issuer)=>new SignJWT({iss,aud:trust.clientId,sub:'partner:user',iat:now,auth_time:now,exp:now+120,nonce}).setProtectedHeader({alg:'RS256',kid:'oidc-rotated'}).sign(key);
 const fetchKeys=async()=>Response.json({keys:[{...await exportJWK(rotated.publicKey),kid:'oidc-rotated',use:'sig',alg:'RS256'}]});
 const stale=new OidcVerifier({...trust,fetch:fetchKeys}),refreshed=new OidcVerifier({...trust,keyIds:[...trust.keyIds,'oidc-rotated'],fetch:fetchKeys});
 await assert.rejects(stale.verify(await make(rotated.privateKey),nonce));
 assert.equal((await refreshed.verify(await make(rotated.privateKey),nonce)).subject,'partner:user');
 await assert.rejects(refreshed.verify(await make(attacker.privateKey),nonce));
 await assert.rejects(refreshed.verify(await make(rotated.privateKey,'https://evil.test'),nonce));
});
