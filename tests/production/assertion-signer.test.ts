import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair,jwtVerify } from 'jose';
import { VaultTransitSigner } from '../../src/identity/assertion-signer.ts';
const pair=await generateKeyPair('RS256'),next=await generateKeyPair('RS256');
const payload={iss:'https://authority.test',aud:'api://proof',sub:'human',iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+60};
function config(patch={}){return{origin:'https://vault.test',mount:'transit',name:'consent',version:1,kid:'authority-v1',publicKey:pair.publicKey,token:()=> 'test-credential',timeoutMs:100,...patch};}
function transport(privateKey=pair.privateKey,version=1){return async(url:unknown,init?:RequestInit)=>{
 assert.equal(String(url),'https://vault.test/v1/transit/sign/consent/sha2-256');assert.equal(init?.redirect,'error');assert.ok(init?.signal);
 const body=JSON.parse(String(init?.body));assert.equal(body.signature_algorithm,'pkcs1v15');assert.equal(body.prehashed,false);assert.equal(body.key_version,version);
 const signature=await crypto.subtle.sign('RSASSA-PKCS1-v1_5',privateKey,Buffer.from(body.input,'base64'));
 return Response.json({data:{signature:`vault:v${version}:`+Buffer.from(signature).toString('base64')}});
};}
test('Transit signs exact RS256 input with pinned key version; JOSE verifies the result',async()=>{
 const signer=new VaultTransitSigner(config({fetch:transport()}));const raw=await signer.sign(payload);const result=await jwtVerify(raw,pair.publicKey);assert.deepEqual(result.payload,payload);assert.equal(result.protectedHeader.kid,'authority-v1');
});
test('rotation selects an explicit version and matching configured public key',async()=>{
 const signer=new VaultTransitSigner(config({version:2,kid:'authority-v2',publicKey:next.publicKey,fetch:transport(next.privateKey,2)}));const raw=await signer.sign(payload);assert.equal((await jwtVerify(raw,next.publicKey)).protectedHeader.kid,'authority-v2');await assert.rejects(jwtVerify(raw,pair.publicKey));
});
for(const fetcher of [async()=>Response.json({data:{signature:'vault:v2:AAAA'}}),async()=>Response.json({data:{signature:'vault:v1:AAAA'}}),async()=>Response.json({errors:['SECRET']},{status:403}),async()=>new Response('',{status:302,headers:{Location:'https://evil.test'}}),async()=>{throw Error('SECRET');},async()=>new Response('x'.repeat(17000)),transport(next.privateKey)])test('invalid signer responses fail closed without exposing credentials',async()=>{
 const signer=new VaultTransitSigner(config({fetch:fetcher}));await assert.rejects(signer.sign(payload),e=>!String(e).includes('SECRET'));
});
test('unavailable signer times out with no retry',async()=>{
 let requests=0;const signer=new VaultTransitSigner(config({fetch:async(_url:unknown,init?:RequestInit)=>{requests++;await new Promise((_resolve,reject)=>{init?.signal?.addEventListener('abort',()=>reject(Error('SECRET')),{once:true});});throw Error();}}));
 // AbortSignal timeout is unref'ed in Node; retain the test event loop until it fires.
 const keepAlive=setTimeout(()=>{},1000);try{await assert.rejects(signer.sign(payload));assert.equal(requests,1);}finally{clearTimeout(keepAlive);}
});
for(const patch of [{origin:'http://vault.test'},{origin:'https://vault.test/path'},{mount:'../other'},{name:'../export/key'},{version:0},{publicKey:pair.privateKey},{timeoutMs:0}])test('Transit refuses unsafe configuration',()=>{assert.throws(()=>new VaultTransitSigner(config(patch)));});
