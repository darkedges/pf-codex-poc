import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {signJwt,verifyJwt} from '../src/lib/jwt.ts';
const k=generateKeyPairSync('rsa',{modulusLength:2048,privateKeyEncoding:{format:'pem',type:'pkcs8'},publicKeyEncoding:{format:'pem',type:'spki'}});
const base={iss:'https://trusted.example',sub:'user-123',aud:'api://one',act:{sub:'agent-123'}};
test('verify signature, subject and actor',()=>assert.equal(verifyJwt(signJwt(base,k.privateKey,'test'),k.publicKey,{issuer:base.iss,audience:base.aud,requireActor:true}).sub,'user-123'));
test('audience mismatch rejects replay across gateways',()=>assert.throws(()=>verifyJwt(signJwt(base,k.privateKey,'test'),k.publicKey,{issuer:base.iss,audience:'api://two'})));
test('issuer mismatch rejects',()=>assert.throws(()=>verifyJwt(signJwt(base,k.privateKey,'test'),k.publicKey,{issuer:'https://attacker.example',audience:base.aud})));
test('tampering rejects',()=>{
  const t=signJwt(base,k.privateKey,'test').split('.');t[1]=Buffer.from(JSON.stringify({...base,sub:'admin'})).toString('base64url');
  assert.throws(()=>verifyJwt(t.join('.'),k.publicKey,{issuer:base.iss,audience:base.aud}));
});
test('missing actor rejects',()=>assert.throws(()=>verifyJwt(signJwt({...base,act:undefined},k.privateKey,'test'),k.publicKey,{issuer:base.iss,audience:base.aud,requireActor:true})));
