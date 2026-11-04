import test from 'node:test';import assert from 'node:assert/strict';import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {OidcClient} from '../../src/identity/oidc.ts';
const keys=await generateKeyPair('RS256');
const config={issuer:'https://pf.example.test',jwksUri:'https://pf.example.test/pf/JWKS',clientId:'mobile-bff',keyIds:['signer'],authorizationEndpoint:'https://pf.example.test/as/authorization.oauth2',parEndpoint:'https://pf.example.test/as/par.oauth2',tokenEndpoint:'https://pf.example.test/as/token.oauth2',redirectUri:'https://agent.example.test/mobile/callback',keyId:'client',clientKey:keys.privateKey,adapterId:'human'};
test('mobile callback requires an explicit server-side callback profile',()=>{assert.throws(()=>new OidcClient(config));assert.doesNotThrow(()=>new OidcClient({...config,callbackPath:'/mobile/callback'}));});
test('explicit mobile callback cannot open arbitrary paths or weaken the original callback profile',()=>{for(const redirectUri of ['https://agent.example.test/callback','https://agent.example.test/other','https://agent.example.test/mobile/callback?next=evil','http://agent.example.test/mobile/callback'])assert.throws(()=>new OidcClient({...config,callbackPath:'/mobile/callback',redirectUri}));assert.throws(()=>new OidcClient({...config,callbackPath:'/other',redirectUri:'https://agent.example.test/other'}));assert.doesNotThrow(()=>new OidcClient({...config,redirectUri:'https://agent.example.test/callback'}));});

test('explicit mobile provider profile requests offline access and retains credentials only server-side',async()=>{
 const state='s'.repeat(43),nonce='n'.repeat(43),verifier='v'.repeat(43);let missing=false;
 const fetcher=async(url,init)=>{
  if(String(url)===config.jwksUri)return Response.json({keys:[{...await exportJWK(keys.publicKey),kid:'signer',alg:'RS256',use:'sig'}]});
  const b=new URLSearchParams(init.body);
  if(String(url)===config.parEndpoint){assert.equal(b.get('scope'),'openid copilot.login offline_access');assert.equal(b.get('resource'),'urn:copilot:login');return Response.json({request_uri:'urn:fixture',expires_in:60});}
  const now=Math.floor(Date.now()/1000),id=await new SignJWT({iss:config.issuer,sub:'human',aud:config.clientId,iat:now,exp:now+120,auth_time:now,nonce}).setProtectedHeader({alg:'RS256',kid:'signer'}).sign(keys.privateKey);
  return Response.json({id_token:id,access_token:'synthetic-provider-fixture',token_type:'Bearer',...(missing?{}:{refresh_token:'synthetic-refresh-fixture'})});
 };
 const client=new OidcClient({...config,callbackPath:'/mobile/callback',providerAuthorization:{scope:'copilot.login',resource:'urn:copilot:login'},fetch:fetcher});await client.start(state,nonce,verifier);
 const r=await client.redeem('code',verifier,nonce);assert.equal(r.login.subject,'human');assert.deepEqual(r.providerCredential,{accessToken:'synthetic-provider-fixture',refreshToken:'synthetic-refresh-fixture'});
 missing=true;await assert.rejects(client.redeem('new-code',verifier,nonce));
 for(const change of [{scope:'admin',resource:'urn:copilot:login'},{scope:'copilot.login',resource:'https://evil.test'}])assert.throws(()=>new OidcClient({...config,callbackPath:'/mobile/callback',providerAuthorization:change}));
});
