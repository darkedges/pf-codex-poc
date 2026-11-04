import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair,SignJWT,exportJWK } from 'jose';
import { OidcClient } from '../../src/identity/oidc.ts';

const keys=await generateKeyPair('RS256');
function setup(browserAuthorizationEndpoint?:string){
 const calls:{url:string;fields:URLSearchParams}[]=[];
 const config={issuer:'https://pf-a.test',jwksUri:'https://pf-a.test/pf/JWKS',clientId:'portal',keyIds:['oidc-1'],authorizationEndpoint:'https://pf-a.test/as/authorization.oauth2',parEndpoint:'https://pf-a.test/as/par.oauth2',tokenEndpoint:'https://pf-a.test/as/token.oauth2',redirectUri:'https://agent.test/callback',keyId:'client-1',clientKey:keys.privateKey,adapterId:'login',browserAuthorizationEndpoint,fetch:async(url:unknown,init?:RequestInit)=>{calls.push({url:String(url),fields:new URLSearchParams(String(init?.body))});return Response.json({request_uri:'urn:example:request:one',expires_in:60});}};
 return{config,calls};
}
const state='s'.repeat(43),nonce='n'.repeat(43),verifier='v'.repeat(43);
test('explicit browser alias changes only the authorization redirect, keeping PAR and issuer private',async()=>{
 const s=setup('https://public-pf.test/as/authorization.oauth2');
 const redirect=new URL(await new OidcClient(s.config).start(state,nonce,verifier));
 assert.equal(redirect.origin,'https://public-pf.test');
 assert.equal(redirect.pathname,'/as/authorization.oauth2');
 assert.deepEqual([...redirect.searchParams.keys()].sort(),['client_id','request_uri']);
 assert.equal(s.calls.length,1);assert.equal(s.calls[0].url,s.config.parEndpoint);
 assert.equal(s.calls[0].fields.get('redirect_uri'),s.config.redirectUri);
 assert.equal(s.calls[0].fields.get('code_challenge_method'),'S256');
 assert.equal(s.calls[0].fields.get('state'),state);assert.equal(s.calls[0].fields.get('nonce'),nonce);
});
test('local authorization endpoint remains the default',async()=>{
 const s=setup();assert.equal(new URL(await new OidcClient(s.config).start(state,nonce,verifier)).origin,'https://pf-a.test');
});
for(const alias of ['http://public-pf.test/as/authorization.oauth2','https://user:password@public-pf.test/as/authorization.oauth2','https://public-pf.test/as/authorization.oauth2?client_id=other','https://public-pf.test/as/authorization.oauth2#fragment','https://public-pf.test/admin','https://public-pf.test/as/authorization.oauth2/']){
 test('reject malformed or different-path browser alias '+alias,()=>{const s=setup(alias);assert.throws(()=>new OidcClient(s.config));assert.equal(s.calls.length,0);});
}
test('a browser alias cannot authorize a different backend token or PAR origin',()=>{
 const s=setup('https://public-pf.test/as/authorization.oauth2');
 for(const field of ['tokenEndpoint','parEndpoint','jwksUri'] as const)assert.throws(()=>new OidcClient({...s.config,[field]:'https://public-pf.test/as/token.oauth2'}));
});

test('recent-session reuse is opt-in and begins only after independently verified first login',async()=>{
 const s=setup();let stale=false,wrongNonce=false;const fetcher=async(url,init)=>{if(String(url)===s.config.jwksUri)return Response.json({keys:[{...await exportJWK(keys.publicKey),kid:'oidc-1',alg:'RS256',use:'sig'}]});if(String(url)===s.config.tokenEndpoint){const now=Math.floor(Date.now()/1000),token=await new SignJWT({iss:s.config.issuer,aud:s.config.clientId,sub:'human',iat:now,auth_time:stale?now-301:now,exp:now+120,nonce:wrongNonce?'wrong':nonce}).setProtectedHeader({alg:'RS256',kid:'oidc-1'}).sign(keys.privateKey);return Response.json({token_type:'Bearer',id_token:token,access_token:'synthetic-access'});}return s.config.fetch(url,init);};
 const client=new OidcClient({...s.config,sessionReuse:'after-first-login',fetch:fetcher});await client.start(state,nonce,verifier);assert.equal(s.calls.at(-1).fields.get('prompt'),'login');assert.equal(s.calls.at(-1).fields.get('max_age'),'0');
 wrongNonce=true;await assert.rejects(client.redeem('code',verifier,nonce));await client.start(state,nonce,verifier);assert.equal(s.calls.at(-1).fields.get('prompt'),'login');wrongNonce=false;await client.redeem('code',verifier,nonce);await client.start(state,nonce,verifier);assert.equal(s.calls.at(-1).fields.has('prompt'),false);assert.equal(s.calls.at(-1).fields.get('max_age'),'300');
 stale=true;await assert.rejects(client.redeem('code',verifier,nonce));
 const legacy=new OidcClient({...s.config,fetch:fetcher});stale=false;await legacy.redeem('code',verifier,nonce);await legacy.start(state,nonce,verifier);assert.equal(s.calls.at(-1).fields.get('prompt'),'login');
 assert.throws(()=>new OidcClient({...s.config,sessionReuse:'unbounded' as any}));
});
