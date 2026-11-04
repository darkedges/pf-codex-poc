import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {ProviderBrowserClient} from '../../src/identity/provider-browser.ts';
const keys=await generateKeyPair('RS256');
const issuer='https://provider.test',state='s'.repeat(43),verifier='v'.repeat(43);
async function setup(patch:Record<string,unknown>={},responsePatch:Record<string,unknown>={}){
 const now=Math.floor(Date.now()/1000),token=await new SignJWT({iss:issuer,aud:'api://copilot-login',sub:'partner:user',scope:'copilot.login',iat:now,nbf:now-1,exp:now+120,jti:'test-token',...patch}).setProtectedHeader({alg:'RS256',kid:'provider-1'}).sign(keys.privateKey);
 const calls:{url:string;init?:RequestInit}[]=[];
 const config={issuer,jwksUri:issuer+'/pf/JWKS',audience:'api://copilot-login',scope:'copilot.login',keyIds:['provider-1'],maxLifetimeSeconds:3600,authorizationEndpoint:issuer+'/as/authorization.oauth2',tokenEndpoint:issuer+'/as/token.oauth2',redirectUri:'https://agent.test/provider-callback',clientId:'generic-oauth',clientSecret:'test-only-secret',adapterId:'login',resource:'urn:copilot:login',timeoutMs:1000,fetch:async(url:unknown,init?:RequestInit)=>{calls.push({url:String(url),init});return String(url).endsWith('/pf/JWKS')?Response.json({keys:[{...await exportJWK(keys.publicKey),kid:'provider-1',alg:'RS256',use:'sig'}]}):Response.json({access_token:token,token_type:'Bearer',...responsePatch});}};
 return{config,calls,token};
}
test('provider browser authorization has fixed resource, callback, state and S256 without credentials',async()=>{
 const s=await setup(),url=new URL(new ProviderBrowserClient(s.config).start(state,verifier));
 assert.equal(url.origin,issuer);assert.equal(url.searchParams.get('redirect_uri'),s.config.redirectUri);
 assert.equal(url.searchParams.get('scope'),'copilot.login');assert.equal(url.searchParams.get('resource'),'urn:copilot:login');
 assert.equal(url.searchParams.get('state'),state);assert.equal(url.searchParams.get('code_challenge_method'),'S256');
 assert.ok(url.searchParams.get('code_challenge'));assert.ok(!url.href.includes(verifier));assert.ok(!url.href.includes('test-only-secret'));assert.equal(s.calls.length,0);
});
test('provider browser redemption verifies user token and keeps secret in the POST body only',async()=>{
 const s=await setup(),result=await new ProviderBrowserClient(s.config).redeem('code',verifier,'partner:user');
 assert.equal(result.token,s.token);assert.equal(result.claims.sub,'partner:user');
 const call=s.calls[0],fields=new URLSearchParams(String(call.init?.body));
 assert.equal(call.url,s.config.tokenEndpoint);assert.equal(call.init?.redirect,'error');assert.ok(call.init?.signal);
 assert.equal(fields.get('client_secret'),'test-only-secret');assert.equal(fields.get('code_verifier'),verifier);assert.equal(fields.get('redirect_uri'),s.config.redirectUri);
});
for(const [name,patch]of Object.entries({differentHuman:{sub:'other:user'},differentIssuer:{iss:'https://other.test'},wrongAudience:{aud:'api://tools'},wrongScope:{scope:'openid'},expired:{exp:1},future:{nbf:Math.floor(Date.now()/1000)+90},delegationInjected:{act:{sub:'agent'}}}))test('provider browser rejects '+name,async()=>{
 const s=await setup(patch);await assert.rejects(new ProviderBrowserClient(s.config).redeem('code',verifier,'partner:user'),/^CopilotError: invalid_token$/);
});
test('provider endpoint errors never escape with credentials or remote response text',async()=>{
 const s=await setup();s.config.fetch=async()=>new Response('test-only-secret signed-code remote-message',{status:400});
 await assert.rejects(new ProviderBrowserClient(s.config).redeem('signed-code',verifier,'partner:user'),/^CopilotError: unavailable$/);
});
test('provider refuses wrong token type and oversized token responses',async()=>{
 const s=await setup({},{token_type:'Other'});await assert.rejects(new ProviderBrowserClient(s.config).redeem('code',verifier,'partner:user'));
 s.config.fetch=async()=>new Response('x'.repeat(40001));await assert.rejects(new ProviderBrowserClient(s.config).redeem('code',verifier,'partner:user'));
});
test('provider configuration cannot change backend origins or use unsafe callbacks',async()=>{
 const s=await setup();for(const patch of [{tokenEndpoint:'https://evil.test/token'},{authorizationEndpoint:'https://evil.test/auth'},{jwksUri:'https://evil.test/keys'},{redirectUri:'http://agent.test/provider-callback'},{redirectUri:'https://agent.test/provider-callback?next=evil'},{redirectUri:'https://agent.test/other'},{clientSecret:''},{timeoutMs:0}])assert.throws(()=>new ProviderBrowserClient({...s.config,...patch}));
});
test('invalid transaction inputs cause no outbound request',async()=>{
 const s=await setup(),client=new ProviderBrowserClient(s.config);assert.throws(()=>client.start('short',verifier));
 await assert.rejects(client.redeem('code','bad','partner:user'));await assert.rejects(client.redeem('',verifier,'partner:user'));assert.equal(s.calls.length,0);
});
