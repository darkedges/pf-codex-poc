import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomBytes} from 'node:crypto';
import {MobileLoginHandoff} from '../../src/mobile/login-handoff.ts';
import {bodyHash} from '../../src/policy/protocol.ts';
function fixture(){let clock=Date.now(),state='',nonce='',pkce='',issued=0;
 const publicKey=generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey.export({type:'spki',format:'der'}).toString('base64url'),secret=randomBytes(32).toString('base64url');
 const authority={termsHash:'fixed-terms',beginEnrollment:async(proof,input)=>{issued++;assert.equal(proof.idToken,'server-private-id-token');assert.equal(proof.nonce,nonce);assert.equal(input.devicePublicKeySpki,publicKey);return{challengeId:crypto.randomUUID(),challenge:'enroll:'+randomBytes(32).toString('base64url'),expiresAt:clock+60000};}};
 const oidc={start:async(s,n,p)=>{state=s;nonce=n;pkce=p;return'https://pf.example.test/as/authorization.oauth2?request_uri=urn:fixture';},redeem:async(code,p,n)=>{assert.equal(code,'server-only-code');assert.equal(p,pkce);assert.equal(n,nonce);return{idToken:'server-private-id-token'};}};
 const options={origin:'https://agent.example.test',authorizationEndpoint:'https://pf.example.test/as/authorization.oauth2',authority,oidc,now:()=>clock};
 const b=new MobileLoginHandoff(options),start=()=>b.start({devicePublicKeySpki:publicKey,claimHash:bodyHash(secret)});
 return{b,options,start,secret,state:()=>state,issued:()=>issued,advance:ms=>clock+=ms,callback:()=>b.callback({state,code:'server-only-code'})};
}
test('PKCE state and nonce stay server-side and handoff binds the initiating phone secret and key',async()=>{
 const f=fixture(),launch=await f.start();assert.equal(launch.authorizationUrl.startsWith('https://pf.example.test/'),true);
 const returned=await f.callback(),u=new URL(returned.returnUrl);assert.equal(u.origin,'https://agent.example.test');assert.equal(u.pathname,'/mobile/return');assert.deepEqual([...u.searchParams.keys()],['handoff']);assert.ok(!JSON.stringify(returned).includes('id-token'));
 await f.b.claim({handoff:u.searchParams.get('handoff'),claimSecret:f.secret,sessionPublicKeySpki:'checked-by-authority',termsHash:'fixed-terms'});assert.equal(f.issued(),1);
 await assert.rejects(f.b.claim({handoff:u.searchParams.get('handoff'),claimSecret:f.secret,sessionPublicKeySpki:'checked-by-authority',termsHash:'fixed-terms'}));
});
test('unknown callback, wrong phone secret and expired return codes never enroll',async()=>{
 for(const mode of ['state','secret','expired']){const f=fixture();await f.start();if(mode==='state'){await assert.rejects(f.b.callback({state:'other',code:'code'}));assert.equal(f.issued(),0);continue;}
  const r=await f.callback(),handoff=new URL(r.returnUrl).searchParams.get('handoff');if(mode==='expired')f.advance(120001);
  await assert.rejects(f.b.claim({handoff,claimSecret:mode==='secret'?'x'.repeat(43):f.secret,sessionPublicKeySpki:'key',termsHash:'fixed-terms'}));assert.equal(f.issued(),0);
 }
});
test('callback is consumed on first redemption and a failed claim is not automatically retried',async()=>{
 const f=fixture();await f.start();const r=await f.callback();await assert.rejects(f.callback());const input={handoff:new URL(r.returnUrl).searchParams.get('handoff'),claimSecret:f.secret,sessionPublicKeySpki:'key',termsHash:'wrong'};
 await assert.rejects(f.b.claim(input));await assert.rejects(f.b.claim({...input,termsHash:'fixed-terms'}));assert.equal(f.issued(),0);
});
test('provider redirects and app return origins are deployment-pinned',async()=>{
 const f=fixture();assert.throws(()=>new MobileLoginHandoff({...f.options,origin:'http://agent.example.test'}));
 const b=new MobileLoginHandoff({...f.options,oidc:{...f.options.oidc,start:async()=> 'https://evil.example.test/auth'}});
 await assert.rejects(b.start({devicePublicKeySpki:'invalid',claimHash:bodyHash(f.secret)}));
 const key=generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey.export({type:'spki',format:'der'}).toString('base64url');await assert.rejects(b.start({devicePublicKeySpki:key,claimHash:bodyHash(f.secret)}));
});

test('closing the broker cancels an in-flight browser callback and rejects new transactions',async()=>{
 const f=fixture();let redeem,release;const entered=new Promise<void>(resolve=>redeem=resolve),barrier=new Promise<void>(resolve=>release=resolve);
 const b=new MobileLoginHandoff({...f.options,oidc:{...f.options.oidc,redeem:async()=>{redeem();await barrier;return{idToken:'must-not-be-returned'};}}});
 const key=generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey.export({type:'spki',format:'der'}).toString('base64url');await b.start({devicePublicKeySpki:key,claimHash:bodyHash(f.secret)});
 const callback=b.callback({state:f.state(),code:'server-only-code'});await entered;b.close();release();await assert.rejects(callback);await assert.rejects(b.start({devicePublicKeySpki:key,claimHash:bodyHash(f.secret)}));
});
