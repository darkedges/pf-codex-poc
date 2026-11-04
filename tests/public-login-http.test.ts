import test from 'node:test';import assert from 'node:assert/strict';
import {publicLoginRequest} from '../scripts/copilot/public-login-http.mjs';
test('public login transport pins host before touching credentials or network',async()=>{
 let called=false;for(const url of ['https://evil.test/as/token.oauth2','http://pf-a.copilot.darkedges.com/as/token.oauth2','https://user:password@pf-a.copilot.darkedges.com/as/token.oauth2']){
  await assert.rejects(publicLoginRequest(url,{client_secret:'disposable-fixture'},{},async()=>{called=true;return new Response();}));
 }assert.equal(called,false);
});
test('public login transport never follows a Microsoft callback redirect',async()=>{
 let calls=0;const result=await publicLoginRequest('https://pf-a.copilot.darkedges.com/as/authorization.oauth2',undefined,{},async(url,init)=>{
  calls++;assert.equal(init.redirect,'manual');assert.ok(init.signal);return new Response('',{status:302,headers:{Location:'https://token.botframework.com/.auth/web/redirect?code=DISPOSABLE'}});
 });assert.equal(calls,1);assert.equal(result.status,302);
});
test('public login errors do not reveal submitted credentials',async()=>{
 await assert.rejects(publicLoginRequest('https://pf-a.copilot.darkedges.com/as/token.oauth2',{client_secret:'DISPOSABLE_SECRET'},{},async()=>{throw Error('DISPOSABLE_SECRET');}),error=>!String(error).includes('DISPOSABLE_SECRET'));
});
