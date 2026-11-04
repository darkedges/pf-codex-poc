import test from 'node:test';
import assert from 'node:assert/strict';
import { ConsentPortal } from '../../src/consent/portal.ts';
const origin='https://portal.test';
const csrf=(html:string)=>html.match(/name="csrf" value="([^"]+)"/)![1];
const cookie=(r:{headers:Record<string,string>})=>r.headers['Set-Cookie'].split(';')[0];
function setup(){let pending:{state:string;nonce:string;verifier:string};let redeems=0,approvals=0;
 const options={human:{subject:'partner:user',organisation:'partner'},agent:{id:'agent',subject:'partner:agent',issuer:'https://agents.test'},capability:{scope:'copilot.invoke',resource:'sharepoint:approved-research'},termsHash:'terms-1',modes:['interactive','autonomous'],durationsSeconds:[3600,86400],grants:[]};
 const portal=new ConsentPortal({origin,capability:options.capability,oidc:{start:async(state,nonce,verifier)=>{pending={state,nonce,verifier};return'https://pf.test/authorize';},redeem:async()=>{redeems++;return{login:{issuer:'https://pf.test',subject:'partner:user',audience:'portal',issuedAt:Date.now(),authTime:Date.now(),expiresAt:Date.now()+60000,tokenHash:'a'.repeat(43),nonceHash:'b'.repeat(43)},idToken:'SECRET-ID-TOKEN'};}},policy:{request:async(path,body)=>{if(path.endsWith('approve')){approvals++;assert.equal(body.idToken,'SECRET-ID-TOKEN');return{grantId:'grant-real',modes:['interactive'],expiresAt:Date.now()+60000};}return options;}}});
 return{portal,pending:()=>pending!,redeems:()=>redeems,approvals:()=>approvals};
}
const input=(method:string,path:string,cookieValue='',body='',requestOrigin=origin)=>({method,path,headers:{cookie:cookieValue,origin:requestOrigin},body});
async function begin(s:ReturnType<typeof setup>){const home=await s.portal.handle(input('GET','/'));const c=cookie(home);const start=await s.portal.handle(input('POST','/login',c,new URLSearchParams({csrf:csrf(home.html)}).toString()));assert.equal(start.status,302);return c;}
test('callback rotates the browser session, consumes state once and never renders tokens',async()=>{
 const s=setup(),c=await begin(s);const path='/callback?code=code&state='+s.pending().state;
 const callback=await s.portal.handle(input('GET',path,c));assert.equal(callback.status,303);assert.notEqual(cookie(callback),c);assert.equal(s.redeems(),1);
 const page=await s.portal.handle(input('GET','/',cookie(callback)));assert.ok(page.html.includes('partner:user'));assert.ok(!page.html.includes('SECRET-ID-TOKEN'));
 assert.equal((await s.portal.handle(input('GET',path,c))).status,403);assert.equal(s.redeems(),1);
});
test('another browser cannot redeem the login callback',async()=>{
 const s=setup(),c=await begin(s);const other=await s.portal.handle(input('GET','/'));const path='/callback?code=code&state='+s.pending().state;
 assert.equal((await s.portal.handle(input('GET',path,cookie(other)))).status,403);assert.equal(s.redeems(),0);
 assert.equal((await s.portal.handle(input('GET',path,c))).status,303);
});
test('consent needs same-origin CSRF and rejects human/scope substitution',async()=>{
 const s=setup(),c=await begin(s);const callback=await s.portal.handle(input('GET','/callback?code=code&state='+s.pending().state,c));const authenticated=cookie(callback),page=await s.portal.handle(input('GET','/',authenticated)),token=csrf(page.html);
 for(const fields of [{csrf:'forged',duration:'3600'},{csrf:token,duration:'3600',sub:'other'},{csrf:token,duration:'3600',scope:'admin'}])assert.ok((await s.portal.handle(input('POST','/approve',authenticated,new URLSearchParams(fields).toString()))).status>=400);
 assert.equal((await s.portal.handle(input('POST','/approve',authenticated,new URLSearchParams({csrf:token,duration:'3600'}).toString(),'https://evil.test'))).status,403);assert.equal(s.approvals(),0);
 assert.equal((await s.portal.handle(input('POST','/approve',authenticated,new URLSearchParams({csrf:token,duration:'3600'}).toString()))).status,303);assert.equal(s.approvals(),1);
});
