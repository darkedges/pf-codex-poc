import test from 'node:test';import assert from 'node:assert/strict';
import {browserAssets,cookieAttributes} from '../scripts/pf/browser-assets.mjs';
const origin='https://pf-a.copilot.darkedges.com';
test('asset review resolves only fixed-origin static resources',()=>{
 assert.deepEqual(browserAssets('<script src="/assets/app.js?v=1"></script><link href="/assets/app.css"><a href="/reset">Reset</a>',origin),[origin+'/assets/app.js?v=1',origin+'/assets/app.css']);
 assert.deepEqual(browserAssets('body{background:url(../images/logo.png)}',origin+'/assets/css/style.css',true),[origin+'/assets/images/logo.png']);
});
test('asset review honors a same-origin HTML base and rejects foreign bases',()=>{
 assert.deepEqual(browserAssets('<base href="/"><link href="assets/css/main.css">',origin+'/as/authorization.oauth2'),[origin+'/assets/css/main.css']);
 assert.throws(()=>browserAssets('<base href="https://evil.test/"><script src="assets/app.js"></script>',origin));
});
test('CSS font fragments are removed before network access',()=>{
 assert.deepEqual(browserAssets('src:url(../fonts/iconfont.eot?#iefix)',origin+'/assets/css/main.css',true),[origin+'/assets/fonts/iconfont.eot']);
});
for(const reference of ['https://evil.test/assets/app.js','//evil.test/assets/app.js','/pf-admin-api/app.js','/assets/../../admin/app.js','javascript:app.js'])test('unapproved browser asset cannot select a request destination',()=>{
 assert.throws(()=>browserAssets(`<script src="${reference}"></script>`,origin));
});
test('cookie review retains attributes without its credential value',()=>{
 const summary=cookieAttributes('PF=DISPOSABLE-SECRET; Path=/; Secure; HttpOnly; SameSite=None');
 assert.deepEqual(summary,{name:'PF',secure:true,httpOnly:true,sameSite:'None',domain:null,path:'/'});assert.ok(!JSON.stringify(summary).includes('DISPOSABLE-SECRET'));
});
