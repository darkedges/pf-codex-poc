import test from 'node:test';import assert from 'node:assert/strict';
import {activationCandidate} from '../scripts/cloudflare/activation-plan.mjs';
const review={callbackCapturedLocally:true,publicNetworkUsed:false,renderedBrowserVerified:false,resources:[{path:'/assets/css/main.css',status:200,directlyLinked:true},{path:'/assets/images/missing.png',status:404,directlyLinked:false}],cookies:[{name:'PF',secure:true,httpOnly:true,domain:null}]};
test('activation candidate allows exact PF A login and reviewed files only',()=>{
 const c=activationCandidate(review),a=new RegExp(c.paths.a),b=new RegExp(c.paths.b);
 for(const path of ['/as/authorization.oauth2','/as/token.oauth2','/as/fixture/resume/as/authorization.ping','/assets/css/main.css','/pf/JWKS'])assert.ok(a.test(path));
 for(const path of ['/pf-admin-api/v1/version','/pingfederate/app','/assets/unknown.js','/assets/images/missing.png','/as/par.oauth2'])assert.ok(!a.test(path));
 assert.ok(b.test('/pf/JWKS'));assert.ok(b.test('/.well-known/openid-configuration'));assert.ok(!b.test('/as/token.oauth2'));assert.ok(!b.test('/as/authorization.oauth2'));assert.ok(!b.test('/assets/css/main.css'));
 assert.equal(c.approved,false);assert.equal(c.certificateVerified,false);assert.equal(c.publicRoutesEnabled,false);
});
test('unreviewed asset destinations and missing direct assets cannot generate routes',()=>{
 for(const path of ['/assets/../admin.js','/admin/app.js','https://evil.test/assets/app.js','/assets/app.js?token=secret'])assert.throws(()=>activationCandidate({...review,resources:[{path,status:200,directlyLinked:true}]}));
 assert.throws(()=>activationCandidate({...review,resources:[{path:'/assets/missing.js',status:404,directlyLinked:true}]}));
});
test('unverified cookie origin/security and absent local callback proof fail closed',()=>{
 for(const cookie of [{name:'PF',secure:false,httpOnly:true,domain:null},{name:'PF',secure:true,httpOnly:false,domain:null},{name:'PF',secure:true,httpOnly:true,domain:'localhost'}])assert.throws(()=>activationCandidate({...review,cookies:[cookie]}));
 assert.throws(()=>activationCandidate({...review,callbackCapturedLocally:false}));
});
