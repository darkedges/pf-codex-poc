import test from 'node:test';import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';import {writeFileSync} from 'node:fs';import {resolve} from 'node:path';
import {root,read} from '../../scripts/pf/common.mjs';
import {copilotProfile as p} from '../../scripts/pf/copilot-config.mjs';
import {profile} from '../../scripts/pf/config.mjs';
import {browserAssets} from '../../scripts/pf/browser-assets.mjs';
import {LocalPublicBrowser,localPublicRequest,forms} from './public-origin.mjs';
test('real public-host login reviews bounded local assets and cookie attributes without exposing credentials',async()=>{
 const b=new LocalPublicBrowser(),state=randomBytes(24).toString('hex');
 const auth=new URL(p.loginIssuer+'/as/authorization.oauth2');auth.search=new URLSearchParams({client_id:p.loginClientId,response_type:'code',scope:'copilot.login',redirect_uri:p.callback,state,pfidpadapterid:'consentHTMLForm',resource:'urn:copilot:login'}).toString();
 const login=await b.request(auth).catch(error=>{console.log(JSON.stringify({event:'blocked_browser_asset',origin:error.resourceOrigin,path:error.resourcePath}));throw error;});assert.equal(login.status,200);
 const form=forms(login.html).find(f=>'pf.pass'in f.fields);assert.ok(form);
 const approval=await b.submit(form,{'pf.username':profile.human,'pf.pass':read('login-password'),'pf.ok':'clicked'});
 const consent=forms(approval.html).find(f=>'pf.oauth.authz.consent'in f.fields);assert.ok(consent);
 const callback=await b.submit(consent,{'pf.oauth.authz.consent':'allow'});assert.equal(callback.callback?.searchParams.get('state'),state);
 const resources=[],direct=new Set(b.assets),queue=[...b.assets],seen=new Set<string>();
 while(queue.length){
  const url=queue.shift()!;if(seen.has(url))continue;seen.add(url);assert.ok(seen.size<=50);
  const response=await localPublicRequest(url);
  if(direct.has(url))assert.equal(response.status,200,'Unavailable directly linked asset: '+new URL(url).pathname);
  else assert.ok([200,404].includes(response.status),'Unexpected CSS asset response');
  assert.equal(response.location,undefined,'Static assets cannot redirect');
  resources.push({path:new URL(url).pathname,status:response.status,contentType:response.contentType,directlyLinked:direct.has(url)});
  if(response.contentType?.includes('text/css')){
   let linked;try{linked=browserAssets(response.html,url,true);}catch(error){console.log(JSON.stringify({event:'blocked_css_asset',origin:error.resourceOrigin,path:error.resourcePath}));throw error;}
   for(const asset of linked)queue.push(asset);
  }
 }
 const cookies=[...b.cookieReview.values()];
 for(const cookie of cookies){assert.ok(cookie.secure,'PF cookies must stay secure');assert.ok(cookie.domain===null||cookie.domain==='pf-a.copilot.darkedges.com','No localhost cookie domain');}
 const summary={verifiedAt:new Date().toISOString(),publicNetworkUsed:false,renderedBrowserVerified:false,
  paths:[...b.paths].map(path=>path.replace(/^\/as\/[A-Za-z0-9_-]+\/resume\//,'/as/{transaction}/resume/')),resources,cookies,unresolvedCssResources:resources.filter(r=>r.status!==200).map(r=>r.path),callbackCapturedLocally:true};
 writeFileSync(resolve(root,'.local/copilot/browser-review.json'),JSON.stringify(summary,null,2),{mode:0o600});
 assert.ok(resources.length>0,'Review must actually retrieve login assets');
 console.log(JSON.stringify({event:'pf_browser_review',assets:resources.length,unresolvedCssResources:summary.unresolvedCssResources,cookieNames:cookies.map(c=>c.name),publicNetworkUsed:false}));
});
