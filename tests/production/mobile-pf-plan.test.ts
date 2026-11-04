import test from 'node:test';import assert from 'node:assert/strict';import {generateKeyPair,exportJWK} from 'jose';
import {mobilePfPlan} from '../../scripts/pf/mobile-profile.mjs';
import {stageMobileProfiles} from '../../scripts/pf/mobile-stage.mjs';
import {documentStageHash} from '../../scripts/pf/document-stage-step.mjs';
const key=await generateKeyPair('RS256'),pub=await exportJWK(key.publicKey),material=Object.fromEntries(['authority','agent','clientA','clientB','upstream'].map(n=>[n,{keys:[{...pub,kid:n,alg:'RS256',use:'sig'}]}]));
test('every mobile manager issues the exact audience required by its exchange verifier',()=>{
 for(const kind of ['chat','document']){
  const plan=mobilePfPlan(kind,material);
  for(const node of ['a','b']){
   const fields=plan[node].tokenManager.configuration.fields.filter(f=>f.name==='Audience Claim Value');
   assert.equal(fields.length,1);
   assert.equal(fields[0].value,plan.exchange[node].trust.audience);
   assert.notEqual(fields[0].value,node==='a'?'api://gateway-2/documents':'api://federated-copilot/documents');
  }
 }
});
test('mobile profile plans isolate clients and preserve provenance with descending native PF lifetimes',()=>{
 const plans=['chat','document'].map(kind=>mobilePfPlan(kind,material));
 for(const p of plans){assert.equal(p.executionProfile,'pf-minute-lifetimes');assert.equal(p.a.client.enabled,false);assert.equal(p.b.client.enabled,false);assert.deepEqual(p.a.client.grantTypes,['TOKEN_EXCHANGE']);assert.equal(p.a.tokenManager.configuration.fields.find(f=>f.name==='Token Lifetime').value,'2');assert.equal(p.b.tokenManager.configuration.fields.find(f=>f.name==='Token Lifetime').value,'1');for(const hop of [p.a,p.b])for(const name of ['original_login_issuer','original_login_audience','original_auth_time','presence_time','authentication_basis','resource']){assert.ok(hop.subjectProcessor.attributeContract.extendedAttributes.some(a=>a.name===name));assert.ok(hop.mapping.attributeContractFulfillment[name]);}assert.equal(p.a.policy.processorMappings[0].subjectTokenType,p.exchange.a.subjectTokenType);}
 assert.notEqual(plans[0].a.client.clientId,plans[1].a.client.clientId);assert.notEqual(plans[0].exchange.b.trust.audience,plans[1].exchange.b.trust.audience);
});
test('invalid capability or private key material cannot enter a public mobile staging plan',()=>{assert.throws(()=>mobilePfPlan('admin',material));assert.throws(()=>mobilePfPlan('chat',{...material,authority:{keys:[{...material.authority.keys[0],d:'private'}]}}));});

function stageFixture(){const materials={chat:structuredClone(material),document:structuredClone(material)},journal={purpose:'mobile-disabled-staging',profileHash:documentStageHash(Object.fromEntries(Object.entries(materials).map(([k,v])=>[k,{...v,upstream:undefined}]))),steps:{}},objects=new Map(),writes=[],snapshots=[];let fail=false;
 const admin=async(node,path,method='GET',body)=>{
  const k=node+':'+path;if(method==='GET'){if(path==='oauth/authServerSettings')return{scopes:[{name:'copilot.invoke',dynamic:false},{name:'m365.document.read',dynamic:false}]};if(path==='oauth/accessTokenMappings')return{items:[...objects.entries()].filter(([key])=>key.startsWith(node+':mapping:')).map(([,v])=>structuredClone(v))};if(objects.has(k))return structuredClone(objects.get(k));const e=Error('not found');e.status=404;throw e;}
  writes.push({node,path,method,body:structuredClone(body)});if(body.clientId)assert.equal(body.enabled,false);
  let target;if(path==='keyPairs/signing/generate')target=node+':keyPairs/signing/'+body.id;else if(path==='oauth/accessTokenMappings')target=node+':mapping:'+body.context.contextRef.id;else target=method==='PUT'?k:k+'/'+(body.id??body.clientId);objects.set(target,structuredClone(body));if(fail){fail=false;throw Error('lost response');}return body;
 };
 return{materials,journal,admin,writes,save:j=>snapshots.push(structuredClone(j)),publishedKeys:async(node,kid)=>({keys:[{...pub,kid,alg:'RS256',use:'sig'}]}),fail:()=>{fail=true;}};
}
test('disabled mobile staging is read-back verified and idempotent without enabling clients',async()=>{const f=stageFixture(),first=await stageMobileProfiles(f);assert.equal(first.status,'STAGED_DISABLED');assert.equal(first.microsoftRequests,0);const writes=f.writes.length;assert.ok(writes>0);assert.equal((await stageMobileProfiles(f)).confirmedSteps,first.confirmedSteps);assert.equal(f.writes.length,writes);});
test('uncertain staging writes preserve pending intent and prohibit an automatic repeat',async()=>{const f=stageFixture();f.fail();await assert.rejects(stageMobileProfiles(f));assert.ok(Object.values(f.journal.steps).some(s=>s.state==='pending'));const count=f.writes.length;await assert.rejects(stageMobileProfiles(f),/uncertain/);assert.equal(f.writes.length,count);});
