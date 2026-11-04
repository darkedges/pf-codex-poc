import test from 'node:test';import assert from 'node:assert/strict';
import {ApprovedSiteDocuments} from '../../src/mobile/site-documents.ts';
const siteUrl='https://example.sharepoint.com/sites/Approved',collection='11111111-1111-1111-1111-111111111111',web='22222222-2222-2222-2222-222222222222',siteId='example.sharepoint.com,'+collection+','+web;
function fixture(change={}){
 const requests=[];let revoked=false;
 const items=[{id:'one',name:'research.txt',text:'The approved research colour is teal.',unique:'33333333-3333-3333-3333-333333333333'},{id:'two',name:'reference.txt',text:'The document reference is DEMO-002.',unique:'44444444-4444-4444-4444-444444444444'}];
 const metadata=i=>({id:i.id,name:i.name,size:Buffer.byteLength(i.text),eTag:'"v1"',file:{mimeType:'text/plain'},parentReference:{driveId:'drive',siteId},sharepointIds:{siteId:collection,webId:web,listItemUniqueId:i.unique},...change});
 const claims={iss:'https://pf-b.example.test',aud:'api://documents',sub:'human',act:{iss:'https://agents.example.test',sub:'agent'},org_id:'org',delegation_id:'grant',execution_mode:'interactive',scope:'m365.document.read',resource:'sharepoint:approved-research',exp:Math.floor(Date.now()/1000)+60};
 const reader=new ApprovedSiteDocuments({siteId,siteUrl,resource:'sharepoint:approved-research',audience:claims.aud,maxDocuments:16,maxNodes:128,maxRequests:40,timeoutMs:5000},{verify:async token=>{assert.equal(token,'synthetic-broker-proof');return claims;},authorise:async()=>{if(revoked)throw Error('revoked');},tokenSource:{getToken:async()=>({value:'synthetic-graph-token',expiresAt:Date.now()+3600000})},fetch:async(url,init)=>{requests.push(String(url));assert.equal(new Headers(init.headers).get('Authorization'),'Bearer synthetic-graph-token');const u=new URL(url);assert.equal(u.origin,'https://graph.microsoft.com');assert.equal(init.redirect,'manual');
  if(u.pathname.endsWith('/drives'))return Response.json({value:[{id:'drive',driveType:'documentLibrary',webUrl:siteUrl+'/Shared Documents'}]});
  if(u.pathname.endsWith('/root/children'))return Response.json({value:items.map(metadata)});
  const i=items.find(i=>u.pathname.endsWith('/items/'+i.id)||u.pathname.endsWith('/items/'+i.id+'/content'));assert.ok(i);
  if(u.pathname.endsWith('/content'))return new Response(i.text,{headers:{'Content-Type':'text/plain'}});return Response.json(metadata(i));
 }});
 return{reader,requests,revoke:()=>revoked=true};
}
test('bounded approved-site discovery grounds a question across multiple independently checked files',async()=>{
 const f=fixture(),r=await f.reader.read('What is the reference and research colour?','synthetic-broker-proof',new AbortController().signal);assert.equal(r.documents.length,2);assert.equal(r.unsupportedCount,0);assert.match(r.fingerprint,/^[a-f0-9]{64}$/);assert.ok(r.documents.some(d=>d.text.includes('DEMO-002')));assert.equal(f.requests.length,6);
});
test('foreign site metadata and remote items cannot become approved document content',async()=>{
 const bad=fixture({sharepointIds:{siteId:'55555555-5555-5555-5555-555555555555',webId:web,listItemUniqueId:'33333333-3333-3333-3333-333333333333'}});await assert.rejects(bad.reader.read('Question','synthetic-broker-proof',new AbortController().signal));assert.equal(bad.requests.some(u=>u.includes('/content')),false);
 const remote=fixture({remoteItem:{id:'foreign'}}),r=await remote.reader.read('Question','synthetic-broker-proof',new AbortController().signal);assert.equal(r.documents.length,0);assert.equal(r.unsupportedCount,2);
});
test('current resource revocation prevents even catalog discovery',async()=>{const f=fixture();f.revoke();await assert.rejects(f.reader.read('Question','synthetic-broker-proof',new AbortController().signal));assert.equal(f.requests.length,0);});
test('unsupported file formats remain visible as unsupported and are never downloaded',async()=>{const f=fixture({file:{mimeType:'application/pdf'}}),r=await f.reader.read('Question','synthetic-broker-proof',new AbortController().signal);assert.equal(r.documents.length,0);assert.equal(r.unsupportedCount,2);assert.equal(f.requests.length,2);});
