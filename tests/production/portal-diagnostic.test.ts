import test from 'node:test';
import assert from 'node:assert/strict';
import {createPortalDiagnostic} from '../../src/copilot/portal-diagnostic.ts';
const signedIn='Authentication status: signed in. Copilot reports User.IsLoggedIn=true. Delegated tool access has not been verified.';
function fixture(options:any={}){
 const now=Math.floor(Date.now()/1000),claims={iss:'https://broker.test',aud:'api://copilot-broker',sub:'partner:user',act:{iss:'https://agents.test',sub:'partner:agent'},org_id:'partner',delegation_id:'owned-grant',execution_mode:'interactive',scope:'copilot.invoke',iat:now,nbf:now-1,exp:now+120,jti:'broker',...options.broker};
 const provider={iss:'https://provider.test',aud:'api://copilot-login',sub:'partner:user',scope:'copilot.login',iat:now,nbf:now-1,exp:now+3600,jti:'provider',...options.provider};
 const config={channel:{endpoint:'https://directline.botframework.com/v3/directline',brokerAudience:claims.aud,ssoAudience:provider.aud,scope:'copilot.invoke',botId:'approved-bot',trustedOrigins:['https://server.invalid'],providerSso:{issuer:provider.iss,audience:provider.aud,scope:'copilot.login',maxLifetimeSeconds:3600},tokenPostRules:[{origin:'https://token.botframework.com',pathExact:'/api/sas/postToken',requiredQueryParameters:['expiry','hmac','id','state']}],timeoutMs:1000,maxSessions:1,sessionLifetimeSeconds:120,maxActivities:100},agent:{issuer:'https://agents.test',subject:'partner:agent'},organisation:'partner',resource:'sharepoint:approved-research',timeoutMs:options.timeoutMs??2000,pollIntervalMs:1};
 let polls=0,tool=false,conversations=0,posts=0,handoffs=0,audits=0,requests=0,revoked=false;const observations:any[]=[];
 const message=(text:string,id:string)=>({id,type:'message',channelId:'directline',conversation:{id:'conversation-1'},from:{id:'approved-bot'},text});
 const perform=createPortalDiagnostic(config as any,{
  observe:event=>observations.push(event),loginVerifier:{verify:async()=>({subject:'partner:user'} as any)},brokerVerifier:{verify:async()=>claims},providerVerifier:{verify:async()=>provider},
  issueBroker:async()=>{if(options.hangIssue)await new Promise(()=>{});return{brokerToken:'synthetic-broker',agentToken:'synthetic-agent'};},authorise:async()=>{if(options.denied||revoked)throw Error('denied');},secret:async()=>'synthetic-channel-secret',
  handoff:async(proof)=>{handoffs++;assert.equal(proof.providerToken,'synthetic-provider');assert.equal(proof.brokerToken,'synthetic-broker');},
  verifyToolAudit:async()=>{audits++;revoked=options.revokeAfterAudit===true;return options.audit!==false;},
  fetch:async(url,init)=>{
   requests++;const u=new URL(String(url)),method=init?.method??'GET';
   if(u.origin==='https://token.botframework.com'){assert.deepEqual(JSON.parse(String(init?.body)),{token:'synthetic-provider'});assert.equal(handoffs,1);return new Response(null,{status:options.postStatus??200});}
   if(u.pathname.endsWith('/tokens/generate'))return Response.json({conversationId:'conversation-1',token:'synthetic-channel',expires_in:120});
   if(u.pathname.endsWith('/conversations'))return Response.json({conversationId:'conversation-1',token:'synthetic-channel',expires_in:120},{status:201});
   if(method==='POST'){const text=JSON.parse(String(init?.body)).text;assert.ok(['/federation-status','verify delegated tool access'].includes(text));if(text==='verify delegated tool access')tool=true;return Response.json({id:'sent'});}
   polls++;let activities:any[]=[];
   if(polls===1)activities=[{...message('','oauth'),attachments:[{contentType:'application/vnd.microsoft.card.oauth',content:{tokenPostResource:{sasUrl:options.sasUrl??'https://token.botframework.com/api/sas/postToken?expiry=example&hmac=example&id=example&state=example'}}}]}];
   else if(!tool)activities=[message(signedIn,'signed-in')];
   else activities=[message('Delegated diagnostic stage: connector started.','start'),message('Delegated diagnostic stage: connector returned.','returned'),message(options.toolDenied?'Delegated tool access not verified.':'Delegated tool access verified.','result')];
   return Response.json({activities,watermark:String(polls)});
  }
 });
 return{perform:()=>perform({grantId:'owned-grant',providerToken:'synthetic-provider',login:{idToken:'synthetic-id-token',nonce:'synthetic-nonce'}},{beforeConversation:()=>{if(conversations)throw Error('spent');conversations++;},beforeTokenPost:()=>{if(posts)throw Error('spent');posts++;}}),counts:()=>({conversations,posts,handoffs,audits,requests}),observations};
}
test('portal diagnostic uses actual Direct Line adapter, fresh card, signed handoff and independent audit gate',async()=>{
 const f=fixture();assert.deepEqual(await f.perform(),{authorized:true});assert.deepEqual({...f.counts(),requests:0},{conversations:1,posts:1,handoffs:1,audits:1,requests:0});
 assert.deepEqual(f.observations,[{event:'portal_diagnostic',stage:'token_post',status:200},{event:'portal_diagnostic',stage:'result',outcome:'verified'}]);assert.ok(!JSON.stringify(f.observations).includes('synthetic'));
});
for(const [name,options]of Object.entries({human:{provider:{sub:'other:user'}},actor:{broker:{act:{iss:'https://agents.test',sub:'other:agent'}}},organisation:{broker:{org_id:'other'}},grant:{broker:{delegation_id:'foreign'}},autonomous:{broker:{execution_mode:'autonomous'}},denied:{denied:true}}))test('portal diagnostic rejects '+name+' before Microsoft traffic',async()=>{
 const f=fixture(options);await assert.rejects(f.perform(),/^PolicyError: unavailable$/);assert.equal(f.counts().requests,0);
});
for(const options of [{audit:false},{toolDenied:true},{postStatus:400},{sasUrl:'https://evil.test/api/sas/postToken?expiry=x&hmac=x&id=x&state=x'}])test('portal diagnostic rejects missing evidence or failed protocol '+JSON.stringify(options),async()=>{
 const f=fixture(options);await assert.rejects(f.perform(),/^PolicyError: unavailable$/);assert.ok(f.counts().posts<=1);assert.equal(f.counts().conversations,1);
});
test('deadline ends a stalled issuance without starting a Microsoft conversation',async()=>{
 const f=fixture({hangIssue:true,timeoutMs:100});await assert.rejects(f.perform(),/^PolicyError: unavailable$/);assert.equal(f.counts().conversations,0);assert.equal(f.counts().requests,0);
});
test('revocation after positive audit prevents reporting successful current access',async()=>{
 const f=fixture({revokeAfterAudit:true});await assert.rejects(f.perform(),/^PolicyError: unavailable$/);assert.equal(f.counts().audits,1);
});
