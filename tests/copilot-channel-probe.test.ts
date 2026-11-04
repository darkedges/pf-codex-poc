import test from 'node:test';
import assert from 'node:assert/strict';
import { discoverChannel,probeChannel,probeAgentChannel,classifyChannelEntrypoint } from '../src/copilot/channel-probe.ts';
const environmentId='11111111-2222-4333-8444-555555555555';
const compact=environmentId.replaceAll('-','');
const endpoint=`https://${compact.slice(0,-2)}.${compact.slice(-2)}.environment.api.powerplatform.com/powervirtualagents/botsbyschema/test_agent/directline/token?api-version=2022-03-01-preview`;
const config={environmentId,schemaName:'test_agent',agentEndpoint:endpoint};
const response=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status});
test('regional discovery uses the explicit tenant environment and sends no credentials',async()=>{
 let count=0;const actual=await discoverChannel(config,async(url,init)=>{count++;assert.ok(String(url).includes('/powervirtualagents/regionalchannelsettings?'));assert.equal(new Headers(init?.headers).has('authorization'),false);assert.equal(init?.redirect,'error');return response({channelUrlsById:{directline:'https://directline.botframework.com/'}});});
 assert.equal(actual,'https://directline.botframework.com/v3/directline');assert.equal(count,1);
});
for(const patch of [{agentEndpoint:endpoint.replace('https:','http:')},{agentEndpoint:endpoint+'&sig=PRIVATE'},{agentEndpoint:endpoint.replace(compact.slice(0,-2),'evil')},{schemaName:'other_agent'},{agentEndpoint:endpoint.replace('/directline/token','/arbitrary')}])test('unapproved discovery URLs fail before network access',async()=>{
 let called=false;await assert.rejects(discoverChannel({...config,...patch},async()=>{called=true;return response({});}));assert.equal(called,false);
});
test('discovered credential destination cannot escape approved Direct Line origins',async()=>{await assert.rejects(discoverChannel(config,async()=>response({channelUrlsById:{directline:'https://directline.botframework.com.evil.invalid/'}})));});
function transport(options:{anonymousAllowed?:boolean;invalidAllowed?:boolean;changedConversation?:boolean}={}){
 let calls=0;return async(url:URL|string|Request,init?:RequestInit)=>{
  calls++;const path=new URL(String(url)).pathname,auth=new Headers(init?.headers).get('authorization');assert.equal(init?.redirect,'error');
  if(path.endsWith('/tokens/generate')){
   if(!auth)return response({},options.anonymousAllowed?200:401);
   if(auth!=='Bearer TEST_CHANNEL_CREDENTIAL')return response({},options.invalidAllowed?200:403);
   return response({conversationId:'conversation1',token:'TEST_CONVERSATION_CREDENTIAL',expires_in:1800});
  }
  assert.equal(auth,'Bearer TEST_CONVERSATION_CREDENTIAL');
  if(init?.method==='POST'&&path.endsWith('/conversations'))return response({conversationId:options.changedConversation?'conversation2':'conversation1',token:'TEST_CONVERSATION_CREDENTIAL',expires_in:1800});
  if(init?.method==='POST')return response({id:'activity1'});
  return response({activities:[{id:'bot1',type:'message',channelId:'directline',conversation:{id:'conversation1'},from:{id:'observed_bot',role:'bot'},text:'PRIVATE_BOT_TEXT',attachments:[{contentType:'application/vnd.microsoft.card.oauth',content:{tokenPostResource:{sasUrl:'https://token.botframework.com/api/usertoken/PostToken?sig=PRIVATE_SAS&nonce=PRIVATE_NONCE'}}}]}],watermark:'1'});
 };
}
test('channel probe checks missing/invalid credentials and reports only sanitized metadata',async()=>{
 const result=await probeChannel('https://directline.botframework.com/v3/directline',async()=>'TEST_CHANNEL_CREDENTIAL',transport());
 assert.equal(result.anonymousRejected,true);assert.equal(result.invalidSecretRejected,true);assert.equal(result.conversationStarted,true);assert.deepEqual(result.observedBotIds,['observed_bot']);assert.equal(result.oauthCards[0].origin,'https://token.botframework.com');assert.deepEqual(result.oauthCards[0].queryKeys,['nonce','sig']);assert.equal(result.federationVerified,false);
 for(const secret of ['TEST_CHANNEL_CREDENTIAL','TEST_CONVERSATION_CREDENTIAL','PRIVATE_SAS','PRIVATE_NONCE','PRIVATE_BOT_TEXT','conversation1'])assert.ok(!JSON.stringify(result).includes(secret));
});
for(const flag of ['anonymousAllowed','invalidAllowed']as const)test('unexpected anonymous/invalid-secret acceptance stops before reading the real credential',async()=>{
 let reads=0;await assert.rejects(probeChannel('https://directline.botframework.com/v3/directline',async()=>{reads++;return'TEST_CHANNEL_CREDENTIAL';},transport({[flag]:true})));assert.equal(reads,0);
});
test('conversation substitution fails closed',async()=>{await assert.rejects(probeChannel('https://directline.botframework.com/v3/directline',async()=>'TEST_CHANNEL_CREDENTIAL',transport({changedConversation:true})));});
test('secret reader failures cannot expose credential details',async()=>{await assert.rejects(probeChannel('https://directline.botframework.com/v3/directline',async()=>{throw Error('PRIVATE_CREDENTIAL');},transport()),error=>!String(error).includes('PRIVATE'));});
test('non-allowlisted channel endpoint never reads credentials or performs requests',async()=>{
 let calls=0;await assert.rejects(probeChannel('https://evil.invalid/v3/directline',async()=>{calls++;return'PRIVATE';},async()=>{calls++;return response({});}));assert.equal(calls,0);
});
test('public Copilot token issuance fails the secured-channel check before reading credentials',async()=>{
 let reads=0;await assert.rejects(probeAgentChannel(config,async()=>{reads++;return'TEST_CHANNEL_CREDENTIAL';},async url=>String(url).includes('regionalchannelsettings')?response({channelUrlsById:{directline:'https://directline.botframework.com/'}}):response({token:'PRIVATE_ANONYMOUS_TOKEN'})));assert.equal(reads,0);
});
test('secured published-agent probe verifies the public token route and then the channel',async()=>{
 const channel=transport();const result=await probeAgentChannel(config,async()=>'TEST_CHANNEL_CREDENTIAL',async(url,init)=>{
  if(String(url).includes('regionalchannelsettings'))return response({channelUrlsById:{directline:'https://directline.botframework.com/'}});
  if(String(url)===endpoint)return response({},403);
  return channel(url,init);
 });assert.equal(result.publicTokenEndpointRejected,true);assert.equal(result.conversationStarted,true);
});
test('a missing public token route is recorded as inconclusive, not proof of secured access',async()=>{
 const channel=transport();const result=await probeAgentChannel(config,async()=>'TEST_CHANNEL_CREDENTIAL',async(url,init)=>{
  if(String(url).includes('regionalchannelsettings'))return response({channelUrlsById:{directline:'https://directline.botframework.com/'}});
  if(String(url)===endpoint)return response({},404);
  return channel(url,init);
 });assert.equal(result.publicTokenEndpointStatus,404);assert.equal(result.publicTokenEndpointRejected,false);assert.equal(result.publicTokenRouteVerified,false);assert.equal(result.conversationStarted,true);
});
test('authenticated runtime endpoint can supply regional discovery but is never used as a Direct Line token URL',async()=>{
 const runtime={...config,agentEndpoint:endpoint.replace('/powervirtualagents/botsbyschema/test_agent/directline/token','/copilotstudio/agenticruntime/3p/dataverse-backed/authenticated/bots/test_agent/conversations')};
 const channel=transport();const result=await probeAgentChannel(runtime,async()=>'TEST_CHANNEL_CREDENTIAL',async(url,init)=>{
  assert.notEqual(String(url),runtime.agentEndpoint);
  if(String(url).includes('regionalchannelsettings'))return response({channelUrlsById:{directline:'https://directline.botframework.com/'}});
  return channel(url,init);
 });assert.equal(result.entrypointKind,'authenticated_runtime');assert.equal(result.publicTokenEndpointStatus,null);assert.equal(result.publicTokenRouteVerified,false);assert.equal(result.conversationStarted,true);
});
test('runtime discovery cannot select another bot schema',async()=>{
 await assert.rejects(discoverChannel({...config,agentEndpoint:endpoint.replace('/powervirtualagents/botsbyschema/test_agent/directline/token','/copilotstudio/agenticruntime/3p/dataverse-backed/authenticated/bots/other_agent/conversations')},async()=>response({})));
});

const modern={...config,agentEndpoint:endpoint.replace('/powervirtualagents/botsbyschema/test_agent/directline/token','/copilotstudio/dataverse-backed/authenticated/bots/test_agent/conversations')};
test('modern authenticated conversation route is classified without network or token issuance',()=>{
 assert.equal(classifyChannelEntrypoint(modern),'authenticated_runtime');
 assert.equal(classifyChannelEntrypoint(config),'directline_token');
});
test('modern authenticated route supplies credential-free regional discovery only',async()=>{
 let requests=0;
 const result=await discoverChannel(modern,async(url,init)=>{requests++;assert.ok(String(url).includes('/regionalchannelsettings?'));assert.notEqual(String(url),modern.agentEndpoint);assert.equal(new Headers(init?.headers).has('authorization'),false);return response({channelUrlsById:{directline:'https://directline.botframework.com/'}});});
 assert.equal(result,'https://directline.botframework.com/v3/directline');assert.equal(requests,1);
});
test('modern authenticated route is never called as an anonymous token endpoint',async()=>{
 const channel=transport();const result=await probeAgentChannel(modern,async()=>'TEST_CHANNEL_CREDENTIAL',async(url,init)=>{
  assert.notEqual(String(url),modern.agentEndpoint);
  if(String(url).includes('regionalchannelsettings'))return response({channelUrlsById:{directline:'https://directline.botframework.com/'}});
  return channel(url,init);
 });assert.equal(result.entrypointKind,'authenticated_runtime');assert.equal(result.publicTokenRouteVerified,false);
});
for(const patch of [{schemaName:'stale_agent'},{agentEndpoint:modern.agentEndpoint.replace('/authenticated/','/anonymous/')},{agentEndpoint:modern.agentEndpoint.replace('/copilotstudio/','/copilotstudio/unknown/')},{agentEndpoint:modern.agentEndpoint+'&sig=PRIVATE'},{agentEndpoint:modern.agentEndpoint.replace('https:','http:')}])test('modern route substitution fails before any request or secret read',async()=>{
 let calls=0;await assert.rejects(probeAgentChannel({...modern,...patch},async()=>{calls++;return'PRIVATE';},async()=>{calls++;return response({});}));assert.equal(calls,0);
});

test('delayed OAuth challenge is collected after a greeting, without duplicate counts or SAS output',async()=>{
 const base=transport();let polls=0,diagnosticMessages=0;
 const result=await probeChannel('https://directline.botframework.com/v3/directline',async()=>'TEST_CHANNEL_CREDENTIAL',async(url,init)=>{
  if(init?.method==='POST'&&String(url).endsWith('/activities')){const body=JSON.parse(String(init.body));if(body.type==='message'){diagnosticMessages++;assert.equal(body.text,'/federation-status');}}
  if(init?.method==='GET'){
   polls++;const full=await (await base(url,init)).json();
   const greeting={id:'greeting',type:'message',from:{id:'observed_bot',role:'bot'},text:'PRIVATE_GREETING'};
   return response({activities:polls<7?[greeting]:[greeting,...full.activities]});
  }
  return base(url,init);
 },async()=>{});
 assert.equal(polls,7);assert.equal(diagnosticMessages,1);assert.equal(result.botActivities,2);assert.equal(result.oauthCardCount,1);assert.equal(result.oauthCards.length,1);
 for(const value of ['PRIVATE_GREETING','PRIVATE_SAS','PRIVATE_NONCE'])assert.ok(!JSON.stringify(result).includes(value));
});
test('an OAuth card without secure token-post resource is observed without following its sign-in URL',async()=>{
 const base=transport();const result=await probeChannel('https://directline.botframework.com/v3/directline',async()=>'TEST_CHANNEL_CREDENTIAL',async(url,init)=>{
  if(init?.method!=='GET')return base(url,init);
  return response({activities:[{id:'oauth',type:'message',from:{id:'observed_bot',role:'bot'},attachments:[{contentType:'application/vnd.microsoft.card.oauth',content:{buttons:[{type:'signin',value:'https://untrusted.invalid/PRIVATE_SESSION'}]}}]}]});
 },async()=>{});
 assert.equal(result.oauthCardCount,1);assert.equal(result.oauthCards.length,0);assert.ok(!JSON.stringify(result).includes('PRIVATE'));
});
test('bounded polling records no challenge after thirty empty reads',async()=>{
 const base=transport();let polls=0;const result=await probeChannel('https://directline.botframework.com/v3/directline',async()=>'TEST_CHANNEL_CREDENTIAL',async(url,init)=>{
  if(init?.method!=='GET')return base(url,init);polls++;return response({activities:[]});
 },async()=>{});assert.equal(polls,30);assert.equal(result.botActivities,0);assert.equal(result.oauthCardCount,0);
});
test('changed content under a repeated activity id fails closed without leaking content',async()=>{
 const base=transport();let polls=0;await assert.rejects(probeChannel('https://directline.botframework.com/v3/directline',async()=>'TEST_CHANNEL_CREDENTIAL',async(url,init)=>{
  if(init?.method!=='GET')return base(url,init);polls++;return response({activities:[{id:'reused',type:'message',from:{id:'observed_bot',role:'bot'},text:'PRIVATE_'+polls}]});
 },async()=>{}),e=>!String(e).includes('PRIVATE'));
});
