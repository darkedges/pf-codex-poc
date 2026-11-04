import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { generateKeyPair,SignJWT,jwtVerify } from 'jose';
import { DirectLineAdapter } from '../../src/adapters/direct-line.ts';
import type { DelegatedClaims } from '../../src/adapters/token-exchange.ts';
const pair=await generateKeyPair('RS256');
const brokerAudience='api://copilot-broker',ssoAudience='api://copilot-tools';
const configuration={endpoint:'https://directline.botframework.com/v3/directline',brokerAudience,ssoAudience,scope:'copilot.invoke',botId:'approved-bot',trustedOrigins:['https://portal.test'],tokenPostRules:[{origin:'https://token.botframework.com',pathPrefix:'/approved/token-post/',requiredQueryParameters:['sig']}],timeoutMs:100,maxSessions:10,sessionLifetimeSeconds:300,maxActivities:100};
const identity={iss:'https://pf-b.test',aud:brokerAudience,sub:'partner:human',act:{iss:'https://agents.test',sub:'partner:agent'},org_id:'partner',delegation_id:'grant-approved',execution_mode:'interactive',scope:'copilot.invoke'};
async function token(now:number,patch={}){const seconds=Math.floor(now/1000);return new SignJWT({...identity,iat:seconds,nbf:seconds,exp:seconds+120,jti:randomUUID(),...patch}).setProtectedHeader({alg:'RS256',kid:'test-key'}).sign(pair.privateKey);}
function fixture(patch={},dependencies={}){
 let now=Date.now(),permit=true,sequence=0,watermark=0,providerCalls=0;const requests:{url:string;method:string;headers:Record<string,string>;body:any}[]=[],events:any[]=[],pages:any[][]=[];
 const verifier=(audience:string)=>({verify:async(raw:string)=>{const {payload}=await jwtVerify(raw,pair.publicKey,{issuer:identity.iss,audience,algorithms:['RS256'],currentDate:new Date(now)});return payload as DelegatedClaims;}});
 const fetcher=async(url:unknown,init?:RequestInit)=>{
  const target=new URL(String(url)),method=init?.method??'GET',body=init?.body?JSON.parse(String(init.body)):undefined,headers=init?.headers as Record<string,string>;requests.push({url:String(url),method,body,headers});
  if(target.pathname.endsWith('/tokens/generate'))return Response.json({conversationId:'conversation-'+(++sequence),token:'test-only-channel-'+sequence,expires_in:120});
  if(target.pathname.endsWith('/tokens/refresh'))return Response.json({conversationId:'conversation-'+sequence,token:'test-only-refreshed-'+sequence,expires_in:120});
  if(target.pathname.endsWith('/conversations'))return Response.json({conversationId:'conversation-'+sequence,token:'test-only-started-'+sequence,expires_in:120,streamUrl:'wss://unapproved.test/never-follow'},{status:201});
  if(target.origin==='https://token.botframework.com')return new Response(null,{status:204});
  if(method==='GET')return Response.json({activities:pages.shift()??[],watermark:String(++watermark)});
  return Response.json({id:'activity-sent'});
 };
 const microsoft=(patch as any).tokenPostRules?.some(r=>r.pathExact==='/api/sas/postToken');
 const providerSso=microsoft?{issuer:'https://provider.test',audience:ssoAudience,scope:'copilot.login',maxLifetimeSeconds:180}:undefined;
 const adapter=new DirectLineAdapter({...configuration,...(providerSso?{providerSso}:{}),...patch},{verifier:verifier(brokerAudience),ssoVerifier:verifier(ssoAudience),...(providerSso?{providerVerifier:{verify:async(raw:string)=>{return(await jwtVerify(raw,pair.publicKey,{issuer:providerSso.issuer,audience:ssoAudience,algorithms:['RS256'],currentDate:new Date(now)})).payload;}},bindProviderIdentity:async(p,b)=>{if(p.sub!==b.sub||b.org_id!==identity.org_id)throw Error();}}:{}),secret:async()=> 'test-only-directline-master',issueSsoToken:async request=>{providerCalls++;return providerSso?token(now,{iss:providerSso.issuer,aud:ssoAudience,scope:providerSso.scope,act:undefined,org_id:undefined,delegation_id:undefined,execution_mode:undefined,jti:randomUUID()}):token(now,{...request.claims,aud:ssoAudience,jti:randomUUID()});},authorise:async()=>{if(!permit)throw Error('PRIVATE');},fetch:fetcher,now:()=>now,observe:event=>events.push(event),...dependencies});
 return{adapter,requests,pages,events,transport:fetcher,now:()=>now,bearer:(patch={})=>token(now,patch),deny:()=>{permit=false;},advance:(ms:number)=>{now+=ms;},providerCalls:()=>providerCalls};
}
function challenge(url='https://token.botframework.com/approved/token-post/one?sig=test-only-signature',patch={}){return{type:'message',id:'oauth-1',channelId:'directline',conversation:{id:'conversation-1'},from:{id:'approved-bot'},attachments:[{contentType:'application/vnd.microsoft.card.oauth',content:{tokenPostResource:{sasUrl:url}}}],...patch};}
function message(text='Approved answer',patch={}){return{type:'message',id:'message-1',channelId:'directline',conversation:{id:'conversation-1'},from:{id:'approved-bot'},text,...patch};}
const exactRule={origin:'https://token.botframework.com',pathExact:'/api/sas/postToken',requiredQueryParameters:['expiry','hmac','id','state']};
const exactChallenge='https://token.botframework.com/api/sas/postToken?expiry=test-expiry&hmac=test-signature&id=test-id&state=test-state';

test('server shutdown discards conversations and permanently denies future operations',async()=>{const f=fixture(),raw=await f.bearer(),opened=await f.adapter.open(raw),before=f.requests.length;f.adapter.shutdown();await assert.rejects(f.adapter.send(opened.handle,raw,'must not send'));await assert.rejects(f.adapter.open(raw));assert.equal(f.requests.length,before);});

test('Microsoft JSON token-post contract preserves signed query bytes and excludes channel credentials',async()=>{
 let captured:RequestInit|undefined,postedUrl='';let s:ReturnType<typeof fixture>;
 s=fixture({tokenPostRules:[exactRule]}, {fetch:async(url:unknown,init?:RequestInit)=>{
  if(String(url).startsWith(exactRule.origin)){postedUrl=String(url);captured=init;return new Response(null,{status:204});}
  return s.transport(url,init);
 }});
 const sas=exactRule.origin+'/api/sas/postToken?state=test%2bstate&expiry=1800000000&hmac=test%2Bsignature%2f%3d&id=test~id';
 const b=await s.bearer(),c=await s.adapter.open(b);s.pages.push([challenge(sas)]);
 assert.equal((await s.adapter.poll(c.handle,b)).state,'token_posted');
 assert.equal(postedUrl,sas);assert.equal(captured?.method,'POST');assert.equal(captured?.redirect,'error');
 const headers=new Headers(captured?.headers);assert.equal(headers.get('content-type'),'application/json');assert.equal(headers.get('authorization'),null);assert.equal(headers.get('cookie'),null);
 const body=JSON.parse(String(captured?.body));assert.deepEqual(Object.keys(body),['token']);
 assert.notEqual(body.token,b);assert.equal((await jwtVerify(body.token,pair.publicKey,{audience:ssoAudience})).payload.sub,identity.sub);
});

test('Microsoft expiry-related HTTP 400 closes the session without retry, credential leak or success',async()=>{
 let posts=0;let s:ReturnType<typeof fixture>;
 s=fixture({tokenPostRules:[exactRule]}, {fetch:async(url:unknown,init?:RequestInit)=>{
  if(String(url).startsWith(exactRule.origin)){posts++;return new Response('Expired PRIVATE_VENDOR_DETAIL',{status:400});}
  return s.transport(url,init);
 }});
 const b=await s.bearer(),c=await s.adapter.open(b);s.pages.push([challenge(exactChallenge),message('Must not escape')]);
 await assert.rejects(s.adapter.poll(c.handle,b),{message:'protocol_error'});
 await assert.rejects(s.adapter.poll(c.handle,b),{message:'session_denied'});
 assert.equal(posts,1);assert.ok(!JSON.stringify(s.events).includes('PRIVATE_VENDOR_DETAIL'));assert.ok(!JSON.stringify(s.events).includes(b));
});
test('observed Microsoft token-post endpoint can be pinned to one exact path',async()=>{
 const s=fixture({tokenPostRules:[exactRule]}),b=await s.bearer(),c=await s.adapter.open(b);s.pages.push([challenge(exactChallenge)]);
 assert.equal((await s.adapter.poll(c.handle,b)).state,'token_posted');
 const posts=s.requests.filter(r=>r.url.startsWith('https://token.botframework.com'));assert.equal(posts.length,1);assert.equal(posts[0].url,exactChallenge);assert.equal(posts[0].headers.Authorization,undefined);assert.ok(posts[0].body.token);
});
for(const url of [exactChallenge.replace('/postToken?','/postTokenOther?'),exactChallenge.replace('/postToken?','/postToken/child?'),exactChallenge.replace('/postToken?','/posttoken?'),exactChallenge.replace('/postToken?','/postToken%2fchild?'),exactChallenge.replace('token.botframework.com','token.botframework.com.evil.invalid'),exactChallenge.replace('&state=test-state',''),exactChallenge+'&hmac=duplicate'])test('exact token-post rule rejects substitution before issuing a token: '+url.split('?')[0],async()=>{
 const s=fixture({tokenPostRules:[exactRule]}),b=await s.bearer(),c=await s.adapter.open(b);s.pages.push([challenge(url)]);await assert.rejects(s.adapter.poll(c.handle,b));assert.equal(s.providerCalls(),0);assert.equal(s.requests.filter(r=>r.url.startsWith('https://token.botframework.com')).length,0);
});
for(const rule of [{...exactRule,pathPrefix:'/api/sas/'},{...exactRule,pathExact:'/'},{...exactRule,pathExact:'/api/sas/../postToken'},{...exactRule,pathExact:'/api/sas/postToken?x=y'}])test('ambiguous or malformed exact-path configuration fails closed',()=>{assert.throws(()=>fixture({tokenPostRules:[rule]}));});
for(const mode of ['interactive','autonomous'])test(`Direct Line binds ${mode} conversation and posts an independently verified SSO token`,async()=>{
 const s=fixture(),bearer=await s.bearer({execution_mode:mode}),opened=await s.adapter.open(bearer);assert.equal(opened.state,'awaiting_oauth');assert.ok(!JSON.stringify(opened).includes('test-only-channel'));
 const generated=s.requests[0];assert.equal(generated.headers.Authorization,'Bearer test-only-directline-master');assert.match(generated.body.user.id,/^dl_[a-f0-9-]+$/);assert.ok(!JSON.stringify(generated.body).includes(identity.sub));
 await s.adapter.send(opened.handle,bearer,'Start the approved conversation');assert.equal(s.requests.at(-1)!.body.from.id,generated.body.user.id);assert.ok(!JSON.stringify(s.requests.at(-1)!.body).includes(bearer));
 s.pages.push([challenge(),message('Suppressed in challenge batch',{id:'message-before-sso'})]);const posted=await s.adapter.poll(opened.handle,bearer);assert.equal(posted.state,'token_posted');assert.deepEqual(posted.messages,[]);
 const post=s.requests.find(r=>r.url.startsWith('https://token.botframework.com'));assert.ok(post);assert.equal(post.headers.Authorization,undefined);assert.notEqual(post.body.token,bearer);assert.equal((await jwtVerify(post.body.token,pair.publicKey,{audience:ssoAudience})).payload.execution_mode,mode);
 s.pages.push([message()]);assert.equal((await s.adapter.poll(opened.handle,bearer)).messages[0].text,'Approved answer');assert.ok(s.requests.every(r=>!r.url.startsWith('wss:')));
 assert.ok(!JSON.stringify(s.events).includes(bearer));
});
test('no OAuth challenge means no SSO success or response release',async()=>{const s=fixture(),b=await s.bearer(),c=await s.adapter.open(b);s.pages.push([message()]);const r=await s.adapter.poll(c.handle,b);assert.equal(r.state,'awaiting_oauth');assert.deepEqual(r.messages,[]);assert.equal(s.providerCalls(),0);});
for(const patch of [{sub:'other-human'},{act:{iss:'https://agents.test',sub:'other-agent'}},{org_id:'other-org'},{delegation_id:'other-grant'},{execution_mode:'autonomous'}])test('another identity, organisation, grant or mode cannot reuse the conversation',async()=>{
 const s=fixture(),b=await s.bearer(),c=await s.adapter.open(b),count=s.requests.length;await assert.rejects(s.adapter.send(c.handle,await s.bearer(patch),'forged'));assert.equal(s.requests.length,count);await s.adapter.send(c.handle,b,'still belongs to owner');
});
test('tampered, expired and wrong-audience broker tokens never reach Direct Line',async()=>{
 const s=fixture();for(const b of ['unsigned',await s.bearer({aud:'other'}),await s.bearer({exp:1})])await assert.rejects(s.adapter.open(b));assert.equal(s.requests.length,0);
});
test('current policy is required before requests and after remote issuance',async()=>{
 const s=fixture(),b=await s.bearer(),c=await s.adapter.open(b);s.deny();const count=s.requests.length;await assert.rejects(s.adapter.send(c.handle,b,'blocked'));assert.equal(s.requests.length,count);
 let calls=0;const t=fixture({}, {authorise:async()=>{if(++calls>=3)throw Error('PRIVATE');}});await assert.rejects(t.adapter.open(await t.bearer()));assert.ok(t.requests.length<=1);
});
for(const url of ['http://token.botframework.com/approved/token-post/a?sig=x','https://evil.test/approved/token-post/a?sig=x','https://token.botframework.com/unapproved/a?sig=x','https://token.botframework.com/approved/token-post/a?sig=x#fragment','https://user:password@token.botframework.com/approved/token-post/a?sig=x','https://token.botframework.com/approved/token-post/a?sig=x&sig=y','https://token.botframework.com/approved/token-post/a','https://token.botframework.com/approved/token-post/%252e%252e/private?sig=x'])test('OAuth card cannot select an unapproved token destination',async()=>{
 const s=fixture(),b=await s.bearer(),c=await s.adapter.open(b);s.pages.push([challenge(url)]);await assert.rejects(s.adapter.poll(c.handle,b));assert.equal(s.providerCalls(),0);assert.ok(!s.requests.some(r=>r.url.startsWith('https://token.botframework.com')));
});
for(const patch of [{from:{id:'untrusted-bot'}},{conversation:{id:'other-conversation'}},{channelId:'other-channel'},{attachments:[{contentType:'application/vnd.microsoft.card.oauth',content:{}}]}])test('forged sender/conversation or malformed OAuth proof cannot post a token',async()=>{
 const s=fixture(),b=await s.bearer(),c=await s.adapter.open(b);s.pages.push([challenge(undefined,patch)]);await assert.rejects(s.adapter.poll(c.handle,b));assert.equal(s.providerCalls(),0);
});
test('duplicate OAuth delivery is idempotent; changed content with an existing activity ID rejects',async()=>{
 const s=fixture(),b=await s.bearer(),c=await s.adapter.open(b);s.pages.push([challenge()],[challenge()],[challenge(undefined,{text:'changed'})]);await s.adapter.poll(c.handle,b);await s.adapter.poll(c.handle,b);assert.equal(s.providerCalls(),1);await assert.rejects(s.adapter.poll(c.handle,b));
});
test('SAS challenge reuse with a new activity ID fails closed',async()=>{const s=fixture(),b=await s.bearer(),c=await s.adapter.open(b);s.pages.push([challenge()],[challenge(undefined,{id:'oauth-2'})]);await s.adapter.poll(c.handle,b);await assert.rejects(s.adapter.poll(c.handle,b));assert.equal(s.providerCalls(),1);});
for(const patch of [{aud:brokerAudience},{sub:'other-human'},{act:{iss:'https://agents.test',sub:'other-agent'}},{delegation_id:'other-grant'},{scope:'admin'},{exp:1}])test('unverified or substituted SSO token is never posted',async()=>{
 let now=Date.now();const s=fixture({}, {issueSsoToken:()=>token(now,{aud:ssoAudience,...patch})}),b=await s.bearer(),c=await s.adapter.open(b);s.pages.push([challenge()]);await assert.rejects(s.adapter.poll(c.handle,b));assert.ok(!s.requests.some(r=>r.url.startsWith('https://token.botframework.com')));
});
test('refresh uses only a conversation token and cannot refresh an expired channel',async()=>{
 const s=fixture(),b=await s.bearer(),c=await s.adapter.open(b);await s.adapter.refresh(c.handle,b);const request=s.requests.find(r=>r.url.endsWith('/tokens/refresh'));assert.ok(request);assert.equal(request.headers.Authorization,'Bearer test-only-started-1');s.advance(121000);await assert.rejects(s.adapter.refresh(c.handle,await s.bearer()));
});
test('SSO expiry requires a new conversation rather than silent unauthenticated continuation',async()=>{const s=fixture({}, {issueSsoToken:()=>token(Date.now(),{aud:ssoAudience,exp:Math.floor(Date.now()/1000)+10})}),b=await s.bearer(),c=await s.adapter.open(b);s.pages.push([challenge()]);await s.adapter.poll(c.handle,b);s.advance(11000);await assert.rejects(s.adapter.send(c.handle,await s.bearer(),'expired'));});
test('known credentials and compact JWTs are redacted from returned text and errors',async()=>{const s=fixture(),b=await s.bearer(),c=await s.adapter.open(b);s.pages.push([challenge()],[message(b+' test-only-started-1')]);await s.adapter.poll(c.handle,b);const r=await s.adapter.poll(c.handle,b);assert.ok(!JSON.stringify(r).includes(b));assert.ok(!JSON.stringify(r).includes('test-only-started-1'));});
test('closed sessions and caller-controlled identity fields cannot be used',async()=>{const s=fixture(),b=await s.bearer(),c=await s.adapter.open(b);await assert.rejects(s.adapter.send(c.handle,b,{text:'text',sub:'forged'} as never));await s.adapter.close(c.handle,b);await assert.rejects(s.adapter.poll(c.handle,b));});
for(const patch of [{endpoint:'http://directline.botframework.com/v3/directline'},{ssoAudience:brokerAudience},{tokenPostRules:[]},{trustedOrigins:[]},{timeoutMs:0}])test('unsafe or incomplete Direct Line configuration fails closed',()=>{assert.throws(()=>fixture(patch));});

test('a failed activity POST is attempted once and cannot be resumed as a successful session',async()=>{
 let s:ReturnType<typeof fixture>,posts=0;s=fixture({}, {fetch:async(url,init)=>{if(init?.method==='POST'&&String(url).endsWith('/activities')){posts++;throw Error('PRIVATE');}return s.transport(url,init);}});
 const b=await s.bearer(),c=await s.adapter.open(b);await assert.rejects(s.adapter.send(c.handle,b,'message'),e=>String(e)==='CopilotError: unavailable');assert.equal(posts,1);await assert.rejects(s.adapter.poll(c.handle,b));
});
test('read-only failures retry once, preserving the watermark',async()=>{
 let s:ReturnType<typeof fixture>,gets=0;s=fixture({}, {fetch:async(url,init)=>{if(init?.method==='GET'&&++gets===1)return new Response('PRIVATE',{status:503});return s.transport(url,init);}});
 const b=await s.bearer(),c=await s.adapter.open(b);await s.adapter.poll(c.handle,b);assert.equal(gets,2);await s.adapter.poll(c.handle,b);assert.ok(s.requests.at(-1)!.url.endsWith('?watermark=1'));
});
test('policy revocation during a GET retry prevents the retry request',async()=>{
 let s:ReturnType<typeof fixture>,gets=0;s=fixture({}, {fetch:async(url,init)=>{if(init?.method==='GET'){gets++;s.deny();return new Response('',{status:503});}return s.transport(url,init);}});
 const b=await s.bearer(),c=await s.adapter.open(b);await assert.rejects(s.adapter.poll(c.handle,b));assert.equal(gets,1);
});
for(const result of [()=>new Response('',{status:302,headers:{Location:'https://evil.test'}}),()=>new Response('PRIVATE',{status:403}),()=>Response.json({error:'PRIVATE'},{status:500})])test('a rejected/redirected secure token POST has no retry or interactive fallback',async()=>{
 let s:ReturnType<typeof fixture>,posts=0;s=fixture({}, {fetch:async(url,init)=>{if(String(url).startsWith('https://token.botframework.com')){posts++;return result();}return s.transport(url,init);}});
 const b=await s.bearer(),c=await s.adapter.open(b);s.pages.push([challenge()]);await assert.rejects(s.adapter.poll(c.handle,b),e=>!String(e).includes('PRIVATE'));assert.equal(posts,1);
});
for(const stage of ['secret','token','sso'])test('credential, channel and SSO timeouts are bounded with no POST replay',async()=>{
 let s:ReturnType<typeof fixture>,posts=0;const overrides=stage==='secret'?{secret:async()=>new Promise<string>(()=>{})}:stage==='sso'?{issueSsoToken:async()=>new Promise<string>(()=>{})}:{fetch:async()=>{posts++;return new Promise<Response>(()=>{});}};
 s=fixture({},overrides);const b=await s.bearer();if(stage==='sso'){const c=await s.adapter.open(b);s.pages.push([challenge()]);await assert.rejects(s.adapter.poll(c.handle,b));assert.equal(s.requests.filter(r=>r.url.startsWith('https://token.botframework.com')).length,0);}else await assert.rejects(s.adapter.open(b));if(stage==='token')assert.equal(posts,1);
});
test('revocation after a successful SSO POST prevents response release',async()=>{
 let s:ReturnType<typeof fixture>;s=fixture({}, {fetch:async(url,init)=>{const result=await s.transport(url,init);if(String(url).startsWith('https://token.botframework.com'))s.deny();return result;}});
 const b=await s.bearer(),c=await s.adapter.open(b);s.pages.push([challenge(),message()]);await assert.rejects(s.adapter.poll(c.handle,b),e=>String(e)==='CopilotError: policy_denied');await assert.rejects(s.adapter.poll(c.handle,b));
});
test('channel expiry during SSO issuance prevents token delivery',async()=>{
 let s:ReturnType<typeof fixture>;s=fixture({}, {issueSsoToken:async()=>{s.advance(121000);return token(s.now(),{aud:ssoAudience});}});
 const b=await s.bearer(),c=await s.adapter.open(b);s.pages.push([challenge()]);await assert.rejects(s.adapter.poll(c.handle,b));assert.ok(!s.requests.some(r=>r.url.startsWith('https://token.botframework.com')));
});
test('refresh cannot change conversation ID or extend the fixed session lifetime',async()=>{
 let s:ReturnType<typeof fixture>;s=fixture({}, {fetch:async(url,init)=>String(url).endsWith('/tokens/refresh')?Response.json({conversationId:'other-conversation',token:'test-only-token',expires_in:120}):s.transport(url,init)});
 const b=await s.bearer(),c=await s.adapter.open(b);await assert.rejects(s.adapter.refresh(c.handle,b));
 const t=fixture({sessionLifetimeSeconds:30}),proof=await t.bearer(),opened=await t.adapter.open(proof);await t.adapter.refresh(opened.handle,proof);t.advance(31000);await assert.rejects(t.adapter.send(opened.handle,await t.bearer(),'outside session'));
});
test('concurrent opens reserve capacity before secret retrieval',async()=>{
 let enter:()=>void,release:()=>void;const entered=new Promise<void>(done=>{enter=done;}),wait=new Promise<void>(done=>{release=done;});
 const s=fixture({maxSessions:1},{secret:async()=>{enter();await wait;return'test-only-master';}}),b=await s.bearer(),first=s.adapter.open(b);await entered;await assert.rejects(s.adapter.open(b),e=>String(e)==='CopilotError: capacity');release();const c=await first;await s.adapter.close(c.handle,b);
});
test('concurrent session operations do not race refresh and polling',async()=>{
 let enter:()=>void,release:()=>void,s:ReturnType<typeof fixture>;const entered=new Promise<void>(done=>{enter=done;}),wait=new Promise<void>(done=>{release=done;});
 s=fixture({}, {fetch:async(url,init)=>{if(init?.method==='GET'){enter();await wait;}return s.transport(url,init);}});const b=await s.bearer(),c=await s.adapter.open(b),first=s.adapter.poll(c.handle,b);await entered;await assert.rejects(s.adapter.refresh(c.handle,b),e=>String(e)==='CopilotError: session_busy');release();await first;await s.adapter.close(c.handle,b);
});
test('a remote service cannot reuse an existing conversation ID for a new owner',async()=>{
 let s:ReturnType<typeof fixture>,generated=0;s=fixture({}, {fetch:async(url,init)=>{const result=await s.transport(url,init);if(String(url).endsWith('/tokens/generate')&&++generated>1)return Response.json({conversationId:'conversation-1',token:'test-only-token',expires_in:120});return result;}});
 const b=await s.bearer(),c=await s.adapter.open(b);await assert.rejects(s.adapter.open(await s.bearer({sub:'other'})));await s.adapter.send(c.handle,b,'owner still active');
});
test('null watermarks preserve the prior cursor and duplicate messages are not released twice',async()=>{
 let s:ReturnType<typeof fixture>,gets=0;s=fixture({}, {fetch:async(url,init)=>{if(init?.method==='GET'&&++gets===3){await s.transport(url,init);return Response.json({activities:[message()],watermark:null});}return s.transport(url,init);}});
 const b=await s.bearer(),c=await s.adapter.open(b);s.pages.push([challenge()],[message()]);await s.adapter.poll(c.handle,b);assert.equal((await s.adapter.poll(c.handle,b)).messages.length,1);assert.equal((await s.adapter.poll(c.handle,b)).messages.length,0);await s.adapter.poll(c.handle,b);assert.ok(s.requests.at(-1)!.url.endsWith('?watermark=2'));
});
for(const response of [()=>new Response('not-json',{headers:{'Content-Type':'application/json'}}),()=>new Response('x'.repeat(262145),{headers:{'Content-Type':'application/json'}}),()=>Response.json({activities:'wrong-type'}),()=>Response.json({activities:[],watermark:'x'.repeat(513)})])test('malformed or oversized responses never release data',async()=>{
 let s:ReturnType<typeof fixture>;s=fixture({}, {fetch:async(url,init)=>init?.method==='GET'?response():s.transport(url,init)});const b=await s.bearer(),c=await s.adapter.open(b);await assert.rejects(s.adapter.poll(c.handle,b));
});
test('an entire activity batch is validated before any token is posted',async()=>{const s=fixture(),b=await s.bearer(),c=await s.adapter.open(b);s.pages.push([challenge(),message('forged',{from:{id:'other'}})]);await assert.rejects(s.adapter.poll(c.handle,b));assert.equal(s.providerCalls(),0);});
test('SAS query ordering cannot bypass replay detection',async()=>{const s=fixture(),b=await s.bearer(),c=await s.adapter.open(b);s.pages.push([challenge('https://token.botframework.com/approved/token-post/a?sig=test-only-signature&sv=1')],[challenge('https://token.botframework.com/approved/token-post/a?sv=1&sig=test-only-signature',{id:'other'})]);await s.adapter.poll(c.handle,b);await assert.rejects(s.adapter.poll(c.handle,b));assert.equal(s.providerCalls(),1);});
test('closed/end-of-conversation activity cannot resume a protected conversation',async()=>{const s=fixture(),b=await s.bearer(),c=await s.adapter.open(b);s.pages.push([message('',{type:'endOfConversation'})]);assert.equal((await s.adapter.poll(c.handle,b)).state,'closed');await assert.rejects(s.adapter.send(c.handle,b,'resume'));});
test('master credentials and endpoint fields cannot be smuggled into config',()=>{for(const patch of [{secret:'test-only-secret'},{tokenPostRules:[{...configuration.tokenPostRules[0],secret:'bad'}]},{endpoint:'https://directline.botframework.com/v3/directline?override=true'}])assert.throws(()=>fixture(patch));});
test('the SSO issuer receives canonical identities and configured audience/scope, not extra token fields',async()=>{
 let s:ReturnType<typeof fixture>;s=fixture({}, {issueSsoToken:async request=>{assert.equal(request.audience,ssoAudience);assert.equal(request.scope,'copilot.invoke');assert.equal('resource'in request.claims,false);assert.equal('prompt'in request.claims,false);return token(s.now(),{aud:ssoAudience});}});
 const b=await s.bearer({resource:'https://graph.microsoft.com/arbitrary',prompt:'escalate'}),c=await s.adapter.open(b);s.pages.push([challenge()]);assert.equal((await s.adapter.poll(c.handle,b)).state,'token_posted');
});
test('plain multiline chat is permitted without allowing identity control characters',async()=>{const s=fixture(),b=await s.bearer(),c=await s.adapter.open(b);await s.adapter.send(c.handle,b,'Please explain:\nfirst item\nsecond item');assert.ok(s.requests.at(-1)!.body.text.includes('\n'));await assert.rejects(s.adapter.send(c.handle,b,'bad\u0000message'));});
for(const stage of ['broker-verifier','policy','sso-verifier'])test(`external identity/policy dependencies have a deadline: ${stage}`,{timeout:1500},async()=>{
 const pending=async()=>new Promise<DelegatedClaims>(()=>{}),dependencies=stage==='broker-verifier'?{verifier:{verify:pending}}:stage==='policy'?{authorise:async()=>new Promise<void>(()=>{})}:{ssoVerifier:{verify:pending}};
 const s=fixture({},dependencies),b=await s.bearer();if(stage==='sso-verifier'){const c=await s.adapter.open(b);s.pages.push([challenge()]);await assert.rejects(s.adapter.poll(c.handle,b));}else await assert.rejects(s.adapter.open(b));assert.ok(!s.requests.some(r=>r.url.startsWith('https://token.botframework.com')));
});
