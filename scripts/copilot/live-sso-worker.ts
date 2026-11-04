// Approved synthetic lab diagnostic. Never expose tokens or follow sign-in links.
import {readFileSync,writeFileSync} from 'node:fs';import {resolve,sep} from 'node:path';import {randomBytes,createHash} from 'node:crypto';
import {importPKCS8,decodeJwt} from 'jose';
import {DirectLineAdapter} from '../../src/adapters/direct-line.ts';
import {JwksTokenVerifier,PingFederateExchange} from '../../src/adapters/pingfederate.ts';
import {PolicyClient} from '../../src/policy/client.ts';import {PolicyStore} from '../../src/policy/store.ts';
import {OidcClient} from '../../src/identity/oidc.ts';
import {assertChannelBinding,assertBoundCredential} from '../../src/copilot/channel-binding.ts';
import {startConsent} from '../pf/run-consent.mjs';import {localToolAuthority} from '../pf/consent-tool-exchange.ts';
import {issueConsentedUpstream} from '../pf/consent-exchange.ts';import {toolTrust} from '../pf/copilot-tool-profile.mjs';
import {LocalBrowser,forms} from '../../tests/live/local-browser.mjs';import {reserveConversation,reserveTimingFollowup,reserveOperatorRetry,reserveProviderCapture,reserveRetainedProviderCapture,reservePublishedProviderCapture,reserveLongerProviderCapture,reserveHourProviderCapture} from './live-budget.mjs';
import {tokenPostErrorMetadata} from './token-post-error.mjs';
import {sasTiming} from './sas-timing.mjs';
import {providerSso,providerVerifier,obtainProviderLogin,bindLabProviderIdentity} from './provider-login.ts';
import {curlTokenPost,redactCapture} from './curl-capture.mjs';
import {createVaultCaptureWriter,executeRetainedPost,captureVaultPath} from './vault-capture.mjs';
import {vault} from '../vault/common.mjs';
import {custody} from '../vault/tool-custody.mjs';
import {revokeOwnedCanaryGrant} from '../vault/enrolled-canary-checks.mjs';
import {revokeOwnedToolConsent} from '../pf/revoke-owned-tool-consent.mjs';
import {root,local,load,read} from '../pf/common.mjs';import {profile} from '../pf/config.mjs';import {capability} from '../pf/policy-setup.ts';
const directory=resolve(root,'.local/copilot'),run=resolve(process.env.COPILOT_LIVE_SSO_RUN_DIR??'');
if(!run.startsWith(resolve(local,'copilot-live-sso')+sep))throw Error('Explicit isolated run directory required');
const results:any[]=[],transportMetadata:any[]=[];let stage='configuration',portal:any;
const check=(value:unknown)=>{if(!value)throw Error('Live check failed');};
const json=(name:string)=>JSON.parse(readFileSync(resolve(directory,name),'utf8'));
const hourMode=process.env.COPILOT_LIVE_SSO_FOLLOWUP==='hour-vault-capture-1',longerMode=process.env.COPILOT_LIVE_SSO_FOLLOWUP==='longer-vault-capture-1',publishedMode=process.env.COPILOT_LIVE_SSO_FOLLOWUP==='published-vault-capture-1',retainedMode=hourMode||longerMode||publishedMode||process.env.COPILOT_LIVE_SSO_FOLLOWUP==='provider-vault-capture-1',captureMode=retainedMode||process.env.COPILOT_LIVE_SSO_FOLLOWUP==='provider-capture-1',captureDirectory=process.env.COPILOT_PROVIDER_CAPTURE_DIR;
if(captureMode&&(!captureDirectory||!captureDirectory.startsWith(resolve(custody,'provider-capture-'))))throw Error('Protected provider capture directory required');
const retainedId=retainedMode?captureDirectory!.slice(resolve(custody,'provider-capture-').length):undefined;
if(retainedMode&&process.env.COPILOT_CAPTURE_WRITER_FILE!==resolve(captureDirectory!,'vault-writer-token'))throw Error('Protected writer credential required');
const privateWriter=retainedMode?createVaultCaptureWriter(retainedId,()=>readFileSync(process.env.COPILOT_CAPTURE_WRITER_FILE!,'utf8').trim(),vault):undefined;
const cardTimes=new Map<string,{wall:number;monotonic:number}>(),secretValues=new Set<string>();
const key=(url:string)=>createHash('sha256').update(url).digest('hex');
async function consentGrant(){
 const b=new LocalBrowser(portal.origin),home=await b.request(portal.origin+'/');
 const login=await b.submit(forms(home.html).find(f=>f.action==='/login'));
 const approval=await b.submit(forms(login.html).find(f=>'pf.pass'in f.fields),{'pf.username':profile.human,'pf.pass':read('login-password'),'pf.ok':'clicked'});
 const review=await b.submit(forms(approval.html).find(f=>'pf.oauth.authz.consent'in f.fields),{'pf.oauth.authz.consent':'allow'});
 const result=await b.submit(forms(review.html).find(f=>f.action==='/approve'),{duration:'3600',...(captureMode?{}:{autonomous:'on'})});
 const revoke=forms(result.html).find(f=>f.action==='/revoke');check(revoke);
 return{id:revoke.fields.grantId,revoke:async()=>{
  const state=()=>{const store=new PolicyStore(process.env.POLICY_DATABASE!,[capability]);try{return store.grant(revoke.fields.grantId)?.state;}finally{store.close();}};
  await revokeOwnedCanaryGrant(state,async()=>{try{await b.submit(revoke,{},{noRedirect:true});}catch{}if(state()!=='revoked')await revokeOwnedToolConsent(portal.origin,revoke.fields.grantId);});
 }};
}
async function loginProof(){
 const client=new OidcClient({...load('oidc-config.json'),redirectUri:portal.origin+'/callback',clientKey:await importPKCS8(read('consent-oidc.private.pem'),'RS256')});
 const nonce=randomBytes(24).toString('hex'),verifier=randomBytes(32).toString('base64url'),b=new LocalBrowser(portal.origin);
 const login=await b.request(await client.start(randomBytes(24).toString('hex'),nonce,verifier));
 const approval=await b.submit(forms(login.html).find(f=>'pf.pass'in f.fields),{'pf.username':profile.human,'pf.pass':read('login-password'),'pf.ok':'clicked'});
 await b.submit(forms(approval.html).find(f=>'pf.oauth.authz.consent'in f.fields),{'pf.oauth.authz.consent':'allow'},{captureCallback:true});
 const result=await client.redeem(new URL(b.callback).searchParams.get('code')!,verifier,nonce);return{idToken:result.idToken,nonce};
}
try{
 const settings=json('channel-settings.json'),binding=json('channel-credential-binding.json'),contract=json('current-channel-contract.json');
 assertChannelBinding(settings,binding);assertChannelBinding(contract.target,binding);
 check(['observed-not-token-posted','observed-token-post-rejected'].includes(contract.status)&&contract.endpoint==='https://directline.botframework.com/v3/directline');
 check(contract.tokenPostRule.origin==='https://token.botframework.com'&&contract.tokenPostRule.pathExact==='/api/sas/postToken'&&JSON.stringify(contract.tokenPostRule.requiredQueryParameters)===JSON.stringify(['expiry','hmac','id','state']));
 portal=await startConsent();const authority=await localToolAuthority(process.env.POLICY_API_ORIGIN!);
 const broker=load('consent-exchange-config.json');
 const policy=new PolicyClient({origin:process.env.POLICY_API_ORIGIN!,clientId:'policy-gateway',keyId:'copilot-policy-gateway',key:await importPKCS8(read('policy-gateway.private.pem'),'RS256'),capability,timeoutMs:5000});
 const exchange=new PingFederateExchange(broker,{clientKey:await importPKCS8(read('consent-gateway-2.private.pem'),'RS256'),authorise:policy.authorise});
 const reserved=json('live-sso-budget.json').reserved;
 const retry=process.env.COPILOT_LIVE_SSO_FOLLOWUP==='operator-retry-1';
 const followup=captureMode||retry||process.env.COPILOT_LIVE_SSO_FOLLOWUP==='interactive-timing';
 const planned=followup?['interactive'] as const:(['interactive','autonomous'] as const).filter(m=>!reserved.includes(m));
 if(planned.some(mode=>mode!=='interactive'))throw Error('Autonomous configured-provider SSO is unverified; no conversation authorized');
 for(const mode of planned){
  stage=mode+':consent';const grant=await consentGrant();let revoked=false,ssoToken='',toolToken='',posts=0,operations=0,brokerToken='';let adapter:DirectLineAdapter|undefined,handle:string|undefined;
  const evidence={mode,tokenPostCount:0,tokenPostAccepted:false,copilotRuntimeSignedIn:false,localPolicyToolVerified:false,revokedTokenDenied:false,revokedChannelDenied:false,copilotToolAcceptanceVerified:false};results.push(evidence);
  const tool=authority.tool(async claims=>{operations++;check(claims.sub===profile.human&&claims.act.sub===profile.agent&&claims.act.iss===profile.agentIssuer&&claims.org_id===profile.org&&claims.delegation_id===grant.id&&claims.execution_mode===mode);return{approved:true};});
  try{
   const login=mode==='interactive'?await loginProof():undefined;
   stage=mode+':broker-issuance';const issued=await exchange.exchange(await issueConsentedUpstream(grant.id,mode,login));brokerToken=issued.accessToken;
   stage=mode+':configured-provider-login';const ssoVerifier=providerVerifier();const provider=await obtainProviderLogin(undefined,ssoVerifier);ssoToken=provider.token;if(hourMode)check(providerSso.maxLifetimeSeconds===3600&&provider.claims.exp-provider.claims.iat===3600);if(longerMode)check(providerSso.maxLifetimeSeconds===300&&provider.claims.exp-provider.claims.iat===300);bindLabProviderIdentity(provider.claims,issued.claims);for(const value of [ssoToken,brokerToken,login?.idToken,grant.id,profile.human,profile.agent])if(value)secretValues.add(value);
   const delegatedTool=await authority.issue(grant.id,mode,login);toolToken=delegatedTool.accessToken;secretValues.add(toolToken);check((await tool.execute(toolToken)).approved===true&&operations===1);evidence.localPolicyToolVerified=true;
   adapter=new DirectLineAdapter({endpoint:contract.endpoint,brokerAudience:broker.downstream.audience,ssoAudience:providerSso.audience,providerSso,scope:capability.scope,botId:contract.botId,
    // Backend-only lab: no browser frontend is deployed at this reserved origin.
    trustedOrigins:['https://server-only.federated-copilot.invalid'],tokenPostRules:[contract.tokenPostRule],timeoutMs:10000,maxSessions:1,sessionLifetimeSeconds:120,maxActivities:100},
    {verifier:new JwksTokenVerifier([broker.downstream],capability.scope,5000),providerVerifier:{verify:async token=>{try{return await ssoVerifier.verify(token);}catch{transportMetadata.push({mode,operation:'provider_verification_rejected',reason:'verification_unavailable_or_invalid'});throw Error('Provider verification rejected');}}},bindProviderIdentity:async(p,b)=>{try{bindLabProviderIdentity(p,b);}catch{transportMetadata.push({mode,operation:'provider_binding_rejected'});throw Error('Provider binding rejected');}},authorise:policy.authorise,
     secret:async()=>{const value=readFileSync(resolve(directory,'direct-line-secret.txt'),'utf8').trim();assertBoundCredential(binding,value);secretValues.add(value);return value;},
     issueSsoToken:async request=>{check(request.audience===providerSso.audience&&request.scope===providerSso.scope);return ssoToken;},
     fetch:async(url,init)=>{const target=new URL(String(url)),post=target.origin==='https://token.botframework.com';if(post){check(target.pathname==='/api/sas/postToken');check(!new Headers(init?.headers).has('authorization'));check(posts===0);const timing=sasTiming(target.searchParams.get('expiry'),Date.now(),null);if(timing.hostRemainingSeconds!==undefined&&timing.hostRemainingSeconds<=0){transportMetadata.push({mode,operation:'token_post_blocked_expiry',sasTiming:timing});throw Error('Expired challenge');}posts++;}
      let requestAt=Date.now(),postMonotonic=performance.now();let response:Response;
      if(post&&captureMode){
       check(JSON.parse(String(init?.body)).token===ssoToken);const card=cardTimes.get(key(String(url)));check(card);
       const actual=privateWriter?await executeRetainedPost(privateWriter,String(url),init,()=>curlTokenPost(String(url),init),card):curlTokenPost(String(url),init);response=actual.response;
       if(privateWriter){requestAt=actual.startedAt;postMonotonic=actual.monotonic;}
       const captured=redactCapture({url:String(url),requestHeaders:init?.headers,response:actual.parsed,secrets:[...secretValues],tokenProfile:{issuer:provider.claims.iss,audience:provider.claims.aud,scope:provider.claims.scope,signatureAndBindingVerified:true,expiresAt:new Date(provider.claims.exp*1000).toISOString()},timing:{cardObservedAt:new Date(card!.wall).toISOString(),postStartedAt:new Date(requestAt).toISOString(),responseReceivedAt:new Date(privateWriter?actual.receivedAt:Date.now()).toISOString(),cardToPostMilliseconds:Math.round((postMonotonic-card!.monotonic)*1000)/1000,measurement:'monotonic elapsed from parsed OAuth-card observation to curl invocation'}});
       if(retainedMode){captured.rawCredentialsRetained=true;captured.rawCredentialsInThisFile=false;captured.rawCredentialsStorage='operator-only-vault';}
       writeFileSync(resolve(captureDirectory!,'request-response.json'),JSON.stringify(captured,null,2),{mode:0o600,flag:'wx'});
       if(retainedMode)writeFileSync(resolve(captureDirectory!,'private-vault-reference.json'),JSON.stringify({vaultPath:captureVaultPath(retainedId).slice(1).replace('/data/','/'),version:2,originalValuesRetained:true,plaintextFilesCreated:false},null,2),{mode:0o600,flag:'wx'});
       writeFileSync(resolve(captureDirectory!,'request-redacted.curl.txt'),'# Real request used curl with signed URL/token on stdin; secrets below are intentionally omitted.\n# Do not execute as another test.\ncurl.exe --disable --request POST "<SIGNED_URL_REDACTED>" --header "accept: application/json" --header "content-type: application/json" --data-raw "{\\"token\\":\\"[REDACTED_CONFIGURED_PROVIDER_USER_TOKEN]\\"}"\n',{mode:0o600,flag:'wx'});
      }else response=await fetch(url,init);
      if(post){evidence.tokenPostCount=posts;evidence.tokenPostAccepted=response.ok;}const entry:any={mode,operation:post?'token_post':init?.method==='GET'?'activity_poll':'channel_post',status:response.status};
      if(post){entry.sasTiming=sasTiming(target.searchParams.get('expiry'),requestAt,response.headers.get('date'));const exp=decodeJwt(ssoToken).exp;if(typeof exp==='number')entry.accessTokenRemainingSeconds=Math.floor(exp-requestAt/1000);}
      if(post&&!response.ok){let text='';const reader=response.clone().body?.getReader();try{if(reader)for(;;){const part=await reader.read();if(part.done)break;text+=Buffer.from(part.value).toString('utf8');if(text.length>16384){await reader.cancel();text='';break;}}entry.error=tokenPostErrorMetadata(text);const id=response.headers.get('x-ms-request-id');if(id&&/^[a-f0-9-]{16,64}$/i.test(id))entry.requestId=id;}finally{reader?.releaseLock();}}
      if(init?.method==='GET'&&response.ok){try{const body=await response.clone().json();entry.activities=(body.activities??[]).map((a:any)=>({type:['message','event','trace','typing'].includes(a.type)?a.type:'other',senderIsPinnedBot:a.from?.id===contract.botId,senderRole:['bot','user'].includes(a.from?.role)?a.from.role:'unspecified',channelIsDirectLine:a.channelId==='directline',hasConversationId:typeof a.conversation?.id==='string'}));entry.challengeTiming=(body.activities??[]).flatMap((a:any)=>(a.attachments??[]).filter((v:any)=>v?.contentType==='application/vnd.microsoft.card.oauth').map((v:any)=>{try{const raw=v.content.tokenPostResource.sasUrl,sas=new URL(raw);if(sas.origin!=='https://token.botframework.com'||sas.pathname!=='/api/sas/postToken')return{format:'unapproved'};if(!cardTimes.has(key(raw))){check(cardTimes.size<8);cardTimes.set(key(raw),{wall:Date.now(),monotonic:performance.now()});}return sasTiming(sas.searchParams.get('expiry'),Date.now(),response.headers.get('date'));}catch{return{format:'unrecognized'};}}));}catch{}}
      transportMetadata.push(entry);return response;},
    });
   stage=mode+':conversation';const budget=hourMode?reserveHourProviderCapture([json('live-sso-budget.json'),json('live-sso-timing-budget.json'),json('live-sso-operator-retry-1-budget.json')],json('live-sso-provider-capture-1-budget.json'),json('live-sso-provider-vault-capture-1-budget.json'),json('live-sso-published-vault-capture-1-budget.json'),json('live-sso-longer-vault-capture-1-budget.json'),json('live-sso-hour-vault-capture-1-budget.json')):longerMode?reserveLongerProviderCapture([json('live-sso-budget.json'),json('live-sso-timing-budget.json'),json('live-sso-operator-retry-1-budget.json')],json('live-sso-provider-capture-1-budget.json'),json('live-sso-provider-vault-capture-1-budget.json'),json('live-sso-published-vault-capture-1-budget.json'),json('live-sso-longer-vault-capture-1-budget.json')):publishedMode?reservePublishedProviderCapture([json('live-sso-budget.json'),json('live-sso-timing-budget.json'),json('live-sso-operator-retry-1-budget.json')],json('live-sso-provider-capture-1-budget.json'),json('live-sso-provider-vault-capture-1-budget.json'),json('live-sso-published-vault-capture-1-budget.json')):retainedMode?reserveRetainedProviderCapture([json('live-sso-budget.json'),json('live-sso-timing-budget.json'),json('live-sso-operator-retry-1-budget.json')],json('live-sso-provider-capture-1-budget.json'),json('live-sso-provider-vault-capture-1-budget.json')):captureMode?reserveProviderCapture([json('live-sso-budget.json'),json('live-sso-timing-budget.json'),json('live-sso-operator-retry-1-budget.json')],json('live-sso-provider-capture-1-budget.json')):retry?reserveOperatorRetry(json('live-sso-budget.json'),json('live-sso-timing-budget.json'),json('live-sso-operator-retry-1-budget.json')):followup?reserveTimingFollowup(json('live-sso-budget.json'),json('live-sso-timing-budget.json')):reserveConversation(json('live-sso-budget.json'),mode);writeFileSync(resolve(directory,hourMode?'live-sso-hour-vault-capture-1-budget.json':longerMode?'live-sso-longer-vault-capture-1-budget.json':publishedMode?'live-sso-published-vault-capture-1-budget.json':retainedMode?'live-sso-provider-vault-capture-1-budget.json':captureMode?'live-sso-provider-capture-1-budget.json':retry?'live-sso-operator-retry-1-budget.json':followup?'live-sso-timing-budget.json':'live-sso-budget.json'),JSON.stringify(budget),{mode:0o600});
   const opened=await adapter.open(issued.accessToken);handle=opened.handle;await adapter.send(opened.handle,issued.accessToken,'/federation-status');
   let signedIn=false;
   for(let attempt=0;attempt<25&&!signedIn;attempt++){
    stage=mode+':poll';const page=await adapter.poll(opened.handle,issued.accessToken);
    signedIn=page.messages.some(m=>m.text==='Authentication status: signed in. Copilot reports User.IsLoggedIn=true. Delegated tool access has not been verified.');
    if(!signedIn)await new Promise(done=>setTimeout(done,1000));
   }
   evidence.copilotRuntimeSignedIn=signedIn;check(posts===1&&ssoToken&&signedIn);
  }finally{
   if(!revoked){await grant.revoke();revoked=true;}
   if(toolToken){try{await tool.execute(toolToken);}catch(error){evidence.revokedTokenDenied=(error as any)?.code==='policy_denied';}check(evidence.revokedTokenDenied&&operations===1);}
   if(adapter&&handle&&brokerToken){try{await adapter.poll(handle,brokerToken);}catch(error){evidence.revokedChannelDenied=(error as any)?.code==='policy_denied';}check(evidence.revokedChannelDenied);}
  }
 }
 writeFileSync(resolve(run,'result.json'),JSON.stringify({status:'completed',results,transportMetadata,copilotToolAcceptanceVerified:false},null,2),{mode:0o600});
 console.log(JSON.stringify({status:'completed',results,copilotToolAcceptanceVerified:false}));
}catch(error){
 const code=error instanceof Error&&['CopilotError','ExchangeError','PolicyError'].includes(error.name)?error.message:'verification_failed';
 const result={status:'failed',stage,code,results,transportMetadata,copilotToolAcceptanceVerified:false};
 writeFileSync(resolve(run,'result.json'),JSON.stringify(result,null,2),{mode:0o600});console.error(JSON.stringify({status:'failed',stage,code,copilotToolAcceptanceVerified:false}));process.exitCode=1;
}finally{if(portal)await portal.stop();}
