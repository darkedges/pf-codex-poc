// Diagnostic transport probe only. This does not compose or bypass the production PF/PDP adapter.
import { randomUUID,createHash } from 'node:crypto';
const origins=new Set(['https://directline.botframework.com','https://europe.directline.botframework.com','https://india.directline.botframework.com','https://australia.directline.botframework.com']);
type Transport=(url:string|URL|Request,init?:RequestInit)=>Promise<Response>;
class ProbeError extends Error{constructor(code:string){super(code);this.name='ChannelProbeError';}}
const object=(value:unknown):value is Record<string,any>=>!!value&&typeof value==='object'&&!Array.isArray(value);
const identifier=(value:unknown):value is string=>typeof value==='string'&&/^[A-Za-z0-9_.:|-]{1,256}$/.test(value);
function approvedEndpoint(value:string){
 const url=new URL(value);
 if(!origins.has(url.origin)||url.username||url.password||url.port||url.search||url.hash||url.pathname!=='/v3/directline'||value.includes('\\'))throw new ProbeError('unapproved_endpoint');
 return url.href;
}
async function request(transport:Transport,url:string,init:RequestInit={}){
 const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),10000);
 try{
  const response=await transport(url,{...init,redirect:'error',signal:controller.signal});
  let data:unknown;const reader=response.body?.getReader();const chunks:Uint8Array[]=[];let size=0;
  if(reader){try{for(;;){const part=await reader.read();if(part.done)break;size+=part.value.byteLength;if(size>262144){await reader.cancel();throw new ProbeError('response_invalid');}chunks.push(part.value);}}finally{reader.releaseLock();}}
  if(size){try{data=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{if(response.ok)throw new ProbeError('response_invalid');}}
  return{status:response.status,ok:response.ok,data};
 }catch(error){throw error instanceof ProbeError?error:new ProbeError('transport_failed');}
 finally{clearTimeout(timer);}
}
export function classifyChannelEntrypoint(config:{environmentId:string;schemaName:string;agentEndpoint:string}):'authenticated_runtime'|'directline_token'{
 try{
  if(!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(config.environmentId)||!/^[A-Za-z0-9_]{1,200}$/.test(config.schemaName))throw Error();
  const compact=config.environmentId.replaceAll('-','').toLowerCase(),endpoint=new URL(config.agentEndpoint);
  const expectedHost=`${compact.slice(0,-2)}.${compact.slice(-2)}.environment.api.powerplatform.com`;
  const validPath=[`/powervirtualagents/botsbyschema/${config.schemaName}/directline/token`,`/copilotstudio/agenticruntime/3p/dataverse-backed/authenticated/bots/${config.schemaName}/conversations`,`/copilotstudio/dataverse-backed/authenticated/bots/${config.schemaName}/conversations`].includes(endpoint.pathname);
  if(endpoint.protocol!=='https:'||endpoint.hostname!==expectedHost||endpoint.port||endpoint.username||endpoint.password||endpoint.hash||!validPath||[...endpoint.searchParams.keys()].length!==1||endpoint.searchParams.get('api-version')!=='2022-03-01-preview'||config.agentEndpoint.includes('\\'))throw Error();
  return endpoint.pathname.startsWith('/copilotstudio/')?'authenticated_runtime':'directline_token';
 }catch{throw new ProbeError('discovery_failed');}
}
export async function discoverChannel(config:{environmentId:string;schemaName:string;agentEndpoint:string},transport:Transport=fetch){
 try{
  classifyChannelEntrypoint(config);
  const endpoint=new URL(config.agentEndpoint);
  const settings=new URL('/powervirtualagents/regionalchannelsettings?api-version=2022-03-01-preview',endpoint);
  const result=await request(transport,settings.href);
  if(!result.ok||!object(result.data)||!object(result.data.channelUrlsById)||typeof result.data.channelUrlsById.directline!=='string')throw Error();
  const regional=new URL(result.data.channelUrlsById.directline);
  if(regional.pathname!=='/'||regional.search||regional.hash||regional.username||regional.password)throw Error();
  return approvedEndpoint(new URL('v3/directline',regional).href);
 }catch(error){throw error instanceof ProbeError?error:new ProbeError('discovery_failed');}
}
export async function probeChannel(endpoint:string,readSecret:()=>Promise<string>,transport:Transport=fetch,pause:()=>Promise<void>=()=>new Promise(resolve=>setTimeout(resolve,1000))){
 try{
  const base=approvedEndpoint(endpoint),call=(suffix:string,method:string,credential?:string,body?:unknown)=>request(transport,base+suffix,{method,headers:{...(credential?{authorization:'Bearer '+credential}:{}),...(body?{'content-type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});
  // No POST retries, including when the result may be ambiguous.
  const anonymous=await call('/tokens/generate','POST');
  if(![401,403].includes(anonymous.status))throw new ProbeError('anonymous_access_not_rejected');
  const invalid=await call('/tokens/generate','POST','invalid_probe_'+randomUUID());
  if(![401,403].includes(invalid.status))throw new ProbeError('invalid_secret_not_rejected');
  let secret:string;try{secret=await readSecret();}catch{throw new ProbeError('credential_unavailable');}
  if(typeof secret!=='string'||!secret.trim()||secret.length>16000||/[\r\n]/.test(secret))throw new ProbeError('credential_invalid');
  const userId='dl_'+randomUUID();
  const generated=await call('/tokens/generate','POST',secret.trim(),{user:{id:userId}});secret='';
  if(!generated.ok||!object(generated.data)||!identifier(generated.data.conversationId)||typeof generated.data.token!=='string'||!generated.data.token||!Number.isInteger(generated.data.expires_in)||generated.data.expires_in<1||generated.data.expires_in>86400)throw new ProbeError('token_generation_failed');
  const conversationId=generated.data.conversationId;let token=generated.data.token;
  const started=await call('/conversations','POST',token);
  if(!started.ok||!object(started.data)||started.data.conversationId!==conversationId)throw new ProbeError('conversation_start_failed');
  if(started.data.token!==undefined){if(typeof started.data.token!=='string'||!started.data.token)throw new ProbeError('response_invalid');token=started.data.token;}
  const submitted=await call(`/conversations/${encodeURIComponent(conversationId)}/activities`,'POST',token,{type:'event',name:'startConversation',from:{id:userId},locale:'en-AU'});
  if(!submitted.ok||!object(submitted.data)||!identifier(submitted.data.id))throw new ProbeError('greeting_failed');
  const diagnostic=await call(`/conversations/${encodeURIComponent(conversationId)}/activities`,'POST',token,{type:'message',text:'/federation-status',from:{id:userId},locale:'en-AU'});
  if(!diagnostic.ok||!object(diagnostic.data)||!identifier(diagnostic.data.id))throw new ProbeError('diagnostic_message_failed');
  const botIds=new Set<string>(),activityTypes=new Set<string>(),seen=new Map<string,string>(),cards:{origin:string;staticPath?:string;queryKeys:string[]}[]=[];let botActivities=0,oauthCardCount=0,watermark:string|undefined;
  const deadline=Date.now()+45000;
  for(let attempt=0;attempt<30&&Date.now()<deadline;attempt++){
   const polled=await call(`/conversations/${encodeURIComponent(conversationId)}/activities`+(watermark===undefined?'':'?watermark='+encodeURIComponent(watermark)),'GET',token);
   if(!polled.ok||!object(polled.data)||!Array.isArray(polled.data.activities)||polled.data.activities.length>100)throw new ProbeError('activities_failed');
   if(polled.data.watermark!==undefined&&polled.data.watermark!==null){if(typeof polled.data.watermark!=='string'||polled.data.watermark.length>1024)throw new ProbeError('activities_failed');watermark=polled.data.watermark;}
   for(const activity of polled.data.activities){
    if(!object(activity)||!identifier(activity.id)||!object(activity.from))throw new ProbeError('activity_invalid');
    if(activity.conversation?.id!==undefined&&activity.conversation.id!==conversationId||activity.channelId!==undefined&&activity.channelId!=='directline')throw new ProbeError('activity_invalid');
    const digest=createHash('sha256').update(JSON.stringify(activity)).digest('hex');
    if(seen.has(activity.id)){if(seen.get(activity.id)!==digest)throw new ProbeError('activity_invalid');continue;}
    seen.set(activity.id,digest);
    if(activity.from.role!=='bot')continue;
    if(!identifier(activity.from.id)||typeof activity.type!=='string')throw new ProbeError('activity_invalid');
    botIds.add(activity.from.id);activityTypes.add(activity.type);botActivities++;
    if(activity.attachments!==undefined&&!Array.isArray(activity.attachments))throw new ProbeError('activity_invalid');
    for(const attachment of activity.attachments??[]){
     if(attachment?.contentType!=='application/vnd.microsoft.card.oauth')continue;
     oauthCardCount++;
     const sas=attachment.content?.tokenPostResource?.sasUrl;
     if(typeof sas!=='string')continue;
     let url:URL;try{url=new URL(sas);}catch{throw new ProbeError('oauth_metadata_invalid');}
     if(url.protocol!=='https:'||url.username||url.password||url.port||url.hash)throw new ProbeError('oauth_metadata_invalid');
     // Only describe the challenge; never follow/post to it, print its values, or infer a trusted audience.
     const names=[...new Set(url.searchParams.keys())].sort();
     if(names.some(name=>!/^[A-Za-z0-9_-]{1,100}$/.test(name)))throw new ProbeError('oauth_metadata_invalid');
     cards.push({origin:url.origin,...(/^\/[A-Za-z/]+$/.test(url.pathname)?{staticPath:url.pathname}:{}),queryKeys:names});
    }
   }
   if(oauthCardCount)break;
   if(attempt<29&&Date.now()<deadline)await pause();
  }
  token='';
  return{anonymousRejected:true,invalidSecretRejected:true,tokenGenerated:true,conversationStarted:true,greetingSubmitted:true,diagnosticMessageSubmitted:true,botActivities,oauthCardCount,observedBotIds:[...botIds].sort(),activityTypes:[...activityTypes].sort(),oauthCards:cards,federationVerified:false,productionAdapterExercised:false};
 }catch(error){throw error instanceof ProbeError?error:new ProbeError('probe_failed');}
}
export async function probeAgentChannel(config:{environmentId:string;schemaName:string;agentEndpoint:string},readSecret:()=>Promise<string>,transport:Transport=fetch){
 const settings={...config};
 const endpoint=await discoverChannel(settings,transport);
 if(classifyChannelEntrypoint(settings)==='authenticated_runtime')return{endpoint,entrypointKind:'authenticated_runtime',publicTokenEndpointStatus:null,publicTokenEndpointRejected:false,publicTokenRouteVerified:false,...await probeChannel(endpoint,readSecret,transport)};
 const anonymous=await request(transport,settings.agentEndpoint);
 if(![401,403,404].includes(anonymous.status))throw new ProbeError('public_token_endpoint_not_rejected');
 const rejected=[401,403].includes(anonymous.status);
 return{endpoint,entrypointKind:'directline_token',publicTokenEndpointStatus:anonymous.status,publicTokenEndpointRejected:rejected,publicTokenRouteVerified:rejected,...await probeChannel(endpoint,readSecret,transport)};
}
