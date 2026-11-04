// Thin web worker: server TLS material only. No Vault, policy/agent/client key,
// operator credential, filesystem secret lookup or outbound Microsoft transport.
import {DocumentChatPortal} from '../../src/consent/document-chat-portal.ts';
import {createAgentPortalServer} from '../../src/consent/agent-server.ts';
import {createDocumentChatRpcClient} from '../../src/consent/document-chat-rpc.ts';
if(!process.send||!process.connected||!process.env.PORTAL_INSTANCE)throw Error('Owned portal controller required');
const instance=process.env.PORTAL_INSTANCE,rpc=createDocumentChatRpcClient(process as any);let server:any,started=false,stopped=false,heartbeat=Date.now(),expiresAt=0,trialEnabled=false,dependencyReady=false;
const stop=()=>{if(stopped)return;stopped=true;clearInterval(timer);rpc.close();server?.beginDrain();if(server){server.close(()=>process.exit(0));server.closeAllConnections();}else process.exit(0);};
const timer=setInterval(()=>{if(started&&(Date.now()>=expiresAt||Date.now()-heartbeat>20000))stop();},1000);
process.once('disconnect',stop);process.once('SIGTERM',stop);process.once('SIGINT',stop);
process.on('message',(m:any)=>{
 if(m?.instance!==instance)return;
 // Availability changes never renew dependency readiness, heartbeat age or expiry.
 if(m.kind==='budget'){if(started&&typeof m.trialEnabled==='boolean')trialEnabled=m.trialEnabled;return;}
 if(m.kind==='heartbeat'){
  if(!started||typeof m.trialEnabled!=='boolean'||typeof m.ready!=='boolean')return;
  heartbeat=Date.now();trialEnabled=m.trialEnabled;dependencyReady=m.ready;if(!dependencyReady)stop();return;
 }
 if(m.kind==='stop'){stop();return;}
 if(m.kind!=='init'||started)return;
 try{
  if(Object.keys(m).sort().join()!=='expiresAt,instance,kind,port,public,tls'||!Number.isSafeInteger(m.expiresAt)||m.expiresAt<=Date.now()+60000||m.expiresAt>Date.now()+3600000||![0,9466].includes(m.port)||!['agent,capability,origin','agent,capability,origin,repeatableSessions'].includes(Object.keys(m.public??{}).sort().join())||m.public.repeatableSessions!==undefined&&m.public.repeatableSessions!==true||m.public.origin!=='https://agent.copilot.darkedges.com'||Object.keys(m.tls??{}).sort().join()!=='cert,key'||typeof m.tls.key!=='string'||m.tls.key.length>16000||typeof m.tls.cert!=='string'||m.tls.cert.length>16000)throw Error();
  started=true;expiresAt=m.expiresAt;dependencyReady=true;
  const portal=new DocumentChatPortal({...m.public,authorizationOrigin:'https://pf-a.copilot.darkedges.com',available:()=>trialEnabled,recordConsentChoice:automatic=>rpc.call('consent.choice',[automatic]),
   oidc:{start:(...args)=>rpc.call('oidc.start',args),redeem:(...args)=>rpc.call('oidc.redeem',args)},
   provider:{start:(...args)=>rpc.call('provider.start',args),redeem:(...args)=>rpc.call('provider.redeem',args)},
   policies:{chat:{request:(...args)=>rpc.call('chat.policy',args)},document:{request:(...args)=>rpc.call('document.policy',args)}},execute:proof=>rpc.call('execute',[proof])});
  server=createAgentPortalServer(m.tls,portal,{origin:m.public.origin,maxConcurrent:4,maxConnections:32,requestsPerMinute:60,maxBodyBytes:8192,ready:()=>!stopped&&dependencyReady&&Date.now()<expiresAt&&Date.now()-heartbeat<=20000});
  server.once('error',()=>{process.send?.({kind:'failed',instance});stop();});
  server.listen(m.port,'127.0.0.1',()=>process.send?.({kind:'ready',instance,host:'127.0.0.1',port:server.address().port}));
 }catch{process.send?.({kind:'failed',instance});stop();}
});
