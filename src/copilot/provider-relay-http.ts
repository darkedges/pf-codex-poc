import {createServer,request,type ServerOptions} from 'node:https';
import {checkServerIdentity} from 'node:tls';
import {ProviderToolRelay,ProviderToolRelayApi,ProviderRelayError} from './provider-tool-relay.ts';
import type {DirectLineDependencies} from '../adapters/copilot.ts';
import type {DirectLineConfig} from '../adapters/copilot.ts';
import {DirectLineAdapter} from '../adapters/direct-line.ts';
import type {ProviderRelayConfig,ProviderRelayDependencies} from './provider-tool-relay.ts';

// No listener or credential enrollment is performed by any factory in this file.
export function providerRelayLifecycle(relay:ProviderToolRelay):NonNullable<DirectLineDependencies['providerSession']>{
 if(!(relay instanceof ProviderToolRelay))throw new ProviderRelayError('configuration');
 return{bind:async(broker,provider,signal)=>{await relay.bind(broker,provider,signal);},invalidate:provider=>relay.invalidate(provider)};
}
export type RelayCredentialHeaderState='missing'|'multiple'|'oversized'|'malformed'|'present';
export type RelayHttpObservation={event:'provider_relay_http';status:number;credentials:{provider:RelayCredentialHeaderState;caller:RelayCredentialHeaderState}};
export type RelayHttpControls={maxConcurrent:number;maxConnections:number;requestsPerMinute:number;providerHeader?:'X-PF-User-Access-Token'|'PfUserAccessToken';observe?:(event:RelayHttpObservation)=>void};
const credentialHeaderState=(values:string[]|undefined,max:number):RelayCredentialHeaderState=>!values?.length?'missing':values.length!==1?'multiple':values[0].length>max?'oversized':!values[0]||/\s/.test(values[0])?'malformed':'present';
export function createProviderRelayServer(tls:ServerOptions,api:ProviderToolRelayApi,controls:RelayHttpControls){
 if(!tls?.key||!tls.cert||!(api instanceof ProviderToolRelayApi)||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||!controls||Object.keys(controls).some(k=>!['maxConcurrent','maxConnections','requestsPerMinute','providerHeader','observe'].includes(k))||controls.providerHeader!==undefined&&!['X-PF-User-Access-Token','PfUserAccessToken'].includes(controls.providerHeader)||!Number.isInteger(controls.maxConcurrent)||controls.maxConcurrent<1||controls.maxConcurrent>32||!Number.isInteger(controls.maxConnections)||controls.maxConnections<controls.maxConcurrent||controls.maxConnections>128||!Number.isInteger(controls.requestsPerMinute)||controls.requestsPerMinute<1||controls.requestsPerMinute>1000||controls.observe!==undefined&&typeof controls.observe!=='function')throw new ProviderRelayError('configuration');
 const maxConcurrent=controls.maxConcurrent,maxConnections=controls.maxConnections,requestsPerMinute=controls.requestsPerMinute,observe=controls.observe;
 const providerHeader=(controls.providerHeader??'X-PF-User-Access-Token').toLowerCase(),otherProviderHeader=providerHeader==='pfuseraccesstoken'?'x-pf-user-access-token':'pfuseraccesstoken';
 let active=0,minute=Math.floor(Date.now()/60000),requests=0,draining=false;
 const server=createServer({...tls,minVersion:'TLSv1.2',handshakeTimeout:5000,maxHeaderSize:20000},async(req,res)=>{
  let entered=false;
  const credentials={provider:credentialHeaderState(req.headersDistinct[providerHeader],16000),caller:credentialHeaderState(req.headersDistinct['x-copilot-connection-key'],512)};
  const send=(status:number,body:Record<string,unknown>)=>{if(res.destroyed)return;const raw=JSON.stringify(body);res.writeHead(status,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(raw),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...(status===429?{'Retry-After':'60'}:{})});res.end(raw);try{observe?.({event:'provider_relay_http',status,credentials:{...credentials}});}catch{}};
  const reject=(status:number,error:string)=>{res.shouldKeepAlive=false;req.resume();send(status,{error});};
  try{
   if(draining||active>=maxConcurrent){reject(503,'unavailable');return;}
   const currentMinute=Math.floor(Date.now()/60000);if(currentMinute!==minute){minute=currentMinute;requests=0;}
   if(requests++>=requestsPerMinute){reject(429,'rate_limited');return;}
   active++;entered=true;
   if(req.method!=='POST'||req.url!=='/v1/copilot-tools/verify-access'||req.headers.authorization!==undefined||req.headers[otherProviderHeader]!==undefined||['x-agent-id','x-user-id','x-grant-id','x-resource','x-forwarded-client-cert'].some(k=>req.headers[k]!==undefined)){reject(400,'invalid_request');return;}
   const providers=req.headersDistinct[providerHeader],callers=req.headersDistinct['x-copilot-connection-key'];
   if(providers?.length!==1||callers?.length!==1||providers[0].length>16000||callers[0].length>512){reject(401,'invalid_token');return;}
   if(req.headersDistinct['content-type']?.length!==1||!/^application\/json(?:;\s*charset=utf-8)?$/i.test(req.headers['content-type']??'')){reject(400,'invalid_request');return;}
   if(req.headers['content-encoding']!==undefined){reject(400,'invalid_request');return;}
   if(Number(req.headers['content-length'])>1024){reject(413,'invalid_request');return;}
   const chunks:Buffer[]=[];let size=0;
   for await(const chunk of req){size+=chunk.length;if(size>1024){reject(413,'invalid_request');return;}chunks.push(chunk);}
   const result=await api.handle({method:'POST',path:req.url,contentType:req.headers['content-type']!,authorization:'Bearer '+providers[0],callerCredential:callers[0],rawBody:Buffer.concat(chunks).toString('utf8')});
   send(result.status,result.body);
  }catch{send(503,{error:'unavailable'});}finally{if(entered)active--;}
 });
 server.maxConnections=maxConnections;server.maxHeadersCount=32;server.headersTimeout=5000;server.requestTimeout=10000;server.setTimeout(10000,s=>s.destroy());
 server.on('clientError',(_error,socket)=>{if(socket.writable)socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');});
 return Object.assign(server,{beginDrain:()=>{draining=true;}});
}

export type PrivateToolConnection={origin:string;key:ServerOptions['key'];cert:ServerOptions['cert'];ca:ServerOptions['ca'];serverCertificateSha256:string;timeoutMs:number};
export function createPrivateToolInvoker(config:PrivateToolConnection){
 let target:URL;
 try{
  target=new URL(config.origin);
  if(target.protocol!=='https:'||target.username||target.password||target.pathname!=='/'||target.search||target.hash||!config.key||!config.cert||!config.ca||!/^([A-F0-9]{2}:){31}[A-F0-9]{2}$/.test(config.serverCertificateSha256)||!Number.isInteger(config.timeoutMs)||config.timeoutMs<100||config.timeoutMs>10000||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error();
 }catch{throw new ProviderRelayError('configuration');}
 const url=new URL('/v1/tools/verify-access',target),pin=config.serverCertificateSha256,timeoutMs=config.timeoutMs;
 // Snapshot TLS material so external configuration mutation cannot change trust.
 const copy=(v:any):any=>Buffer.isBuffer(v)?Buffer.from(v):Array.isArray(v)?v.map(copy):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).map(([k,value])=>[k,copy(value)])):v;
 const key=copy(config.key),cert=copy(config.cert),ca=copy(config.ca);
 return async(toolToken:string,signal:AbortSignal):Promise<{authorized:true}>=>{
  if(signal.aborted||typeof toolToken!=='string'||!toolToken||toolToken.length>16000||/\s/.test(toolToken))throw new ProviderRelayError('unavailable');
  return new Promise<{authorized:true}>((done,reject)=>{
   let finished=false;let timer:ReturnType<typeof setTimeout>|undefined;
   const finish=(value?:{authorized:true})=>{if(finished)return;finished=true;if(timer)clearTimeout(timer);signal.removeEventListener('abort',abort);if(value)done(value);else reject(new ProviderRelayError('unavailable'));};
   const req=request(url,{family:url.hostname==='localhost'?4:undefined,method:'POST',key,cert,ca,agent:false,minVersion:'TLSv1.2',rejectUnauthorized:true,checkServerIdentity:(host,certificate)=>checkServerIdentity(host,certificate)??(certificate.fingerprint256===pin?undefined:Error('Unapproved private tool peer')),headers:{Authorization:'Bearer '+toolToken,'Content-Type':'application/json',Accept:'application/json','Content-Length':2}},res=>{
    if(res.statusCode!==200||!/^application\/json(?:;|$)/i.test(res.headers['content-type']??'')||res.headers['content-encoding']!==undefined){res.resume();finish();return;}
    const chunks:Buffer[]=[];let size=0;
    res.on('data',chunk=>{size+=chunk.length;if(size>1024){req.destroy();finish();}else chunks.push(chunk);});
    res.on('error',()=>finish());
    res.on('end',()=>{try{const body=JSON.parse(Buffer.concat(chunks).toString('utf8'));if(!body||typeof body!=='object'||Object.keys(body).length!==1||body.authorized!==true)throw Error();finish({authorized:true});}catch{finish();}});
   });
   const abort=()=>{req.destroy();finish();};
   signal.addEventListener('abort',abort,{once:true});timer=setTimeout(abort,timeoutMs);
   req.on('error',()=>finish());req.end('{}');if(signal.aborted)abort();
  }).catch(()=>{throw new ProviderRelayError('unavailable');});
 };
}

export function composeProviderToolConnection(options:{
 relayConfig:ProviderRelayConfig;
 relayDependencies:Omit<ProviderRelayDependencies,'invokeTool'>;
 directLineConfig:DirectLineConfig;
 directLineDependencies:Omit<DirectLineDependencies,'verifier'|'providerVerifier'|'bindProviderIdentity'|'providerSession'>;
 privateTool:PrivateToolConnection;tls:ServerOptions;controls:RelayHttpControls;
}){
 const r=options.relayConfig,d=options.directLineConfig,p=d.providerSso;
 if(!p||r.brokerAudience!==d.brokerAudience||r.scope!==d.scope||r.provider.issuer!==p.issuer||r.provider.audience!==p.audience||r.provider.scope!==p.scope)throw new ProviderRelayError('configuration');
 const deps=options.relayDependencies;
 const relay=new ProviderToolRelay(r,{...deps,invokeTool:createPrivateToolInvoker(options.privateTool)});
 const adapter=new DirectLineAdapter(d,{...options.directLineDependencies,verifier:deps.brokerVerifier,providerVerifier:deps.providerVerifier,bindProviderIdentity:async(provider,broker)=>deps.bindProviderIdentity(provider,broker),providerSession:providerRelayLifecycle(relay)});
 const server=createProviderRelayServer(options.tls,new ProviderToolRelayApi(relay),options.controls);
 return{relay,adapter,server};
}
