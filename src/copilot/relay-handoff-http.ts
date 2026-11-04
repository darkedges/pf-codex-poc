import {createServer,request,type ServerOptions} from 'node:https';
import type {IncomingMessage,ServerResponse} from 'node:http';
import {checkServerIdentity,TLSSocket} from 'node:tls';
import {createHash,randomUUID} from 'node:crypto';
import {SignJWT} from 'jose';
import {GatewayProofHandoff} from './relay-handoff.ts';
import {ProviderRelayError} from './provider-tool-relay.ts';

const path='/v1/internal/relay/proofs';
const pin=(v:unknown):v is string=>typeof v==='string'&&/^([A-F0-9]{2}:){31}[A-F0-9]{2}$/.test(v);
const text=(v:unknown,max=16000):v is string=>typeof v==='string'&&v.length>0&&v.length<=max&&!/[\u0000-\u0020\u007f]/.test(v);
const unavailable=()=>new ProviderRelayError('unavailable');
const copy=(v:any):any=>Buffer.isBuffer(v)?Buffer.from(v):Array.isArray(v)?v.map(copy):v&&Object.getPrototypeOf(v)===Object.prototype?Object.fromEntries(Object.entries(v).map(([k,value])=>[k,copy(value)])):v;
type Controls={certificateSha256:string;maxConcurrent:number;maxConnections:number;requestsPerMinute:number;timeoutMs:number;observe?:(event:{event:'gateway_handoff_http';status:number})=>void};

// Private control plane only. Construction never calls listen or enrolls trust.
export function createGatewayHandoffServer(tls:ServerOptions,handoff:GatewayProofHandoff,controls:Controls){
 if(!tls?.key||!tls.cert||!tls.ca||!(handoff instanceof GatewayProofHandoff)||!pin(controls?.certificateSha256)||!Number.isInteger(controls.maxConcurrent)||controls.maxConcurrent<1||controls.maxConcurrent>16||!Number.isInteger(controls.maxConnections)||controls.maxConnections<controls.maxConcurrent||controls.maxConnections>64||!Number.isInteger(controls.requestsPerMinute)||controls.requestsPerMinute<1||controls.requestsPerMinute>1000||!Number.isInteger(controls.timeoutMs)||controls.timeoutMs<100||controls.timeoutMs>10000||controls.observe!==undefined&&typeof controls.observe!=='function'||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw new ProviderRelayError('configuration');
 const c={...controls},active=new Set<AbortController>(),jobs=new Set<Promise<void>>();let draining=false,minute=Math.floor(Date.now()/60000),requests=0,stopping:Promise<void>|undefined;
 const handle=async(req:IncomingMessage,res:ServerResponse)=>{
  const controller=new AbortController();let entered=false,timer:ReturnType<typeof setTimeout>|undefined;
  const abort=()=>controller.abort(),disconnect=()=>{if(!res.writableFinished)abort();},destroy=()=>req.destroy();
  const send=(status:number,body:Record<string,unknown>)=>{if(res.destroyed||res.writableEnded)return;const raw=JSON.stringify(body);res.writeHead(status,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(raw),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',Connection:'close'});res.end(raw);try{c.observe?.({event:'gateway_handoff_http',status});}catch{}};
  const reject=(status:number,error:string)=>{req.resume();send(status,{error});};
  try{
   const socket=req.socket;
   if(req.rawHeaders.length>48){reject(400,'invalid_request');return;}
   if(!(socket instanceof TLSSocket)||!socket.authorized||socket.getPeerCertificate().fingerprint256!==c.certificateSha256){reject(403,'binding_denied');return;}
   if(draining||active.size>=c.maxConcurrent){reject(503,'unavailable');return;}
   const current=Math.floor(Date.now()/60000);if(current!==minute){minute=current;requests=0;}if(requests++>=c.requestsPerMinute){reject(429,'unavailable');return;}
   active.add(controller);entered=true;req.once('aborted',abort);res.once('close',disconnect);controller.signal.addEventListener('abort',destroy,{once:true});timer=setTimeout(abort,c.timeoutMs);
   if(req.method!=='POST'||req.url!==path||['x-agent-id','x-user-id','x-grant-id','x-resource','x-forwarded-client-cert','x-pf-user-access-token','x-copilot-connection-key'].some(k=>req.headers[k]!==undefined)){reject(400,'invalid_request');return;}
   const credentials=req.headersDistinct.authorization;
   if(credentials?.length!==1||credentials[0].length>16008||!/^Gateway [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(credentials[0])){reject(401,'binding_denied');return;}
   if(req.headersDistinct['content-type']?.length!==1||!/^application\/json(?:;\s*charset=utf-8)?$/i.test(req.headers['content-type']??'')||req.headers['content-encoding']!==undefined){reject(400,'invalid_request');return;}
   if(Number(req.headers['content-length'])>40000){reject(413,'invalid_request');return;}
   const chunks:Buffer[]=[];let size=0;for await(const chunk of req){size+=chunk.length;if(size>40000){reject(413,'invalid_request');return;}chunks.push(chunk);}
   let raw:string;try{raw=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(Buffer.concat(chunks));}catch{reject(400,'invalid_request');return;}
   if(controller.signal.aborted)throw unavailable();
   const result=await handoff.receive(credentials[0].slice(8),raw,controller.signal);
   if(controller.signal.aborted)throw unavailable();send(201,result);
  }catch{send(403,{error:'binding_denied'});}
  finally{if(timer)clearTimeout(timer);req.removeListener('aborted',abort);res.removeListener('close',disconnect);controller.signal.removeEventListener('abort',destroy);controller.abort();if(entered)active.delete(controller);}
 };
 const server=createServer({key:copy(tls.key),cert:copy(tls.cert),ca:copy(tls.ca),requestCert:true,rejectUnauthorized:true,minVersion:'TLSv1.2',handshakeTimeout:5000,maxHeaderSize:20000,ALPNProtocols:['http/1.1']},(req,res)=>{const job=handle(req,res);jobs.add(job);void job.then(()=>jobs.delete(job),()=>jobs.delete(job));});
 // Inspect every header pair before enforcing the count; parser truncation must
 // never hide a duplicate credential beyond a count cutoff. Bytes stay bounded.
 server.maxConnections=c.maxConnections;server.maxHeadersCount=0;server.headersTimeout=5000;server.requestTimeout=10000;server.setTimeout(10000,s=>s.destroy());
 server.on('clientError',(_e,socket)=>{if(socket.writable)socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');});
 const beginDrain=()=>{draining=true;for(const controller of active)controller.abort();};
 const shutdown=()=>stopping??= (async()=>{beginDrain();if(server.listening)await new Promise<void>((done,reject)=>{server.close(error=>error?reject(unavailable()):done());server.closeAllConnections();});await Promise.allSettled([...jobs]);})();
 return Object.assign(server,{beginDrain,shutdown});
}

type ClientConfig={origin:string;issuer:string;subject:string;audience:string;keyId:string;signingKey:CryptoKey;key:ServerOptions['key'];cert:ServerOptions['cert'];ca:ServerOptions['ca'];serverCertificateSha256:string;timeoutMs:number};
type Proof={providerToken?:string;brokerToken:string;agentToken:string;login:{idToken:string;nonce:string}};
export function createGatewayHandoffClient(config:ClientConfig){
 let target:URL;
 try{const u=new URL(config.origin);if(u.protocol!=='https:'||u.username||u.password||u.pathname!=='/'||u.search||u.hash||![config.issuer,config.subject,config.audience,config.keyId].every(v=>text(v,2048))||config.signingKey?.type!=='private'||!config.key||!config.cert||!config.ca||!pin(config.serverCertificateSha256)||!Number.isInteger(config.timeoutMs)||config.timeoutMs<100||config.timeoutMs>10000||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error();target=new URL(path,u);}catch{throw new ProviderRelayError('configuration');}
 const c={...config,key:copy(config.key),cert:copy(config.cert),ca:copy(config.ca)};
 return async(proof:Proof,external:AbortSignal):Promise<{registered:true;expiresAt:number}>=>{
  let timer:ReturnType<typeof setTimeout>|undefined;const controller=new AbortController(),abort=()=>controller.abort();external.addEventListener('abort',abort,{once:true});timer=setTimeout(abort,c.timeoutMs);
  const check=()=>{if(controller.signal.aborted||external.aborted)throw unavailable();};
  try{
   check();if(!proof||!['agentToken,brokerToken,login','agentToken,brokerToken,login,providerToken'].includes(Object.keys(proof).sort().join())||(proof.providerToken!==undefined&&!text(proof.providerToken))||![proof.brokerToken,proof.agentToken,proof.login?.idToken].every(v=>text(v))||Object.keys(proof.login).sort().join()!=='idToken,nonce'||!text(proof.login.nonce,256)||proof.login.nonce.length<16)throw unavailable();
   const raw=JSON.stringify(proof);if(Buffer.byteLength(raw)>40000)throw unavailable();
   const assertion=await new SignJWT({body_sha256:createHash('sha256').update(raw).digest('base64url')}).setProtectedHeader({alg:'RS256',kid:c.keyId}).setIssuer(c.issuer).setSubject(c.subject).setAudience(c.audience).setIssuedAt().setNotBefore('0s').setExpirationTime('60s').setJti(randomUUID()).sign(c.signingKey);check();
   return await new Promise<{registered:true;expiresAt:number}>((done,reject)=>{
    const req=request(target,{family:target.hostname==='localhost'?4:undefined,method:'POST',key:c.key,cert:c.cert,ca:c.ca,agent:false,minVersion:'TLSv1.2',rejectUnauthorized:true,signal:controller.signal,checkServerIdentity:(host,certificate)=>checkServerIdentity(host,certificate)??(certificate.fingerprint256===c.serverCertificateSha256?undefined:unavailable()),headers:{Authorization:'Gateway '+assertion,'Content-Type':'application/json',Accept:'application/json','Content-Length':Buffer.byteLength(raw)}},res=>{
     if(res.statusCode!==201||!/^application\/json(?:;|$)/i.test(res.headers['content-type']??'')||res.headers['content-encoding']!==undefined){res.resume();reject(unavailable());return;}
     let body='';res.on('data',chunk=>{body+=chunk;if(Buffer.byteLength(body)>1024){req.destroy();reject(unavailable());}});res.on('error',()=>reject(unavailable()));res.on('end',()=>{try{check();const value=JSON.parse(body);if(!value||Object.keys(value).sort().join()!=='expiresAt,registered'||value.registered!==true||!Number.isSafeInteger(value.expiresAt)||value.expiresAt<=Date.now()||value.expiresAt>Date.now()+60000)throw unavailable();done(value);}catch{reject(unavailable());}});
    });req.on('error',()=>reject(unavailable()));req.end(raw);
   });
  }catch{throw unavailable();}
  finally{controller.abort();if(timer)clearTimeout(timer);external.removeEventListener('abort',abort);}
 };
}
