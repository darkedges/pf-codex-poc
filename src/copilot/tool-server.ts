import {createServer,type ServerOptions} from 'node:https';
import type {TLSSocket} from 'node:tls';
import {ToolApi} from './tool-api.ts';
import {ToolAdmission,defaultToolLimits,type ToolAdmissionLimits} from './tool-admission.ts';

export type ToolSenderTrust={certificateSha256:string[]};

// Factory only: no listener, certificate acquisition or public deployment.
// Workload identity (mTLS) and delegated human/agent authority are independent.
export function createToolServer(tls:ServerOptions,api:ToolApi,senders:ToolSenderTrust,controls:{admission?:ToolAdmissionLimits;ready?:()=>Promise<boolean>;metrics?:()=>Record<string,unknown>;observe?:(event:Record<string,unknown>)=>void}={}){
  if(!tls?.key||!tls.cert||!tls.ca||!(api instanceof ToolApi)||!Array.isArray(senders?.certificateSha256)||!senders.certificateSha256.length||senders.certificateSha256.length>20||senders.certificateSha256.some(pin=>typeof pin!=='string'||!/^([A-F0-9]{2}:){31}[A-F0-9]{2}$/.test(pin))||new Set(senders.certificateSha256).size!==senders.certificateSha256.length||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error('Tool HTTPS sender trust required');
  const pins=new Set(senders.certificateSha256);
  if(Object.keys(controls).some(k=>!['admission','ready','metrics','observe'].includes(k))||controls.ready!==undefined&&typeof controls.ready!=='function'||controls.metrics!==undefined&&typeof controls.metrics!=='function'||controls.observe!==undefined&&typeof controls.observe!=='function')throw Error('Invalid tool controls');
  const limits=controls.admission===undefined?defaultToolLimits:controls.admission,admission=new ToolAdmission(limits,[...pins]);
  const readyCheck=controls.ready;
  const observe=controls.observe;
  const metrics=controls.metrics;
  const server=createServer({...tls,minVersion:'TLSv1.2',requestCert:true,rejectUnauthorized:true,handshakeTimeout:5000,maxHeaderSize:20000},async(req,res)=>{
    let release:(()=>void)|undefined;
    const send=(status:number,value:unknown,retryAfter?:number)=>{
      if(res.destroyed)return;const raw=JSON.stringify(value);
      res.writeHead(status,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(raw),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...(retryAfter?{'Retry-After':String(retryAfter)}:{})});res.end(raw);
      try{observe?.({event:'tool_http',operation:req.url==='/health/ready'?'readiness':req.url==='/health/live'?'liveness':req.url==='/health/metrics'?'metrics':req.url==='/v1/tools/verify-access'?'tool':'other',status,...(['overloaded','rate_limited','sender_denied'].includes(String((value as {error?:string})?.error))?{code:(value as {error:string}).error}:{})});}catch{}
    };
    try{
      const socket=req.socket as TLSSocket;
      if(!socket.authorized||!pins.has(socket.getPeerCertificate().fingerprint256)){send(403,{error:'sender_denied'});return;}
      const slot=admission.enter(socket.getPeerCertificate().fingerprint256);
      if(!slot.allowed){res.shouldKeepAlive=false;send(slot.status,{error:slot.code},slot.retryAfter);req.resume();return;}release=slot.release;
      if(req.method==='GET'&&['/health/live','/health/ready','/health/metrics'].includes(req.url??'')){
        if(req.headers['transfer-encoding']||req.headers['content-length']&&req.headers['content-length']!=='0'){send(400,{error:'invalid_request'});req.resume();return;}
        if(req.url==='/health/live'){send(200,{live:true});return;}
        if(req.url==='/health/metrics'){send(metrics?200:503,metrics?metrics():{error:'unavailable'});return;}
        let timer:ReturnType<typeof setTimeout>|undefined;
        try{const ready=readyCheck?await Promise.race([readyCheck(),new Promise<boolean>(done=>{timer=setTimeout(()=>done(false),2500);})]):false;send(ready===true?200:503,{ready:ready===true});}finally{if(timer)clearTimeout(timer);}return;
      }
      if(req.headersDistinct.authorization?.length!==1){send(401,{error:'invalid_token'});return;}
      if(req.method!=='POST'||req.headersDistinct['content-type']?.length!==1||(req.headers['content-type']??'').toLowerCase()!=='application/json'){send(400,{error:'invalid_request'});return;}
      const chunks:Buffer[]=[];let length=0;
      for await(const chunk of req){length+=chunk.length;if(length>1024){send(413,{error:'invalid_request'});return;}chunks.push(chunk);}
      const result=await api.handle({method:req.method,path:req.url??'',authorization:req.headers.authorization??'',rawBody:Buffer.concat(chunks).toString('utf8')});
      send(result.status,result.body);
    }catch{send(503,{error:'tool_failed'});}finally{release?.();}
  });
  server.maxConnections=limits.maxConnections;
  server.on('tlsClientError',()=>{try{observe?.({event:'tool_tls_rejected'});}catch{}});
  server.headersTimeout=5000;server.requestTimeout=10000;server.maxHeadersCount=32;server.setTimeout(10000,socket=>socket.destroy());
  return Object.assign(server,{beginDrain:()=>admission.drain()});
}
