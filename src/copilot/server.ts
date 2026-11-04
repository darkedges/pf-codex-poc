import { createServer,type ServerOptions } from 'node:https';
import type { CopilotApi } from './api.ts';
// Composition explicitly supplies verified trust, policy and signing dependencies.
// The factory does not open a listener or select a mock implementation.
export function createCopilotServer(tls:ServerOptions,api:CopilotApi){
 if(!tls.key||!tls.cert)throw Error('Copilot HTTPS credentials required');
 const server=createServer({...tls,minVersion:'TLSv1.2',handshakeTimeout:5000,maxHeaderSize:20000},async(req,res)=>{
  const send=(status:number,value:unknown)=>{if(res.destroyed)return;const raw=JSON.stringify(value);res.writeHead(status,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(raw),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(raw);};
  try{
   if(req.headersDistinct.authorization?.length!==1){send(401,{error:'invalid_token'});return;}
   if(req.method==='POST'&&(req.headers['content-type']??'').split(';',1)[0].toLowerCase()!=='application/json'){send(400,{error:'invalid_request'});return;}
   const chunks:Buffer[]=[];let bytes=0;
   for await(const chunk of req){bytes+=chunk.length;if(bytes>8192){send(413,{error:'invalid_request'});return;}chunks.push(chunk);}
   const result=await api.handle({method:req.method??'',path:req.url??'',authorization:req.headers.authorization??'',rawBody:Buffer.concat(chunks).toString('utf8')});send(result.status,result.body);
  }catch{send(503,{error:'unavailable'});}
 });
 server.headersTimeout=5000;server.requestTimeout=10000;server.maxHeadersCount=32;server.setTimeout(10000,socket=>socket.destroy());return server;
}
