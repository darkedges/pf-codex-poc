import { createServer,type ServerOptions } from 'node:https';
import type { PolicyApi } from './api.ts';

export function createPolicyServer(tls:ServerOptions,api:PolicyApi){
  if(!tls.key||!tls.cert)throw Error('Policy HTTPS credentials required');
  const server=createServer({...tls,minVersion:'TLSv1.2'},async(req,res)=>{
    const send=(status:number,value:unknown)=>{if(res.destroyed)return;const data=JSON.stringify(value);res.writeHead(status,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(data),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(data);};
    try{
      if(req.method!=='POST'||!(req.headers['content-type']??'').startsWith('application/json')){send(400,{error:'invalid_request'});return;}
      let raw='';for await(const chunk of req){raw+=chunk;if(Buffer.byteLength(raw)>50000){send(413,{error:'invalid_request'});return;}}
      const result=await api.handle({method:req.method,path:req.url??'',authorization:req.headers.authorization??'',rawBody:raw});
      send(result.status,result.body);
    }catch{send(503,{error:'unavailable'});}
  });
  server.requestTimeout=10000;server.headersTimeout=5000;server.setTimeout(10000,socket=>socket.destroy());server.maxHeadersCount=32;
  return server;
}
