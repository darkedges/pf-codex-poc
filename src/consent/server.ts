import { createServer,type ServerOptions } from 'node:https';
import type { ConsentPortal } from './portal.ts';
export function createConsentServer(tls:ServerOptions,portal:ConsentPortal){
 if(!tls.key||!tls.cert)throw Error('Consent HTTPS credentials required');
 const server=createServer({...tls,minVersion:'TLSv1.2'},async(req,res)=>{
  try{
   if(req.method==='POST'&&!(req.headers['content-type']??'').startsWith('application/x-www-form-urlencoded')){res.writeHead(400,{'Cache-Control':'no-store'});res.end();return;}
   let body='';for await(const chunk of req){body+=chunk;if(Buffer.byteLength(body)>8192){res.writeHead(413,{'Cache-Control':'no-store'});res.end();return;}}
   const result=await portal.handle({method:req.method??'',path:req.url??'',headers:{cookie:req.headers.cookie,origin:req.headers.origin},body});
   res.writeHead(result.status,{...result.headers,'Content-Length':Buffer.byteLength(result.html)});res.end(result.html);
  }catch{if(!res.destroyed){res.writeHead(503,{'Cache-Control':'no-store'});res.end();}}
 });
 server.requestTimeout=10000;server.headersTimeout=5000;server.setTimeout(10000,s=>s.destroy());server.maxHeadersCount=32;return server;
}
