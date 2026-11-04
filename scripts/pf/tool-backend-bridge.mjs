// Isolated Docker LAB bridge only. No arbitrary targets, redirects or secrets
// in telemetry. The tool runtime does not include this file in its image.
import {readFileSync} from 'node:fs';
import {createServer,request} from 'node:https';
import {backendRoute} from './tool-backend-route.mjs';
const read=name=>readFileSync('/run/bridge/'+name);
const config=JSON.parse(read('config.json'));
if(!Number.isInteger(config.policyPort)||config.policyPort<1||config.policyPort>65535||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error('Invalid isolated backend bridge');
const server=createServer({key:read('server-key.pem'),cert:read('server-cert.pem'),minVersion:'TLSv1.2',maxHeaderSize:20000},async(req,res)=>{
 const send=(status,body)=>{if(!res.destroyed){res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(body));}};
 try{
  const route=backendRoute(req.method,req.url);if(!route){send(404,{error:'not_found'});return;}
  if(route!=='jwks'&&(req.headersDistinct.authorization?.length!==1||!req.headers.authorization?.startsWith('Policy ')||(req.headers['content-type']??'')!=='application/json')){send(401,{error:'unauthenticated'});return;}
  const chunks=[];let bytes=0;for await(const chunk of req){bytes+=chunk.length;if(bytes>50000){send(413,{error:'invalid_request'});return;}chunks.push(chunk);}
  if(route==='jwks'&&bytes){send(400,{error:'invalid_request'});return;}
  const body=Buffer.concat(chunks),headers={Accept:'application/json',...(route!=='jwks'?{'Content-Type':'application/json',Authorization:req.headers.authorization,'Content-Length':body.length}:{})};
  const result=await new Promise((done,reject)=>{
   const upstream=request({hostname:'host.docker.internal',port:route==='jwks'?9034:config.policyPort,servername:'localhost',ca:read('pf-ca.pem'),rejectUnauthorized:true,method:route==='jwks'?'GET':'POST',path:route==='jwks'?'/pf/JWKS':route==='health'?'/v1/health':'/v1/decisions',headers,timeout:2000},response=>{
    let raw='';response.on('data',chunk=>{raw+=chunk;if(raw.length>262144)upstream.destroy();});response.on('end',()=>{try{done({status:response.statusCode,body:JSON.parse(raw)});}catch{reject(Error());}});response.on('error',reject);
   });upstream.on('error',reject);upstream.on('timeout',()=>upstream.destroy());upstream.end(route!=='jwks'?body:undefined);
  });
  send(result.status,result.body);
 }catch{send(503,{error:'unavailable'});}
});
server.requestTimeout=5000;server.headersTimeout=3000;server.maxHeadersCount=32;server.setTimeout(5000,s=>s.destroy());
server.listen(7443,'0.0.0.0',()=>console.log('Private lab backend bridge listening'));
process.once('SIGTERM',()=>{server.close(()=>process.exit(0));server.closeAllConnections();});
