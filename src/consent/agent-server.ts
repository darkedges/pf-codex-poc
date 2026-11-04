import {createServer,type ServerOptions} from 'node:https';
import {PolicyError} from '../policy/contracts.ts';
import type {PortalResponse} from './portal.ts';
type Portal={handle(input:{method:string;path:string;headers:{cookie?:string;origin?:string};body?:string}):Promise<PortalResponse>};
type Controls={origin:string;maxConcurrent:number;maxConnections:number;requestsPerMinute:number;maxBodyBytes?:1024|8192;ready():boolean;observe?:(event:{event:'portal_http';status:number})=>void};
// Factory opens no listener. The owning service must bind only 127.0.0.1:9466.
export function createAgentPortalServer(tls:ServerOptions,portal:Portal,controls:Controls){
 const origin=new URL(controls.origin);
 if(origin.protocol!=='https:'||origin.username||origin.password||origin.pathname!=='/'||origin.search||origin.hash||!tls.key||!tls.cert||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||!Number.isInteger(controls.maxConcurrent)||controls.maxConcurrent<1||controls.maxConcurrent>8||!Number.isInteger(controls.maxConnections)||controls.maxConnections<controls.maxConcurrent||controls.maxConnections>64||!Number.isInteger(controls.requestsPerMinute)||controls.requestsPerMinute<1||controls.requestsPerMinute>300||typeof controls.ready!=='function')throw new PolicyError('configuration');
 if(controls.maxBodyBytes!==undefined&&![1024,8192].includes(controls.maxBodyBytes))throw new PolicyError('configuration');
 const maxBodyBytes=controls.maxBodyBytes??1024,expectedHost=origin.host,expectedOrigin=origin.origin,ready=controls.ready,observe=controls.observe,maxConcurrent=controls.maxConcurrent,requestsPerMinute=controls.requestsPerMinute;
 let draining=false,active=0,minute=Math.floor(Date.now()/60000),requests=0;
 const server=createServer({...tls,minVersion:'TLSv1.2',maxHeaderSize:12000,handshakeTimeout:5000},async(req,res)=>{
  let entered=false;
  const send=(status:number,html='',headers:Record<string,string>={})=>{
   if(res.destroyed)return;
   res.writeHead(status,{...headers,'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Referrer-Policy':status===200?'same-origin':'no-referrer','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Content-Length':Buffer.byteLength(html),...(status===429?{'Retry-After':'60'}:{})});res.end(html);
   try{observe?.({event:'portal_http',status});}catch{}
  };
  const reject=(status:number)=>{res.shouldKeepAlive=false;req.resume();send(status);};
  try{
   if(draining||active>=maxConcurrent||!ready()){reject(503);return;}
   const current=Math.floor(Date.now()/60000);if(current!==minute){minute=current;requests=0;}
   if(requests++>=requestsPerMinute){reject(429);return;}
   active++;entered=true;
   if(req.headersDistinct.host?.length!==1||req.headers.host!==expectedHost||['cookie','origin','content-type','content-length','transfer-encoding'].some(h=>(req.headersDistinct[h]?.length??0)>1)||req.headers.authorization!==undefined||['x-user-id','x-agent-id','x-grant-id','x-resource','x-forwarded-client-cert'].some(h=>req.headers[h]!==undefined)){reject(400);return;}
   const path=req.url??'',method=req.method??'';
   const get=method==='GET'&&(path==='/'||/^\/(?:callback|provider-callback)\?[^#]{1,8000}$/.test(path));
   const post=method==='POST'&&/^\/(?:login|approve|provider-login|check|revoke|logout)$/.test(path);
   if(!get&&!post){reject(404);return;}
   if(req.headers['content-encoding']!==undefined){reject(400);return;}
   if(post){
    if(req.headers.origin!==expectedOrigin){reject(403);return;}
    if(req.headersDistinct['content-type']?.length!==1||!/^application\/x-www-form-urlencoded(?:;\s*charset=utf-8)?$/i.test(req.headers['content-type']??'')){reject(400);return;}
   }else if(req.headers['transfer-encoding']!==undefined||Number(req.headers['content-length']??0)!==0){reject(400);return;}
   if(Number(req.headers['content-length']??0)>maxBodyBytes){reject(413);return;}
   let size=0;const chunks:Buffer[]=[];
   for await(const chunk of req){size+=chunk.length;if(size>maxBodyBytes){reject(413);return;}chunks.push(chunk);}
   const response=await portal.handle({method,path,headers:{cookie:req.headers.cookie,origin:req.headers.origin},body:Buffer.concat(chunks).toString('utf8')});
   send(response.status,response.html,response.headers);
  }catch{if(!res.headersSent)send(503);else res.destroy();}finally{if(entered)active--;}
 });
 // Uploads remain bounded to ten seconds; a fixed live diagnostic may need
 // longer to finish its server-side polling. Its executor must enforce a deadline.
 server.maxConnections=controls.maxConnections;server.maxHeadersCount=32;server.requestTimeout=10000;server.headersTimeout=5000;server.setTimeout(90000,s=>s.destroy());
 server.on('clientError',(_error,socket)=>{if(socket.writable)socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');});
 return Object.assign(server,{beginDrain:()=>{draining=true;}});
}
