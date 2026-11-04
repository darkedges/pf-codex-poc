import {createServer,type ServerOptions} from 'node:https';
import type {AddressInfo} from 'node:net';
import {androidAssociation} from './android-links.ts';
import type {MobileHttpApi} from './http-api.ts';

type Config={origin:string;port:0|9468;tls:Pick<ServerOptions,'key'|'cert'>;androidCertificateSha256:string};
/** Loopback-only listener. Public tunnel activation, protected credential loading
 * and scheduled startup are separate reviewed deployment operations. */
export async function startMobileHttpsHost(config:Config,api:Pick<MobileHttpApi,'handle'>){
 const u=new URL(config.origin);if(u.protocol!=='https:'||u.origin!==config.origin||![0,9468].includes(config.port)||!config.tls.key||!config.tls.cert||typeof api.handle!=='function'||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error('mobile_host_configuration');
 const association=JSON.stringify(androidAssociation(config.androidCertificateSha256)),sockets=new Set<import('node:net').Socket>();let stopped=false;
 const server=createServer({...config.tls,minVersion:'TLSv1.2'},(incoming,outgoing)=>{
  const controller=new AbortController();let responded=false;
  const reject=(status:number)=>{if(responded)return;responded=true;outgoing.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store','Connection':'close'});outgoing.end('{"error":"mobile_request_rejected"}');};
  incoming.once('aborted',()=>controller.abort());outgoing.once('close',()=>{if(!outgoing.writableEnded)controller.abort();});
  void(async()=>{try{
   if(stopped||incoming.headers.host!==u.host||!incoming.url?.startsWith('/')||incoming.url.startsWith('//')||incoming.url.length>8192){reject(400);return;}
   if(incoming.method==='GET'&&incoming.url==='/.well-known/assetlinks.json'){responded=true;outgoing.writeHead(200,{'Content-Type':'application/json','Cache-Control':'public, max-age=300','X-Content-Type-Options':'nosniff'});outgoing.end(association);return;}
   if(incoming.method==='GET'&&incoming.url==='/'){responded=true;outgoing.writeHead(200,{'Content-Type':'text/plain; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});outgoing.end('Federated Copilot Android API. Open the installed application.');return;}
   const chunks:Buffer[]=[];let length=0;for await(const part of incoming){length+=part.length;if(length>16000){controller.abort();reject(413);return;}chunks.push(part);}
   const headers=new Headers();for(const [k,v]of Object.entries(incoming.headers))if(v!==undefined)headers.set(k,Array.isArray(v)?v.join(','):v);
   const method=incoming.method??'GET',request=new Request(config.origin+incoming.url,{method,headers,signal:controller.signal,...(!['GET','HEAD'].includes(method)?{body:Buffer.concat(chunks)}:{})});
   const result=await api.handle(request);if(stopped||controller.signal.aborted){reject(503);return;}responded=true;outgoing.writeHead(result.status,Object.fromEntries(result.headers));outgoing.end(Buffer.from(await result.arrayBuffer()));
  }catch{controller.abort();reject(400);}})();
 });
 server.maxHeadersCount=32;server.headersTimeout=5000;server.requestTimeout=10000;server.keepAliveTimeout=1000;server.maxRequestsPerSocket=30;
 server.on('connection',socket=>{if(stopped||sockets.size>=32){socket.destroy();return;}sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});server.on('clientError',(_error,socket)=>socket.destroy());
 try{await new Promise<void>((done,fail)=>{const error=()=>{server.removeListener('listening',ready);fail(Error('mobile_host_unavailable'));},ready=()=>{server.removeListener('error',error);done();};server.once('error',error);server.once('listening',ready);server.listen(config.port,'127.0.0.1');});}
 catch{server.close();throw Error('mobile_host_unavailable');}
 server.on('error',()=>{stopped=true;for(const socket of sockets)socket.destroy();});
 return{port:(server.address() as AddressInfo).port,host:'127.0.0.1' as const,stop:()=>new Promise<void>(done=>{stopped=true;server.close(()=>done());for(const socket of sockets)socket.destroy();})};
}
