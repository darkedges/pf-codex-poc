import type {ServerOptions} from 'node:https';import type {PolicyApi} from '../policy/api.ts';import {createPolicyServer} from '../policy/server.ts';
// Bounded loopback host. The caller owns credential loading, approval and the
// registry handle. Stop never deletes policy/replay/audit or grant evidence.
export async function startDocumentPolicyHost(tls:ServerOptions,api:PolicyApi,options:{port:0|9453;expiresAt:number}){
 if(![0,9453].includes(options.port)||!Number.isSafeInteger(options.expiresAt)||options.expiresAt<=Date.now()||options.expiresAt>Date.now()+3600000||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error('document_host_configuration');
 const server=createPolicyServer(tls,api);server.maxConnections=32;let stopped=false,stopPromise:Promise<void>|undefined,timer:ReturnType<typeof setTimeout>|undefined;
 const stop=()=>stopPromise??=(async()=>{stopped=true;clearTimeout(timer);if(!server.listening)return;await new Promise<void>((done,reject)=>{const deadline=setTimeout(()=>reject(Error('document_host_drain_failed')),5000);server.close(error=>{clearTimeout(deadline);if(error)reject(Error('document_host_drain_failed'));else done();});server.closeAllConnections();});})();
 try{
  await new Promise<void>((done,reject)=>{const fail=()=>reject(Error('document_host_unavailable'));server.once('error',fail);server.listen(options.port,'127.0.0.1',()=>{server.removeListener('error',fail);done();});});
  const address=server.address();if(!address||typeof address==='string')throw Error();timer=setTimeout(()=>{void stop().catch(()=>{});},Math.max(1,options.expiresAt-Date.now()));
  return{origin:'https://localhost:'+address.port,port:address.port,expiresAt:options.expiresAt,ready:()=>!stopped&&server.listening&&Date.now()<options.expiresAt,stop};
 }catch{await stop();throw Error('document_host_unavailable');}
}
