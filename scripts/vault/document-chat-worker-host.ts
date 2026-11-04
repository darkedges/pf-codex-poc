import {spawn} from 'node:child_process';import {randomUUID} from 'node:crypto';
import {resolve} from 'node:path';import {root} from '../pf/common.mjs';
import {attachDocumentChatRpcServer,type DocumentChatRpcMethods} from '../../src/consent/document-chat-rpc.ts';
import {PolicyError} from '../../src/policy/contracts.ts';
export async function startDocumentChatWorker(options:{tls:{key:string;cert:string};public:{origin:string;capability:{scope:string;resource:string};agent:{issuer:string;subject:string}};expiresAt:number;port:0|9466;methods:DocumentChatRpcMethods;afterCall?:()=>void;onSpawn?:(pid:number)=>void;onExit?:()=>void}){
 const instance=randomUUID();
 const env=Object.fromEntries(['SystemRoot','WINDIR','TEMP','TMP'].flatMap(k=>process.env[k]?[[k,process.env[k]!]]:[]));
 const child=spawn(process.execPath,['--experimental-strip-types',resolve(root,'scripts/vault/document-chat-web-worker.ts')],{cwd:root,env:{...env,PORTAL_INSTANCE:instance},stdio:['ignore','ignore','ignore','ipc'],windowsHide:true});
 child.on('error',()=>{});
 const methods=Object.fromEntries(Object.entries(options.methods).map(([name,handler])=>[name,async(...args:any[])=>{try{return await handler!(...args);}finally{try{options.afterCall?.();}catch{}}}]));
 const rpc=attachDocumentChatRpcServer(child as any,methods);let stopping=false,port=0;
 const exited=new Promise<void>(done=>child.once('exit',()=>{rpc.close();if(!stopping)options.onExit?.();done();}));
 const stop=async()=>{
  if(stopping)return exited;stopping=true;
  const drained=rpc.drain();if(child.connected)child.send({kind:'stop',instance});
  let timer:ReturnType<typeof setTimeout>|undefined;
  try{await Promise.race([exited,new Promise<void>(done=>{timer=setTimeout(()=>{child.kill();done();},5000);})]);await drained;}
  finally{clearTimeout(timer);rpc.close();}
 };
 try{
  if(!child.pid)throw new PolicyError('unavailable');options.onSpawn?.(child.pid);
  await new Promise<void>((done,reject)=>{
   const cleanup=()=>{clearTimeout(timer);child.removeListener('message',message);child.removeListener('error',fail);child.removeListener('exit',fail);};
   const fail=()=>{cleanup();reject(new PolicyError('unavailable'));};
   const message=(m:any)=>{if(m?.instance!==instance)return;if(m.kind==='failed'){fail();return;}if(m.kind!=='ready')return;
    if(m.host!=='127.0.0.1'||!Number.isInteger(m.port)||m.port<1||m.port>65535||options.port!==0&&m.port!==options.port){fail();return;}port=m.port;cleanup();done();};
   const timer=setTimeout(fail,10000);child.on('message',message);child.once('error',fail);child.once('exit',fail);
   child.send({kind:'init',instance,expiresAt:options.expiresAt,port:options.port,public:structuredClone(options.public),tls:{key:options.tls.key,cert:options.tls.cert}});
  });
  return{instance,pid:child.pid!,port,exited,heartbeat:(ready:boolean,trialEnabled:boolean)=>{if(!stopping&&child.connected)child.send({kind:'heartbeat',instance,ready,trialEnabled});},budget:(trialEnabled:boolean)=>{if(!stopping&&child.connected)child.send({kind:'budget',instance,trialEnabled});},stop};
 }catch{await stop();throw new PolicyError('unavailable');}
}
