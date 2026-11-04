import {readFileSync,writeFileSync,existsSync} from 'node:fs';import {resolve} from 'node:path';import {fileURLToPath} from 'node:url';
import {root} from '../pf/common.mjs';import {assertMobileActivation,approvedMobileProfile} from './mobile-activation-guard.mjs';import {openMobileRuntime} from './mobile-runtime.ts';import {startMobileHttpsHost} from '../../src/mobile/https-host.ts';
import {claimMobileServiceLock} from './mobile-service-lock.mjs';
const directory=resolve(root,'.local/tool-vault/mobile'),path=(name:string)=>resolve(directory,name),save=(name:string,value:unknown)=>writeFileSync(path(name),JSON.stringify(value,null,2)+'\n',{mode:0o600});
export async function serveMobile(){
 const manifest=assertMobileActivation(),profile=approvedMobileProfile();if(!existsSync(path('activation-ready.json')))throw Error('mobile_activation_not_ready');
 const lock=claimMobileServiceLock(path('service.lock'),manifest.ownerSid);let runtime:Awaited<ReturnType<typeof openMobileRuntime>>|undefined,host:Awaited<ReturnType<typeof startMobileHttpsHost>>|undefined,timer:ReturnType<typeof setInterval>|undefined,stopped=false,stopping:Promise<void>|undefined,complete!:()=>void;
 const done=new Promise<void>(resolve=>complete=resolve),status=(state:string)=>save('service-status.json',{state,pid:process.pid,instance:lock.record.instance,at:new Date().toISOString(),host:'127.0.0.1',port:9468,automaticOperatorAccess:false});
 const stop=(reason:string)=>stopping??=(async()=>{stopped=true;clearInterval(timer);status('stopping');try{await host?.stop();runtime?.close();status('stopped');lock.release();}catch{status('cleanup-required');process.exitCode=1;}finally{save('service-stop.json',{reason,at:new Date().toISOString()});complete();}})();
 const signal=()=>{void stop('signal');};
 try{
  status('starting');runtime=await openMobileRuntime(profile,()=>{if(stopped)throw Error('mobile_stopped');assertMobileActivation();});
  if(!runtime.ready())throw Error('mobile_dependencies_unavailable');host=await startMobileHttpsHost({origin:profile.origin,port:9468,tls:runtime.tls,androidCertificateSha256:manifest.apk.signingCertificateSha256},runtime.application.api);
  status('ready');runtime.signal.addEventListener('abort',()=>{void stop('dependency-unavailable');},{once:true});
  timer=setInterval(()=>{try{if(!runtime!.ready())throw Error();if(existsSync(path('stop-request.json'))){const request=JSON.parse(readFileSync(path('stop-request.json'),'utf8'));if(request.pid===process.pid&&request.instance===lock.record.instance){void stop('operator-stop');return;}}status('ready');}catch{void stop('dependency-unavailable');}},10000);
  process.once('SIGINT',signal);process.once('SIGTERM',signal);await done;
 }catch{await stop('startup-failed');throw Error('mobile_service_unavailable');}
 finally{clearInterval(timer);process.removeListener('SIGINT',signal);process.removeListener('SIGTERM',signal);}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){try{const args=process.argv.slice(2).join();if(args==='--serve')await serveMobile();else if(args==='--status')console.log(existsSync(path('service-status.json'))?readFileSync(path('service-status.json'),'utf8'):'{"state":"not-started"}');else if(args==='--stop'){assertMobileActivation();const s=JSON.parse(readFileSync(path('service-status.json'),'utf8'));save('stop-request.json',{pid:s.pid,instance:s.instance});console.log('{"stopRequested":true}');}else console.log('{"action":"preview","active":false,"port":9468,"microsoftRequests":0}');}catch{console.error('Mobile service unavailable. No fallback or automatic credential replay.');process.exitCode=1;}}
