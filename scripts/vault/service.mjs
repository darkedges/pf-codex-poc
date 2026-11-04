import {readFileSync,existsSync} from 'node:fs';
import {resolve} from 'node:path';
import {protect} from './tool-custody.mjs';
import {startLocalToolService,currentOwnerSid,serviceDirectory,serviceLock,saveServiceJson} from './local-tool-service.mjs';
import {recoverLocalToolService,processPresent} from './recover-local-service.mjs';
const args=process.argv.slice(2);
try{
 if(!args.length){console.log(JSON.stringify({purpose:'local private tool service controller',actions:['configure','serve','status','stop','recover'],opensHostPorts:false,changesPfClients:false,automaticRestart:false,requiresOperationsSelection:true}));}
 else if(args.length===3&&args[0]==='--configure'&&args[1]==='--retention-days'&&['1','7'].includes(args[2])){
  protect();if(existsSync(serviceLock))throw Error();
  const {mkdirSync}=await import('node:fs');mkdirSync(serviceDirectory,{recursive:true,mode:0o700});saveServiceJson('operations.json',{ownerSid:currentOwnerSid(),retentionDays:Number(args[2])});console.log(JSON.stringify({configured:true,retentionDays:Number(args[2]),started:false}));
 }else if(args.length===1&&args[0]==='--serve'){
  protect();const operations=JSON.parse(readFileSync(resolve(serviceDirectory,'operations.json'),'utf8'));if(![1,7].includes(operations.retentionDays))throw Error();
  const service=await startLocalToolService(operations);const stop=()=>{void service.stop('signal').catch(()=>{process.exitCode=1;});};process.once('SIGINT',stop);process.once('SIGTERM',stop);
  console.log(JSON.stringify({state:'ready',opensHostPorts:false,automaticRestart:false}));const result=await service.exited;if(!result.stopped)process.exitCode=1;console.log(JSON.stringify(result));
 }else if(args.length===1&&args[0]==='--status'){
  protect();const status=JSON.parse(readFileSync(resolve(serviceDirectory,'status.json'),'utf8')),age=Math.max(0,Math.floor((Date.now()-Date.parse(status.at))/1000));
  const locked=existsSync(serviceLock),state=!locked&&status.state==='stopped'?'stopped':locked&&age<=75&&['ready','unready','starting','draining','recovery-required'].includes(status.state)?status.state:'unknown';
  console.log(JSON.stringify({state,observedSecondsAgo:Number.isFinite(age)?age:null,controllerLockPresent:locked,opensHostPorts:false}));
 }else if(args.length===1&&args[0]==='--stop'){
  protect();const instance=JSON.parse(readFileSync(resolve(serviceDirectory,'instance.json'),'utf8'));if(!existsSync(serviceLock)||!processPresent(instance.pid))throw Error('Recovery required');saveServiceJson('stop-request.json',{instance:instance.instance});
  const until=Date.now()+30000;while(existsSync(serviceLock)&&Date.now()<until)await new Promise(done=>setTimeout(done,500));if(existsSync(serviceLock))throw Error();console.log(JSON.stringify({stopped:true}));
 }else if(args.length===1&&args[0]==='--recover'){console.log(JSON.stringify(await recoverLocalToolService()));}
 else throw Error();
}catch{console.error('Local service action failed; inspect the restricted status and recovery procedure');process.exitCode=1;}
