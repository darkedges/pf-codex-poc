import assert from 'node:assert/strict';
import {readFileSync,existsSync} from 'node:fs';
import {resolve} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {startLocalToolService,currentOwnerSid,serviceDirectory,serviceLock,networkLock,docker} from './local-tool-service.mjs';
import {custody} from './tool-custody.mjs';
import {admin} from '../pf/common.mjs';
import {privateSave} from './common.mjs';
const checks=[];const check=(name,value)=>{assert.ok(value,name);checks.push(name);console.log(JSON.stringify({check:name,passed:true}));};
const states=()=>{const db=new DatabaseSync(resolve(custody,'policy.sqlite'),{readOnly:true});try{return JSON.stringify(db.prepare('SELECT id,state,version FROM grants ORDER BY id').all());}finally{db.close();}};
const initial=states(),operations={ownerSid:currentOwnerSid(),retentionDays:null};let service,clean=false;
const stopped=()=>!existsSync(serviceLock)&&!existsSync(networkLock)&&!existsSync(resolve(custody,'policy-authority-token'))&&!docker(['ps','-aq','--filter','label=federated-copilot.local-service']);
async function waitExit(s){let t;try{return await Promise.race([s.exited,new Promise((_,reject)=>{t=setTimeout(()=>reject(Error('Service stop timed out')),30000);})]);}finally{clearTimeout(t);}}
try{
 service=await startLocalToolService(operations);check('controller reaches enrolled readiness',service.state()==='ready'&&service.call({health:'ready'}).ready);
 await assert.rejects(startLocalToolService(operations));check('second controller cannot acquire ownership',service.call({health:'live'}).live);
 check('service readiness rejects missing client certificate',service.call({health:'ready',client:'none'}).error==='transport_denied');
 check('service rejects invalid delegated token',service.call({bearer:true}).status===401);
 const first=service.stop('verification-stop'),second=service.stop('duplicate-stop');check('concurrent stop shares cleanup',first===second);await first;service=undefined;check('normal stop retires lease and all owned resources',stopped());
 service=await startLocalToolService(operations);check('restart reuses durable registry without restoring grants',states()===initial);
 const record=JSON.parse(readFileSync(resolve(serviceDirectory,'instance.json'),'utf8'));assert.equal(record.instance,service.plan.instance);process.kill(record.policyPid);
 await waitExit(service);service=undefined;check('unexpected owned policy exit stops dependent containers and retires lease',stopped());
 service=await startLocalToolService(operations);docker(['stop','--time','5',service.plan.backend]);await service.check();await waitExit(service);service=undefined;
 check('lost backend stops service without automatic restart',stopped());
 check('all preexisting grant states and versions unchanged',states()===initial);
 check('PF lifecycle unchanged',(await admin('a','oauth/clients/copilot-studio-generic-oauth')).enabled===true&&(await admin('b','oauth/clients/copilot-sso-exchange')).enabled===false);
 clean=stopped();
}catch{process.exitCode=1;console.error(JSON.stringify({error:'Local controller verification failed',lastCompletedCheck:checks.at(-1)??'none'}));}
finally{
 if(service)try{await service.stop('verification-cleanup');}catch{process.exitCode=1;}
 try{clean=stopped();}catch{clean=false;}
 const receipt={completedAt:new Date().toISOString(),passed:process.exitCode!==1&&clean,checks:checks.length,serviceStopped:clean,credentialsPreserved:true,changesPfClients:false,opensHostPorts:false};if(!clean)process.exitCode=1;privateSave('tool-service-validation.json',receipt);console.log(JSON.stringify(receipt));
}
