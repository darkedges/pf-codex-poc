import {spawn,spawnSync} from 'node:child_process';
import {readFileSync,existsSync} from 'node:fs';
import {resolve} from 'node:path';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
import {root} from '../pf/common.mjs';
import {custody} from './tool-custody.mjs';
import {serviceDirectory,serviceLock,networkLock,docker} from './local-tool-service.mjs';
import {processPresent,recoverLocalToolService} from './recover-local-service.mjs';
import {privateSave} from './common.mjs';
const checks=[];const check=(name,value)=>{assert.ok(value,name);checks.push(name);console.log(JSON.stringify({check:name,passed:true}));};
const command=action=>spawnSync(process.execPath,['--experimental-strip-types',resolve(root,'scripts/vault/service.mjs'),action],{cwd:root,encoding:'utf8',windowsHide:true,timeout:40000});
async function worker(){const child=spawn(process.execPath,['--experimental-strip-types',resolve(root,'scripts/vault/service-verification-worker.mjs')],{cwd:root,stdio:['ignore','ignore','ignore','ipc'],windowsHide:true});await new Promise((done,reject)=>{const timer=setTimeout(()=>reject(Error('Worker deadline')),45000);child.once('error',()=>{clearTimeout(timer);reject(Error('Worker unavailable'));});child.once('exit',()=>{clearTimeout(timer);reject(Error('Worker stopped'));});child.once('message',m=>{clearTimeout(timer);if(m?.ready)done();else reject(Error('Worker readiness invalid'));});});return child;}
async function gone(pid){const until=Date.now()+15000;while(processPresent(pid)&&Date.now()<until)await new Promise(done=>setTimeout(done,250));assert.equal(processPresent(pid),false);}
const auditPath=resolve(serviceDirectory,'audit/tool-access.jsonl'),digest=()=>createHash('sha256').update(readFileSync(auditPath)).digest('hex');
let child,record,clean=false;
try{
 child=await worker();record=JSON.parse(readFileSync(resolve(serviceDirectory,'instance.json'),'utf8'));assert.equal(record.pid,child.pid);
 check('status reports current controller readiness',JSON.parse(command('--status').stdout).state==='ready');
 const denied=command('--recover');check('crash recovery refuses a live controller',denied.status===1&&JSON.parse(command('--status').stdout).state==='ready');
 check('stop command completes owned cleanup',command('--stop').status===0);await gone(child.pid);child=undefined;
 check('command stop leaves no signing token or execution lock',!existsSync(serviceLock)&&!existsSync(networkLock)&&!existsSync(resolve(custody,'policy-authority-token')));
 child=await worker();record=JSON.parse(readFileSync(resolve(serviceDirectory,'instance.json'),'utf8'));assert.equal(record.pid,child.pid);const retained=digest();
 child.kill();await gone(child.pid);await gone(record.policyPid);child=undefined;
 check('cold controller crash leaves tracked recovery material',existsSync(serviceLock)&&existsSync(resolve(custody,'policy-authority-lease.json')));
 const recovered=command('--recover');check('recovery command removes only owned crash resources',recovered.status===0&&JSON.parse(recovered.stdout).recovered===true&&!docker(['ps','-aq','--filter','label=federated-copilot.local-service']));
 check('crash recovery preserves journal and retires tracked lease',digest()===retained&&!existsSync(serviceLock)&&!existsSync(networkLock)&&!existsSync(resolve(custody,'policy-authority-token')));
 clean=true;
}catch{process.exitCode=1;console.error(JSON.stringify({error:'Controller command verification failed',lastCompletedCheck:checks.at(-1)??'none'}));}
finally{
 if(child&&child.exitCode===null){child.kill();try{await gone(child.pid);}catch{}}
 if(!clean&&record)try{await gone(record.policyPid);await recoverLocalToolService();clean=true;}catch{}
 const receipt={completedAt:new Date().toISOString(),passed:process.exitCode!==1&&clean,checks:checks.length,serviceStopped:clean,auditPreserved:true,opensHostPorts:false};privateSave('tool-service-command-validation.json',receipt);console.log(JSON.stringify(receipt));
}
