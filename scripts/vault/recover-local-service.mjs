import {readFileSync,existsSync,rmSync} from 'node:fs';
import {resolve} from 'node:path';
import {serviceDirectory,serviceLock,networkLock,currentOwnerSid,docker,inspectOwnedContainer,saveServiceJson} from './local-tool-service.mjs';
import {custody,protect} from './tool-custody.mjs';
import {servicePlan,ownedResource} from './service-lifecycle.mjs';
import {vault,privateLoad} from './common.mjs';
import {retireRuntimeLease} from './retire-lease.mjs';
export function processPresent(pid){if(!Number.isSafeInteger(pid)||pid<=0)throw Error('Invalid recorded process');try{process.kill(pid,0);return true;}catch(e){if(e.code==='ESRCH')return false;throw Error('Process ownership unavailable');}}
export async function recoverLocalToolService(){
 protect();const record=JSON.parse(readFileSync(resolve(serviceDirectory,'instance.json'),'utf8'));
 const plan=servicePlan({instance:record.instance,image:record.image,ownerSid:record.ownerSid,retentionDays:record.retentionDays});
 if(plan.ownerSid!==currentOwnerSid()||processPresent(record.pid)||record.policyPid&&processPresent(record.policyPid))throw Error('Recorded controller/policy may be alive; recovery refused');
 const locks=[serviceLock,networkLock];for(const file of locks)if(existsSync(file)&&JSON.parse(readFileSync(file,'utf8')).instance!==plan.instance)throw Error('Foreign execution lock; recovery refused');
 const policyLock=resolve(custody,'policy-service.lock'),leaseFile=resolve(custody,'policy-authority-lease.json'),tokenFile=resolve(custody,'policy-authority-token');
 if(existsSync(policyLock)&&JSON.parse(readFileSync(policyLock,'utf8')).ownerInstance!==plan.instance)throw Error('Foreign policy owner; recovery refused');
 let lease;if(existsSync(leaseFile)){lease=JSON.parse(readFileSync(leaseFile,'utf8'));if(lease.ownerInstance!==plan.instance)throw Error('Foreign signing lease; recovery refused');}else if(existsSync(tokenFile))throw Error('Untracked signing token; recovery refused');
 for(const name of [plan.tool,plan.backend])inspectOwnedContainer(name,plan);
 let network;if(docker(['network','ls','-q','--filter','name=^'+plan.network+'$'])){network=JSON.parse(docker(['network','inspect',plan.network]))[0];if(!ownedResource({name:network.Name,labels:network.Labels},plan))throw Error('Foreign network; recovery refused');}
 for(const name of [plan.tool,plan.backend]){const c=inspectOwnedContainer(name,plan);if(c)docker(['rm','-f',c.Id]);}
 if(network)docker(['network','rm',plan.network]);
 if(lease)await retireRuntimeLease(vault,privateLoad('bootstrap.json').root_token,lease.accessor);
 for(const name of ['bridge','probe']){const dir=resolve(serviceDirectory,'instances',plan.instance,name);if(!dir.startsWith(resolve(serviceDirectory,'instances')+'\\'))throw Error();if(existsSync(dir))rmSync(dir,{recursive:true,force:true});}
 for(const file of [leaseFile,tokenFile,policyLock,...locks])if(existsSync(file))rmSync(file);
 saveServiceJson('status.json',{state:'stopped',reason:'owned-crash-recovery',instance:plan.instance,at:new Date().toISOString(),opensHostPorts:false,automaticRestart:false});
 return{recovered:true,auditPreserved:true,credentialsPreserved:true};
}
