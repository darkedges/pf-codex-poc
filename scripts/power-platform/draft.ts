import { readFileSync,existsSync,mkdirSync,writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { runPacJson } from './pac-runner.ts';
import { planEnvironment,ProvisioningError } from '../../src/provisioning/power-platform.ts';
const workspace=resolve(import.meta.dirname,'../..'),directory=resolve(workspace,'.local/power-platform'),path=resolve(directory,'environment.json');
try{
 if(existsSync(path))throw new ProvisioningError('draft_already_exists');
 const profile=await runPacJson(['auth','who','--json'],30000);
 if(!Array.isArray(profile))throw new ProvisioningError('response_invalid');
 const tenants=profile.filter(r=>r?.Key?.toLowerCase().replace(/[^a-z0-9]/g,'')==='tenantid');
 if(tenants.length!==1)throw new ProvisioningError('authentication_required');
 const config=JSON.parse(readFileSync(resolve(workspace,'infra/power-platform/environment.example.json'),'utf8'));config.tenantId=tenants[0].Value;
 const plan=planEnvironment(config);mkdirSync(directory,{recursive:true});writeFileSync(path,JSON.stringify(config,null,2),{mode:0o600});
 console.log(JSON.stringify({draft:path,cloudChanges:false,blockers:plan.blockers,approved:false},null,2));
}catch(error){console.error(JSON.stringify({error:error instanceof ProvisioningError?error.message:'unavailable',cloudChanges:false}));process.exitCode=1;}
