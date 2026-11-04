import { readFileSync,mkdirSync,writeFileSync,renameSync,existsSync,unlinkSync,openSync,closeSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { randomUUID,createHash } from 'node:crypto';
import { planEnvironment,provisionEnvironment,ProvisioningError,type ProvisioningReceipt } from '../../src/provisioning/power-platform.ts';
import { runPacJson } from './pac-runner.ts';
const workspace=resolve(import.meta.dirname,'../..');
try{
 const {values}=parseArgs({options:{config:{type:'string',default:resolve(workspace,'infra/power-platform/environment.example.json')},apply:{type:'boolean',default:false},inspect:{type:'boolean',default:false},'approved-plan':{type:'string'}},allowPositionals:false});
 if(values.apply&&values.inspect)throw new ProvisioningError('invalid_arguments');
 const source=readFileSync(resolve(values.config),'utf8');if(source.length>10000)throw new ProvisioningError('invalid_configuration');const config=JSON.parse(source),plan=planEnvironment(config);
 const directory=resolve(workspace,'.local/power-platform'),identifier=createHash('sha256').update(JSON.stringify([plan.tenantId,plan.requested.domain])).digest('hex').slice(0,24),state=resolve(directory,identifier+'.json'),lock=resolve(directory,identifier+'.lock');
 const result=await provisionEnvironment(config,{apply:values.apply,inspect:values.inspect,approvedPlan:values['approved-plan']},{
  run:runPacJson,
  read:async()=>existsSync(state)?JSON.parse(readFileSync(state,'utf8'))as ProvisioningReceipt:undefined,
  write:async receipt=>{mkdirSync(directory,{recursive:true});const temporary=state+'.tmp-'+randomUUID();writeFileSync(temporary,JSON.stringify(receipt,null,2),{mode:0o600});renameSync(temporary,state);},
  lock:async work=>{mkdirSync(directory,{recursive:true});let fd:number;try{fd=openSync(lock,'wx',0o600);}catch{throw new ProvisioningError('operation_locked');}try{return await work();}finally{closeSync(fd);unlinkSync(lock);}},
 });
 if(!values.apply&&!values.inspect){mkdirSync(directory,{recursive:true});writeFileSync(resolve(directory,'last-plan.json'),JSON.stringify(result,null,2),{mode:0o600});}
 console.log(JSON.stringify(result,null,2));
}catch(error){console.error(JSON.stringify({error:error instanceof ProvisioningError?error.message:'unavailable',liveCreationVerified:false}));process.exitCode=1;}
