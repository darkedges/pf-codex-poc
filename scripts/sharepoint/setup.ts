import {spawn} from 'node:child_process';import {readFileSync,writeFileSync,mkdirSync,existsSync,openSync,closeSync,unlinkSync,renameSync} from 'node:fs';import {resolve} from 'node:path';import {randomUUID} from 'node:crypto';import {parseArgs} from 'node:util';
import {planSharePointSetup,applySharePointSetup,SharePointSetupError} from '../../src/provisioning/sharepoint.ts';
const root=resolve(import.meta.dirname,'../..'),directory=resolve(root,'.local/sharepoint'),requests=resolve(directory,'requests');
async function azure(value:unknown){
 mkdirSync(requests,{recursive:true,mode:0o700});const path=resolve(requests,randomUUID()+'.json');writeFileSync(path,JSON.stringify(value),{mode:0o600,flag:'wx'});
 try{return await new Promise<any>((done,reject)=>{let output='',bytes=0;const child=spawn('pwsh.exe',['-NoProfile','-File',resolve(root,'scripts/sharepoint/azure-request.ps1'),'-RequestFile',path],{windowsHide:true,stdio:['ignore','pipe','pipe']}),timer=setTimeout(()=>{child.kill();reject(Error());},60000);child.stdout.on('data',chunk=>{bytes+=chunk.length;if(bytes>1048576){child.kill();reject(Error());}else output+=chunk;});child.stderr.on('data',()=>{});child.once('error',()=>{clearTimeout(timer);reject(Error());});child.once('exit',code=>{clearTimeout(timer);try{if(code!==0)throw Error();done(JSON.parse(output));}catch{reject(Error());}});});}finally{unlinkSync(path);}
}
try{
 const {values}=parseArgs({options:{config:{type:'string',default:'infra/sharepoint/poc-site.json'},apply:{type:'boolean'},'approved-plan':{type:'string'}},allowPositionals:false}),config=JSON.parse(readFileSync(resolve(root,values.config),'utf8')),plan=planSharePointSetup(config);
 mkdirSync(directory,{recursive:true,mode:0o700});
 if(!values.apply){writeFileSync(resolve(directory,'last-plan.json'),JSON.stringify(plan,null,2),{mode:0o600});console.log(JSON.stringify({status:'planned',...plan},null,2));}
 else{const path=resolve(directory,plan.hash+'.receipt.json'),result=await applySharePointSetup(config,values['approved-plan']??'',{
 identity:()=>azure({kind:'identity'}),request:(method,path,body)=>azure({kind:'graph',method,url:'https://graph.microsoft.com/v1.0'+path,body}),read:async()=>existsSync(path)?JSON.parse(readFileSync(path,'utf8')):undefined,
 write:async receipt=>{const temporary=path+'.'+randomUUID()+'.tmp';writeFileSync(temporary,JSON.stringify(receipt,null,2),{mode:0o600,flag:'wx'});renameSync(temporary,path);},
 lock:async fn=>{const lock=resolve(directory,'setup.lock');let fd:number;try{fd=openSync(lock,'wx',0o600);}catch{throw new SharePointSetupError('operation_locked');}try{return await fn();}finally{closeSync(fd);unlinkSync(lock);}}
 });console.log(JSON.stringify(result,null,2));}
}catch(e){console.error(JSON.stringify({error:e instanceof SharePointSetupError?e.message:'unavailable',graphDataAccessVerified:false,automaticRetry:false}));process.exitCode=1;}
