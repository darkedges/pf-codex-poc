import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve,sep } from 'node:path';
import { ProvisioningError } from '../../src/provisioning/power-platform.ts';
import { confirmEmptyPacList } from '../../src/provisioning/pac-output.ts';
const workspace=resolve(import.meta.dirname,'../..');
export async function runPacJson(args:string[],timeoutMs=60000,confirmingEmpty=false):Promise<unknown>{
 try{
  const permitted=args[0]==='auth'&&args[1]==='who'||args[0]==='admin'&&['list','create'].includes(args[1])||args[0]==='environment-management'&&args[1]==='get-environment-by-id-for-user';
  if(!permitted||(!args.includes('--json')&&!(confirmingEmpty&&args[0]==='admin'&&args[1]==='list')))throw Error();
  const tool=JSON.parse(readFileSync(resolve(workspace,'infra/power-platform/pac-tool.json'),'utf8')),runtime=JSON.parse(readFileSync(resolve(workspace,'infra/power-platform/dotnet-runtime.json'),'utf8'));
  const root=resolve(workspace,'.local/tools','pac-'+tool.version),installed=JSON.parse(readFileSync(resolve(root,'installation.json'),'utf8'));
  const entry=resolve(root,installed.entryPoint);if(installed.sha512!==tool.sha512||!entry.startsWith(root+sep))throw Error();
  const host=resolve(workspace,'.local/tools','dotnet-'+runtime.version,'dotnet.exe');
  const output=await new Promise<string>((done,reject)=>{
   const child=spawn(host,[entry,...args],{cwd:workspace,windowsHide:true,shell:false,stdio:['ignore','pipe','pipe']});
   let stdout='',bytes=0;const timer=setTimeout(()=>{child.kill();reject(new ProvisioningError('cli_unavailable'));},timeoutMs);
   child.stdout.on('data',chunk=>{bytes+=chunk.length;if(bytes>1048576){child.kill();reject(new ProvisioningError('response_invalid'));}else stdout+=chunk;});
   child.stderr.on('data',chunk=>{bytes+=chunk.length;if(bytes>1048576){child.kill();reject(new ProvisioningError('response_invalid'));}});
   child.once('error',()=>{clearTimeout(timer);reject(new ProvisioningError('cli_unavailable'));});
   child.once('close',code=>{clearTimeout(timer);if(code!==0){reject(new ProvisioningError('cli_unavailable'));return;}done(stdout);});
  });
  if(confirmingEmpty)return confirmEmptyPacList(output);
  if(!output.trim()&&args[0]==='admin'&&args[1]==='list')return await runPacJson(args.filter(arg=>arg!=='--json'),timeoutMs,true);
  try{return JSON.parse(output.replace(/^\uFEFF/,''));}catch{throw new ProvisioningError('response_invalid');}
 }catch(error){throw error instanceof ProvisioningError?error:new ProvisioningError('cli_unavailable');}
}
