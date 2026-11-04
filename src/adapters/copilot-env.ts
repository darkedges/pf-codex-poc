import { open,stat } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { CopilotError,type DirectLineConfig,type DirectLineDependencies } from './copilot.ts';
import { DirectLineAdapter } from './direct-line.ts';
async function readBoundedFile(path:string,limit:number,signal:AbortSignal){
 const file=await open(path,'r');
 try{
  const metadata=await file.stat();if(!metadata.isFile()||metadata.size<1||metadata.size>limit)throw Error();
  const buffer=Buffer.alloc(limit+1);let bytes=0;
  for(;;){signal.throwIfAborted();const result=await file.read(buffer,bytes,buffer.length-bytes,null);bytes+=result.bytesRead;if(bytes>limit)throw Error();if(result.bytesRead===0)break;}
  signal.throwIfAborted();return buffer.subarray(0,bytes).toString('utf8');
 }finally{await file.close();}
}
// A secret-manager mounted file may rotate between requests. The value is never configuration/output.
export async function directLineFromEnvironment(dependencies:Omit<DirectLineDependencies,'secret'>,env:Record<string,string|undefined>=process.env){
 try{
  if(env.COPILOT_MODE!=='directline'||!env.COPILOT_DIRECT_LINE_SECRET_FILE||!isAbsolute(env.COPILOT_DIRECT_LINE_SECRET_FILE)||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error();
  if(Number(!!env.COPILOT_DIRECT_LINE_CONFIG)+Number(!!env.COPILOT_DIRECT_LINE_CONFIG_FILE)!==1)throw Error();
  if(env.COPILOT_DIRECT_LINE_CONFIG_FILE&&!isAbsolute(env.COPILOT_DIRECT_LINE_CONFIG_FILE))throw Error();
  const source=env.COPILOT_DIRECT_LINE_CONFIG??await readBoundedFile(env.COPILOT_DIRECT_LINE_CONFIG_FILE!,50000,AbortSignal.timeout(5000));if(source.length>50000)throw Error();
  const config=JSON.parse(source)as DirectLineConfig,path=env.COPILOT_DIRECT_LINE_SECRET_FILE;
  const metadata=await stat(path);if(!metadata.isFile()||metadata.size<1||metadata.size>16000)throw Error();
  return new DirectLineAdapter(config,{...dependencies,secret:async signal=>{try{return(await readBoundedFile(path,16000,signal)).trim();}catch{throw new CopilotError('unavailable');}}});
 }catch{throw new CopilotError('configuration');}
}
