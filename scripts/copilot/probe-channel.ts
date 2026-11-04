import { readFile,stat,writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { probeAgentChannel,discoverChannel,classifyChannelEntrypoint } from '../../src/copilot/channel-probe.ts';
import {assertChannelBinding,assertBoundCredential} from '../../src/copilot/channel-binding.ts';
const root=resolve(import.meta.dirname,'../..'),directory=resolve(root,'.local/copilot');
try{
 const args=process.argv.slice(2);if(args.length>1||args.some(a=>a!=='--discover-only'))throw Error();
 const config=JSON.parse(await readFile(resolve(directory,'channel-settings.json'),'utf8'));
 if(args[0]==='--discover-only'){
  const safe={checkedAt:new Date().toISOString(),schemaName:config.schemaName,entrypointKind:classifyChannelEntrypoint(config),endpoint:await discoverChannel(config),credentialRead:false,conversationStarted:false,channelBindingVerified:false,federationVerified:false};
  await writeFile(resolve(directory,'channel-discovery.json'),JSON.stringify(safe,null,2),{mode:0o600});console.log(JSON.stringify(safe,null,2));process.exit(0);
 }
 let binding:unknown;try{binding=JSON.parse(await readFile(resolve(directory,'channel-credential-binding.json'),'utf8'));}catch{}
 assertChannelBinding(config,binding);
 const result=await probeAgentChannel(config,async()=>{
  const file=resolve(directory,'direct-line-secret.txt'),size=(await stat(file)).size;
  if(size<1||size>16000)throw Error();
  const secret=(await readFile(file,'utf8')).trim();assertBoundCredential(binding,secret);return secret;
 });
 const safe={checkedAt:new Date().toISOString(),...result};
 await writeFile(resolve(directory,'channel-probe.json'),JSON.stringify(safe,null,2),{mode:0o600});
 console.log(JSON.stringify(safe,null,2));
}catch(error){
 const code=error instanceof Error&&error.name==='ChannelProbeError'?error.message:'probe_unavailable';
 const safe={checkedAt:new Date().toISOString(),error:code,federationVerified:false};
 await writeFile(resolve(directory,'channel-probe.json'),JSON.stringify(safe,null,2),{mode:0o600});
 console.error(JSON.stringify(safe));process.exitCode=1;
}
