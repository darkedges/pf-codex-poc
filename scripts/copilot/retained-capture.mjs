import {spawnSync} from 'node:child_process';
import {readPrivateCapture} from './vault-capture-access.mjs';
import {captureVaultPath} from './vault-capture.mjs';
import {retainedHttpPacket} from './retained-packet.mjs';
const args=process.argv.slice(2);
try{
 if(args.length!==2||!['--inspect','--copy-private'].includes(args[0]))throw Error();const id=args[1],path=captureVaultPath(id);const record=await readPrivateCapture(id),data=record.data,request=JSON.parse(data.request.body),url=new URL(data.request.url);
 if(args[0]==='--inspect')console.log(JSON.stringify({vaultPath:path.slice(1).replace('/data/','/'),version:record.metadata.version,state:data.state,originalTokenRetained:typeof request.token==='string'&&request.token.length>0,originalSignedUrlRetained:true,queryParameters:[...url.searchParams.keys()],allQueryValuesPresent:[...url.searchParams.values()].every(Boolean),rawResponseRetained:typeof data.rawResponse==='string',rawValuesPrinted:false}));
 else{
  if(process.platform!=='win32')throw Error();const packet=retainedHttpPacket(data);
  const result=spawnSync('pwsh',['-NoProfile','-Command','$privatePacket=[Console]::In.ReadToEnd(); Set-Clipboard -Value $privatePacket'],{input:packet,encoding:'utf8',windowsHide:true,timeout:15000,stdio:['pipe','ignore','pipe']});if(result.status!==0)throw Error();console.log(JSON.stringify({privateOriginalPacketCopiedToLocalClipboard:true,rawValuesPrinted:false}));
 }
}catch{console.error('Private capture action unavailable; no raw values printed');process.exitCode=1;}
