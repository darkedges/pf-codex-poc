import {createServer} from 'node:http';import {readFileSync,writeFileSync} from 'node:fs';import {resolve} from 'node:path';import {fileURLToPath} from 'node:url';import {createHash} from 'node:crypto';
export const apkPath='/downloads/federated-copilot-v5.apk';
export function apkHandler(bytes,expiresAt,now=Date.now,path=apkPath){
 if(!Buffer.isBuffer(bytes)||!Number.isSafeInteger(expiresAt)||!/^\/downloads\/federated-copilot-v[56789]\.apk$/.test(path))throw Error('invalid_download');
 return(request,response)=>{
  const allowed=request.url===path&&['GET','HEAD'].includes(request.method);
  if(!allowed||now()>=expiresAt){response.writeHead(404,{'Cache-Control':'no-store'});response.end();return;}
  response.writeHead(200,{'Content-Type':'application/vnd.android.package-archive','Content-Disposition':'attachment; filename="'+path.split('/').at(-1)+'"','Content-Length':bytes.length,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});response.end(request.method==='HEAD'?undefined:bytes);
 };
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const root=resolve(fileURLToPath(new URL('../',import.meta.url))),bytes=readFileSync(resolve(root,'.local/mobile/releases/federated-copilot-live-v5-candidate.apk'));
 if(createHash('sha256').update(bytes).digest('hex')!=='6aabdbab5b7307bd51c7d500a9c3af16bcf1b5eab5345a581fefcc12af7e6ae0')throw Error('apk_pin_mismatch');
 if(!['','--diagnostics','--diagnostics-v7','--diagnostics-v8','--diagnostics-v9'].includes(process.argv.slice(2).join()))throw Error('invalid_download_mode');
 const expiresAt=Date.now()+86400000,handlers=new Map([[apkPath,apkHandler(bytes,expiresAt)]]);
 if(process.argv[2])for(const version of process.argv[2]==='--diagnostics-v9'?[6,7,8,9]:process.argv[2]==='--diagnostics-v8'?[6,7,8]:process.argv[2]==='--diagnostics-v7'?[6,7]:[6]){
  const suffix=version===6?'diagnostics':version===7?'signin-fix':version===8?'browser-fix':'clock-fix',diagnostic=readFileSync(resolve(root,`.local/mobile/releases/federated-copilot-live-v${version}-${suffix}.apk`)),receipt=JSON.parse(readFileSync(resolve(root,`.local/mobile/releases/v${version}-${suffix}-receipt.json`),'utf8'));
  if(receipt.versionCode!==version||receipt.signingCertificateSha256!=='4d8b412744cc5a821ca093c265a6b4fa28317a520ec5f9445001839d9a14c68a'||!/^[a-f0-9]{64}$/.test(receipt.apkSha256)||createHash('sha256').update(diagnostic).digest('hex')!==receipt.apkSha256)throw Error('diagnostic_apk_pin_mismatch');
  const path=`/downloads/federated-copilot-v${version}.apk`;handlers.set(path,apkHandler(diagnostic,expiresAt,Date.now,path));
 }
 const server=createServer((request,response)=>{const handler=handlers.get(request.url);if(handler)handler(request,response);else{response.writeHead(404,{'Cache-Control':'no-store'});response.end();}});server.maxHeadersCount=24;server.headersTimeout=5000;server.requestTimeout=15000;
 server.listen(9469,'127.0.0.1',()=>writeFileSync(resolve(root,'.local/mobile/apk-download.json'),JSON.stringify({pid:process.pid,host:'127.0.0.1',port:9469,path:apkPath,paths:[...handlers.keys()],expiresAt:new Date(expiresAt).toISOString()},null,2)+'\n',{mode:0o600}));
 setTimeout(()=>server.close(),86400000).unref();
}
