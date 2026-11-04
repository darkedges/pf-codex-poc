import {spawn} from 'node:child_process';import {readFileSync} from 'node:fs';import {resolve,sep} from 'node:path';
const root=resolve(import.meta.dirname,'../..');
export async function withPowerPlatformToken(action){
 let token;
 try{const tool=JSON.parse(readFileSync(resolve(root,'infra/power-platform/pac-tool.json'),'utf8')),runtime=JSON.parse(readFileSync(resolve(root,'infra/power-platform/dotnet-runtime.json'),'utf8')),folder=resolve(root,'.local/tools','pac-'+tool.version),installed=JSON.parse(readFileSync(resolve(folder,'installation.json'),'utf8')),entry=resolve(folder,installed.entryPoint);if(installed.sha512!==tool.sha512||!entry.startsWith(folder+sep))throw Error();
  const raw=await new Promise((done,reject)=>{const child=spawn(resolve(root,'.local/tools','dotnet-'+runtime.version,'dotnet.exe'),[entry,'auth','token'],{windowsHide:true,stdio:['ignore','pipe','pipe']}),timer=setTimeout(()=>{child.kill();reject(Error());},30000);let output='',size=0;child.stdout.on('data',chunk=>{size+=chunk.length;if(size>65536){child.kill();reject(Error());}else output+=chunk;});child.stderr.on('data',()=>{});child.once('error',()=>{clearTimeout(timer);reject(Error());});child.once('exit',code=>{clearTimeout(timer);code===0?done(output):reject(Error());});});
  token=String(raw).match(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/)?.[0];if(!token)throw Error();const claims=JSON.parse(Buffer.from(token.split('.')[1],'base64url').toString());if(claims.aud!=='https://api.powerplatform.com'||claims.tid!=='4161be3f-bf2b-41d4-a02b-e6f82b529d53'||claims.exp*1000<=Date.now()+60000)throw Error();return await action(token);
 }catch{throw Error('Approved Power Platform API request unavailable');}finally{token=undefined;}
}
