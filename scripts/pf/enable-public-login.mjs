import {spawnSync} from 'node:child_process';import {readFileSync,writeFileSync,existsSync} from 'node:fs';import {resolve} from 'node:path';
import {admin,root} from './common.mjs';import {copilotProfile as p} from './copilot-config.mjs';
const args=process.argv.slice(2);
if(args.length>1||args.some(a=>!['--enable-and-verify','--verify'].includes(a)))throw Error('Use preview, --enable-and-verify or --verify');
if(!args.length){console.log(JSON.stringify({clientId:p.loginClientId,issuer:p.loginIssuer,callback:p.callback,scope:'copilot.login',toolClientRemainsDisabled:true}));process.exit(0);}
const enable=args[0]==='--enable-and-verify',path=resolve(root,'.local/copilot/public-login-activation.json');
if(enable&&existsSync(path))throw Error('Activation receipt exists; reconcile rather than repeating enablement');
const ingress=JSON.parse(readFileSync(resolve(root,'.local/cloudflare-connector/ingress-activation.json'),'utf8'));
if(ingress.status!=='activated-ready')throw Error('Reviewed ingress must be active and verified');
const client=await admin('a','oauth/clients/'+p.loginClientId),tool=await admin('b','oauth/clients/'+p.toolClientId);
if(tool.enabled!==false||client.clientAuth?.type!=='SECRET'||JSON.stringify(client.grantTypes)!==JSON.stringify(['AUTHORIZATION_CODE'])||JSON.stringify(client.redirectUris)!==JSON.stringify([p.callback])||JSON.stringify(client.restrictedScopes)!==JSON.stringify(['copilot.login'])||client.restrictScopes!==true||client.defaultAccessTokenManagerRef?.id!=='copilotLoginJWT'||client.restrictToDefaultAccessTokenManager!==true)throw Error('Dedicated client profile drift');
if(client.enabled!==!enable)throw Error('Unexpected login client state; reconcile without changing other clients');
const receipt={status:enable?'enable-intent':'verification-in-progress',at:new Date().toISOString(),clientId:p.loginClientId,toolClientEnabled:false,tenantConfigurationChanged:false,microsoftCallbackContacted:false};
if(enable)writeFileSync(path,JSON.stringify(receipt,null,2),{flag:'wx',mode:0o600});
let success=false;
try{
 if(enable)await admin('a','oauth/clients/'+p.loginClientId,'PUT',{...client,enabled:true,name:'Copilot human login — public lab'});
 const result=spawnSync(process.execPath,['--experimental-strip-types','--test','tests/live-copilot/public-login.integration.ts'],{cwd:root,env:process.env,stdio:'inherit',windowsHide:true,timeout:90000});
 if(result.status!==0)throw Error('Public login verification failed');
 if((await admin('b','oauth/clients/'+p.toolClientId)).enabled!==false)throw Error('Tool client state changed');
 success=true;receipt.status='public-login-enabled-verified';receipt.completedAt=new Date().toISOString();
 receipt.verification='actual public HTTPS authorization-code flow, pinned JWT and three negative checks';writeFileSync(path,JSON.stringify(receipt,null,2),{mode:0o600});
 console.log(JSON.stringify({status:receipt.status,loginClientEnabled:true,toolClientEnabled:false,tenantConfigurationChanged:false}));
}finally{
 if(enable&&!success){const current=await admin('a','oauth/clients/'+p.loginClientId);await admin('a','oauth/clients/'+p.loginClientId,'PUT',{...current,enabled:false});receipt.status='verification-failed-login-disabled';writeFileSync(path,JSON.stringify(receipt,null,2),{mode:0o600});}
}
