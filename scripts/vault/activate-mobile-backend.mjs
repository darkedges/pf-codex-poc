import {readFileSync,writeFileSync,existsSync,openSync,closeSync,fsyncSync,unlinkSync} from 'node:fs';import {resolve} from 'node:path';import {fileURLToPath} from 'node:url';
import {root,admin} from '../pf/common.mjs';import {vault,privateLoad} from './common.mjs';import {documentStageStep,documentStageHash} from '../pf/document-stage-step.mjs';import {documentChatPfFingerprint} from '../pf/document-chat-pf-lease.mjs';import {assertMobileActivation} from './mobile-activation-guard.mjs';import {enrollMobileOriginTls} from './mobile-origin-tls.mjs';
const dir=resolve(root,'.local/tool-vault/mobile'),review=resolve(root,'.local/mobile/activation-review'),json=p=>JSON.parse(readFileSync(p,'utf8'));
function save(path,v,exclusive=false){const fd=openSync(path,exclusive?'wx':'w',0o600);try{writeFileSync(fd,JSON.stringify(v,null,2)+'\n');fsyncSync(fd);}finally{closeSync(fd);}}
const normalized=v=>{if(!v)return v;const c=structuredClone(v);delete c.modificationDate;return c;};
export async function activateMobileBackend(){
 assertMobileActivation();const lockPath=resolve(dir,'activation.lock'),lock=openSync(lockPath,'wx',0o600);let phase='preflight';
 try{
  const plan=json(resolve(review,'login-plan.json')),before=json(resolve(review,'pf-before.json')),profile=json(resolve(review,'profile.template.json')),journalPath=resolve(dir,'activation-journal.json'),planHash=documentStageHash(plan),journal=existsSync(journalPath)?json(journalPath):{purpose:'mobile-backend-activation',planHash,steps:{}};
  if(journal.planHash!==planHash||Object.values(journal.steps).some(s=>s.state==='pending'))throw Error('mobile_activation_uncertain');
  const clients=new Map(Object.keys(before).map(v=>[v.split(':').slice(1).join(':'),v.split(':')[0]]));clients.set('mobile-copilot-login','a');
  const control=async(node,path,method='GET',body)=>{assertMobileActivation();phase=node+':'+method+':'+path;let allowed=false;
   if(method==='GET')allowed=node==='a'&&['oauth/accessTokenManagers/mobileLoginJWT','oauth/openIdConnect/policies/mobileLoginOIDC','oauth/accessTokenMappings'].includes(path)||[...clients].some(([id,n])=>n===node&&path==='oauth/clients/'+id);
   if(method==='POST')allowed=node==='a'&&(path==='oauth/clients'&&body?.clientId==='mobile-copilot-login'&&body.enabled===false||path==='oauth/accessTokenManagers'&&body?.id==='mobileLoginJWT'||path==='oauth/openIdConnect/policies'&&body?.id==='mobileLoginOIDC'||path==='oauth/accessTokenMappings'&&body?.accessTokenManagerRef?.id==='mobileLoginJWT');
   if(method==='PUT')allowed=[...clients].some(([id,n])=>n===node&&path==='oauth/clients/'+id&&body?.clientId===id);
   if(!allowed)throw Error('mobile_activation_path');return admin(node,path,method,body);
  };
  const get=async(node,path)=>{try{return await control(node,path);}catch(e){if(e.status===404)return null;throw e;}};
  const step=(id,read,expected,write,previousHash)=>documentStageStep({id,journal,save:j=>save(journalPath,j),read,expected,write,previousHash});
  const initial={...plan.client,restrictToDefaultAccessTokenManager:false,oidcPolicy:{...plan.client.oidcPolicy,policyGroup:{id:'consentLoginOIDC'}}};delete initial.defaultAccessTokenManagerRef;
  const readClient=async id=>normalized(await get(clients.get(id),'oauth/clients/'+id));
  if(!journal.steps['login-final'])await step('login-initial',()=>readClient('mobile-copilot-login'),initial,()=>control('a','oauth/clients','POST',initial));
  await step('login-manager',()=>get('a','oauth/accessTokenManagers/mobileLoginJWT'),plan.tokenManager,()=>control('a','oauth/accessTokenManagers','POST',plan.tokenManager));
  await step('login-oidc',()=>get('a','oauth/openIdConnect/policies/mobileLoginOIDC'),plan.oidcPolicy,()=>control('a','oauth/openIdConnect/policies','POST',plan.oidcPolicy));
  const readMapping=async()=>{const response=await control('a','oauth/accessTokenMappings'),all=response.items??response,m=all.filter(v=>v.context?.type==='DEFAULT'&&v.accessTokenManagerRef?.id==='mobileLoginJWT');if(m.length>1)throw Error();return m[0]??null;};
  await step('login-mapping',readMapping,plan.mapping,()=>control('a','oauth/accessTokenMappings','POST',plan.mapping));
  if(!journal.steps['enable-mobile-copilot-login'])await step('login-final',()=>readClient('mobile-copilot-login'),plan.client,()=>control('a','oauth/clients/mobile-copilot-login','PUT',plan.client),journal.steps['login-initial'].hash);
  phase='origin-tls';const token=privateLoad('bootstrap.json').root_token,tls=await enrollMobileOriginTls((path,options={})=>{assertMobileActivation();if(path!=='/mobile-runtime/data/credentials'||!['GET','POST'].includes(options.method??'GET'))throw Error('mobile_tls_path');return vault(path,{...options,token});});
  const readyProfile={...profile,serverTlsCertificateSha256:tls.certificateSha256},profilePath=resolve(dir,'runtime-profile.json');if(existsSync(profilePath)){if(documentStageHash(json(profilePath))!==documentStageHash(readyProfile))throw Error('mobile_runtime_profile_drift');}else save(profilePath,readyProfile,true);
  for(const [id,node]of clients){const current=await control(node,'oauth/clients/'+id),entry=journal.steps['enable-'+id];if(entry?.state==='confirmed'){await step('enable-'+id,()=>readClient(id),normalized({...current,enabled:true}),async()=>{throw Error('unexpected enable repeat');});continue;}
   if(current.enabled!==false||id!=='mobile-copilot-login'&&documentChatPfFingerprint(current)!==before[node+':'+id].fingerprint)throw Error('mobile_client_drift');
   await step('enable-'+id,()=>readClient(id),normalized({...current,enabled:true}),()=>control(node,'oauth/clients/'+id,'PUT',{...current,enabled:true}),documentStageHash(normalized(current)));
  }
  const receipt={status:'BACKEND_CONFIGURED',clientsEnabled:5,newLoginClient:'mobile-copilot-login',credentialVersion:2,certificateSha256:tls.certificateSha256,pfTokenRequests:0,microsoftRequests:0,publicRouteChanged:false};save(resolve(dir,'activation-ready.json'),receipt);return receipt;
 }catch{save(resolve(dir,'activation-status.json'),{status:'INCOMPLETE',phase,at:new Date().toISOString(),noAutomaticRetry:true});throw Error('mobile_backend_activation_incomplete');}
 finally{closeSync(lock);unlinkSync(lockPath);}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){try{if(process.argv.slice(2).join()!=='--activate')throw Error();console.log(JSON.stringify(await activateMobileBackend()));}catch{console.error('Mobile backend activation stopped. Preserve intent and reconcile owned objects before any repeat.');process.exitCode=1;}}
