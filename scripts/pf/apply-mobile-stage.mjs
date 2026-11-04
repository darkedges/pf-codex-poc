import {readFileSync,writeFileSync,existsSync,openSync,closeSync,fsyncSync,unlinkSync} from 'node:fs';import {resolve} from 'node:path';import {fileURLToPath} from 'node:url';
import {root,admin,call,nodes} from './common.mjs';import {stageMobileProfiles} from './mobile-stage.mjs';import {mobilePfPlan} from './mobile-profile.mjs';
import {documentStageHash} from './document-stage-step.mjs';import {assertMobileApproval} from '../vault/mobile-enrollment.mjs';
const directory=resolve(root,'.local/tool-vault/mobile'),json=p=>JSON.parse(readFileSync(p,'utf8'));
function save(path,value,exclusive=false){const fd=openSync(path,exclusive?'wx':'w',0o600);try{writeFileSync(fd,JSON.stringify(value,null,2)+'\n');fsyncSync(fd);}finally{closeSync(fd);}}
export async function applyMobileStage(){
 assertMobileApproval();const receipt=json(resolve(directory,'enrollment-receipt.json'));if(receipt.status!=='ENROLLED'||receipt.verificationRuns<1||receipt.verificationRuns>2)throw Error('mobile_custody_not_ready');
 const lockPath=resolve(directory,'pf-stage.lock'),lock=openSync(lockPath,'wx',0o600);let stage='preflight';
 try{
  const pins=json(resolve(directory,'public-keys.json')),materials={};for(const kind of ['chat','document'])materials[kind]={authority:pins.authority,agent:pins.agent,clientA:{keys:[pins.clients[`mobile-${kind}-gateway-1`]]},clientB:{keys:[pins.clients[`mobile-${kind}-gateway-2`]]},upstream:pins.agent};
  const plans=Object.fromEntries(['chat','document'].map(k=>[k,mobilePfPlan(k,materials[k])])),paths={};
  for(const node of ['a','b']){paths[node]={clients:new Set(),processors:new Set(),policies:new Set(),managers:new Set(),signers:new Set()};for(const p of Object.values(plans)){const n=p[node];paths[node].clients.add(n.client.clientId);paths[node].processors.add(n.subjectProcessor.id);if(n.actorProcessor)paths[node].processors.add(n.actorProcessor.id);paths[node].policies.add(n.policy.id);paths[node].managers.add(n.tokenManager.id);paths[node].signers.add(n.signingId);}}
  const guardedAdmin=async(node,path,method='GET',body)=>{
   assertMobileApproval();const p=paths[node];if(!p)throw Error('mobile_pf_node');stage=node+':'+method+':'+path;
   let allowed=false;
   if(method==='GET'){allowed=['oauth/authServerSettings','oauth/accessTokenMappings'].includes(path)||[...p.clients].some(id=>path==='oauth/clients/'+id)||[...p.processors].some(id=>path==='idp/tokenProcessors/'+id)||[...p.policies].some(id=>path==='oauth/tokenExchange/processor/policies/'+id)||[...p.managers].some(id=>path==='oauth/accessTokenManagers/'+id)||[...p.signers].some(id=>path==='keyPairs/signing/'+id);}
   else if(method==='POST')allowed=path==='keyPairs/signing/generate'&&p.signers.has(body?.id)&&body.keyAlgorithm==='RSA'&&body.keySize===4096&&body.validDays===30||path==='idp/tokenProcessors'&&p.processors.has(body?.id)||path==='oauth/tokenExchange/processor/policies'&&p.policies.has(body?.id)||path==='oauth/clients'&&p.clients.has(body?.clientId)&&body.enabled===false||path==='oauth/accessTokenManagers'&&p.managers.has(body?.id)||path==='oauth/accessTokenMappings'&&p.policies.has(body?.context?.contextRef?.id)&&p.managers.has(body?.accessTokenManagerRef?.id);
   else if(method==='PUT')allowed=p.clients.has(body?.clientId)&&path==='oauth/clients/'+body.clientId&&body.enabled===false;
   if(!allowed)throw Error('mobile_pf_path');return admin(node,path,method,body);
  };
  const path=resolve(directory,'pf-stage-journal.json'),profileHash=documentStageHash(Object.fromEntries(Object.entries(materials).map(([k,v])=>[k,{...v,upstream:undefined}]))),journal=existsSync(path)?json(path):{purpose:'mobile-disabled-staging',profileHash,steps:{}};
  const result=await stageMobileProfiles({materials,journal,save:j=>save(path,j),admin:guardedAdmin,publishedKeys:async(node,kid)=>{
   assertMobileApproval();const r=await call(nodes[node].issuer+'/pf/JWKS');if(r.status!==200||!Array.isArray(r.value?.keys))throw Error('mobile_pf_jwks');const keys=r.value.keys.filter(k=>k.kid===kid);if(keys.length!==1)throw Error('mobile_pf_signing_pin');const pin={keys:keys.map(k=>Object.fromEntries(['kty','n','e','kid','alg','use'].map(f=>[f,k[f]??(f==='alg'?'RS256':f==='use'?'sig':undefined)])))};
   const target=resolve(directory,kid+'-jwks.json');if(existsSync(target)){if(documentStageHash(json(target))!==documentStageHash(pin))throw Error('mobile_pf_pin_changed');}else save(target,pin,true);return pin;
  }});
  const output=resolve(directory,'pf-profiles.json');if(existsSync(output)){if(documentStageHash(json(output))!==documentStageHash(result.profiles))throw Error('mobile_pf_profile_changed');}else save(output,result.profiles,true);
  const summary={status:result.status,confirmedSteps:result.confirmedSteps,clientsEnabled:false,pfTokenRequests:0,microsoftRequests:0};save(resolve(directory,'pf-stage-receipt.json'),summary);save(resolve(directory,'pf-stage-status.json'),summary);return summary;
 }catch{save(resolve(directory,'pf-stage-status.json'),{status:'INCOMPLETE',stage,noAutomaticRetry:true,at:new Date().toISOString()});throw Error('mobile_pf_staging_incomplete');}
 finally{closeSync(lock);unlinkSync(lockPath);}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){try{if(process.argv.slice(2).join()!=='--stage')throw Error();console.log(JSON.stringify(await applyMobileStage()));}catch{console.error('Mobile PF staging incomplete. Preserve the private journal; reconcile pending writes before repeating. No client was enabled.');process.exitCode=1;}}
