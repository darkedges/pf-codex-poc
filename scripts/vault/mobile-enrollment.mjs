import {createHash,generateKeyPairSync,createPrivateKey,createPublicKey,X509Certificate,randomBytes,verify} from 'node:crypto';
import {readFileSync,writeFileSync,existsSync,openSync,closeSync,fsyncSync,unlinkSync,lstatSync} from 'node:fs';
import {resolve} from 'node:path';import {fileURLToPath} from 'node:url';import {execFileSync} from 'node:child_process';
import {root} from '../pf/common.mjs';import {vault,privateLoad} from './common.mjs';
import {mobileCustodyPlan} from './mobile-custody-plan.mjs';import {documentStageStep,documentStageHash} from '../pf/document-stage-step.mjs';
import {validateGraphCredential} from '../../src/m365/vault-credential.mjs';
const directory=resolve(root,'.local/tool-vault/mobile'),review=resolve(root,'.local/mobile/staging-review'),digest=v=>createHash('sha256').update(v).digest('hex');
const json=path=>JSON.parse(readFileSync(path,'utf8'));
export function assertMobileApproval(){
 const raw=readFileSync(resolve(review,'manifest.json')),m=JSON.parse(raw),approval=json(resolve(review,'approval.json'));
 if(digest(raw)!=='3762aa52c8fa3d7fb45c2730f25f972bf47946184eec29f480f53b6ba85ac09e'||approval.manifestSha256!==digest(raw)||approval.purpose!=='mobile-disabled-staging'||approval.approved!==true||documentStageHash(m.recipe)!==documentStageHash(mobileCustodyPlan()))throw Error('mobile_staging_approval');
 for(const [file,hash]of Object.entries(m.source))if(digest(readFileSync(resolve(root,file)))!==hash)throw Error('mobile_staging_source_drift');
 for(const [file,hash]of Object.entries(approval.implementation??{}))if(digest(readFileSync(resolve(root,file)))!==hash)throw Error('mobile_staging_implementation_drift');
 if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||process.env.NODE_DEBUG||process.env.NODE_OPTIONS||process.env.SSLKEYLOGFILE)throw Error('mobile_staging_environment');return m;
}
function save(path,value,exclusive=false){const fd=openSync(path,exclusive?'wx':'w',0o600);try{writeFileSync(fd,JSON.stringify(value,null,2)+'\n');fsyncSync(fd);}finally{closeSync(fd);}}
function selected(r){if(r.status===404)return null;if(r.status!==200)throw Error('mobile_enrollment_read');return r.value?.data;}
export function mobilePublicKey(pem,kid){const key=pem?.type==='public'?pem:createPublicKey(pem);if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails.modulusLength<3072)throw Error('mobile_key_invalid');return{...key.export({format:'jwk'}),kid,alg:'RS256',use:'sig'};}
export function mobilePolicyText(paths){return Object.entries(paths).map(([path,capabilities])=>'path '+JSON.stringify(path)+' { capabilities = '+JSON.stringify(capabilities)+' }').join('\n');}
export function mobileRoleBody(spec,certificate){return{certificate,token_policies:spec.policies,token_no_default_policy:true,token_ttl:spec.tokenTtlSeconds,token_max_ttl:spec.tokenMaxTtlSeconds,token_explicit_max_ttl:spec.tokenMaxTtlSeconds,token_num_uses:spec.tokenNumUses,token_type:'service'};}
function credentials(spec){
 const certPath=resolve(directory,spec.name+'-cert.pem'),keyPath=resolve(directory,spec.name+'-key.pem');
 if(!existsSync(certPath)&&!existsSync(keyPath))execFileSync('openssl',['req','-x509','-newkey','rsa:3072','-nodes','-keyout',keyPath,'-out',certPath,'-subj','/CN='+spec.name,'-addext','basicConstraints=critical,CA:FALSE','-addext','keyUsage=critical,digitalSignature','-addext','extendedKeyUsage=clientAuth','-days','30'],{stdio:'ignore',windowsHide:true,timeout:20000});
 for(const path of [certPath,keyPath]){const s=lstatSync(path);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.size>16384)throw Error('mobile_certificate_invalid');}
 const cert=readFileSync(certPath,'utf8'),key=readFileSync(keyPath,'utf8'),c=new X509Certificate(cert),k=createPrivateKey(key);
 if(c.ca||!c.checkPrivateKey(k)||k.asymmetricKeyType!=='rsa'||k.asymmetricKeyDetails.modulusLength<3072||c.subject!=='CN='+spec.name||!c.keyUsage?.includes('1.3.6.1.5.5.7.3.2')||Date.parse(c.validFrom)>Date.now()||Date.parse(c.validTo)<=Date.now()+300000||Date.parse(c.validTo)>Date.now()+30*86400000+60000)throw Error('mobile_certificate_invalid');return{cert,key};
}
export async function enrollMobileCustody(){
 assertMobileApproval();execFileSync('pwsh',['-NoProfile','-File',resolve(root,'scripts/vault/protect-mobile-directory.ps1')],{stdio:'ignore',windowsHide:true,timeout:15000});
 const lockPath=resolve(directory,'enrollment.lock'),fd=openSync(lockPath,'wx',0o600),journalPath=resolve(directory,'enrollment-journal.json');let stage='preflight';
 try{
  const plan=mobileCustodyPlan(),journal=existsSync(journalPath)?json(journalPath):{purpose:plan.purpose,recipeHash:documentStageHash(plan),steps:{},signatures:0,denials:0,verificationRuns:0};
  if(journal.recipeHash!==documentStageHash(plan)||Object.values(journal.steps).some(s=>s.state==='pending')||journal.verificationRuns>=2)throw Error('mobile_enrollment_uncertain_or_spent');
  const persist=()=>save(journalPath,journal),operatorToken=privateLoad('bootstrap.json').root_token;
  const allowedRead=new Set(['/sys/mounts','/federated-copilot-tool-secrets/data/portal-controller','/mobile-runtime/data/credentials',...plan.mounts.map(m=>'/'+m.path+'/config'),...plan.transitKeys.map(k=>'/transit/keys/'+k.name),...Object.keys(plan.policies).map(p=>'/sys/policies/acl/'+p),...plan.certificateRoles.map(r=>'/auth/tool-cert/certs/'+r.name)]);
  const allowedWrite=new Set([...plan.mounts.map(m=>'/sys/mounts/'+m.path),...plan.mounts.map(m=>'/'+m.path+'/config'),...plan.transitKeys.map(k=>'/transit/keys/'+k.name),...Object.keys(plan.policies).map(p=>'/sys/policies/acl/'+p),...plan.certificateRoles.map(r=>'/auth/tool-cert/certs/'+r.name),'/mobile-runtime/data/credentials']);
  const call=async(path,options={})=>{assertMobileApproval();const method=options.method??'GET';if(method==='GET'?!allowedRead.has(path):!['POST','PUT'].includes(method)||!allowedWrite.has(path))throw Error('mobile_enrollment_path');return vault(path,{...options,token:operatorToken});};
  const step=async(id,read,expected,write,previousHash)=>{stage=id;return documentStageStep({id,journal,save:persist,read,expected,write,previousHash});};
  for(const mount of plan.mounts){
   await step(mount.path+'-mount',async()=>{const r=await call('/sys/mounts');if(r.status!==200)throw Error();const m=(r.value?.data??r.value)?.[mount.path+'/'];return m?{type:m.type,version:m.options?.version}:null;},{type:'kv',version:'2'},async()=>{const r=await call('/sys/mounts/'+mount.path,{method:'POST',body:{type:'kv',options:{version:'2'}}});if(![200,204].includes(r.status))throw Error();});
   const path='/'+mount.path+'/config',read=async()=>{const d=selected(await call(path));return d?{max_versions:d.max_versions,cas_required:d.cas_required}:null;},before=await read();
   if(!journal.steps[mount.path+'-config']&&(before?.max_versions!==0||before?.cas_required!==false))throw Error('mobile_mount_foreign_config');
   await step(mount.path+'-config',read,{max_versions:1,cas_required:true},async()=>{const r=await call(path,{method:'POST',body:{max_versions:1,cas_required:true}});if(![200,204].includes(r.status))throw Error();},documentStageHash(before));
  }
  const transit={};for(const spec of plan.transitKeys){const path='/transit/keys/'+spec.name,read=async()=>{const d=selected(await call(path));if(!d)return null;if(d.latest_version!==1||!d.keys?.['1']?.public_key)throw Error('mobile_transit_invalid');return{type:d.type,exportable:d.exportable,allow_plaintext_backup:d.allow_plaintext_backup,latest_version:1,publicJwk:mobilePublicKey(d.keys['1'].public_key,spec.name)};};
   transit[spec.name]=await step(spec.name,read,{type:'rsa-3072',exportable:false,allow_plaintext_backup:false,latest_version:1},async()=>{const r=await call(path,{method:'POST',body:{type:spec.type,exportable:false,allow_plaintext_backup:false}});if(![200,204].includes(r.status))throw Error();});
  }
  stage='runtime-record';const existing=await call('/mobile-runtime/data/credentials');let record;
  if(existing.status===404){if(journal.runtimePublic)throw Error('mobile_record_uncertain');const source=await call('/federated-copilot-tool-secrets/data/portal-controller'),secret=source.value?.data?.data?.directLineSecret;if(source.status!==200||typeof secret!=='string'||!secret||secret.length>16000||/\s/.test(secret))throw Error('mobile_channel_unavailable');
   const keys={},pub={};for(const name of plan.record.newPrivateKeys){const pair=generateKeyPairSync('rsa',{modulusLength:3072});keys[name]=pair.privateKey.export({format:'pem',type:'pkcs8'});pub[name]=mobilePublicKey(pair.publicKey,name);}record={schemaVersion:1,purpose:'mobile-runtime',keys,directLineSecret:secret};journal.runtimePublic=pub;journal.channelHash=digest(secret);persist();
  }else if(existing.status!==200||!journal.runtimePublic)throw Error('mobile_record_foreign');
  const projection=async()=>{const r=await call('/mobile-runtime/data/credentials');if(r.status===404)return null;const v=r.value?.data?.data;if(r.status!==200||r.value?.data?.metadata?.version!==1||v?.schemaVersion!==1||v.purpose!=='mobile-runtime'||Object.keys(v.keys??{}).sort().join()!==[...plan.record.newPrivateKeys].sort().join()||digest(v.directLineSecret)!==journal.channelHash)throw Error('mobile_record_invalid');return{schemaVersion:1,purpose:v.purpose,publicKeys:Object.fromEntries(plan.record.newPrivateKeys.map(name=>[name,mobilePublicKey(createPublicKey(createPrivateKey(v.keys[name])),name)])),channelHash:journal.channelHash};};
  await step('runtime-record',projection,{schemaVersion:1,purpose:'mobile-runtime',publicKeys:journal.runtimePublic,channelHash:journal.channelHash},async()=>{if(!record)throw Error('mobile_record_missing');const r=await call('/mobile-runtime/data/credentials',{method:'POST',body:{options:{cas:0},data:record}});if(r.status!==200||r.value?.data?.version!==1)throw Error('mobile_record_write');});record=undefined;
  const certs={};for(const spec of plan.certificateRoles){
   const certificate=credentials(spec);certs[spec.name]=certificate;const policy=spec.policies[0],path='/sys/policies/acl/'+policy,text=mobilePolicyText(plan.policies[policy]);
   await step(policy+'-policy',async()=>{const d=selected(await call(path));return d?{policy:d.policy}:null;},{policy:text},async()=>{const r=await call(path,{method:'PUT',body:{policy:text}});if(![200,204].includes(r.status))throw Error();});
   const rolePath='/auth/tool-cert/certs/'+spec.name,body=mobileRoleBody(spec,certificate.cert),read=async()=>{const d=selected(await call(rolePath));if(!d)return null;return Object.fromEntries(Object.keys(body).map(k=>[k,k==='certificate'?d[k]?.trim():d[k]]));};
   await step(spec.name+'-role',read,{...body,certificate:body.certificate.trim()},async()=>{const r=await call(rolePath,{method:'POST',body});if(![200,204].includes(r.status))throw Error();});
  }
  const pins={schemaVersion:1,authority:{keys:[transit['mobile-authority-v1'].publicJwk]},agent:{keys:[transit['mobile-agent-v1'].publicJwk]},clients:journal.runtimePublic};
  const pinPath=resolve(directory,'public-keys.json');if(existsSync(pinPath)){if(documentStageHash(json(pinPath))!==documentStageHash(pins))throw Error('mobile_pin_drift');}else save(pinPath,pins,true);
  stage='verification';journal.verificationRuns++;persist();
  const login=async spec=>{const r=await vault('/auth/tool-cert/login',{...certs[spec.name],method:'POST',body:{name:spec.name}}),a=r.value?.auth;if(r.status!==200||JSON.stringify(a?.policies)!==JSON.stringify(spec.policies)||a.num_uses!==spec.tokenNumUses||!Number.isInteger(a.lease_duration)||a.lease_duration<1||a.lease_duration>spec.tokenTtlSeconds||typeof a.client_token!=='string'||!a.client_token||/[\r\n]/.test(a.client_token))throw Error('mobile_role_lease');return a.client_token;};
  for(const spec of plan.certificateRoles){const token=await login(spec),tls=certs[spec.name],policy=spec.policies[0];
   if(policy==='mobile-runtime-read'){const r=await vault('/mobile-runtime/data/credentials',{...tls,token});if(r.status!==200||r.value?.data?.metadata?.version!==1||digest(r.value.data.data.directLineSecret)!==journal.channelHash)throw Error('mobile_readback');}
   else if(policy==='mobile-graph-read'){const r=await vault('/federated-copilot-tool-secrets/data/sharepoint-broker',{...tls,token});if(r.status!==200)throw Error();validateGraphCredential(r.value?.data?.data,json(resolve(directory,'../sharepoint-broker-trust.json')));}
   else if(policy==='mobile-provider-store'){const r=await vault('/mobile-provider/data/'+'a'.repeat(43),{...tls,token});if(r.status!==404)throw Error('mobile_provider_mount_not_empty');}
   else{const name=policy==='mobile-agent-sign'?'mobile-agent-v1':'mobile-authority-v1';if(journal.signatures>=4)throw Error('mobile_signature_budget');journal.signatures++;persist();const challenge=randomBytes(32),r=await vault('/transit/sign/'+name+'/sha2-256',{...tls,token,method:'POST',body:{input:challenge.toString('base64'),key_version:1,signature_algorithm:'pkcs1v15',prehashed:false}}),signature=r.value?.data?.signature;if(r.status!==200||typeof signature!=='string'||!/^vault:v1:[A-Za-z0-9+/]+={0,2}$/.test(signature)||!verify('sha256',challenge,createPublicKey({key:transit[name].publicJwk,format:'jwk'}),Buffer.from(signature.slice(9),'base64')))throw Error('mobile_signature_verification');}
   const paths=['/sys/policies/acl/mobile-runtime-read','/transit/keys/mobile-authority-v1',policy==='mobile-runtime-read'?'/federated-copilot-tool-secrets/data/sharepoint-broker':'/mobile-runtime/data/credentials',policy==='mobile-provider-store'?'/federated-copilot-tool-secrets/data/portal-controller':'/mobile-provider/data/'+'a'.repeat(43)];
   for(const target of paths){if(journal.denials>=60)throw Error('mobile_denial_budget');journal.denials++;persist();const r=await vault(target,{...tls,token:await login(spec)});if(r.status!==403)throw Error('mobile_access_denial');}
   if(journal.verificationRuns===1)for(const other of plan.certificateRoles.filter(r=>r.name!==spec.name)){if(journal.denials>=60)throw Error();journal.denials++;persist();const r=await vault('/auth/tool-cert/login',{...tls,method:'POST',body:{name:other.name}});if(![400,403].includes(r.status))throw Error('mobile_certificate_role_denial');}
  }
  const receipt={status:'ENROLLED',verificationRuns:journal.verificationRuns,signatures:journal.signatures,denials:journal.denials,steps:Object.keys(journal.steps).length,pfTokenRequests:0,microsoftRequests:0,providerRefreshRequests:0};save(resolve(directory,'enrollment-receipt.json'),receipt);return receipt;
 }catch(error){save(resolve(directory,'enrollment-status.json'),{status:'INCOMPLETE',stage,at:new Date().toISOString(),noAutomaticRetry:true});throw Error('mobile_enrollment_incomplete_'+stage);}
 finally{closeSync(fd);unlinkSync(lockPath);}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){try{if(process.argv.slice(2).join()!=='--enroll')throw Error();console.log(JSON.stringify(await enrollMobileCustody()));}catch(error){console.error(String(error.message).startsWith('mobile_enrollment_incomplete_')?error.message:'Mobile staging unavailable; preserve all local journals and reconcile before another attempt.');process.exitCode=1;}}
