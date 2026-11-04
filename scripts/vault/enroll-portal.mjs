import {readFileSync,writeFileSync,existsSync,openSync,closeSync,rmSync} from 'node:fs';
import {resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash,X509Certificate,createPrivateKey} from 'node:crypto';
import {root,read,load} from '../pf/common.mjs';
import {operator,vault,privateLoad} from './common.mjs';
import {protect,custody,readProtected} from './tool-custody.mjs';
import {assertBoundCredential,assertChannelBinding} from '../../src/copilot/channel-binding.ts';
import {portalVaultPath,portalVaultRole,portalVaultPolicy,portalVaultPolicyText,validatePortalRecord,fetchPortalRecord} from '../../src/consent/portal-vault.mjs';
const args=process.argv.slice(2);
if(args.length===0){console.log(JSON.stringify({action:'preview',record:portalVaultPath,role:portalVaultRole,credentials:['OIDC client key','consent policy key','Generic OAuth secret','Direct Line channel secret'],agentKeyIncluded:false,operatorTokenIncluded:false,publicRoutesChanged:false,microsoftRequests:0,startsService:false}));}
else if(args.join()==='--enroll'){
 let lock;const lockPath=resolve(custody,'portal-enrollment.lock');
 try{
  if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||process.env.NODE_DEBUG||process.env.SSLKEYLOGFILE||process.env.NODE_OPTIONS)throw Error();
  protect();lock=openSync(lockPath,'wx',0o600);
  const config=resolve(root,'.local/copilot'),binding=JSON.parse(readFileSync(resolve(config,'channel-credential-binding.json'),'utf8')),settings=JSON.parse(readFileSync(resolve(config,'channel-settings.json'),'utf8'));
  assertChannelBinding(settings,binding);
  const record={schemaVersion:1,purpose:'portal-controller',oidcClientKeyPem:read('consent-oidc.private.pem'),policyConsentKeyPem:read('policy-consent.private.pem'),providerClientSecret:readFileSync(resolve(config,'pf-generic-oauth-client-secret.txt'),'utf8').trim(),directLineSecret:readFileSync(resolve(config,'direct-line-secret.txt'),'utf8').trim()};
  assertBoundCredential(binding,record.directLineSecret);
  const digest=v=>createHash('sha256').update(v).digest('hex');
  const trust={oidcClientJwk:load('consent-oidc.jwks.json').keys[0],policyConsentJwk:load('policy-consent.jwks.json').keys[0],providerClientSecretSha256:digest(record.providerClientSecret),directLineSecretSha256:digest(record.directLineSecret)};
  validatePortalRecord(record,trust);
  const trustFile=resolve(custody,'portal-controller-trust.json');
  if(existsSync(trustFile)){if(JSON.stringify(JSON.parse(readFileSync(trustFile,'utf8')))!==JSON.stringify(trust))throw Error();}else writeFileSync(trustFile,JSON.stringify(trust),{mode:0o600,flag:'wx'});
  const certPath=resolve(custody,'portal-renderer-cert.pem'),keyPath=resolve(custody,'portal-renderer-key.pem');
  if(!existsSync(certPath)&&!existsSync(keyPath))execFileSync('openssl',['req','-x509','-newkey','rsa:3072','-nodes','-keyout',keyPath,'-out',certPath,'-subj','/CN=copilot-portal-controller-reader','-addext','basicConstraints=critical,CA:FALSE','-addext','keyUsage=critical,digitalSignature','-addext','extendedKeyUsage=clientAuth','-days','30'],{stdio:'ignore',windowsHide:true,timeout:20000});
  const cert=readProtected('portal-renderer-cert.pem'),key=readProtected('portal-renderer-key.pem'),x=new X509Certificate(cert);
  if(x.ca||!x.checkPrivateKey(createPrivateKey(key))||Date.parse(x.validFrom)>Date.now()||Date.parse(x.validTo)<=Date.now()+300000||!x.keyUsage?.includes('1.3.6.1.5.5.7.3.2'))throw Error();
  const token=privateLoad('bootstrap.json').root_token,current=await vault(portalVaultPath,{token});
  if(current.status===404)await operator(portalVaultPath,{method:'POST',body:{options:{cas:0},data:record}});
  else if(current.status!==200||current.value?.data?.metadata?.version!==1)throw Error();
  else validatePortalRecord(current.value.data.data,trust);
  const policyPath='/sys/policies/acl/'+portalVaultPolicy,p=await vault(policyPath,{token});
  if(p.status===404)await operator(policyPath,{method:'PUT',body:{policy:portalVaultPolicyText}});else if(p.status!==200||p.value?.data?.policy!==portalVaultPolicyText)throw Error();
  const rolePath='/auth/tool-cert/certs/'+portalVaultRole,r=await vault(rolePath,{token});
  const role={certificate:cert,token_policies:[portalVaultPolicy],token_no_default_policy:true,token_ttl:120,token_max_ttl:120,token_explicit_max_ttl:120,token_num_uses:1,token_type:'service'};
  if(r.status===404)await operator(rolePath,{method:'POST',body:role});
  else if(r.status!==200||r.value?.data?.certificate.trim()!==cert.trim()||r.value.data.token_policies?.join()!==portalVaultPolicy||r.value.data.token_no_default_policy!==true||r.value.data.token_ttl!==120||r.value.data.token_max_ttl!==120||r.value.data.token_explicit_max_ttl!==120||r.value.data.token_num_uses!==1||r.value.data.token_type!=='service')throw Error();
  const call=(path,options)=>vault(path,{...options,cert,key}),loaded=await fetchPortalRecord(call,trust);let denials=0;
  for(const path of ['/federated-copilot-tool-secrets/data/relay-connection','/federated-copilot-tool-secrets/data/relay-authority-runtime','/federated-copilot-tool-secrets/data/relay-gateway-client','/federated-copilot-tool-secrets/data/runtime','/transit/keys/consent-authority']){
   const login=await call('/auth/tool-cert/login',{method:'POST',body:{name:portalVaultRole}});
   if(login.status!==200||(await call(path,{token:login.value.auth.client_token})).status!==403)throw Error();denials++;
  }
  // Cross-role impersonation must also fail with this dedicated certificate.
  for(const name of ['copilot-relay-authority-reader','copilot-relay-renderer']){const result=await call('/auth/tool-cert/login',{method:'POST',body:{name}});if(result.status===200)throw Error();denials++;}
  const receipt={verifiedAt:new Date().toISOString(),recordVersion:loaded.version,readerRole:portalVaultRole,unrelatedAuthorityDenials:denials,agentKeyIncluded:false,operatorTokenIncluded:false,publicRoutesChanged:false,microsoftRequests:0,startsService:false};
  writeFileSync(resolve(custody,'portal-enrollment.json'),JSON.stringify(receipt,null,2),{mode:0o600});console.log(JSON.stringify(receipt));
 }catch{console.error('Portal enrollment incomplete; no existing credential or role was overwritten. Reconcile with the same command.');process.exitCode=1;}
 finally{if(lock!==undefined){closeSync(lock);rmSync(lockPath);}}
}else{console.error('Use preview or --enroll only');process.exitCode=1;}
