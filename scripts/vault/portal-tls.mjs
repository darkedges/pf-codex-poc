import {readFileSync,writeFileSync,existsSync,mkdirSync,rmSync} from 'node:fs';import {resolve,sep} from 'node:path';import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';import {randomUUID,X509Certificate,createPrivateKey} from 'node:crypto';
import {vault,operator,privateLoad} from './common.mjs';import {protect,custody,readProtected} from './tool-custody.mjs';
export const tlsPath='/federated-copilot-tool-secrets/data/portal-web-tls',tlsRole='copilot-portal-tls-reader',tlsPolicy='copilot-portal-tls-read';
const policyText='path "federated-copilot-tool-secrets/data/portal-web-tls" { capabilities = ["read"] }';
export function validatePortalTls(record,pinnedCert){
 try{
  if(!record||Object.keys(record).sort().join()!=='purpose,schemaVersion,serverCertificatePem,serverKeyPem'||record.schemaVersion!==1||record.purpose!=='portal-web-tls'||record.serverCertificatePem!==pinnedCert||typeof record.serverKeyPem!=='string'||record.serverKeyPem.length>16000||typeof pinnedCert!=='string'||pinnedCert.length>16000)throw Error();
  const c=new X509Certificate(pinnedCert),key=createPrivateKey(record.serverKeyPem);
  if(c.ca||c.checkHost('localhost')!=='localhost'||!c.checkPrivateKey(key)||key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails.modulusLength<3072||!c.keyUsage?.includes('1.3.6.1.5.5.7.3.1')||c.keyUsage?.includes('1.3.6.1.5.5.7.3.2')||Date.parse(c.validFrom)>Date.now()||Date.parse(c.validTo)<=Date.now()+8*3600000)throw Error();
  return{key:record.serverKeyPem,cert:record.serverCertificatePem};
 }catch{throw Error('Portal server TLS unavailable');}
}
export async function fetchPortalTls(call,pinnedCert){
 try{
  const login=await call('/auth/tool-cert/login',{method:'POST',body:{name:tlsRole}}),auth=login.value?.auth;
  if(login.status!==200||typeof auth?.client_token!=='string'||!auth.client_token||auth.policies?.join()!==tlsPolicy||auth.num_uses!==1||!Number.isInteger(auth.lease_duration)||auth.lease_duration<1||auth.lease_duration>120)throw Error();
  const result=await call(tlsPath,{token:auth.client_token});if(result.status!==200||result.value?.data?.metadata?.version!==1)throw Error();
  return validatePortalTls(result.value.data.data,pinnedCert);
 }catch{throw Error('Portal server TLS unavailable');}
}
async function main(){
 const args=process.argv.slice(2);if(args.length===0){console.log(JSON.stringify({action:'preview',record:tlsPath,role:tlsRole,newServerOnlyIdentity:true,reusesAgentOrGatewayKeys:false,opensListener:false,publicRoutesChanged:false}));return;}
 if(args.join()!=='--enroll')throw Error();
 let stage;
 try{
  if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||process.env.NODE_DEBUG||process.env.SSLKEYLOGFILE||process.env.NODE_OPTIONS)throw Error();protect();
  const token=privateLoad('bootstrap.json').root_token,current=await vault(tlsPath,{token}),pinPath=resolve(custody,'portal-origin-cert.pem');let record;
  if(current.status===404){
   if(existsSync(pinPath))throw Error();stage=resolve(custody,'portal-tls-stage-'+randomUUID());mkdirSync(stage,{mode:0o700});
   execFileSync('openssl',['req','-x509','-newkey','rsa:3072','-nodes','-keyout',resolve(stage,'key.pem'),'-out',resolve(stage,'cert.pem'),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-addext','basicConstraints=critical,CA:FALSE','-addext','keyUsage=critical,digitalSignature,keyEncipherment','-addext','extendedKeyUsage=serverAuth','-days','30'],{stdio:'ignore',windowsHide:true,timeout:20000});
   record={schemaVersion:1,purpose:'portal-web-tls',serverKeyPem:readFileSync(resolve(stage,'key.pem'),'utf8'),serverCertificatePem:readFileSync(resolve(stage,'cert.pem'),'utf8')};validatePortalTls(record,record.serverCertificatePem);
   writeFileSync(pinPath,record.serverCertificatePem,{mode:0o600,flag:'wx'});await operator(tlsPath,{method:'POST',body:{options:{cas:0},data:record}});
  }else if(current.status===200&&current.value?.data?.metadata?.version===1){record=current.value.data.data;validatePortalTls(record,readProtected('portal-origin-cert.pem'));}else throw Error();
  const pp='/sys/policies/acl/'+tlsPolicy,p=await vault(pp,{token});if(p.status===404)await operator(pp,{method:'PUT',body:{policy:policyText}});else if(p.status!==200||p.value?.data?.policy!==policyText)throw Error();
  const cert=readProtected('portal-renderer-cert.pem'),key=readProtected('portal-renderer-key.pem'),rp='/auth/tool-cert/certs/'+tlsRole,r=await vault(rp,{token});
  if(r.status===404)await operator(rp,{method:'POST',body:{certificate:cert,token_policies:[tlsPolicy],token_no_default_policy:true,token_ttl:120,token_max_ttl:120,token_explicit_max_ttl:120,token_num_uses:1,token_type:'service'}});
  else if(r.status!==200||r.value?.data?.certificate.trim()!==cert.trim()||r.value.data.token_policies?.join()!==tlsPolicy||r.value.data.token_no_default_policy!==true||r.value.data.token_num_uses!==1||r.value.data.token_ttl!==120||r.value.data.token_max_ttl!==120||r.value.data.token_explicit_max_ttl!==120||r.value.data.token_type!=='service')throw Error();
  const call=(path,options)=>vault(path,{...options,cert,key}),tls=await fetchPortalTls(call,readProtected('portal-origin-cert.pem'));let denials=0;
  for(const path of ['/federated-copilot-tool-secrets/data/portal-executor','/federated-copilot-tool-secrets/data/portal-controller','/federated-copilot-tool-secrets/data/relay-connection']){const l=await call('/auth/tool-cert/login',{method:'POST',body:{name:tlsRole}});if(l.status!==200||(await call(path,{token:l.value.auth.client_token})).status!==403)throw Error();denials++;}
  const receipt={verifiedAt:new Date().toISOString(),version:1,serverCertificateSha256:new X509Certificate(tls.cert).fingerprint256,denials,newServerOnlyIdentity:true,reusesAgentOrGatewayKeys:false,publicRoutesChanged:false,opensListener:false,microsoftRequests:0};writeFileSync(resolve(custody,'portal-tls-enrollment.json'),JSON.stringify(receipt,null,2),{mode:0o600});console.log(JSON.stringify(receipt));
 }finally{if(stage){if(resolve(stage)!==stage||!stage.startsWith(resolve(custody)+sep))throw Error('Unsafe TLS staging cleanup');rmSync(stage,{recursive:true,force:true});}}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(()=>{console.error('Portal TLS enrollment incomplete; existing TLS identity was not overwritten.');process.exitCode=1;});
