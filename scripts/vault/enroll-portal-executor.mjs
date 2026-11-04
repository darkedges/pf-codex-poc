import {readFileSync,writeFileSync,existsSync,openSync,closeSync,rmSync} from 'node:fs';
import {resolve} from 'node:path';import {execFileSync} from 'node:child_process';
import {X509Certificate,createPrivateKey} from 'node:crypto';
import {read} from '../pf/common.mjs';import {operator,vault,privateLoad} from './common.mjs';import {protect,custody,readProtected} from './tool-custody.mjs';
import {portalExecutorTrust} from './portal-executor-trust.mjs';
import {executorPath,executorRole,executorPolicy,executorPolicyText,validatePortalExecutor,fetchPortalExecutor} from './portal-executor-profile.mjs';
const args=process.argv.slice(2);
if(args.length===0)console.log(JSON.stringify({action:'preview',record:executorPath,role:executorRole,passedToWebWorker:false,operatorTokenIncluded:false,publicRoutesChanged:false,microsoftRequests:0}));
else if(args.join()==='--enroll'){
 let lock;const path=resolve(custody,'portal-executor-enrollment.lock');
 try{
  if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||process.env.NODE_DEBUG||process.env.SSLKEYLOGFILE||process.env.NODE_OPTIONS)throw Error();
  protect();lock=openSync(path,'wx',0o600);const trust=portalExecutorTrust(),token=privateLoad('bootstrap.json').root_token;
  const authority=(await operator('/federated-copilot-tool-secrets/data/relay-authority-runtime')).data.data,gateway=(await operator('/federated-copilot-tool-secrets/data/relay-gateway-client')).data.data;
  const {schemaVersion:_schema,purpose:_purpose,...authorityKeys}=authority;
  const record={schemaVersion:1,purpose:'portal-gateway-executor',...authorityKeys,pfBClientKeyPem:read('consent-gateway-2.private.pem'),agentKeyPem:read('agent.private.pem'),gatewayKeyPem:gateway.keyPem,gatewayCertificatePem:gateway.certificatePem,gatewaySigningKeyPem:gateway.signingKeyPem};
  validatePortalExecutor(record,trust);
  const current=await vault(executorPath,{token});if(current.status===404)await operator(executorPath,{method:'POST',body:{options:{cas:0},data:record}});else if(current.status!==200||current.value?.data?.metadata?.version!==1)throw Error();else validatePortalExecutor(current.value.data.data,trust);
  const certFile=resolve(custody,'portal-executor-cert.pem'),keyFile=resolve(custody,'portal-executor-key.pem');
  if(!existsSync(certFile)&&!existsSync(keyFile))execFileSync('openssl',['req','-x509','-newkey','rsa:3072','-nodes','-keyout',keyFile,'-out',certFile,'-subj','/CN=copilot-portal-executor-reader','-addext','basicConstraints=critical,CA:FALSE','-addext','keyUsage=critical,digitalSignature','-addext','extendedKeyUsage=clientAuth','-days','30'],{stdio:'ignore',windowsHide:true,timeout:20000});
  const cert=readProtected('portal-executor-cert.pem'),key=readProtected('portal-executor-key.pem'),x=new X509Certificate(cert);
  if(x.ca||!x.checkPrivateKey(createPrivateKey(key))||Date.parse(x.validFrom)>Date.now()||Date.parse(x.validTo)<=Date.now()+300000||!x.keyUsage?.includes('1.3.6.1.5.5.7.3.2'))throw Error();
  const pp='/sys/policies/acl/'+executorPolicy,p=await vault(pp,{token});if(p.status===404)await operator(pp,{method:'PUT',body:{policy:executorPolicyText}});else if(p.status!==200||p.value?.data?.policy!==executorPolicyText)throw Error();
  const rp='/auth/tool-cert/certs/'+executorRole,r=await vault(rp,{token}),role={certificate:cert,token_policies:[executorPolicy],token_no_default_policy:true,token_ttl:120,token_max_ttl:120,token_explicit_max_ttl:120,token_num_uses:1,token_type:'service'};
  if(r.status===404)await operator(rp,{method:'POST',body:role});else if(r.status!==200||r.value?.data?.certificate.trim()!==cert.trim()||r.value.data.token_policies?.join()!==executorPolicy||r.value.data.token_no_default_policy!==true||r.value.data.token_ttl!==120||r.value.data.token_max_ttl!==120||r.value.data.token_explicit_max_ttl!==120||r.value.data.token_num_uses!==1||r.value.data.token_type!=='service')throw Error();
  const call=(path,options)=>vault(path,{...options,cert,key}),loaded=await fetchPortalExecutor(call,trust);let denials=0;
  for(const path of ['/federated-copilot-tool-secrets/data/portal-controller','/federated-copilot-tool-secrets/data/relay-connection','/federated-copilot-tool-secrets/data/runtime','/transit/keys/consent-authority']){const login=await call('/auth/tool-cert/login',{method:'POST',body:{name:executorRole}});if(login.status!==200||(await call(path,{token:login.value.auth.client_token})).status!==403)throw Error();denials++;}
  const other=await call('/auth/tool-cert/login',{method:'POST',body:{name:'copilot-portal-controller-reader'}});if(other.status===200)throw Error();denials++;
  const receipt={verifiedAt:new Date().toISOString(),recordVersion:loaded.version,readerRole:executorRole,unrelatedAuthorityDenials:denials,passedToWebWorker:false,operatorTokenIncluded:false,publicRoutesChanged:false,microsoftRequests:0};writeFileSync(resolve(custody,'portal-executor-enrollment.json'),JSON.stringify(receipt,null,2),{mode:0o600});console.log(JSON.stringify(receipt));
 }catch{console.error('Portal gateway enrollment incomplete; existing credentials and roles were not overwritten.');process.exitCode=1;}
 finally{if(lock!==undefined){closeSync(lock);rmSync(path);}}
}else{console.error('Use preview or --enroll only');process.exitCode=1;}
