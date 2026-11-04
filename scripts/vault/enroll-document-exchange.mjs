import {generateKeyPairSync,X509Certificate} from 'node:crypto';
import {writeFileSync,existsSync,openSync,closeSync,rmSync} from 'node:fs';import {resolve} from 'node:path';import {execFileSync} from 'node:child_process';
import {vault,privateLoad} from './common.mjs';import {custody,protect,readProtected} from './tool-custody.mjs';
import {assertDocumentEnrollmentApproval,checkedBytes} from './document-exchange-approval.mjs';import {reconcileDocumentExchangeReader} from './document-exchange-reader.mjs';
import {documentExchangePath,documentExchangeRole,validateDocumentExchangeCredential,fetchDocumentExchangeCredential} from '../../src/m365/document-exchange-custody.mjs';
const save=(p,v)=>writeFileSync(p,JSON.stringify(v,null,2),{mode:0o600,flag:'wx'});
if(process.argv.length===2)console.log(JSON.stringify({action:'preview',record:documentExchangePath,role:documentExchangeRole,newRsaKeys:2,rsaBits:3072,readerCertificateDays:30,pfMutations:0,microsoftRequests:0}));
else if(process.argv.slice(2).join()==='--enroll'){
 let lock;const lockPath=resolve(custody,'document-exchange-enrollment.lock'),intentPath=resolve(custody,'document-exchange-enrollment-intent.json'),trustPath=resolve(custody,'document-exchange-trust.json');
 try{
  assertDocumentEnrollmentApproval();if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||process.env.NODE_DEBUG||process.env.SSLKEYLOGFILE||process.env.NODE_OPTIONS)throw Error();
  protect();lock=openSync(lockPath,'wx',0o600);
  const token=privateLoad('bootstrap.json').root_token,call=(path,options={})=>vault(path,{...options,token}),current=await call(documentExchangePath);let record,trust;
  if(current.status===404){
   if(existsSync(intentPath)||existsSync(trustPath))throw Error();
   const keys=['clientA','clientB'].map(()=>generateKeyPairSync('rsa',{modulusLength:3072}));
   trust={schemaVersion:1,...Object.fromEntries(keys.map((k,i)=>[i===0?'clientA':'clientB',{...k.publicKey.export({format:'jwk'}),kid:'document-gateway-'+(i+1),alg:'RS256',use:'sig'}]))};
   record={schemaVersion:1,purpose:'document-exchange-clients',clientAKeyPem:keys[0].privateKey.export({format:'pem',type:'pkcs8'}),clientBKeyPem:keys[1].privateKey.export({format:'pem',type:'pkcs8'})};
   validateDocumentExchangeCredential(record,trust);save(trustPath,trust);save(intentPath,{purpose:'document-exchange-clients',record:documentExchangePath,expectedVersion:1,createdAt:new Date().toISOString()});
   const written=await call(documentExchangePath,{method:'POST',body:{options:{cas:0},data:record}});if(written.status!==200)throw Error();
  }else if(current.status===200&&current.value?.data?.metadata?.version===1){trust=JSON.parse(checkedBytes(trustPath));record=validateDocumentExchangeCredential(current.value.data.data,trust);}
  else throw Error();
  const confirm=await call(documentExchangePath);if(confirm.status!==200||confirm.value?.data?.metadata?.version!==1)throw Error();validateDocumentExchangeCredential(confirm.value.data.data,trust);
  const certPath=resolve(custody,'document-exchange-reader-cert.pem'),keyPath=resolve(custody,'document-exchange-reader-key.pem');
  if(!existsSync(certPath)&&!existsSync(keyPath))execFileSync('openssl',['req','-x509','-newkey','rsa:3072','-nodes','-keyout',keyPath,'-out',certPath,'-subj','/CN=copilot-document-exchange-reader','-addext','basicConstraints=critical,CA:FALSE','-addext','keyUsage=critical,digitalSignature','-addext','extendedKeyUsage=clientAuth','-days','30'],{stdio:'ignore',windowsHide:true,timeout:20000});
  const cert=readProtected('document-exchange-reader-cert.pem'),key=readProtected('document-exchange-reader-key.pem');
  await reconcileDocumentExchangeReader(call,cert,key);
  const reader=(path,options={})=>vault(path,{...options,cert,key});const loaded=await fetchDocumentExchangeCredential(reader,trust);let denials=0;
  for(const path of ['/federated-copilot-tool-secrets/data/sharepoint-broker','/federated-copilot-tool-secrets/data/portal-executor','/federated-copilot-tool-secrets/data/portal-controller','/federated-copilot-tool-secrets/data/relay-authority-runtime','/transit/keys/consent-authority']){
   const login=await reader('/auth/tool-cert/login',{method:'POST',body:{name:documentExchangeRole}});if(login.status!==200||(await reader(path,{token:login.value?.auth?.client_token})).status!==403)throw Error();denials++;
  }
  for(const name of ['copilot-portal-executor-reader','copilot-sharepoint-broker-reader']){const denied=await reader('/auth/tool-cert/login',{method:'POST',body:{name}});if(![400,403].includes(denied.status))throw Error();denials++;}
  const receipt={verifiedAt:new Date().toISOString(),recordVersion:loaded.version,readerRole:documentExchangeRole,readerCertificateExpiresAt:new X509Certificate(cert).validTo,denials,pfMutations:0,microsoftRequests:0};
  writeFileSync(resolve(custody,'document-exchange-enrollment.json'),JSON.stringify(receipt,null,2),{mode:0o600});console.log(JSON.stringify(receipt));
 }catch{console.error('Document exchange enrollment incomplete; preserve intent and public pins. Never regenerate, overwrite or blindly repeat an uncertain write.');process.exitCode=1;}
 finally{if(lock!==undefined){closeSync(lock);rmSync(lockPath);}}
}else{console.error('Use preview or --enroll only');process.exitCode=1;}
