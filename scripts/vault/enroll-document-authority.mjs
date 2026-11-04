import {generateKeyPairSync} from 'node:crypto';import {writeFileSync,existsSync,openSync,closeSync,rmSync} from 'node:fs';import {resolve} from 'node:path';import {execFileSync} from 'node:child_process';
import {vault,privateLoad} from './common.mjs';import {custody,protect,readProtected} from './tool-custody.mjs';
import {checkedBytes} from './document-exchange-approval.mjs';import {assertDocumentAuthorityApproval} from './document-authority-approval.mjs';import {reconcileDocumentAuthorityRole,verifyDocumentAuthorityChallenge} from './document-authority-roles.mjs';
import {documentWorkloads,documentSignerSpec,documentTransitProfile,validateDocumentWorkload,fetchDocumentWorkload,validatedDocumentLease} from '../../src/m365/document-authority-custody.mjs';
const save=(p,v)=>writeFileSync(p,JSON.stringify(v,null,2),{flag:'wx',mode:0o600}),json=p=>JSON.parse(checkedBytes(p));
if(process.argv.length===2)console.log(JSON.stringify({action:'preview',newTransitKey:'document-authority',exportable:false,newPolicyClientKeys:3,newCertificateRoles:4,readerCertificateDays:30,grantAssertionsIssued:0,pfMutations:0,microsoftRequests:0}));
else if(process.argv.slice(2).join()==='--enroll'){
 let lock;const lockPath=resolve(custody,'document-authority-enrollment.lock');
 try{
  assertDocumentAuthorityApproval();if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||process.env.NODE_DEBUG||process.env.SSLKEYLOGFILE||process.env.NODE_OPTIONS)throw Error();protect();lock=openSync(lockPath,'wx',0o600);
  const token=privateLoad('bootstrap.json').root_token,call=(p,o={})=>vault(p,{...o,token}),keyPath='/transit/keys/document-authority',keyIntent=resolve(custody,'document-authority-key-intent.json'),keyTrust=resolve(custody,'document-authority-transit.json');
  let current=await call(keyPath);
  if(current.status===404){
   if(existsSync(keyIntent)||existsSync(keyTrust))throw Error();save(keyIntent,{purpose:'document-authority-transit',name:documentSignerSpec.name,version:1,createdAt:new Date().toISOString()});
   const w=await call(keyPath,{method:'POST',body:{type:'rsa-3072',exportable:false,allow_plaintext_backup:false}});if(![200,204].includes(w.status))throw Error();current=await call(keyPath);
  }else if(current.status!==200||!existsSync(keyIntent))throw Error();
  if(current.status!==200)throw Error();const transit=documentTransitProfile(current.value?.data);
  if(existsSync(keyTrust)){if(JSON.stringify(json(keyTrust))!==JSON.stringify(transit))throw Error();}else save(keyTrust,transit);
  const trusts={};
  for(const [name,s]of Object.entries(documentWorkloads)){
   const path=resolve(custody,'document-policy-'+name+'-trust.json'),intent=resolve(custody,'document-policy-'+name+'-intent.json'),r=await call(s.path);let record,trust;
   if(r.status===404){
    if(existsSync(path)||existsSync(intent))throw Error();const pair=generateKeyPairSync('rsa',{modulusLength:3072});
    trust={clientId:s.clientId,keyId:s.keyId,publicJwk:{...pair.publicKey.export({format:'jwk'}),kid:s.keyId,alg:'RS256',use:'sig'}};
    record={schemaVersion:1,purpose:'document-policy-workload',clientId:s.clientId,keyId:s.keyId,privateKeyPem:pair.privateKey.export({format:'pem',type:'pkcs8'})};validateDocumentWorkload(name,record,trust);
    save(path,trust);save(intent,{purpose:'document-policy-workload',clientId:s.clientId,record:s.path,expectedVersion:1,createdAt:new Date().toISOString()});
    const w=await call(s.path,{method:'POST',body:{options:{cas:0},data:record}});if(w.status!==200)throw Error();
   }else if(r.status===200&&r.value?.data?.metadata?.version===1&&existsSync(intent)){trust=json(path);record=validateDocumentWorkload(name,r.value.data.data,trust);}else throw Error();
   const confirmed=await call(s.path);if(confirmed.status!==200||confirmed.value?.data?.metadata?.version!==1)throw Error();validateDocumentWorkload(name,confirmed.value.data.data,trust);trusts[name]=trust;
  }
  if(new Set([transit.publicJwk.n,...Object.values(trusts).map(t=>t.publicJwk.n)]).size!==4)throw Error();
  const identities={};
  for(const name of ['signer',...Object.keys(documentWorkloads)]){
   const prefix='document-authority-'+name,certFile=prefix+'-cert.pem',keyFile=prefix+'-key.pem',certPath=resolve(custody,certFile),privatePath=resolve(custody,keyFile);
   if(!existsSync(certPath)&&!existsSync(privatePath))execFileSync('openssl',['req','-x509','-newkey','rsa:3072','-nodes','-keyout',privatePath,'-out',certPath,'-subj','/CN=copilot-document-'+name,'-addext','basicConstraints=critical,CA:FALSE','-addext','keyUsage=critical,digitalSignature','-addext','extendedKeyUsage=clientAuth','-days','30'],{stdio:'ignore',windowsHide:true,timeout:20000});
   const cert=readProtected(certFile),key=readProtected(keyFile);await reconcileDocumentAuthorityRole(call,name,cert,key);identities[name]=(p,o={})=>vault(p,{...o,cert,key});
  }
  await verifyDocumentAuthorityChallenge(identities.signer,transit);
  for(const name of Object.keys(documentWorkloads))await fetchDocumentWorkload(name,identities[name],trusts[name]);
  let denials=0;
  for(const [name,identity]of Object.entries(identities)){
   const s=name==='signer'?documentSignerSpec:documentWorkloads[name];
   for(const path of [...Object.values(documentWorkloads).map(v=>v.path),'/federated-copilot-tool-secrets/data/document-exchange','/federated-copilot-tool-secrets/data/sharepoint-broker','/federated-copilot-tool-secrets/data/portal-executor','/transit/keys/consent-authority']){
    if(path===s.path)continue;const t=validatedDocumentLease(await identity('/auth/tool-cert/login',{method:'POST',body:{name:s.role}}),s.policy);if((await identity(path,{token:t})).status!==403)throw Error();denials++;
   }
   for(const path of ['/transit/sign/consent-authority/sha2-256',...(name==='signer'?[]:[documentSignerSpec.path])]){
    const t=validatedDocumentLease(await identity('/auth/tool-cert/login',{method:'POST',body:{name:s.role}}),s.policy);if((await identity(path,{method:'POST',token:t,body:{input:'c3ludGhldGlj',key_version:1,signature_algorithm:'pkcs1v15'}})).status!==403)throw Error();denials++;
   }
   for(const role of [documentSignerSpec.role,...Object.values(documentWorkloads).map(v=>v.role),'copilot-document-exchange-reader']){
    if(role===s.role)continue;const r=await identity('/auth/tool-cert/login',{method:'POST',body:{name:role}});if(![400,403].includes(r.status))throw Error();denials++;
   }
  }
  if(denials!==48)throw Error();const receipt={verifiedAt:new Date().toISOString(),transitName:transit.name,transitVersion:1,exportable:false,workloadVersions:{consent:1,agent:1,reader:1},positiveWorkloadReads:3,syntheticChallenges:1,accessDenials:denials,grantAssertionsIssued:0,pfMutations:0,microsoftRequests:0};
  writeFileSync(resolve(custody,'document-authority-enrollment.json'),JSON.stringify(receipt,null,2),{mode:0o600});console.log(JSON.stringify(receipt));
 }catch{console.error('Document authority enrollment incomplete; retain intents/public pins and independently reconcile uncertain writes. No key regeneration, rotation or overwrite is authorized.');process.exitCode=1;}
 finally{if(lock!==undefined){closeSync(lock);rmSync(lockPath);}}
}else{console.error('Use preview or --enroll only');process.exitCode=1;}
