import {randomBytes,randomUUID,X509Certificate,createPrivateKey} from 'node:crypto';
import {writeFileSync,openSync,closeSync,rmSync,mkdirSync} from 'node:fs';
import {resolve,sep} from 'node:path';
import {operator,vault,privateLoad} from './common.mjs';
import {custody,protect,readProtected} from './tool-custody.mjs';
import {fetchCustodyKey,custodyKeyPolicy,custodyKeyRole,custodyKeyPath,custodyKeyPolicyText} from '../../src/copilot/relay-custody-key.mjs';
import {RelayProofStore} from '../../src/copilot/relay-proof-store.ts';

if(process.argv.slice(2).join()!=='--enroll'){
 console.log(JSON.stringify({action:'preview',record:custodyKeyPath,role:custodyKeyRole,policy:custodyKeyPolicy,overwriteExistingKey:false,publicRoutesChanged:false,persistentRelayStarted:false}));
}else{
 let fd,temporary,key;const lock=resolve(custody,'relay-custody-enrollment.lock');let checks=0;
 const check=value=>{if(!value)throw Error();checks++;};
 try{
  protect();fd=openSync(lock,'wx',0o600);
  const cert=readProtected('relay-renderer-cert.pem'),privateKey=readProtected('relay-renderer-key.pem'),x=new X509Certificate(cert);
  check(x.checkPrivateKey(createPrivateKey(privateKey))&&Date.parse(x.validFrom)<=Date.now()&&Date.parse(x.validTo)>Date.now()+300000);
  const identity={cert,key:privateKey},call=(path,options)=>vault(path,{...options,...identity});
  const existing=await vault(custodyKeyPath,{token:privateLoad('bootstrap.json').root_token});
  check(existing.status===404||existing.status===200);
  if(existing.status===404){const bytes=randomBytes(32);try{await operator(custodyKeyPath,{method:'POST',body:{options:{cas:0},data:{schemaVersion:1,purpose:'relay-proof-encryption',keyHex:bytes.toString('hex')}}});}finally{bytes.fill(0);}}
  // Idempotent reconciliation refuses foreign policies and never rewrites a key.
  const root=privateLoad('bootstrap.json').root_token;
  const policyPath='/sys/policies/acl/'+custodyKeyPolicy,p=await vault(policyPath,{token:root});
  check(p.status===404||(p.status===200&&p.value?.data?.policy===custodyKeyPolicyText));
  if(p.status===404)await operator(policyPath,{method:'PUT',body:{policy:custodyKeyPolicyText}});
  const rolePath='/auth/tool-cert/certs/'+custodyKeyRole,r=await vault(rolePath,{token:root});
  check(r.status===404||(r.status===200&&r.value?.data?.certificate.trim()===cert.trim()&&r.value.data.token_policies?.join()===custodyKeyPolicy&&r.value.data.token_no_default_policy===true&&r.value.data.token_num_uses===1&&r.value.data.token_max_ttl===120&&r.value.data.token_explicit_max_ttl===120));
  if(r.status===404)await operator(rolePath,{method:'POST',body:{certificate:cert,token_policies:[custodyKeyPolicy],token_no_default_policy:true,token_ttl:120,token_max_ttl:120,token_explicit_max_ttl:120,token_num_uses:1,token_type:'service'}});
  const loaded=await fetchCustodyKey(call);key=loaded.key;
  for(const path of ['/federated-copilot-tool-secrets/data/relay-connection','/federated-copilot-tool-secrets/data/runtime','/federated-copilot-tool-secrets/data/relay-runtime']){
   const a=await call('/auth/tool-cert/login',{method:'POST',body:{name:custodyKeyRole}});check(a.status===200&&typeof a.value?.auth?.client_token==='string');check((await call(path,{token:a.value.auth.client_token})).status===403);
  }
  temporary=resolve(custody,'custody-check-'+randomUUID());mkdirSync(temporary,{mode:0o700});
  const path=resolve(temporary,'proof.sqlite'),proof={brokerToken:'synthetic-broker',agentToken:'synthetic-agent',login:{idToken:'synthetic-human',nonce:'synthetic-nonce'}},signal=new AbortController().signal;
  let store=new RelayProofStore({path,key,maxEntries:20});try{store.accept(proof,{},Date.now()+30000,signal);store.commit(proof.brokerToken,signal);check(store.reserveReplay('synthetic-issuer','synthetic-jti',Date.now()+30000));}finally{store.close();}
  store=new RelayProofStore({path,key,maxEntries:20});try{check(store.take(proof.brokerToken).proof.agentToken===proof.agentToken);check(!store.reserveReplay('synthetic-issuer','synthetic-jti',Date.now()+30000));let denied=false;try{store.take(proof.brokerToken);}catch{denied=true;}check(denied);}finally{store.close();}
  const receipt={version:1,keyVersion:loaded.version,verifiedAt:new Date().toISOString(),checks,keyRecord:custodyKeyPath,readerRole:custodyKeyRole,keyPrinted:false,existingKeyRewritten:false,persistentRelayStarted:false,publicRoutesChanged:false,microsoftRequests:0};
  writeFileSync(resolve(custody,'relay-custody-enrollment.json'),JSON.stringify(receipt,null,2),{mode:0o600});console.log(JSON.stringify(receipt));
 }catch{console.error('Relay custody enrollment/verification failed; existing key was not replaced. Reconcile with the same command.');process.exitCode=1;}
 finally{key?.fill(0);if(temporary){if(resolve(temporary)!==temporary||!temporary.startsWith(resolve(custody)+sep))throw Error('Refused custody cleanup');rmSync(temporary,{recursive:true,force:true});}if(fd!==undefined){closeSync(fd);rmSync(lock);}}
}
