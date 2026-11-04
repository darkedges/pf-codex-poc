import {createPrivateKey,createPublicKey} from 'node:crypto';
const workload=name=>{const path='/federated-copilot-tool-secrets/data/document-policy-'+name,policy='copilot-document-policy-'+name+'-read';return Object.freeze({clientId:'policy-document-'+name,keyId:'document-policy-'+name,path,role:'copilot-document-policy-'+name+'-reader',policy,policyText:`path "${path.slice(1)}" { capabilities = ["read"] }`});};
export const documentWorkloads=Object.freeze(Object.fromEntries(['consent','agent','reader'].map(n=>[n,workload(n)])));
export const documentSignerSpec=Object.freeze({name:'document-authority',role:'copilot-document-authority-signer',policy:'copilot-document-authority-sign',path:'/transit/sign/document-authority/sha2-256',policyText:'path "transit/sign/document-authority/sha2-256" { capabilities = ["update"] }'});
const spec=name=>{if(!Object.hasOwn(documentWorkloads,name))throw Error('document_workload_unknown');return documentWorkloads[name];};
export function validateDocumentWorkload(name,record,trust){
 try{
  const s=spec(name);
  if(!trust||Object.keys(trust).sort().join()!=='clientId,keyId,publicJwk'||trust.clientId!==s.clientId||trust.keyId!==s.keyId||!record||Object.keys(record).sort().join()!=='clientId,keyId,privateKeyPem,purpose,schemaVersion'||record.schemaVersion!==1||record.purpose!=='document-policy-workload'||record.clientId!==s.clientId||record.keyId!==s.keyId||typeof record.privateKeyPem!=='string'||record.privateKeyPem.length>16384)throw Error();
  const pin=trust.publicJwk;if(!pin||Object.keys(pin).sort().join()!=='alg,e,kid,kty,n,use'||pin.kty!=='RSA'||pin.kid!==s.keyId||pin.alg!=='RS256'||pin.use!=='sig')throw Error();
  const key=createPrivateKey(record.privateKeyPem),publicKey=createPublicKey(key),pub=publicKey.export({format:'jwk'});if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails.modulusLength<3072||pub.n!==pin.n||pub.e!==pin.e)throw Error();return{...record};
 }catch{throw Error('Document workload credential unavailable');}
}
export function documentTransitProfile(metadata){
 try{
  if(!metadata||metadata.type!=='rsa-3072'||metadata.exportable!==false||metadata.allow_plaintext_backup!==false||metadata.deletion_allowed!==false||metadata.latest_version!==1||metadata.min_decryption_version!==1||![0,1].includes(metadata.min_encryption_version)||Object.keys(metadata.keys??{}).join()!=='1')throw Error();
  const key=createPublicKey(metadata.keys['1'].public_key);if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails.modulusLength<3072)throw Error();
  return{origin:'https://localhost:9470',mount:'transit',name:documentSignerSpec.name,version:1,kid:'document-authority-v1',publicJwk:{...key.export({format:'jwk'}),kid:'document-authority-v1',alg:'RS256',use:'sig'},timeoutMs:3000};
 }catch{throw Error('Document Transit trust unavailable');}
}
export function validatedDocumentLease(login,policy){
 const a=login?.value?.auth;
 if(login.status!==200||typeof a?.client_token!=='string'||!a.client_token||/[\r\n]/.test(a.client_token)||JSON.stringify(a.policies)!==JSON.stringify([policy])||a.num_uses!==1||!Number.isInteger(a.lease_duration)||a.lease_duration<1||a.lease_duration>120)throw Error('Document workload lease unavailable');return a.client_token;
}
export async function fetchDocumentWorkload(name,call,trust){
 try{
  const s=spec(name),token=validatedDocumentLease(await call('/auth/tool-cert/login',{method:'POST',body:{name:s.role}}),s.policy),r=await call(s.path,{token});
  if(r.status!==200||r.value?.data?.metadata?.version!==1)throw Error();return{record:validateDocumentWorkload(name,r.value.data.data,trust),version:1};
 }catch{throw Error('Document workload credential unavailable');}
}
