import {createPrivateKey,createPublicKey,createHash} from 'node:crypto';
export const portalVaultPath='/federated-copilot-tool-secrets/data/portal-controller';
export const portalVaultRole='copilot-portal-controller-reader',portalVaultPolicy='copilot-portal-controller-read';
export const portalVaultPolicyText='path "federated-copilot-tool-secrets/data/portal-controller" { capabilities = ["read"] }';
const fields=['oidcClientKeyPem','policyConsentKeyPem','providerClientSecret','directLineSecret'];
const digest=value=>createHash('sha256').update(value).digest('hex');
export function validatePortalRecord(record,trust){
 try{
  if(!record||Object.keys(record).sort().join()!==[...fields,'schemaVersion','purpose'].sort().join()||record.schemaVersion!==1||record.purpose!=='portal-controller')throw Error();
  for(const field of fields)if(typeof record[field]!=='string'||!record[field]||record[field].length>16000)throw Error();
  for(const [field,pinned]of [['oidcClientKeyPem',trust.oidcClientJwk],['policyConsentKeyPem',trust.policyConsentJwk]]){
   const key=createPrivateKey(record[field]),pub=createPublicKey(key).export({format:'jwk'});
   if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails.modulusLength<2048||!pinned||pinned.kty!=='RSA'||pinned.d||pub.n!==pinned.n||pub.e!==pinned.e)throw Error();
  }
  for(const [field,pinned]of [['providerClientSecret',trust.providerClientSecretSha256],['directLineSecret',trust.directLineSecretSha256]])if(record[field].length>4096||/\s/.test(record[field])||!record[field]||!/^[a-f0-9]{64}$/.test(pinned)||digest(record[field])!==pinned)throw Error();
  return{...record};
 }catch{throw Error('Portal controller credentials unavailable');}
}
export async function fetchPortalRecord(call,trust){
 try{
  const login=await call('/auth/tool-cert/login',{method:'POST',body:{name:portalVaultRole}}),auth=login.value?.auth;
  if(login.status!==200||typeof auth?.client_token!=='string'||!auth.client_token||auth.policies?.join()!==portalVaultPolicy||auth.num_uses!==1||!Number.isInteger(auth.lease_duration)||auth.lease_duration<1||auth.lease_duration>120)throw Error();
  const result=await call(portalVaultPath,{token:auth.client_token});
  if(result.status!==200||!Number.isSafeInteger(result.value?.data?.metadata?.version)||result.value.data.metadata.version<1)throw Error();
  return{record:validatePortalRecord(result.value.data.data,trust),version:result.value.data.metadata.version};
 }catch{throw Error('Portal controller credentials unavailable');}
}
