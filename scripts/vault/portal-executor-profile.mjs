import {createPrivateKey,createPublicKey,X509Certificate} from 'node:crypto';
import {validateAuthorityClients,authorityFields} from './relay-host-profile.mjs';
export const executorPath='/federated-copilot-tool-secrets/data/portal-executor',executorRole='copilot-portal-executor-reader',executorPolicy='copilot-portal-executor-read';
export const executorPolicyText='path "federated-copilot-tool-secrets/data/portal-executor" { capabilities = ["read"] }';
const fields=[...authorityFields,'agentKeyPem','gatewayKeyPem','gatewayCertificatePem','gatewaySigningKeyPem'];
function matching(pem,pin){const key=createPrivateKey(pem),pub=createPublicKey(key).export({format:'jwk'});if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails.modulusLength<2048||!pin||pin.kty!=='RSA'||pin.d||pub.n!==pin.n||pub.e!==pin.e)throw Error();return key;}
export function validatePortalExecutor(record,trust){
 try{
  if(!record||Object.keys(record).sort().join()!==[...fields,'schemaVersion','purpose'].sort().join()||record.schemaVersion!==1||record.purpose!=='portal-gateway-executor'||fields.some(k=>typeof record[k]!=='string'||record[k].length>16000))throw Error();
  validateAuthorityClients({schemaVersion:1,purpose:'relay-authority-clients',...Object.fromEntries(authorityFields.map(k=>[k,record[k]]))},trust.authority);
  matching(record.agentKeyPem,trust.agentJwk);matching(record.gatewaySigningKeyPem,trust.gateway.publicJwk);
  const certificate=new X509Certificate(record.gatewayCertificatePem);
  if(certificate.ca||certificate.fingerprint256!==trust.gateway.certificateSha256||!certificate.checkPrivateKey(createPrivateKey(record.gatewayKeyPem))||!certificate.keyUsage?.includes('1.3.6.1.5.5.7.3.2')||Date.parse(certificate.validFrom)>Date.now()||Date.parse(certificate.validTo)<=Date.now()+300000)throw Error();
  return{...record};
 }catch{throw Error('Portal gateway credentials unavailable');}
}
export async function fetchPortalExecutor(call,trust){
 try{
  const login=await call('/auth/tool-cert/login',{method:'POST',body:{name:executorRole}}),auth=login.value?.auth;
  if(login.status!==200||typeof auth?.client_token!=='string'||!auth.client_token||auth.policies?.join()!==executorPolicy||auth.num_uses!==1||!Number.isInteger(auth.lease_duration)||auth.lease_duration<1||auth.lease_duration>120)throw Error();
  const result=await call(executorPath,{token:auth.client_token});
  if(result.status!==200||!Number.isSafeInteger(result.value?.data?.metadata?.version)||result.value.data.metadata.version<1)throw Error();
  return{record:validatePortalExecutor(result.value.data.data,trust),version:result.value.data.metadata.version};
 }catch{throw Error('Portal gateway credentials unavailable');}
}
