import {createPrivateKey,createHash,X509Certificate} from 'node:crypto';
export const graphVaultPath='/federated-copilot-tool-secrets/data/sharepoint-broker';
export const graphVaultRole='copilot-sharepoint-broker-reader',graphVaultPolicy='copilot-sharepoint-broker-read';
export const graphVaultPolicyText='path "federated-copilot-tool-secrets/data/sharepoint-broker" { capabilities = ["read"] }';
const guid=v=>typeof v==='string'&&/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(v);
export function validateGraphCredential(record,trust){
 try{
  if(!trust||Object.keys(trust).sort().join()!=='certificateSha256,clientId,tenantId'||!guid(trust.tenantId)||!guid(trust.clientId)||!/^[a-f0-9]{64}$/.test(trust.certificateSha256)||!record||Object.keys(record).sort().join()!=='certificatePem,clientId,privateKeyPem,purpose,schemaVersion,tenantId'||record.schemaVersion!==1||record.purpose!=='sharepoint-broker'||record.tenantId!==trust.tenantId||record.clientId!==trust.clientId||typeof record.certificatePem!=='string'||record.certificatePem.length>16384||typeof record.privateKeyPem!=='string'||record.privateKeyPem.length>16384)throw Error();
  const cert=new X509Certificate(record.certificatePem),key=createPrivateKey(record.privateKeyPem),digest=createHash('sha256').update(cert.raw).digest('hex');
  if(digest!==trust.certificateSha256||cert.ca||key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails.modulusLength<3072||!cert.checkPrivateKey(key)||Date.parse(cert.validFrom)>Date.now()||Date.parse(cert.validTo)<=Date.now()+300000||!cert.keyUsage?.includes('1.3.6.1.5.5.7.3.2'))throw Error();
  return{...record};
 }catch{throw Error('SharePoint broker credential unavailable');}
}
export async function fetchGraphCredential(call,trust){
 try{
  const login=await call('/auth/tool-cert/login',{method:'POST',body:{name:graphVaultRole}}),auth=login.value?.auth;
  if(login.status!==200||typeof auth?.client_token!=='string'||!auth.client_token||/[\r\n]/.test(auth.client_token)||JSON.stringify(auth.policies)!==JSON.stringify([graphVaultPolicy])||auth.num_uses!==1||!Number.isInteger(auth.lease_duration)||auth.lease_duration<1||auth.lease_duration>120)throw Error();
  const result=await call(graphVaultPath,{token:auth.client_token});
  if(result.status!==200||result.value?.data?.metadata?.version!==1)throw Error();
  return{record:validateGraphCredential(result.value.data.data,trust),version:1};
 }catch{throw Error('SharePoint broker credential unavailable');}
}
