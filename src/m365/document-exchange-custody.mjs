import {createPrivateKey,createPublicKey} from 'node:crypto';
export const documentExchangePath='/federated-copilot-tool-secrets/data/document-exchange';
export const documentExchangeRole='copilot-document-exchange-reader',documentExchangePolicy='copilot-document-exchange-read';
export const documentExchangePolicyText='path "federated-copilot-tool-secrets/data/document-exchange" { capabilities = ["read"] }';
function pin(key,kid){
 if(!key||Object.keys(key).sort().join()!=='alg,e,kid,kty,n,use'||key.kid!==kid||key.kty!=='RSA'||key.alg!=='RS256'||key.use!=='sig')throw Error();
 const publicKey=createPublicKey({key,format:'jwk'});if(publicKey.asymmetricKeyDetails.modulusLength<3072)throw Error();return key;
}
export function validateDocumentExchangeCredential(record,trust){
 try{
  if(!trust||Object.keys(trust).sort().join()!=='clientA,clientB,schemaVersion'||trust.schemaVersion!==1||!record||Object.keys(record).sort().join()!=='clientAKeyPem,clientBKeyPem,purpose,schemaVersion'||record.schemaVersion!==1||record.purpose!=='document-exchange-clients')throw Error();
  const pins=[pin(trust.clientA,'document-gateway-1'),pin(trust.clientB,'document-gateway-2')];if(pins[0].n===pins[1].n)throw Error();
  for(const [index,field]of ['clientAKeyPem','clientBKeyPem'].entries()){
   if(typeof record[field]!=='string'||record[field].length>16384)throw Error();
   const key=createPrivateKey(record[field]),pub=createPublicKey(key).export({format:'jwk'});if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails.modulusLength<3072||pub.n!==pins[index].n||pub.e!==pins[index].e)throw Error();
  }
  return{...record};
 }catch{throw Error('Document exchange credential unavailable');}
}
export async function fetchDocumentExchangeCredential(call,trust){
 try{
  const login=await call('/auth/tool-cert/login',{method:'POST',body:{name:documentExchangeRole}}),auth=login.value?.auth;
  if(login.status!==200||typeof auth?.client_token!=='string'||!auth.client_token||/[\r\n]/.test(auth.client_token)||JSON.stringify(auth.policies)!==JSON.stringify([documentExchangePolicy])||auth.num_uses!==1||!Number.isInteger(auth.lease_duration)||auth.lease_duration<1||auth.lease_duration>120)throw Error();
  const result=await call(documentExchangePath,{token:auth.client_token});if(result.status!==200||result.value?.data?.metadata?.version!==1)throw Error();
  return{record:validateDocumentExchangeCredential(result.value.data.data,trust),version:1};
 }catch{throw Error('Document exchange credential unavailable');}
}
