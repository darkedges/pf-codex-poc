export const custodyKeyPolicy='copilot-relay-custody-read',custodyKeyRole='copilot-relay-custody-reader',custodyKeyPath='/federated-copilot-tool-secrets/data/relay-proof-key';
export const custodyKeyPolicyText=`path "federated-copilot-tool-secrets/data/relay-proof-key" { capabilities = ["read"] }`;
export async function fetchCustodyKey(call){
 try{
  const login=await call('/auth/tool-cert/login',{method:'POST',body:{name:custodyKeyRole}}),a=login.value?.auth;
  if(login.status!==200||typeof a?.client_token!=='string'||!a.client_token||a.policies?.length!==1||a.policies[0]!==custodyKeyPolicy||a.num_uses!==1||!Number.isInteger(a.lease_duration)||a.lease_duration<=0||a.lease_duration>120)throw Error();
  const result=await call(custodyKeyPath,{token:a.client_token}),data=result.value?.data,record=data?.data;
  if(result.status!==200||!Number.isSafeInteger(data?.metadata?.version)||data.metadata.version<1||!record||Object.keys(record).sort().join()!=='keyHex,purpose,schemaVersion'||record.schemaVersion!==1||record.purpose!=='relay-proof-encryption'||typeof record.keyHex!=='string'||!/^[a-f0-9]{64}$/.test(record.keyHex))throw Error();
  return{key:Buffer.from(record.keyHex,'hex'),version:data.metadata.version};
 }catch{throw Error('Relay custody key unavailable');}
}
