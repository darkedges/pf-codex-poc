import {createHash} from 'node:crypto';
import {validateRelayRecord} from '../../src/copilot/relay-credentials.mjs';
export {validateRelayRecord} from '../../src/copilot/relay-credentials.mjs';
export const relayPolicy='copilot-relay-runtime-read',relayRole='copilot-relay-renderer',relayMount='federated-copilot-tool-secrets';
export const relayRecordDigest=value=>createHash('sha256').update(JSON.stringify(Object.fromEntries(Object.entries(value).sort(([a],[b])=>a.localeCompare(b))))).digest('hex');
export async function fetchRelayRecord(call){
 try{
  const login=await call('/auth/tool-cert/login',{method:'POST',body:{name:relayRole}}),a=login.value?.auth;
  if(login.status!==200||typeof a?.client_token!=='string'||a.policies?.length!==1||a.policies[0]!==relayPolicy||a.num_uses!==1||a.lease_duration<=0||a.lease_duration>120)throw Error();
  const response=await call('/'+relayMount+'/data/relay-runtime',{token:a.client_token});
  if(response.status!==200||!Number.isSafeInteger(response.value?.data?.metadata?.version)||response.value.data.metadata.version<1)throw Error();
  const record=response.value.data.data;validateRelayRecord(record);return{record,version:response.value.data.metadata.version};
 }catch{throw Error('Relay Vault credentials unavailable');}
}
export function relayCandidatePlan(input){
 if(!input||Object.keys(input).sort().join()!=='id,image'||!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(input.id)||!/^sha256:[a-f0-9]{64}$/.test(input.image))throw Error('Invalid relay candidate plan');
 return{network:'fc-relay-'+input.id,tool:'fc-relay-tool-'+input.id,backend:'fc-relay-backend-'+input.id,hostname:'relay-tool-'+input.id,label:'federated-copilot.relay-candidate='+input.id,image:input.image,internal:true,subnet:'10.236.250.64/28',hostPorts:[],mountOperatorCredentials:false,mountConnectionKey:false};
}
