import {captureVaultPath} from './vault-capture.mjs';
import {operator,vault,privateLoad} from '../vault/common.mjs';
import {retireRuntimeLease} from '../vault/retire-lease.mjs';
export async function prepareCaptureWriter(id){
 const path=captureVaultPath(id),policy='provider-capture-'+id;
 const audits=(await operator('/sys/audit')).data,tune=(await operator('/sys/mounts/federated-copilot-tool-secrets/tune')).data;
 if(!audits||!Object.keys(audits).length||Object.values(audits).some(a=>a.options?.log_raw==='true')||(tune.audit_non_hmac_request_keys??[]).length||(tune.audit_non_hmac_response_keys??[]).length)throw Error('Credential-safe Vault auditing required');
 await operator('/sys/policies/acl/'+policy,{method:'PUT',body:{policy:'path "'+path.slice(1)+'" { capabilities = ["create", "update"] }'}});
 const r=await operator('/auth/token/create',{method:'POST',body:{policies:[policy],no_default_policy:true,ttl:'5m',explicit_max_ttl:'5m',renewable:false,num_uses:2,display_name:'local-private-capture-writer'}});
 if(typeof r.auth?.client_token!=='string'||typeof r.auth.accessor!=='string'||r.auth.policies?.length!==1||r.auth.policies[0]!==policy||r.auth.num_uses!==2)throw Error('Private capture writer unavailable');
 return{path,policy,token:r.auth.client_token,accessor:r.auth.accessor};
}
export async function retireCaptureWriter(writer){
 await retireRuntimeLease(vault,privateLoad('bootstrap.json').root_token,writer.accessor);
 await operator('/sys/policies/acl/'+writer.policy,{method:'DELETE'});
}
export async function readPrivateCapture(id){const r=await operator(captureVaultPath(id));if(r.data?.data?.purpose!=='user-approved-original-token-and-signed-url-retention')throw Error('Private capture record unavailable');return r.data;}
