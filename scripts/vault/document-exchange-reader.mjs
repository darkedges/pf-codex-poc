import {X509Certificate,createPrivateKey} from 'node:crypto';
import {documentExchangeRole,documentExchangePolicy,documentExchangePolicyText} from '../../src/m365/document-exchange-custody.mjs';
export async function reconcileDocumentExchangeReader(call,certificatePem,keyPem){
 const cert=new X509Certificate(certificatePem),key=createPrivateKey(keyPem);
 if(cert.ca||!cert.checkPrivateKey(key)||key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails.modulusLength<3072||Date.parse(cert.validFrom)>Date.now()||Date.parse(cert.validTo)<=Date.now()+300000||!cert.keyUsage?.includes('1.3.6.1.5.5.7.3.2'))throw Error('document_reader_certificate_invalid');
 const policyPath='/sys/policies/acl/'+documentExchangePolicy,rolePath='/auth/tool-cert/certs/'+documentExchangeRole;
 const policy=await call(policyPath);
 if(policy.status===404){const r=await call(policyPath,{method:'PUT',body:{policy:documentExchangePolicyText}});if(r.status!==204&&r.status!==200)throw Error('document_reader_enrollment_unconfirmed');}
 else if(policy.status!==200||policy.value?.data?.policy!==documentExchangePolicyText)throw Error('document_reader_policy_drift');
 const role={certificate:certificatePem,token_policies:[documentExchangePolicy],token_no_default_policy:true,token_ttl:120,token_max_ttl:120,token_explicit_max_ttl:120,token_num_uses:1,token_type:'service'},current=await call(rolePath);
 const matches=r=>r?.certificate?.trim()===certificatePem.trim()&&Object.entries(role).every(([k,v])=>k==='certificate'||JSON.stringify(r[k])===JSON.stringify(v));
 if(current.status===404){const r=await call(rolePath,{method:'POST',body:role});if(r.status!==204&&r.status!==200)throw Error('document_reader_enrollment_unconfirmed');}
 else if(current.status!==200||!matches(current.value?.data))throw Error('document_reader_role_drift');
 const [p,r]=await Promise.all([call(policyPath),call(rolePath)]);
 if(p.status!==200||p.value?.data?.policy!==documentExchangePolicyText||r.status!==200||!matches(r.value?.data))throw Error('document_reader_enrollment_unconfirmed');
 return{verified:true};
}
