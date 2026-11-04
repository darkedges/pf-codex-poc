import {X509Certificate,createPrivateKey,createPublicKey,randomBytes,verify} from 'node:crypto';
import {documentWorkloads,documentSignerSpec,validatedDocumentLease} from '../../src/m365/document-authority-custody.mjs';
function selected(name){const s=name==='signer'?documentSignerSpec:Object.hasOwn(documentWorkloads,name)?documentWorkloads[name]:undefined;if(!s)throw Error('document_role_unknown');return s;}
export async function reconcileDocumentAuthorityRole(call,name,certPem,keyPem){
 const s=selected(name),cert=new X509Certificate(certPem),key=createPrivateKey(keyPem);
 if(cert.ca||!cert.checkPrivateKey(key)||key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails.modulusLength<3072||Date.parse(cert.validFrom)>Date.now()||Date.parse(cert.validTo)<=Date.now()+300000||!cert.keyUsage?.includes('1.3.6.1.5.5.7.3.2'))throw Error('document_role_certificate_invalid');
 const policyPath='/sys/policies/acl/'+s.policy,rolePath='/auth/tool-cert/certs/'+s.role,p=await call(policyPath);
 if(p.status===404){const w=await call(policyPath,{method:'PUT',body:{policy:s.policyText}});if(![200,204].includes(w.status))throw Error('document_role_write_unconfirmed');}
 else if(p.status!==200||p.value?.data?.policy!==s.policyText)throw Error('document_role_policy_drift');
 const role={certificate:certPem,token_policies:[s.policy],token_no_default_policy:true,token_ttl:120,token_max_ttl:120,token_explicit_max_ttl:120,token_num_uses:1,token_type:'service'},r=await call(rolePath);
 const matches=v=>v?.certificate?.trim()===certPem.trim()&&Object.entries(role).every(([k,value])=>k==='certificate'||JSON.stringify(v[k])===JSON.stringify(value));
 if(r.status===404){const w=await call(rolePath,{method:'POST',body:role});if(![200,204].includes(w.status))throw Error('document_role_write_unconfirmed');}
 else if(r.status!==200||!matches(r.value?.data))throw Error('document_role_drift');
 const [pp,rr]=await Promise.all([call(policyPath),call(rolePath)]);if(pp.status!==200||pp.value?.data?.policy!==s.policyText||rr.status!==200||!matches(rr.value?.data))throw Error('document_role_readback_unconfirmed');return{verified:true};
}
export async function verifyDocumentAuthorityChallenge(call,profile){
 if(profile?.name!=='document-authority'||profile.version!==1||profile.kid!=='document-authority-v1'||profile.publicJwk?.d)throw Error('document_authority_pin_invalid');
 const token=validatedDocumentLease(await call('/auth/tool-cert/login',{method:'POST',body:{name:documentSignerSpec.role}}),documentSignerSpec.policy),challenge=randomBytes(32);
 const r=await call(documentSignerSpec.path,{method:'POST',token,body:{input:challenge.toString('base64'),key_version:1,signature_algorithm:'pkcs1v15',prehashed:false}}),signature=r.value?.data?.signature;
 if(r.status!==200||typeof signature!=='string'||!/^vault:v1:[A-Za-z0-9+/]+={0,2}$/.test(signature)||!verify('sha256',challenge,createPublicKey({key:profile.publicJwk,format:'jwk'}),Buffer.from(signature.slice('vault:v1:'.length),'base64')))throw Error('document_authority_challenge_failed');return{verified:true,grantAssertionsIssued:0};
}
