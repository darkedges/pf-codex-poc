/** Deployment-generated public association data; never accept a request-selected signer. */
export function androidAssociation(certificateSha256:string){
 if(typeof certificateSha256!=='string'||!/^[0-9a-fA-F]{64}$/.test(certificateSha256))throw Error('invalid_android_signer');
 return[{relation:['delegate_permission/common.handle_all_urls'],target:{namespace:'android_app',package_name:'com.darkedges.federatedcopilot.demo',sha256_cert_fingerprints:[certificateSha256.toUpperCase().match(/../g)!.join(':')]}}];
}
