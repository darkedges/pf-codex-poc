export function createDocumentVerificationTransport(options){
 const authority=structuredClone(options.authorityJwk),deadline=options.deadlineAt,request=options.fetch;
 if(!Number.isSafeInteger(deadline)||typeof options.reserveTokenPost!=='function'||typeof request!=='function'||!authority||authority.d)throw Error('document_verification_transport_configuration');
 return async(url,init)=>{
  if(Date.now()>deadline)throw Error('document_verification_deadline');const u=new URL(String(url)),method=String(init?.method??'GET').toUpperCase();
  if(u.href==='https://partner-a.test/document-authority/jwks'){if(method!=='GET')throw Error('document_registry_method');return Response.json({keys:[authority]});}
  if(!['https://localhost:9033','https://localhost:9034','https://localhost:9453'].includes(u.origin)||u.username||u.password||u.hash)throw Error('document_network_target_denied');
  const token=u.pathname==='/as/token.oauth2'&&method==='POST';if(token)options.reserveTokenPost();
  const manual=!token&&u.origin==='https://localhost:9033'&&init?.redirect==='manual';
  const operation=token?'pf_token':u.origin==='https://localhost:9453'?'policy':u.pathname==='/as/par.oauth2'?'pf_par':'pf_browser_or_jwks';
  options.observe?.({operation,method});
  // LocalBrowser validates each redirect destination itself. Forcing error here
  // prevents it from receiving PF's302 login/resume response. Never auto-follow.
  const response=await request(url,{...init,method,redirect:manual?'manual':'error'});options.observe?.({operation,method,status:response.status});return response;
 };
}
export const isExplicitDocumentPolicyDenial=error=>error?.name==='PolicyError'&&error.code==='forbidden';
