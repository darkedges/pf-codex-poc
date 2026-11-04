import {documentPfProfile} from './document-profile.mjs';
// Public, offline planning only. Applying this plan needs its own reviewed
// preflight/ownership journal and explicit approval; no admin client is imported.
export function documentStagePlan(publicTrust){
 const p=documentPfProfile(publicTrust),operations=[];
 for(const node of ['a','b']){
  const n=p[node],add=(path,body,method='POST')=>operations.push({node,method,path:'/pf-admin-api/v1/'+path,body});
  add('keyPairs/signing/generate',{id:n.signingId,keyAlgorithm:'RSA',keySize:4096,validDays:30,commonName:n.signingId,organization:'Local document PoC',country:'AU'});
  add('idp/tokenProcessors',n.subjectProcessor);if(n.actorProcessor)add('idp/tokenProcessors',n.actorProcessor);
  add('oauth/tokenExchange/processor/policies',n.policy);
  const initial={...n.client,restrictToDefaultAccessTokenManager:false};delete initial.defaultAccessTokenManagerRef;
  add('oauth/clients',initial);add('oauth/accessTokenManagers',n.tokenManager);add('oauth/accessTokenMappings',n.mapping);
  add('oauth/clients/'+n.client.clientId,n.client,'PUT');
 }
 return{schemaVersion:1,purpose:'disabled-document-pf-stage',readyToApply:false,prerequisites:['approved-dedicated-public-key-pins','document-scope-registration-reviewed','all-target-objects-absent-or-owned-and-identical','durable-intent-before-each-write','reconcile-uncertain-response-before-any-repeat','actual-pf-a-signing-key-pin-before-pf-b-processor','absolute-expiry-configuration-verified-before-enabling'],clientsEnabled:false,tokenRequests:0,microsoftRequests:0,operations};
}
