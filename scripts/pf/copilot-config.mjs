import { processor,client,tokenManager,exchangePolicy,accessTokenMapping } from './config.mjs';

// Fixed, additive LAB profiles. Never mutate the working localhost profiles.
export const copilotProfile=Object.freeze({loginClientId:'copilot-studio-generic-oauth',toolClientId:'copilot-sso-exchange',
 callback:'https://token.botframework.com/.auth/web/redirect',loginIssuer:'https://pf-a.copilot.darkedges.com',
 toolIssuer:'https://pf-b.copilot.darkedges.com',loginAudience:'api://copilot-login',toolAudience:'api://copilot-tool',loginLifetimeSeconds:3600});
const from=(type,value)=>({source:{type},value});
function signing(manager,kid){
 manager.configuration.fields.find(f=>f.name==='Active Signing Certificate Key ID').value=kid;
 manager.configuration.tables[0].rows[0].fields.forEach(f=>{f.value=kid;});
 return manager;
}
function publicKeys(jwks){
 if(!jwks||!Array.isArray(jwks.keys)||!jwks.keys.length||jwks.keys.some(k=>k.kty!=='RSA'||k.alg!=='RS256'||k.use!=='sig'||!k.kid||!k.n||!k.e||['d','p','q','dp','dq','qi','k'].some(p=>p in k)))throw Error('Explicit public RS256 signing keys required');
 return jwks;
}
export function loginObjects(secret){
 if(typeof secret!=='string'||secret.length<16||secret.length>256)throw Error('Explicit dedicated login secret required');
 const p=copilotProfile,id='copilotLoginJWT';
 const c={clientId:p.loginClientId,name:'Copilot human login — staged disabled',enabled:false,clientAuth:{type:'SECRET',secret},
  grantTypes:['AUTHORIZATION_CODE'],redirectUris:[p.callback],restrictScopes:true,restrictedScopes:['copilot.login'],
  bypassApprovalPage:false,defaultAccessTokenManagerRef:{id},restrictToDefaultAccessTokenManager:true};
 const manager=signing(tokenManager('a',p.loginIssuer,p.loginAudience),'copilot-login-signing');
 manager.configuration.fields.find(f=>f.name==='Token Lifetime').value=String(p.loginLifetimeSeconds/60);
 manager.id=id;manager.name='Copilot human login only — not delegated tool authority';
 manager.attributeContract.extendedAttributes=[{name:'sub'}];
 manager.selectionSettings.resourceUris=['urn:copilot:login'];manager.accessControlSettings.allowedClients=[{id:c.clientId}];
 return{client:c,manager,mapping:{context:{type:'DEFAULT'},accessTokenManagerRef:{id},attributeContractFulfillment:{sub:from('OAUTH_PERSISTENT_GRANT','USER_KEY')}}};
}
export function toolObjects(upstreamJwks,clientJwks){
 publicKeys(upstreamJwks);publicKeys(clientJwks);
 const p=copilotProfile,id='copilotToolJWT',policyId='copilotToolPolicy';
 // Branch from fresh verified PF A proof. Chaining two one-minute PF B tokens
 // cannot narrow expiry safely with this plugin's whole-minute granularity.
 const trust=processor('copilotToolBroker','https://localhost:9033','api://gateway-2',upstreamJwks,['exp']);
 const policy=exchangePolicy('b');policy.id=policyId;policy.name='Copilot delegated tool profile — lab identities';
 policy.processorMappings[0].subjectTokenProcessor.id=trust.id;
 policy.attributeContract.extendedAttributes.push({name:'upstream_exp'});
 policy.processorMappings[0].attributeContractFulfillment.upstream_exp=from('SUBJECT_TOKEN','exp');
 policy.processorMappings[0].issuanceCriteria.conditionalCriteria=policy.processorMappings[0].issuanceCriteria.conditionalCriteria.filter(c=>c.attributeName!=='delegation_id');
 const c={...client(p.toolClientId,policyId,id,clientJwks),enabled:false};
 const manager=signing(tokenManager('b',p.toolIssuer,p.toolAudience),'copilot-tool-signing');
 manager.id=id;manager.name='Copilot delegated tool audience — staged disabled client';
 manager.selectionSettings.resourceUris=['urn:copilot:delegated:tool'];manager.accessControlSettings.allowedClients=[{id:c.clientId}];
 const mapping=accessTokenMapping('b');mapping.context.contextRef.id=policyId;mapping.accessTokenManagerRef.id=id;
 manager.attributeContract.extendedAttributes.push({name:'exp'});
 mapping.attributeContractFulfillment.exp=from('EXPRESSION','#expiry=@java.lang.Long@parseLong(#this.get("tepp.upstream_exp").toString()), @java.lang.Math@min(2, @java.lang.Math@floor((#expiry - (@java.lang.System@currentTimeMillis() / 1000) - 10) / 60.0).intValue()).toString()');
 mapping.issuanceCriteria={expressionCriteria:[{expression:'#expiry=@java.lang.Long@parseLong(#this.get("tepp.upstream_exp").toString()), #remaining=#expiry - (@java.lang.System@currentTimeMillis() / 1000), #remaining >= 75 && #remaining <= 185',errorResult:'Insufficient verified token lifetime'}]};
 return{processor:trust,policy,client:c,manager,mapping};
}
