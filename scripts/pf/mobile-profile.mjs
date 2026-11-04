import {documentPfProfile} from './document-profile.mjs';
import {processor} from './config.mjs';
const provenance=['resource','authentication_basis','hardware_attestation','original_login_issuer','original_login_audience','original_auth_time','presence_time'];
const from=(type,value)=>({source:{type},value});
/** Public, offline plan only. No file/secret/admin access and no activation.
 * material.upstream must be the exact key generated for the owned PF A ATM,
 * independently read back and pinned before staging the PF B processor. */
export function mobilePfPlan(kind,material){
 if(!['chat','document'].includes(kind))throw Error('mobile_pf_configuration');
 const base=documentPfProfile(material),label=kind==='chat'?'Chat':'Document',scope=kind==='chat'?'copilot.invoke':'m365.document.read',resource='sharepoint:approved-research';
 const authorityIssuer='https://partner-a.test/mobile-authority',authorityAudience=`api://pf-a/mobile-${kind}-proof`,agentAudience=`api://pf-a/mobile-${kind}-agent`,upstreamAudience=`api://gateway-2/mobile-${kind}`,audience=kind==='chat'?'api://copilot-broker':'api://federated-copilot/mobile-documents';
 const subjectTokenType=`urn:example:token-type:mobile-${kind}-interactive`,actorTokenType=`urn:example:token-type:mobile-${kind}-agent`;
 const result={schemaVersion:1,purpose:`disabled-mobile-${kind}-pf-stage`,executionProfile:'pf-minute-lifetimes',clientsEnabled:false,authorityIssuer};
 const trusts={};
 for(const node of ['a','b']){
  const n=structuredClone(base[node]),upper=node.toUpperCase(),issuer=node==='a'?'https://localhost:9033':'https://localhost:9034',clientId=`mobile-${kind}-gateway-${node==='a'?'1':'2'}`,policyId=`mobile${label}${upper}Policy`,atmId=`mobile${label}${upper}JWT`,signingId=`mobile-${kind}-${node}-signing`;
  n.signingId=signingId;n.client.clientId=clientId;n.client.name=clientId;n.client.enabled=false;n.client.restrictedScopes=[scope];n.client.tokenExchangeProcessorPolicyRef={id:policyId};n.client.defaultAccessTokenManagerRef={id:atmId};
  n.policy.id=policyId;n.policy.name=`Mobile ${kind} delegated ${node}`;n.policy.attributeContract.extendedAttributes.push(...provenance.map(name=>({name})));
  const m=n.policy.processorMappings[0];m.subjectTokenProcessor={id:`mobile${label}${node==='a'?'Proof':'Upstream'}`};
  if(node==='a'){m.subjectTokenType=subjectTokenType;m.actorTokenType=actorTokenType;m.actorTokenProcessor={id:`mobile${label}Agent`};}
  for(const name of provenance)m.attributeContractFulfillment[name]=from('SUBJECT_TOKEN',name);
  for(const condition of m.issuanceCriteria.conditionalCriteria)if(condition.attributeName==='scope')condition.value=scope;
  for(const [attributeName,value]of Object.entries({resource,authentication_basis:'registered-device-key',hardware_attestation:'UNVERIFIED',original_login_issuer:'https://pf-a.copilot.darkedges.com',original_login_audience:'mobile-copilot-login'}))m.issuanceCriteria.conditionalCriteria.push({source:{type:'SUBJECT_TOKEN'},attributeName,condition:'EQUALS',value});
  n.subjectProcessor=processor(m.subjectTokenProcessor.id,node==='a'?authorityIssuer:'https://localhost:9033',node==='a'?authorityAudience:upstreamAudience,node==='a'?material.authority:material.upstream,provenance);
  if(node==='a')n.actorProcessor=processor(`mobile${label}Agent`,'https://partner-a.test/agents',agentAudience,material.agent);
  n.tokenManager.id=atmId;n.tokenManager.name=`Mobile ${kind} delegation ${node}`;n.tokenManager.configuration.fields.find(f=>f.name==="Audience Claim Value").value=node==="a"?upstreamAudience:audience;n.tokenManager.configuration.fields.find(f=>f.name==='Token Lifetime').value=node==='a'?'2':'1';n.tokenManager.configuration.fields.find(f=>f.name==='Active Signing Certificate Key ID').value=signingId;
  for(const field of n.tokenManager.configuration.tables[0].rows[0].fields)field.value=signingId;
  n.tokenManager.attributeContract.extendedAttributes.push(...provenance.map(name=>({name})));n.tokenManager.accessControlSettings.allowedClients=[{id:clientId}];n.tokenManager.selectionSettings.resourceUris=[`urn:copilot:mobile:${kind}:${node==='a'?'gateway-2':'broker'}`];
  n.mapping.context.contextRef={id:policyId};n.mapping.accessTokenManagerRef={id:atmId};for(const name of provenance)n.mapping.attributeContractFulfillment[name]=from('TOKEN_EXCHANGE_PROCESSOR_POLICY',name);
  for(const name of ['original_auth_time','presence_time'])n.mapping.attributeContractFulfillment[name]=from('EXPRESSION',`new java.lang.Long(#this.get("tepp.${name}").toString())`);
  trusts[node]={issuer,jwksUri:issuer+'/pf/JWKS',audience:node==='a'?upstreamAudience:audience,algorithms:['RS256'],keyIds:node==='a'?material.upstream.keys.map(k=>k.kid):[signingId],organisations:['partner-a'],actorIssuers:['https://partner-a.test/agents'],maxLifetimeSeconds:node==='a'?120:60};result[node]=n;
 }
 const hop=node=>({trust:trusts[node],tokenEndpoint:trusts[node].issuer+'/as/token.oauth2',clientId:result[node].client.clientId,clientKeyId:material[node==='a'?'clientA':'clientB'].keys[0].kid,clientAssertionAudience:trusts[node].issuer,requestedResource:result[node].tokenManager.selectionSettings.resourceUris[0]});
 result.exchange={scope,resource,executionProfile:'pf-minute-lifetimes',authority:{issuer:authorityIssuer,jwksUri:authorityIssuer+'/jwks',audience:authorityAudience,algorithms:['RS256'],keyIds:material.authority.keys.map(k=>k.kid),organisations:['partner-a'],actorIssuers:['https://partner-a.test/agents'],maxLifetimeSeconds:180},a:{...hop('a'),subjectTokenType,actorTokenType},b:hop('b'),agent:{issuer:'https://partner-a.test/agents',audience:agentAudience,keyId:material.agent.keys[0].kid},timeoutMs:10000};
 return result;
}
