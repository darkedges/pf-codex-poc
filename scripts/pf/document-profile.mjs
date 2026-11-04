import {createPublicKey} from 'node:crypto';
import {processor,client,tokenManager,exchangePolicy,accessTokenMapping,profile} from './config.mjs';

// Pure plan builder. No administration, key generation, file access or activation.
// Public key inputs must be explicitly selected and reviewed by the operator.
export const documentProfile=Object.freeze({scope:'m365.document.read',resource:'sharepoint:approved-research',authorityIssuer:'https://partner-a.test/document-authority',authorityAudience:'api://pf-a/document-consent-proof',agentAudience:'api://pf-a/document-agent-proof',upstreamAudience:'api://gateway-2/documents',audience:'api://federated-copilot/documents'});
function publicJwks(value){
 if(!value||Object.keys(value).join()!=='keys'||!Array.isArray(value.keys)||!value.keys.length||value.keys.length>4)throw Error('document_public_trust_required');
 const ids=new Set();
 for(const k of value.keys){
  if(!k||Object.keys(k).some(n=>!['kty','n','e','kid','alg','use'].includes(n))||k.kty!=='RSA'||k.alg!=='RS256'||k.use!=='sig'||typeof k.kid!=='string'||!/^[A-Za-z0-9_-]{1,100}$/.test(k.kid)||ids.has(k.kid)||typeof k.n!=='string'||typeof k.e!=='string'||!/^[A-Za-z0-9_-]+$/.test(k.n)||!/^[A-Za-z0-9_-]+$/.test(k.e))throw Error('document_public_trust_required');
  const key=createPublicKey({key:k,format:'jwk'});if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails.modulusLength<2048)throw Error('document_public_trust_required');ids.add(k.kid);
 }
 return structuredClone(value);
}
export function documentPfProfile(material){
 if(!material||Object.keys(material).sort().join()!=='agent,authority,clientA,clientB,upstream')throw Error('document_public_trust_required');
 const keys=Object.fromEntries(Object.entries(material).map(([k,v])=>[k,publicJwks(v)]));
 const d=documentProfile,issuers={a:'https://localhost:9033',b:'https://localhost:9034'};
 const result={authorityIssuer:d.authorityIssuer};
 for(const node of ['a','b']){
  const upper=node.toUpperCase(),policy=exchangePolicy(node),clientId=`document-gateway-${node==='a'?'1':'2'}`,atmId=`document${upper}JWT`,signingId=`document-${node}-signing`;
  policy.id=`document${upper}Policy`;policy.name=`Document interactive delegation ${node}`;
  policy.processorMappings=policy.processorMappings.slice(0,1);
  const m=policy.processorMappings[0];m.subjectTokenProcessor.id=node==='a'?'documentGrantProof':'documentUpstream';
  if(node==='a'){m.subjectTokenType='urn:example:token-type:document-consented-interactive';m.actorTokenType='urn:example:token-type:document-agent-proof';m.actorTokenProcessor.id='documentAgent';}
  m.issuanceCriteria.conditionalCriteria=m.issuanceCriteria.conditionalCriteria.filter(c=>c.attributeName!=='delegation_id');
  for(const c of m.issuanceCriteria.conditionalCriteria)if(c.attributeName==='scope')c.value=d.scope;
  if(!m.issuanceCriteria.conditionalCriteria.some(c=>c.attributeName==='execution_mode'))m.issuanceCriteria.conditionalCriteria.push({source:{type:'SUBJECT_TOKEN'},attributeName:'execution_mode',condition:'EQUALS',value:'interactive'});
  const c=client(clientId,policy.id,atmId,node==='a'?keys.clientA:keys.clientB);c.enabled=false;c.restrictedScopes=[d.scope];
  const atm=tokenManager(node,issuers[node],node==='a'?d.upstreamAudience:d.audience);atm.id=atmId;atm.name=`Document delegation ${node}`;
  atm.configuration.fields.find(f=>f.name==='Token Lifetime').value=node==='a'?'2':'1';
  atm.configuration.fields.find(f=>f.name==='Active Signing Certificate Key ID').value=signingId;
  for(const field of atm.configuration.tables[0].rows[0].fields)field.value=signingId;
  atm.accessControlSettings.allowedClients=[{id:clientId}];atm.selectionSettings.resourceUris=[node==='a'?'urn:copilot:document:gateway-2':'urn:copilot:document:broker'];
  const mapping=accessTokenMapping(node);mapping.context.contextRef.id=policy.id;mapping.accessTokenManagerRef.id=atmId;
  result[node]={client:c,policy,tokenManager:atm,mapping,signingId,subjectProcessor:processor(node==='a'?'documentGrantProof':'documentUpstream',node==='a'?d.authorityIssuer:issuers.a,node==='a'?d.authorityAudience:d.upstreamAudience,node==='a'?keys.authority:keys.upstream),...(node==='a'?{actorProcessor:processor('documentAgent',profile.agentIssuer,d.agentAudience,keys.agent)}:{})};
 }
 const trust=(node,audience,keyIds)=>({issuer:issuers[node],jwksUri:issuers[node]+'/pf/JWKS',audience,algorithms:['RS256'],keyIds,organisations:[profile.org],actorIssuers:[profile.agentIssuer],maxLifetimeSeconds:node==='a'?120:60});
 result.exchange={upstream:[trust('a',d.upstreamAudience,keys.upstream.keys.map(k=>k.kid))],downstream:trust('b',d.audience,['document-b-signing']),tokenEndpoint:issuers.b+'/as/token.oauth2',clientId:'document-gateway-2',clientKeyId:keys.clientB.keys[0].kid,clientAlgorithm:'RS256',clientAssertionAudience:issuers.b,targetParameter:'resource',requestedResource:'urn:copilot:document:broker',scope:d.scope,timeoutMs:5000};
 return result;
}
