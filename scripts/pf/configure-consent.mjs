import { randomBytes } from 'node:crypto';
import { generateKeyPair,exportPKCS8,exportJWK } from 'jose';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { admin,call,local,load,read,save,nodes } from './common.mjs';
import { profile,processor,client,tokenManager,exchangePolicy,accessTokenMapping } from './config.mjs';
import { authorityTrust } from './authority-config.mjs';
for(const name of ['consent-oidc','consent-gateway-1','consent-gateway-2','consent-authority'])if(!existsSync(resolve(local,`${name}.private.pem`))){
 const pair=await generateKeyPair('RS256',{extractable:true});save(`${name}.private.pem`,await exportPKCS8(pair.privateKey));save(`${name}.jwks.json`,{keys:[{...await exportJWK(pair.publicKey),kid:`copilot-${name}`,alg:'RS256',use:'sig'}]});
}
for(const name of ['login-password','other-login-password'])if(!existsSync(resolve(local,name)))save(name,'Fc!a'+randomBytes(24).toString('hex'));
async function upsert(node,collection,id,value){const current=await call(`${nodes[node].admin}/pf-admin-api/v1/${collection}/${encodeURIComponent(id)}`,{admin:load(`admin-${node}.json`)});if(![200,404].includes(current.status))throw Error(`Cannot reconcile consent object ${collection}`);return admin(node,current.status===200?`${collection}/${encodeURIComponent(id)}`:collection,current.status===200?'PUT':'POST',value);}
async function mapping(node,value){const all=await admin(node,'oauth/accessTokenMappings');const existing=(Array.isArray(all)?all:all.items).find(m=>m.context?.type===value.context.type&&m.context?.contextRef?.id===value.context.contextRef?.id&&m.accessTokenManagerRef?.id===value.accessTokenManagerRef.id);return admin(node,existing?`oauth/accessTokenMappings/${encodeURIComponent(existing.id)}`:'oauth/accessTokenMappings',existing?'PUT':'POST',value);}
const settings=await admin('a','oauth/authServerSettings');settings.parStatus='ENABLED';settings.parReferenceTimeout=120;settings.disallowPlainPKCE=true;await admin('a','oauth/authServerSettings','PUT',settings);
await upsert('a','passwordCredentialValidators','consentUsers',{id:'consentUsers',name:'Local consent login test accounts',pluginDescriptorRef:{id:'org.sourceid.saml20.domain.SimpleUsernamePasswordCredentialValidator'},attributeContract:{},configuration:{tables:[{name:'Users',rows:[
 [profile.human,'login-password'],['partner-a:user-other','other-login-password'],
].map(([username,file])=>({defaultRow:false,fields:[{name:'Username',value:username},{name:'Relax Password Requirements',value:'false'},{name:'Password',value:read(file)},{name:'Confirm Password',value:read(file)}]}))}]}});
await upsert('a','idp/adapters','consentHTMLForm',{id:'consentHTMLForm',name:'Consent portal PF login',pluginDescriptorRef:{id:'com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter'},configuration:{fields:[{name:'Challenge Retries',value:'3'},{name:'Session State',value:'None'},{name:'Login Template',value:'html.form.login.template.html'},{name:'Allow Password Changes',value:'false'},{name:"Enable 'Remember My Username'",value:'false'}],tables:[{name:'Credential Validators',rows:[{fields:[{name:'Password Credential Validator Instance',value:'consentUsers'}]}]}]},attributeContract:{coreAttributes:[{name:'policy.action',pseudonym:false,masked:false},{name:'username',pseudonym:true,masked:false}],uniqueUserKeyAttribute:'username'},attributeMapping:{attributeContractFulfillment:{'policy.action':{source:{type:'ADAPTER'},value:'policy.action'},username:{source:{type:'ADAPTER'},value:'username'}}}});
await upsert('a','oauth/idpAdapterMappings','consentHTMLForm',{id:'consentHTMLForm',idpAdapterRef:{id:'consentHTMLForm'},attributeContractFulfillment:{USER_KEY:{source:{type:'ADAPTER'},value:'username'},USER_NAME:{source:{type:'ADAPTER'},value:'username'}}});
const oidcClient={clientId:'copilot-consent-portal',name:'Delegated access consent portal',enabled:false,clientAuth:{type:'PRIVATE_KEY_JWT',enforceReplayPrevention:true,tokenEndpointAuthSigningAlgorithm:'RS256'},jwksSettings:{jwks:JSON.stringify(load('consent-oidc.jwks.json'))},grantTypes:['AUTHORIZATION_CODE'],redirectUris:['https://localhost:9460/callback','https://localhost:9461/callback'],requirePushedAuthorizationRequests:true,requireProofKeyForCodeExchange:true,restrictScopes:true,restrictedScopes:['openid'],bypassApprovalPage:false};
await upsert('a','oauth/clients',oidcClient.clientId,oidcClient);
await upsert('a','oauth/accessTokenManagers','consentLoginATM',{id:'consentLoginATM',name:'Consent portal login tokens',pluginDescriptorRef:{id:'org.sourceid.oauth20.token.plugin.impl.ReferenceBearerAccessTokenManagementPlugin'},configuration:{fields:[{name:'Token Length',value:'56'},{name:'Token Lifetime',value:'5'}]},attributeContract:{extendedAttributes:['sub','iss','aud'].map(name=>({name}))},accessControlSettings:{restrictClients:true,allowedClients:[{id:oidcClient.clientId}]}});
await mapping('a',{context:{type:'DEFAULT'},accessTokenManagerRef:{id:'consentLoginATM'},attributeContractFulfillment:{sub:{source:{type:'OAUTH_PERSISTENT_GRANT'},value:'USER_KEY'},iss:{source:{type:'TEXT'},value:nodes.a.issuer},aud:{source:{type:'TEXT'},value:oidcClient.clientId}}});
await upsert('a','oauth/openIdConnect/policies','consentLoginOIDC',{id:'consentLoginOIDC',name:'Consent portal identity',accessTokenManagerRef:{id:'consentLoginATM'},attributeContract:{extendedAttributes:[]},attributeMapping:{attributeContractFulfillment:{sub:{source:{type:'TOKEN'},value:'sub'}}},idTokenLifetime:5,allowIdTokenIntrospection:false});
await upsert('a','oauth/clients',oidcClient.clientId,{...oidcClient,enabled:true,defaultAccessTokenManagerRef:{id:'consentLoginATM'},restrictToDefaultAccessTokenManager:true,oidcPolicy:{policyGroup:{id:'consentLoginOIDC'},idTokenSigningAlgorithm:'RS256'}});
for(const node of ['a','b']){
 const kid=`consent-${node}-signing`,keys=await admin(node,'keyPairs/signing');if(!keys.items.some(k=>k.id===kid))await admin(node,'keyPairs/signing/generate','POST',{id:kid,keyAlgorithm:'RSA',keySize:2048,validDays:365,commonName:kid,organization:'Local consent integration',country:'AU'});
 if(node==='a')await upsert(node,'idp/tokenProcessors','consentGrantProof',processor('consentGrantProof',profile.consentAuthorityIssuer,'api://pf-a/consent-proof',authorityTrust()));
 else{
  const published=await call(nodes.a.issuer+'/pf/JWKS');const pinned={keys:published.value?.keys?.filter(k=>k.kid==='consent-a-signing')};if(published.status!==200||!pinned.keys?.length)throw Error('Consent PF A key unavailable');
  await upsert(node,'idp/tokenProcessors','consentUpstream',processor('consentUpstream',nodes.a.issuer,'api://gateway-2',pinned));
 }
 const policy=exchangePolicy(node);policy.id=`consent${node.toUpperCase()}Policy`;policy.name='Consented delegation '+node;
 for(const [index,m]of policy.processorMappings.entries()){
  m.subjectTokenProcessor.id=node==='a'?'consentGrantProof':'consentUpstream';if(node==='a')m.subjectTokenType=index===0?'urn:example:token-type:consented-interactive':'urn:example:token-type:consented-autonomous';
  m.issuanceCriteria.conditionalCriteria=m.issuanceCriteria.conditionalCriteria.filter(c=>c.attributeName!=='delegation_id');
 }
 await upsert(node,'oauth/tokenExchange/processor/policies',policy.id,policy);
 const clientId=node==='a'?'consent-gateway-1':'consent-gateway-2',atmId=`consent${node.toUpperCase()}JWT`;
 const c=client(clientId,policy.id,atmId,load(`${clientId}.jwks.json`));await upsert(node,'oauth/clients',clientId,{...c,enabled:false,defaultAccessTokenManagerRef:undefined,restrictToDefaultAccessTokenManager:false});
 const atm=tokenManager(node,nodes[node].issuer,node==='a'?'api://gateway-2':'api://copilot-broker');atm.id=atmId;atm.name='Consented delegation '+node;atm.accessControlSettings.allowedClients=[{id:clientId}];
 atm.selectionSettings.resourceUris=[node==='a'?'urn:copilot:consent:gateway-2':'urn:copilot:consent:broker'];
 atm.configuration.fields.find(f=>f.name==='Active Signing Certificate Key ID').value=kid;
 atm.configuration.tables[0].rows[0].fields.forEach(f=>{f.value=kid;});await upsert(node,'oauth/accessTokenManagers',atmId,atm);
 const map=accessTokenMapping(node);map.context.contextRef.id=policy.id;map.accessTokenManagerRef.id=atmId;await mapping(node,map);
 await upsert(node,'oauth/clients',clientId,c);
}
const config=load('exchange-config.json');config.upstream[0].keyIds=[...new Set([...config.upstream[0].keyIds,'consent-a-signing'])];config.downstream.keyIds=[...new Set([...config.downstream.keyIds,'consent-b-signing'])];save('exchange-config.json',config);
save('consent-exchange-config.json',{...config,upstream:[{...config.upstream[0],keyIds:['consent-a-signing']}],downstream:{...config.downstream,keyIds:['consent-b-signing']},clientId:'consent-gateway-2',clientKeyId:'copilot-consent-gateway-2',requestedResource:'urn:copilot:consent:broker'});
const jwks=await call(nodes.a.issuer+'/pf/JWKS');if(jwks.status!==200)throw Error('PF A OIDC verification keys unavailable');
save('oidc-config.json',{issuer:nodes.a.issuer,jwksUri:nodes.a.issuer+'/pf/JWKS',authorizationEndpoint:nodes.a.issuer+'/as/authorization.oauth2',parEndpoint:nodes.a.issuer+'/as/par.oauth2',tokenEndpoint:nodes.a.issuer+'/as/token.oauth2',clientId:oidcClient.clientId,keyIds:jwks.value.keys.filter(k=>k.kty==='RSA'&&k.use==='sig'&&(!k.alg||k.alg==='RS256')).map(k=>k.kid),keyId:'copilot-consent-oidc',adapterId:'consentHTMLForm'});
console.log('PF A login/PAR/PKCE client and consent-backed PF A/B exchange profiles configured. Local test passwords were not printed.');
