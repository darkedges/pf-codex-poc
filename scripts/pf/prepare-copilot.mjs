import { randomBytes } from 'node:crypto';
import { existsSync,writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { generateKeyPair,exportPKCS8,exportJWK } from 'jose';
import { admin,call,load,nodes,root } from './common.mjs';
import { copilotProfile,loginObjects,toolObjects } from './copilot-config.mjs';

const mode=process.argv.slice(2);
if(mode.length>1||mode.some(v=>v!=='--stage-disabled'))throw Error('Use no arguments for preview, or --stage-disabled for isolated local staging');
const folder=resolve(root,'.local/copilot'),receiptPath=resolve(folder,'pf-staging-receipt.json');
const summary={profile:'isolated-local-PF-Copilot-staging',...copilotProfile,clientsEnabled:false,publicRoutesEnabled:false,
 changesGlobalBaseUrls:false,changesExistingClients:false,changesExistingTrustRegistries:false,addsScope:'copilot.login',
 liveOAuthVerified:false,liveToolIssuanceVerified:false};
if(!mode.length){console.log(JSON.stringify(summary,null,2));process.exit(0);}
// The Windows credential helper creates this protected directory. Require its
// DACL before writing credentials; never create a weaker platform fallback.
if(!existsSync(folder))throw Error('Protected Copilot credential directory required');
if(process.platform!=='win32')throw Error('Windows protected-file staging required for this local lab');
const aclCheck=spawnSync('pwsh',['-NoProfile','-Command',"$ErrorActionPreference='Stop'; $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; $acl=Get-Acl -LiteralPath '.local/copilot'; $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])); if(!$acl.AreAccessRulesProtected -or $rules.Count -ne 2 -or @($rules | Where-Object { $_.IdentityReference.Value -notin @($sid,'S-1-5-18') -or $_.AccessControlType -ne 'Allow' -or ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl }).Count){exit 1}"],{cwd:root,stdio:'pipe',windowsHide:true});
if(aclCheck.status!==0)throw Error('Protected current-user/SYSTEM DACL required');
if(existsSync(receiptPath))throw Error('Staging receipt already exists: reconcile it; never retry uncertain POSTs');
if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error('Verified TLS required');
const collections=[['a','oauth/clients',copilotProfile.loginClientId],['a','oauth/accessTokenManagers','copilotLoginJWT'],
 ['a','keyPairs/signing','copilot-login-signing'],['b','idp/tokenProcessors','copilotToolBroker'],
 ['b','oauth/tokenExchange/processor/policies','copilotToolPolicy'],['b','oauth/clients',copilotProfile.toolClientId],
 ['b','oauth/accessTokenManagers','copilotToolJWT'],['b','keyPairs/signing','copilot-tool-signing']];
const baseUrls={};
for(const node of ['a','b'])baseUrls[node]=(await admin(node,'serverSettings')).federationInfo.baseUrl;
for(const [node,path,id]of collections){
 const current=await call(`${nodes[node].admin}/pf-admin-api/v1/${path}/${id}`,{admin:load(`admin-${node}.json`)});
 if(current.status!==404)throw Error('Staging object already exists or cannot be inspected; reconcile without overwrite');
}
const jwks=await call(nodes.a.issuer+'/pf/JWKS');
// PF's published RSA key omits alg; explicitly constrain this pinned copy to
// the existing consent broker manager's RS256 algorithm.
const brokerManager=await admin('a','oauth/accessTokenManagers/consentAJWT');
if(brokerManager.configuration.fields.find(f=>f.name==='JWS Algorithm')?.value!=='RS256')throw Error('Unexpected broker signing algorithm');
const brokerJwks={keys:jwks.value?.keys?.filter(k=>k.kid==='consent-a-signing').map(k=>({...k,alg:k.alg??'RS256'}))};
if(jwks.status!==200||!brokerJwks.keys?.length)throw Error('Pinned consent broker signing key required');
const secretPath=resolve(folder,'pf-generic-oauth-client-secret.txt'),privatePath=resolve(folder,'pf-sso-exchange.private.pem');
if(existsSync(secretPath)||existsSync(privatePath))throw Error('Unexpected existing staging credentials; reconcile without overwrite');
const secret=randomBytes(48).toString('base64url'),pair=await generateKeyPair('RS256',{extractable:true});
const clientJwks={keys:[{...await exportJWK(pair.publicKey),kid:'copilot-sso-exchange',alg:'RS256',use:'sig'}]};
const login=loginObjects(secret),tool=toolObjects(brokerJwks,clientJwks);
const receipt={...summary,status:'staging',createdAt:new Date().toISOString(),baseUrls,completed:[]};
writeFileSync(receiptPath,JSON.stringify(receipt,null,2),{flag:'wx',mode:0o600});
writeFileSync(secretPath,secret,{flag:'wx',mode:0o600});
writeFileSync(privatePath,await exportPKCS8(pair.privateKey),{flag:'wx',mode:0o600});
writeFileSync(resolve(folder,'pf-sso-exchange.jwks.json'),JSON.stringify(clientJwks,null,2),{flag:'wx',mode:0o600});
async function create(node,path,body){
 await admin(node,path,'POST',body);
 receipt.completed.push({node,path,id:body.id??body.clientId??body.accessTokenManagerRef?.id});
 writeFileSync(receiptPath,JSON.stringify(receipt,null,2),{mode:0o600});
}
try{
 const authSettings=await admin('a','oauth/authServerSettings');
 if(!authSettings.scopes.some(s=>s.name==='copilot.login')){
  authSettings.scopes.push({name:'copilot.login',description:'Isolated Copilot human login; no delegated tool access'});
  await admin('a','oauth/authServerSettings','PUT',authSettings);
  receipt.completed.push({node:'a',path:'oauth/authServerSettings',id:'scope:copilot.login'});
  writeFileSync(receiptPath,JSON.stringify(receipt,null,2),{mode:0o600});
 }
 // Disabled clients precede manager ACL references; final PUT binds each to its own manager.
 for(const [node,objects,kid]of [['a',login,'copilot-login-signing'],['b',tool,'copilot-tool-signing']]){
  if(objects.processor)await create(node,'idp/tokenProcessors',objects.processor);
  if(objects.policy)await create(node,'oauth/tokenExchange/processor/policies',objects.policy);
  await create(node,'oauth/clients',{...objects.client,defaultAccessTokenManagerRef:undefined,restrictToDefaultAccessTokenManager:false});
  await create(node,'keyPairs/signing/generate',{id:kid,keyAlgorithm:'RSA',keySize:2048,validDays:365,commonName:kid,organization:'Isolated Copilot lab',country:'AU'});
  await create(node,'oauth/accessTokenManagers',objects.manager);
  await create(node,'oauth/accessTokenMappings',objects.mapping);
  await admin(node,'oauth/clients/'+objects.client.clientId,'PUT',objects.client);
 }
 for(const node of ['a','b'])if((await admin(node,'serverSettings')).federationInfo.baseUrl!==baseUrls[node])throw Error('Global PF base URL drift');
 for(const [node,id]of [['a',copilotProfile.loginClientId],['b',copilotProfile.toolClientId]])if((await admin(node,'oauth/clients/'+id)).enabled!==false)throw Error('Staged client must remain disabled');
 receipt.status='staged-disabled';receipt.completedAt=new Date().toISOString();
 writeFileSync(receiptPath,JSON.stringify(receipt,null,2),{mode:0o600});
 console.log(JSON.stringify({...summary,status:receipt.status,createdObjects:receipt.completed.length},null,2));
}catch{
 receipt.status='reconciliation-required';writeFileSync(receiptPath,JSON.stringify(receipt,null,2),{mode:0o600});
 throw Error('Staging incomplete; inspect protected receipt/private PF diagnostics, do not retry or enable clients');
}
