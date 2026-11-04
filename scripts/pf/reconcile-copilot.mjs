import {readFileSync,writeFileSync,existsSync} from 'node:fs';
import {resolve} from 'node:path';
import {admin,call,load,nodes,root} from './common.mjs';
import {toolObjects,copilotProfile} from './copilot-config.mjs';
const args=process.argv.slice(2);
if(args.length>1||args.some(a=>!['--apply-disabled','--resume-disabled'].includes(a)))throw Error('Use preview, --apply-disabled or inspected --resume-disabled');
if(!args.length){console.log('Reconcile disabled tool profile with PF A proof and expiry cap; add exact virtual issuers/hostnames. No client enablement, base URL, DNS or tunnel changes.');process.exit(0);}
const folder=resolve(root,'.local/copilot'),receiptFile=resolve(folder,'pf-public-profile-receipt.json');
const resume=args[0]==='--resume-disabled';
if(existsSync(receiptFile)&&!resume)throw Error('Reconciliation receipt exists; inspect before any repeat');
if(resume&&!existsSync(receiptFile))throw Error('Resume requires an inspected receipt');
const staged=JSON.parse(readFileSync(resolve(folder,'pf-staging-receipt.json'),'utf8'));
if(staged.status!=='staged-disabled')throw Error('Expected completed disabled staging');
for(const [node,id] of [['a',copilotProfile.loginClientId],['b',copilotProfile.toolClientId]])if((await admin(node,'oauth/clients/'+id)).enabled!==false)throw Error('Both new clients must be disabled');
const jwks=await call(nodes.a.issuer+'/pf/JWKS');
if(jwks.status!==200)throw Error('Verified upstream JWKS unavailable');
const keys={keys:jwks.value.keys.filter(k=>k.kid==='consent-a-signing').map(k=>({...k,alg:k.alg??'RS256'}))};
const objects=toolObjects(keys,JSON.parse(readFileSync(resolve(folder,'pf-sso-exchange.jwks.json'),'utf8')));
const mappings=await admin('b','oauth/accessTokenMappings');
const mapping=(Array.isArray(mappings)?mappings:mappings.items).find(m=>m.context?.type==='TOKEN_EXCHANGE_PROCESSOR_POLICY'&&m.context?.contextRef?.id===objects.policy.id&&m.accessTokenManagerRef?.id===objects.manager.id);
if(!mapping)throw Error('Dedicated mapping missing');
const before={processor:await admin('b','idp/tokenProcessors/'+objects.processor.id),policy:await admin('b','oauth/tokenExchange/processor/policies/'+objects.policy.id),manager:await admin('b','oauth/accessTokenManagers/'+objects.manager.id),mapping};
const receipt=resume?JSON.parse(readFileSync(receiptFile,'utf8')):{status:'applying-disabled',createdAt:new Date().toISOString(),before,completed:[]};
if(resume){
 const expected=['b/idp/tokenProcessors/copilotToolBroker','b/oauth/tokenExchange/processor/policies/copilotToolPolicy','b/oauth/accessTokenManagers/copilotToolJWT'];
 if(receipt.status!=='reconciliation-required'||JSON.stringify(receipt.completed)!==JSON.stringify(expected)||!before.processor.attributeContract.extendedAttributes.some(a=>a.name==='exp')||!before.policy.attributeContract.extendedAttributes.some(a=>a.name==='upstream_exp')||!before.manager.attributeContract.extendedAttributes.some(a=>a.name==='exp'))throw Error('Resume state differs from inspected partial operation');
}else writeFileSync(receiptFile,JSON.stringify(receipt,null,2),{flag:'wx',mode:0o600});
const record=step=>{receipt.completed.push(step);writeFileSync(receiptFile,JSON.stringify(receipt,null,2),{mode:0o600});};
try{
 for(const [path,value]of [['idp/tokenProcessors/'+objects.processor.id,objects.processor],['oauth/tokenExchange/processor/policies/'+objects.policy.id,objects.policy],['oauth/accessTokenManagers/'+objects.manager.id,objects.manager],['oauth/accessTokenMappings/'+encodeURIComponent(mapping.id),objects.mapping]]){if(receipt.completed.includes('b/'+path))continue;await admin('b',path,'PUT',value);record('b/'+path);}
 for(const node of ['a','b']){
  const host=new URL(node==='a'?copilotProfile.loginIssuer:copilotProfile.toolIssuer).hostname;
  const issuer={id:'copilotPublic'+node.toUpperCase(),name:'Copilot public '+node.toUpperCase(),host};
  const issuers=await admin(node,'oauth/issuers');
  if(issuers.items.some(i=>i.id===issuer.id||i.host===host))throw Error('Unexpected existing virtual issuer; reconcile without overwrite');
  await admin(node,'oauth/issuers','POST',issuer);record(node+'/oauth/issuers/'+issuer.id);
  const hosts=await admin(node,'virtualHostNames');
  if(!hosts.virtualHostNames.includes(host)){hosts.virtualHostNames.push(host);await admin(node,'virtualHostNames','PUT',hosts);record(node+'/virtualHostNames/'+host);}
  if((await admin(node,'serverSettings')).federationInfo.baseUrl!==nodes[node].issuer)throw Error('Local base URL drift');
 }
 receipt.status='reconciled-disabled';record('verified');
 console.log(JSON.stringify({status:receipt.status,clientsEnabled:false,publicRoutesEnabled:false,baseUrlsUnchanged:true,steps:receipt.completed.length}));
}catch{receipt.status='reconciliation-required';writeFileSync(receiptFile,JSON.stringify(receipt,null,2),{mode:0o600});throw Error('Reconciliation incomplete; inspect protected receipts/diagnostics without blind retry');}
