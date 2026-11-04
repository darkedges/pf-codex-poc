import {mobilePfPlan} from './mobile-profile.mjs';
import {documentStageStep,documentStageHash} from './document-stage-step.mjs';

/** Injected control-plane operations. No operator lookup or automatic apply.
 * The caller must verify the exact reviewed recipe/source/approval before entry.
 * Durable pending entries stop repeats, including a lost write response. */
export async function stageMobileProfiles({materials,journal,save,admin,publishedKeys}){
 if(!journal||journal.purpose!=='mobile-disabled-staging'||!journal.steps||typeof save!=='function'||typeof admin!=='function'||typeof publishedKeys!=='function')throw Error('mobile_stage_configuration');
 const hash=documentStageHash(Object.fromEntries(['chat','document'].map(k=>[k,{...materials[k],upstream:undefined}])));
 if(journal.profileHash!==hash||Object.values(journal.steps).some(s=>s.state==='pending'))throw Error('mobile_stage_uncertain_or_changed');
 const get=async(node,path)=>{try{return await admin(node,path);}catch(e){if(e.status===404)return null;throw e;}};
 // Existing catalogs must already contain both approved scopes. This helper does
 // not modify global scope catalogs, existing clients or authentication policy.
 for(const node of ['a','b']){const settings=await get(node,'oauth/authServerSettings');if(!['copilot.invoke','m365.document.read'].every(name=>settings?.scopes?.some(s=>s.name===name&&s.dynamic===false)))throw Error('mobile_stage_scope_missing');}
 const profiles={};
 for(const kind of ['chat','document']){
  const material=structuredClone(materials[kind]);let plan=mobilePfPlan(kind,material);
  const step=(id,node,path,body,method='POST',readPath,previousHash)=>documentStageStep({id:kind+'-'+id,journal,save,expected:body,previousHash,read:()=>get(node,readPath??path+'/'+(body.id??body.clientId)),write:()=>admin(node,path,method,body)});
  for(const node of ['a','b']){
   const p=plan[node],id=node+'-key';
   await documentStageStep({id:kind+'-'+id,journal,save,expected:{id:p.signingId,keyAlgorithm:'RSA',keySize:4096},read:()=>get(node,'keyPairs/signing/'+p.signingId),write:()=>admin(node,'keyPairs/signing/generate','POST',{id:p.signingId,keyAlgorithm:'RSA',keySize:4096,validDays:30,commonName:p.signingId,organization:'Mobile federated PoC',country:'AU'})});
   await step(node+'-subject',node,'idp/tokenProcessors',p.subjectProcessor);if(p.actorProcessor)await step(node+'-actor',node,'idp/tokenProcessors',p.actorProcessor);
   await step(node+'-policy',node,'oauth/tokenExchange/processor/policies',p.policy);
   const initial={...p.client,restrictToDefaultAccessTokenManager:false};delete initial.defaultAccessTokenManagerRef;
   if(!journal.steps[kind+'-'+node+'-client-final'])await step(node+'-client-initial',node,'oauth/clients',initial);
   await step(node+'-manager',node,'oauth/accessTokenManagers',p.tokenManager);
   const mappingRead=async()=>{const all=await admin(node,'oauth/accessTokenMappings'),items=all.items??all;if(!Array.isArray(items))throw Error('mobile_stage_mapping');const found=items.filter(m=>m.context?.type===p.mapping.context.type&&m.context?.contextRef?.id===p.policy.id&&m.accessTokenManagerRef?.id===p.tokenManager.id);if(found.length>1)throw Error('mobile_stage_mapping');return found[0]??null;};
   await documentStageStep({id:kind+'-'+node+'-mapping',journal,save,expected:p.mapping,read:mappingRead,write:()=>admin(node,'oauth/accessTokenMappings','POST',p.mapping)});
   await step(node+'-client-final',node,'oauth/clients/'+p.client.clientId,p.client,'PUT','oauth/clients/'+p.client.clientId,journal.steps[kind+'-'+node+'-client-initial'].hash);
   const keys=await publishedKeys(node,p.signingId);if(!keys||keys.keys?.length!==1||keys.keys[0].kid!==p.signingId)throw Error('mobile_stage_public_pin');
   if(node==='a'){material.upstream=keys;plan=mobilePfPlan(kind,material);}
  }
  profiles[kind]=plan;
 }
 return{status:'STAGED_DISABLED',profiles,confirmedSteps:Object.keys(journal.steps).length,tokenRequests:0,microsoftRequests:0};
}
