import {documentStageHash} from './document-stage-step.mjs';
// PF updates modificationDate on each owned flag write; every other field stays pinned.
export const documentChatPfFingerprint=client=>{const copy=structuredClone(client);delete copy.modificationDate;return documentStageHash(copy);};
export const documentChatPfClients=Object.freeze([{node:'a',id:'document-gateway-1',scope:'m365.document.read'},{node:'b',id:'document-gateway-2',scope:'m365.document.read'},{node:'a',id:'consent-gateway-1',scope:'copilot.invoke'},{node:'b',id:'consent-gateway-2',scope:'copilot.invoke'}].map(Object.freeze));
export function createDocumentChatPfLease(options){
 const owner=structuredClone(options.owner),baselines=structuredClone(options.baselines),expiresAt=options.expiresAt;
 if(!/^[a-f0-9-]{36}$/.test(owner?.instance)||!Number.isSafeInteger(owner.pid)||owner.pid<1||!Number.isSafeInteger(expiresAt)||expiresAt<=Date.now()||expiresAt>Date.now()+3600000)throw Error('document_chat_pf_lease_configuration');
 const owned=state=>state&&documentStageHash(state.owner)===documentStageHash(owner);
 const save=state=>options.save(structuredClone(state));
 return{
  acquire:async()=>{
   if(options.read())throw Error('document_chat_pf_lease_exists');const entries=[];
   for(const spec of documentChatPfClients){const c=await options.admin(spec.node,'oauth/clients/'+spec.id);if(documentChatPfFingerprint(c)!==baselines[spec.node+':'+spec.id]||typeof c.enabled!=='boolean'||c.clientId!==spec.id||c.clientAuth?.type!=='PRIVATE_KEY_JWT'||c.clientAuth.enforceReplayPrevention!==true||JSON.stringify(c.grantTypes)!=='["TOKEN_EXCHANGE"]'||c.restrictScopes!==true||JSON.stringify(c.restrictedScopes)!==JSON.stringify([spec.scope]))throw Error('document_chat_pf_baseline_drift');entries.push({...spec,beforeHash:documentChatPfFingerprint(c),beforeEnabled:c.enabled,enabledHash:documentChatPfFingerprint({...c,enabled:true}),state:'planned'});}
   const state={schemaVersion:1,owner,expiresAt,state:'active',entries};save(state);
   for(const e of entries){if(Date.now()>=expiresAt)throw Error('document_chat_pf_expired');const current=await options.admin(e.node,'oauth/clients/'+e.id);if(documentChatPfFingerprint(current)!==e.beforeHash)throw Error('document_chat_pf_drift');e.state='pending';save(state);if(!e.beforeEnabled)await options.admin(e.node,'oauth/clients/'+e.id,'PUT',{...current,enabled:true});const after=await options.admin(e.node,'oauth/clients/'+e.id);if(documentChatPfFingerprint(after)!==e.enabledHash)throw Error('document_chat_pf_unconfirmed');e.state='enabled';save(state);}
  },
  check:async()=>{const state=options.read();if(!owned(state)||state.state!=='active'||Date.now()>=state.expiresAt)throw Error('document_chat_pf_unavailable');for(const e of state.entries)if(e.state!=='enabled'||documentChatPfFingerprint(await options.admin(e.node,'oauth/clients/'+e.id))!==e.enabledHash)throw Error('document_chat_pf_drift');},
  release:async()=>{
   const state=options.read();if(!state)return;if(!owned(state))throw Error('document_chat_pf_foreign_owner');if(state.state==='released')return;
   for(const e of [...state.entries].reverse()){
    if(!documentChatPfClients.some(s=>s.node===e.node&&s.id===e.id))throw Error('document_chat_pf_foreign_client');const current=await options.admin(e.node,'oauth/clients/'+e.id),hash=documentChatPfFingerprint(current);
    if(hash===e.beforeHash){e.state='restored';save(state);continue;}
    if(hash!==e.enabledHash||e.beforeEnabled)throw Error('document_chat_pf_drift');await options.admin(e.node,'oauth/clients/'+e.id,'PUT',{...current,enabled:false});if(documentChatPfFingerprint(await options.admin(e.node,'oauth/clients/'+e.id))!==e.beforeHash)throw Error('document_chat_pf_restore_unconfirmed');e.state='restored';save(state);
   }
   state.state='released';save(state);
  }
 };
}
