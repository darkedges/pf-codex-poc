import {documentStageHash} from './document-stage-step.mjs';
// PF re-encrypts this field on GET. It is not a stable credential fingerprint.
// Keep all other fields (including modificationDate and secondary secrets).
// The controller credential is independently digest-pinned by its Vault loader;
// the actual provider token exchange must still authenticate against PF.
export function documentChatCallbackFingerprint(client){
 const copy=structuredClone(client);
 if(copy?.clientId==='copilot-studio-generic-oauth'&&copy.clientAuth?.type==='SECRET')delete copy.clientAuth.encryptedSecret;
 return documentStageHash(copy);
}
