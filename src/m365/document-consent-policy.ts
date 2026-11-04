import type {PolicyStore} from '../policy/store.ts';import type {VerifiedLogin} from '../policy/contracts.ts';
export const documentCapability=Object.freeze({scope:'m365.document.read',resource:'sharepoint:approved-research'});
export const documentConsentRecorder='policy-document-consent';
export function createDocumentConsentPolicy(store:PolicyStore){
 const owned=(grantId:string,tokenHash:string)=>{const grant=store.grant(grantId),consent=store.consentForGrant(grantId);if(!grant||!consent||!(Number(grant.expires_at)-Number(grant.approved_at)>0&&Number(grant.expires_at)-Number(grant.approved_at)<=300000)||grant.recorded_by!==documentConsentRecorder||consent.token_hash!==tokenHash||JSON.stringify(JSON.parse(String(grant.scopes)))!==JSON.stringify([documentCapability.scope])||JSON.stringify(JSON.parse(String(grant.resources)))!==JSON.stringify([documentCapability.resource])||JSON.stringify(JSON.parse(String(grant.modes)))!=='["interactive"]')throw Error('document_consent_denied');return grant;};
 return{
  check:async(input:{grantId:string;login:VerifiedLogin;agent:{issuer:string;subject:string}})=>{owned(input.grantId,input.login.tokenHash);return store.authoriseConsentedGrant(input.grantId,input.agent,'interactive',documentCapability,'policy-document-reader',input.login);},
  authorise:async(claims:any,evidence:{accessToken:string;capability:{scope:string;resource:string}})=>{if(!evidence.accessToken||evidence.capability.scope!==documentCapability.scope||evidence.capability.resource!==documentCapability.resource||!store.decide(claims,documentCapability,'policy-document-reader').permit)throw Error('document_policy_denied');},
  cleanup:async(grantId:string,tokenHash:string)=>{const grant=owned(grantId,tokenHash);if(grant.state!=='revoked')store.revokeGrant(grantId,'document-read-cleanup');if(store.grant(grantId)?.state!=='revoked')throw Error('document_cleanup_unconfirmed');return{revoked:true as const};}
 };
}
