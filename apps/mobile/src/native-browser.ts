import {Capacitor,registerPlugin} from '@capacitor/core';
export type PendingBrowserLogin={pending:false}|{pending:true;attemptId:string;devicePublicKeySpki:string;claimHash:string;expiresInMs:number};
export type EnrollmentReference={enrolled:false}|{enrolled:true;enrollmentId:string;enrollmentExpiresAt:number};
export type NativeBrowser={
 beginLogin():Promise<PendingBrowserLogin>;
 getPendingLogin():Promise<PendingBrowserLogin>;
 openLogin(input:{attemptId:string;authorizationUrl:string}):Promise<void>;
 consumeReturn(input:{attemptId:string;returnUrl:string}):Promise<{handoff:string;claimSecret:string;devicePublicKeySpki:string}>;
 cancelLogin():Promise<void>;
 getEnrollmentReference():Promise<EnrollmentReference>;
 saveEnrollmentReference(input:{enrollmentId:string;enrollmentExpiresAt:number}):Promise<void>;
 forgetLocalEnrollment():Promise<void>;
 getConsentPreference():Promise<{enabled:boolean}>;
 setConsentPreference(input:{enabled:boolean}):Promise<void>;
};
const plugin=registerPlugin<NativeBrowser>('BrowserLogin');
const android=()=>{if(Capacitor.getPlatform()!=='android')throw Error('android_device_required');};
export const nativeBrowser:NativeBrowser={
 beginLogin:async()=>{android();return plugin.beginLogin();},getPendingLogin:async()=>{android();return plugin.getPendingLogin();},
 openLogin:async input=>{android();await plugin.openLogin(input);},consumeReturn:async input=>{android();return plugin.consumeReturn(input);},
 cancelLogin:async()=>{android();await plugin.cancelLogin();},getEnrollmentReference:async()=>{android();return plugin.getEnrollmentReference();},
 saveEnrollmentReference:async input=>{android();await plugin.saveEnrollmentReference(input);},forgetLocalEnrollment:async()=>{android();await plugin.forgetLocalEnrollment();},
 getConsentPreference:async()=>{android();return plugin.getConsentPreference();},setConsentPreference:async input=>{android();await plugin.setConsentPreference(input);}
};
