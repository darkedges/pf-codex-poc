import type {NativeDevice} from './device-contract.ts';
import type {NativeBrowser,EnrollmentReference} from './native-browser.ts';
import type {MobileHttpsTransport} from './http-transport.ts';
import {parseMobileReturn} from './http-transport.ts';
import type {LiveDeviceSession} from './live-device-session.ts';
import {SignInDiagnostics,type SignInStage} from './signin-diagnostics.ts';
import {MobileTransportError} from './http-transport.ts';
type Message={id:string;role:'user'|'assistant';text:string};
type State={phase:'locked'|'starting'|'browser'|'completing'|'consent'|'chat'|'error';enrolled:boolean;chatId:string|null;messages:Message[];error:string|null;autoApprove:boolean;resourceRevoked:boolean;resourceDescription:string};
type Options={origin:string;device:NativeDevice;browser:NativeBrowser;
 transport:Pick<MobileHttpsTransport,'config'|'startLogin'|'claim'|'chat'|'cancelPending'|'resourceTerms'|'resourceStatus'|'approveResources'|'revokeResources'>;
 session:Pick<LiveDeviceSession,'enroll'|'resume'|'request'|'lock'>};

/** Foreground lifecycle composition. Snapshots contain no handoff, secret, token,
 * request proof, provider URL or trusted identity. No network/mock fallback. */
export class MobileAppController {
 #options:Options;#generation=0;#busy=false;#sending=false;#listeners=new Set<()=>void>();
 #termsHash='';#enrollmentExpiresAt=0;#preferenceEpoch=0;
 #preferenceWrites:Promise<void>=Promise.resolve();#preferenceError=false;
 #diagnostics=new SignInDiagnostics();
 #state:State={phase:'locked',enrolled:false,chatId:null,messages:[],error:null,autoApprove:true,resourceRevoked:false,resourceDescription:''};
 constructor(options:Options){const u=new URL(options.origin);if(u.protocol!=='https:'||u.origin!==options.origin)throw Error('invalid_mobile_origin');this.#options=options;}
 snapshot(){return{...structuredClone(this.#state),diagnostics:this.#diagnostics.snapshot()};}
 diagnosticReport(){return this.#diagnostics.report();}
 subscribe(listener:()=>void){this.#listeners.add(listener);return()=>{this.#listeners.delete(listener);};}
 #set(patch:Partial<State>){this.#state={...this.#state,...patch};for(const listener of this.#listeners)listener();}
 #check(generation:number){if(generation!==this.#generation)throw Error('mobile_operation_cancelled');}
 #record(stage:SignInStage,outcome:'started'|'passed'|'failed'|'cancelled',error?:unknown){
  let code:unknown;try{code=(error as {code?:unknown})?.code;}catch{}
  this.#diagnostics.record(stage,outcome,{code,...(error instanceof MobileTransportError?{httpStatus:error.httpStatus}:{})});this.#set({});
 }
 async #step<T>(stage:SignInStage,generation:number,work:()=>Promise<T>){
  this.#check(generation);this.#record(stage,'started');
  try{const result=await work();this.#check(generation);this.#record(stage,'passed');return result;}
  catch(error){if(generation===this.#generation)this.#record(stage,'failed',error);throw error;}
 }
 async initialize(){
  const generation=this.#generation,preferenceEpoch=this.#preferenceEpoch;try{const r=await this.#options.browser.getEnrollmentReference();this.#check(generation);this.#set({enrolled:r.enrolled});const p=await this.#options.browser.getConsentPreference();this.#check(generation);if(typeof p.enabled!=='boolean')throw Error();if(preferenceEpoch===this.#preferenceEpoch)this.#set({autoApprove:p.enabled});}catch{/* Entry rechecks native preference; unknown metadata never grants access. */}
 }
 async setAutoApprove(enabled:boolean){
  if(typeof enabled!=='boolean'||this.#busy||!['locked','error','consent'].includes(this.#state.phase))throw Error('mobile_preference_unavailable');
  const epoch=++this.#preferenceEpoch;
  const write=this.#preferenceWrites.then(()=>this.#options.browser.setConsentPreference({enabled}));this.#preferenceWrites=write.catch(()=>{});
  try{await write;if(epoch===this.#preferenceEpoch){this.#preferenceError=false;this.#set({autoApprove:enabled,error:null});}}
  catch{if(epoch===this.#preferenceEpoch){this.#preferenceError=true;this.#set({error:'The preference was not saved. Check the setting before continuing.'});}throw Error('mobile_preference_unavailable');}
 }
 async #fail(generation:number){
  if(generation!==this.#generation)return;
  this.#options.transport.cancelPending();await this.#options.session.lock();
  if(generation!==this.#generation)return;
  try{await this.#options.browser.cancelLogin();}catch{}
  if(generation!==this.#generation)return;
  this.#set({phase:'error',chatId:null,messages:[],error:'This attempt was not completed. Unlock again or start a new sign-in. No automatic retry was made.'});
 }
 #chat(){this.#set({phase:'chat',enrolled:true,chatId:crypto.randomUUID(),messages:[],error:null});}
 #status(status:Awaited<ReturnType<MobileHttpsTransport['resourceStatus']>>){if(status.termsHash!==this.#termsHash||status.expiresAt!==this.#enrollmentExpiresAt||status.approved&&status.revoked)throw Error('mobile_consent_mismatch');}
 async #approve(mode:'auto'|'manual',generation:number){
  const request=await this.#options.session.request(JSON.stringify({termsHash:this.#termsHash,mode}),'/v1/mobile/access/approve');this.#check(generation);
  const status=await this.#options.transport.approveResources(request);this.#check(generation);this.#status(status);if(!status.approved||status.revoked)throw Error();this.#set({resourceRevoked:false});this.#chat();
 }
 async #enter(generation:number,expiresAt:number){
  this.#enrollmentExpiresAt=expiresAt;
  await this.#preferenceWrites;this.#check(generation);if(this.#preferenceError)throw Error();
  const preference=await this.#options.browser.getConsentPreference();this.#check(generation);if(typeof preference.enabled!=='boolean')throw Error();this.#set({autoApprove:preference.enabled,enrolled:true});
  const terms=await this.#options.transport.resourceTerms();this.#check(generation);this.#termsHash=terms.termsHash;this.#set({resourceDescription:terms.description});
  const request=await this.#options.session.request('{}','/v1/mobile/access/status');this.#check(generation);
  const status=await this.#options.transport.resourceStatus(request);this.#check(generation);this.#status(status);this.#set({resourceRevoked:status.revoked});
  if(status.revoked){await this.#options.session.lock();this.#check(generation);this.#set({phase:'consent',chatId:null,messages:[],error:null});return;}
  if(status.approved){this.#chat();return;}
  if(preference.enabled){await this.#approve('auto',generation);return;}
  this.#set({phase:'consent',chatId:null,messages:[],error:null});
 }
 async approveAccess(){
  if(this.#busy||this.#state.phase!=='consent'||this.#state.resourceRevoked)throw Error('mobile_consent_unavailable');
  const generation=++this.#generation;this.#busy=true;this.#set({phase:'completing',error:null});
  try{await this.#approve('manual',generation);}catch{await this.#fail(generation);}finally{if(generation===this.#generation)this.#busy=false;}
 }
 async revokeAccess(){
  if(this.#busy||this.#state.phase!=='chat')throw Error('mobile_consent_unavailable');
  const generation=++this.#generation;this.#busy=true;this.#sending=false;this.#options.transport.cancelPending();this.#set({phase:'completing',chatId:null,messages:[],error:null});
  try{
   const request=await this.#options.session.request('{}','/v1/mobile/access/revoke');this.#check(generation);
   const status=await this.#options.transport.revokeResources(request);this.#check(generation);this.#status(status);if(status.approved||!status.revoked)throw Error();
   await this.#options.session.lock();this.#check(generation);this.#set({phase:'consent',resourceRevoked:true,error:null});
  }catch{await this.#fail(generation);}finally{if(generation===this.#generation)this.#busy=false;}
 }
 async signIn(resetLocal=false){
  if(this.#busy||this.#state.phase==='chat')throw Error('mobile_operation_in_progress');
  this.#diagnostics.begin();
  this.#busy=true;const generation=++this.#generation;this.#set({phase:'starting',chatId:null,messages:[],error:null});
  try{
   await this.#step('session_lock',generation,()=>this.#options.session.lock());
   await this.#step('pending_clear',generation,()=>this.#options.browser.cancelLogin());
   if(resetLocal){await this.#step('local_reset',generation,()=>this.#options.browser.forgetLocalEnrollment());this.#set({enrolled:false});}
   await this.#step('biometric_check',generation,async()=>{const status=await this.#options.device.getStatus();if(!status.available)throw Error();});
   const key=await this.#step('device_key',generation,async()=>{const value=await this.#options.device.createKey();if(!['tee','strongbox'].includes(value.securityLevel))throw Error();return value;});
   const pending=await this.#step('pending_login',generation,async()=>{const value=await this.#options.browser.beginLogin();if(!value.pending||value.devicePublicKeySpki!==key.publicKeySpki||value.expiresInMs<=0||value.expiresInMs>300000)throw Error();return value;});
   const launch=await this.#step('backend_login',generation,()=>this.#options.transport.startLogin({devicePublicKeySpki:key.publicKeySpki,claimHash:pending.claimHash}));
   // Set before opening: Android may stop this activity before the plugin resolves.
   this.#set({phase:'browser'});
   await this.#step('browser_launch',generation,()=>this.#options.browser.openLogin({attemptId:pending.attemptId,authorizationUrl:launch.authorizationUrl}));
  }catch{await this.#fail(generation);}
  finally{if(generation===this.#generation)this.#busy=false;}
 }
 async handleReturn(returnUrl:string){
  try{parseMobileReturn(returnUrl,this.#options.origin);}catch{return;}
  this.#record('browser_return','passed');
  const epoch=this.#generation;
  if(this.#busy&&this.#state.phase!=='browser')return;
  const pending=await this.#options.browser.getPendingLogin().catch(()=>({pending:false as const}));if(epoch!==this.#generation||!pending.pending||this.#state.phase==='chat')return;
  this.#record('pending_return','passed');
  const generation=++this.#generation;this.#busy=true;this.#set({phase:'completing',chatId:null,messages:[],error:null});
  try{
   const config=await this.#step('backend_config',generation,()=>this.#options.transport.config());
   const claim=await this.#step('return_claim',generation,async()=>{const value=await this.#options.browser.consumeReturn({attemptId:pending.attemptId,returnUrl});if(value.handoff!==parseMobileReturn(returnUrl,this.#options.origin)||value.devicePublicKeySpki!==pending.devicePublicKeySpki)throw Error();return value;});
   const enrollment=await this.#step('device_enrollment',generation,()=>this.#options.session.enroll(async keys=>{
    this.#check(generation);if(keys.devicePublicKeySpki!==claim.devicePublicKeySpki)throw Error();
    return this.#options.transport.claim({handoff:claim.handoff,claimSecret:claim.claimSecret,sessionPublicKeySpki:keys.sessionPublicKeySpki,termsHash:config.termsHash});
   }));
   await this.#step('enrollment_save',generation,()=>this.#options.browser.saveEnrollmentReference(enrollment));await this.#step('resource_access',generation,()=>this.#enter(generation,enrollment.enrollmentExpiresAt));
  }catch{await this.#fail(generation);}
  finally{if(generation===this.#generation)this.#busy=false;}
 }
 async unlock(){
  if(this.#busy||this.#state.phase==='chat')throw Error('mobile_operation_in_progress');
  const generation=++this.#generation;this.#busy=true;this.#set({phase:'completing',chatId:null,messages:[],error:null});
  try{
   await this.#options.browser.cancelLogin();this.#check(generation);
   const reference:EnrollmentReference=await this.#options.browser.getEnrollmentReference();this.#check(generation);if(!reference.enrolled)throw Error();
   const current=await this.#options.session.resume(reference.enrollmentId);this.#check(generation);
   if(current.enrollmentId!==reference.enrollmentId||current.enrollmentExpiresAt!==reference.enrollmentExpiresAt)throw Error();await this.#enter(generation,current.enrollmentExpiresAt);
  }catch{await this.#fail(generation);}
  finally{if(generation===this.#generation)this.#busy=false;}
 }
 async send(question:string){
  if(this.#state.phase!=='chat'||this.#sending||typeof question!=='string'||!question.trim()||question.length>2000||this.#state.messages.length>=100||/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(question))throw Error('mobile_message_unavailable');
  const generation=this.#generation;this.#sending=true;
  try{
   const text=question.trim(),request=await this.#options.session.request(JSON.stringify({question:text}));this.#check(generation);
   const response=await this.#options.transport.chat(request,async(body,path)=>{this.#check(generation);const signed=await this.#options.session.request(body,path);this.#check(generation);return signed;});this.#check(generation);
   this.#set({messages:[...this.#state.messages,{id:crypto.randomUUID(),role:'user',text},{id:crypto.randomUUID(),role:'assistant',text:response.answer}]});
  }catch{await this.#fail(generation);}
  finally{if(generation===this.#generation)this.#sending=false;}
 }
 async background(){
  this.#record('app_background','passed');
  const preserve=this.#state.phase==='browser',generation=++this.#generation;this.#busy=false;this.#sending=false;
  this.#options.transport.cancelPending();this.#set({phase:preserve?'browser':'locked',chatId:null,messages:[],error:null});
  await this.#options.session.lock();if(!preserve&&generation===this.#generation)try{await this.#options.browser.cancelLogin();}catch{}
 }
 async cancelSignIn(){this.#record('cancelled','cancelled');const generation=++this.#generation;this.#busy=false;this.#sending=false;this.#options.transport.cancelPending();this.#set({phase:'locked',chatId:null,messages:[],error:null});await this.#options.session.lock();if(generation===this.#generation)try{await this.#options.browser.cancelLogin();}catch{}}
}
