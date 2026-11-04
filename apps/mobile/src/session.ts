import {createChallenge} from './device-contract.ts';import type {NativeDevice,DeviceProof} from './device-contract.ts';
type Message={id:string;role:'user'|'assistant';text:string};
type State={phase:'locked'|'unlocking'|'chat'|'error';chatId:string|null;messages:Message[];error:string|null};
// Local hardware spike only. This class grants no server/PF/Copilot authority.
// No storage, network request or browser-biometric fallback is implemented.
export class DeviceTestSession{
 #native:NativeDevice;#verify:(proof:DeviceProof)=>Promise<boolean>;#generation=0;#busy=false;#listeners=new Set<()=>void>();
 #state:State={phase:'locked',chatId:null,messages:[],error:null};
 constructor(native:NativeDevice,verify:(proof:DeviceProof)=>Promise<boolean>){this.#native=native;this.#verify=verify;}
 snapshot(){return structuredClone(this.#state);}
 subscribe(listener:()=>void){this.#listeners.add(listener);return()=>{this.#listeners.delete(listener);};}
 #set(state:State){this.#state=state;for(const listener of this.#listeners)listener();}
 async unlock(){
  if(this.#busy||this.#state.phase==='chat')throw Error('device_operation_in_progress');
  this.#busy=true;const generation=++this.#generation;this.#set({phase:'unlocking',chatId:null,messages:[],error:null});
  try{
   const status=await this.#native.getStatus();if(!status.available)throw Error();if(generation!==this.#generation)return;
   const metadata=await this.#native.createKey();if(!['tee','strongbox'].includes(metadata.securityLevel)||!metadata.publicKeySpki)throw Error();if(generation!==this.#generation)return;
   const challenge=createChallenge(),proof=await this.#native.signChallenge({challenge});if(generation!==this.#generation)return;
   if(proof.challenge!==challenge||proof.publicKeySpki!==metadata.publicKeySpki||!await this.#verify(proof))throw Error();if(generation!==this.#generation)return;
   this.#set({phase:'chat',chatId:crypto.randomUUID(),messages:[],error:null});
  }catch{if(generation===this.#generation)this.#set({phase:'error',chatId:null,messages:[],error:'Fingerprint unlock was not completed. This test requires Android with an enrolled strong biometric and a hardware-backed key.'});}
  finally{if(generation===this.#generation)this.#busy=false;}
 }
 async lock(){++this.#generation;this.#busy=false;this.#set({phase:'locked',chatId:null,messages:[],error:null});try{await this.#native.lock();}catch{/* Remain locked even if native cancellation fails. */}}
 send(value:string){
  if(this.#state.phase!=='chat'||typeof value!=='string'||!value.trim()||value.length>2000||/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value)||this.#state.messages.length>=100)throw Error('message_not_available');
  this.#set({...this.#state,messages:[...this.#state.messages,{id:crypto.randomUUID(),role:'user',text:value.trim()},{id:crypto.randomUUID(),role:'assistant',text:'Device test reply — not Copilot. Your message stayed in this app. Live PF sign-in, Copilot and SharePoint are not connected in this build.'}]});
 }
}
