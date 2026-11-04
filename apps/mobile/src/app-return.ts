import {App} from '@capacitor/app';
import {Capacitor} from '@capacitor/core';
import {parseMobileReturn} from './http-transport.ts';
type Runtime={addListener(name:'appUrlOpen',callback:(event:{url:string})=>void):Promise<{remove():Promise<void>}>;getLaunchUrl():Promise<{url:string}|undefined>};
/** Attach only while a phone-bound login is pending; a cold start without its
 * secret requires a fresh sign-in. Never log incoming links or return codes. */
export async function listenForMobileReturn(origin:string,onHandoff:(handoff:string)=>Promise<void>,runtime?:Runtime,readLaunch=true){
 if(!runtime&&Capacitor.getPlatform()!=='android')throw Error('android_device_required');
 const source=runtime??App,seen=new Set<string>();let active=true;
 const receive=(event:{url:string})=>{
  if(!active)return;let handoff:string;try{handoff=parseMobileReturn(event.url,origin);}catch{return;}
  if(seen.has(handoff)||seen.size>=8)return;seen.add(handoff);
  void onHandoff(handoff).catch(()=>{/* Caller owns a sanitized error state; never retry a spent handoff. */});
 };
 const listener=await source.addListener('appUrlOpen',receive);
 try{const launch=readLaunch?await source.getLaunchUrl():undefined;if(launch)receive(launch);}catch{await listener.remove();throw Error('mobile_return_unavailable');}
 return async()=>{active=false;seen.clear();await listener.remove();};
}
