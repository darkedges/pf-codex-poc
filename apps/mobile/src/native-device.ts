import {Capacitor,registerPlugin} from '@capacitor/core';import type {NativeDevice} from './device-contract.ts';
const plugin=registerPlugin<NativeDevice>('DevicePresence');
const livePlugin=registerPlugin<NativeDevice>('MobilePresence');
const android=()=>{if(Capacitor.getPlatform()!=='android')throw Error('android_device_required');};
export const nativeDevice:NativeDevice={
 getStatus:async()=>{android();return plugin.getStatus();},createKey:async()=>{android();return plugin.createKey();},
 signChallenge:async options=>{android();return plugin.signChallenge(options);},lock:async()=>{android();await plugin.lock();}
};
// Separate native key alias and restricted live challenge domain. No browser fallback.
export const liveNativeDevice:NativeDevice={
 getStatus:async()=>{android();return livePlugin.getStatus();},createKey:async()=>{android();return livePlugin.createKey();},
 signChallenge:async options=>{android();return livePlugin.signChallenge(options);},lock:async()=>{android();await livePlugin.lock();}
};
