import {nativeBrowser} from './native-browser.ts';
import {liveNativeDevice} from './native-device.ts';
import {MobileHttpsTransport} from './http-transport.ts';
import {LiveDeviceSession} from './live-device-session.ts';
import {MobileAppController} from './mobile-controller.ts';
export const mobileOrigin='https://agent.copilot.darkedges.com';
export function createMobileController(){
 const transport=new MobileHttpsTransport(mobileOrigin,'https://pf-a.copilot.darkedges.com/as/authorization.oauth2');
 return new MobileAppController({origin:mobileOrigin,transport,device:liveNativeDevice,browser:nativeBrowser,session:new LiveDeviceSession(mobileOrigin,liveNativeDevice,transport)});
}
