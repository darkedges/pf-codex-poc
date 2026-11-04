import test from 'node:test';import assert from 'node:assert/strict';
import {mobileMode,mobileHtml} from '../src/build-mode.ts';
import {nativeBrowser} from '../src/native-browser.ts';
test('live build is explicit and permits only the pinned API in its content policy',()=>{
 assert.equal(mobileMode(undefined),'device-test');assert.equal(mobileMode('live'),'live');
 for(const v of ['',true,'production','mock'])assert.throws(()=>mobileMode(v));
 const html='<meta content="connect-src \'none\'">Federated Copilot — device test';
 assert.equal(mobileHtml(html,'device-test'),html);assert.ok(mobileHtml(html,'live').includes('connect-src https://agent.copilot.darkedges.com'));assert.throws(()=>mobileHtml('<html>no policy</html>','live'));
});
test('browser cannot obtain pending-login secrets or enrollment-reference custody',async()=>{
 await assert.rejects(nativeBrowser.beginLogin(),/android_device_required/);await assert.rejects(nativeBrowser.getPendingLogin(),/android_device_required/);
 await assert.rejects(nativeBrowser.consumeReturn({attemptId:'x',returnUrl:'https://agent.copilot.darkedges.com/mobile/return'}),/android_device_required/);
 await assert.rejects(nativeBrowser.getEnrollmentReference(),/android_device_required/);await assert.rejects(nativeBrowser.forgetLocalEnrollment(),/android_device_required/);
 await assert.rejects(nativeBrowser.getConsentPreference(),/android_device_required/);await assert.rejects(nativeBrowser.setConsentPreference({enabled:true}),/android_device_required/);
});
