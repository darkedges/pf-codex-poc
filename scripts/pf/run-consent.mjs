import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { root,local } from './common.mjs';
export async function startConsent(env=process.env){
 const child=spawn(process.execPath,['--experimental-strip-types','scripts/pf/consent-service.ts'],{cwd:root,env:{...env,NODE_EXTRA_CA_CERTS:resolve(local,'ca.pem'),CONSENT_PORT:env.CONSENT_PORT??'9461'},stdio:['ignore','inherit','inherit','ipc'],windowsHide:true});
 const origin=await new Promise((done,reject)=>{const timer=setTimeout(()=>{child.kill();reject(Error('Consent portal startup timed out'));},15000);child.once('error',()=>{clearTimeout(timer);reject(Error('Consent portal process unavailable'));});child.once('exit',()=>{clearTimeout(timer);reject(Error('Consent portal exited before readiness'));});child.once('message',m=>{clearTimeout(timer);if(m?.ready&&/^https:\/\/localhost:946[01]$/.test(m.origin))done(m.origin);else{child.kill();reject(Error('Invalid consent readiness'));}});});
 return{origin,stop:async()=>{if(child.exitCode!==null)return;await new Promise(done=>{child.once('exit',done);if(child.connected)child.disconnect();else child.kill();});}};
}
