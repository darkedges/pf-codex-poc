import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { local,root } from './common.mjs';
import { authoritySettings } from './authority-config.mjs';
export async function startPolicy(env=process.env){
  // This launcher is explicitly the local PF lab. The service itself requires a backend.
  const child=spawn(process.execPath,['--experimental-strip-types','scripts/pf/policy-service.ts'],{cwd:root,env:{...env,...authoritySettings(env),NODE_EXTRA_CA_CERTS:resolve(local,'ca.pem'),POLICY_PORT:'0'},stdio:['ignore','inherit','inherit','ipc'],windowsHide:true});
  const ready=await new Promise((resolveReady,reject)=>{
    const timer=setTimeout(()=>{child.kill();reject(Error('Policy API startup timed out'));},15000);
    child.once('error',()=>{clearTimeout(timer);reject(Error('Policy API process unavailable'));});
    child.once('exit',()=>{clearTimeout(timer);reject(Error('Policy API exited before readiness'));});
    child.once('message',message=>{clearTimeout(timer);if(message?.ready&&/^https:\/\/localhost:\d+$/.test(message.origin))resolveReady(message.origin);else{child.kill();reject(Error('Invalid policy readiness'));}});
  });
  return{origin:ready,stop:async()=>{
    if(child.exitCode!==null)return;
    await new Promise(resolveStop=>{child.once('exit',resolveStop);if(child.connected)child.disconnect();else child.kill();});
  }};
}
