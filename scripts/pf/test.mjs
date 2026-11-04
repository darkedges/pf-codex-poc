import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { local, root, load, save } from './common.mjs';
import { startPolicy } from './run-policy.mjs';
import { authoritySettings } from './authority-config.mjs';
if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') throw Error('Live PF tests require TLS verification');
const runDirectory=resolve(local,'policy-tests',randomUUID());
mkdirSync(runDirectory,{recursive:true});
const env={...process.env,...authoritySettings(),NODE_EXTRA_CA_CERTS:resolve(local,'ca.pem'),POLICY_DATABASE:resolve(runDirectory,'policy.sqlite')};
const policy=await startPolicy(env);
try{
  const result=spawnSync(process.execPath,['--experimental-strip-types','--test','tests/live/*.test.ts'],{cwd:root,env:{...env,POLICY_API_ORIGIN:policy.origin},stdio:'inherit'});
  save('validation.json',{completedAt:new Date().toISOString(),exitCode:result.status??1,versions:{a:load('version-a.json'),b:load('version-b.json')},
    environment:'real local PF containers; PF browser login/consent; authenticated consent authority with cross-process replay protection; consent-backed exchange; retained isolated fixture regressions; persistent policy API',authoritySigner:env.AUTHORITY_SIGNER,policyDatabase:env.POLICY_DATABASE});
  process.exitCode=result.status??1;
}finally{await policy.stop();}
