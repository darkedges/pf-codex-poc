import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { local,root } from './common.mjs';
import { authoritySettings } from './authority-config.mjs';
const result=spawnSync(process.execPath,['--experimental-strip-types','scripts/pf/policy-service.ts'],{
  cwd:root,env:{...process.env,...authoritySettings(),NODE_EXTRA_CA_CERTS:resolve(local,'ca.pem')},stdio:'inherit',windowsHide:true,
});
process.exitCode=result.status??1;
