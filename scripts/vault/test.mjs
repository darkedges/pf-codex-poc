import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { root,local,save,load } from '../pf/common.mjs';
import { authoritySettings } from '../pf/authority-config.mjs';
const settings=authoritySettings();if(settings.AUTHORITY_SIGNER!=='vault-transit')throw Error('Explicit configured Vault profile required');
const result=spawnSync(process.execPath,['--experimental-strip-types','--test','tests/vault/*.test.ts'],{cwd:root,env:{...process.env,...settings,NODE_EXTRA_CA_CERTS:resolve(local,'ca.pem')},stdio:'inherit',windowsHide:true});
save('vault-validation.json',{completedAt:new Date().toISOString(),exitCode:result.status??1,environment:'actual isolated TLS Vault + PF A/B; non-exportable RSA Transit key, sign-only credential, credential revocation/expiry, seal/stop/restart, PF key overlap/retirement and credential-free logs',version:load('authority-transit-config.json').version});
process.exitCode=result.status??1;
