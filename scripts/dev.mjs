import { spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
const root=resolve('.local/keys/pf-a.private.pem');
if (!existsSync(root)) {
  const g=spawnSync(process.execPath,['scripts/generate-dev-keys.mjs'],{stdio:'inherit'});
  if (g.status!==0) process.exit(g.status||1);
}
const services=['mock-pf-a','delegation','mock-pf-b','copilot-broker','gateway-2','gateway-1'];
const children=services.map(service=>{
  const child=spawn(process.execPath,['--experimental-strip-types',`src/services/${service}.ts`],{env:{...process.env,DEMO_ONLY:'true',COPILOT_MODE:'mock',M365_MODE:'mock'},stdio:'inherit'});
  child.on('exit',(code)=>{if(!shuttingDown && code!==0){console.error(`${service} exited ${code}`); stop();}});
  return child;
});
let shuttingDown=false;
function stop(){if(shuttingDown)return;shuttingDown=true;for(const child of children)child.kill('SIGTERM');}
process.on('SIGINT',stop);process.on('SIGTERM',stop);
console.log('Local services starting. Run `npm run smoke` in another terminal. Ctrl+C to stop.');
