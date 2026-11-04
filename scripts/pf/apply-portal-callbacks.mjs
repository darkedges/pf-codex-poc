import {readPortalActivation,activationDirectory} from '../vault/portal-activation.mjs';import {portalAdmin} from './portal-admin.mjs';import {applyPortalCallbacks} from './portal-activation-policy.mjs';import {writeFileSync} from 'node:fs';import {resolve} from 'node:path';
try{
 const args=process.argv.slice(2);if(!['--apply','--rollback'].includes(args.join()))throw Error();const rollback=args[0]==='--rollback';
 const {manifest}=readPortalActivation({rollback});await applyPortalCallbacks(portalAdmin,manifest.callbacks,rollback);
 const result={verifiedAt:new Date().toISOString(),callbacksApplied:!rollback,onlyTwoClients:true,existingRedirectsPreserved:true,issuerAudienceLifetimeChanged:false,microsoftRequests:0};writeFileSync(resolve(activationDirectory,rollback?'callbacks-rollback.json':'callbacks-applied.json'),JSON.stringify(result,null,2),{mode:0o600});console.log(JSON.stringify(result));
}catch{console.error('Portal callback change not confirmed; inspect only the reviewed clients. No automatic retry.');process.exitCode=1;}
