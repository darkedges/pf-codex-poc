import {readFileSync,writeFileSync,mkdirSync,existsSync,copyFileSync,constants} from 'node:fs';
import {resolve} from 'node:path';import {createHash} from 'node:crypto';import {fileURLToPath} from 'node:url';
import {mobileCustodyPlan} from './mobile-custody-plan.mjs';
const root=resolve(fileURLToPath(new URL('../../',import.meta.url))),hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const files=['AGENTS.md','src/identity/oidc.ts','src/identity/provider-access.ts','src/identity/assertion-signer.ts','src/adapters/direct-line.ts','src/mobile/application.ts','src/mobile/provider-sessions.ts','src/mobile/provider-enrollment.ts','src/mobile/site-documents.ts','src/mobile/chat-executor.ts','src/mobile/chat-jobs.ts','src/mobile/http-api.ts','src/mobile/https-host.ts','src/mobile/device-authority.ts','src/mobile/execution-authority.ts','src/mobile/federation-runtime.ts','src/mobile/pf-exchange.ts','scripts/pf/mobile-profile.mjs','scripts/pf/mobile-stage.mjs','scripts/pf/config.mjs','scripts/pf/document-profile.mjs','scripts/pf/document-stage-step.mjs','scripts/vault/mobile-custody-plan.mjs','scripts/vault/prepare-mobile-staging-review.mjs','docs/mobile-staging-review.md'];
try{
 if(process.argv.length!==2)throw Error();
 const directory=resolve(root,'.local/mobile/staging-review'),manifest=resolve(directory,'manifest.json'),apk=resolve(root,'apps/mobile/android/app/build/outputs/apk/debug/app-debug.apk'),release=resolve(root,'.local/mobile/releases/federated-copilot-live-v5-candidate.apk');
 const sha=hash(readFileSync(apk));if(sha!=='6aabdbab5b7307bd51c7d500a9c3af16bcf1b5eab5345a581fefcc12af7e6ae0')throw Error();
 mkdirSync(directory,{recursive:true,mode:0o700});mkdirSync(resolve(root,'.local/mobile/releases'),{recursive:true,mode:0o700});
 if(existsSync(release)){if(hash(readFileSync(release))!==sha)throw Error();}else copyFileSync(apk,release,constants.COPYFILE_EXCL);
 const packet={schemaVersion:1,purpose:'mobile-disabled-staging',approved:false,recipe:mobileCustodyPlan(),source: Object.fromEntries(files.map(f=>[f,hash(readFileSync(resolve(root,f)))])),apk:{path:'.local/mobile/releases/federated-copilot-live-v5-candidate.apk',sha256:sha,versionCode:5,versionName:'0.2.0',signingCertificateSha256:'4d8b412744cc5a821ca093c265a6b4fa28317a520ec5f9445001839d9a14c68a'},microsoftRequests:0,pfTokenRequests:0,publicChanges:0};
 const raw=JSON.stringify(packet,null,2)+'\n';if(existsSync(manifest)){if(readFileSync(manifest,'utf8')!==raw)throw Error();}else writeFileSync(manifest,raw,{flag:'wx',mode:0o600});
 console.log(JSON.stringify({prepared:true,approved:false,manifestSha256:hash(Buffer.from(raw)),files:files.length,apkSha256:sha,pfTokenRequests:0,microsoftRequests:0}));
}catch{console.error('Mobile review preparation stopped. Existing packets and APKs were preserved; no live changes were applied.');process.exitCode=1;}
