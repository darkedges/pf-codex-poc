// Narrow operator-approved local PF change; never reconfigure other managers/clients.
import {isDeepStrictEqual} from 'node:util';
import {writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {admin,root} from './common.mjs';
import {copilotProfile as p} from './copilot-config.mjs';
const args=process.argv.slice(2);
if(args.length!==1||args[0]!=='--apply')throw Error('Explicit --apply required for the approved sixty-minute local login profile');
const managerPath='oauth/accessTokenManagers/copilotLoginJWT';
const before=await admin('a',managerPath),login=await admin('a','oauth/clients/'+p.loginClientId),tool=await admin('b','oauth/clients/'+p.toolClientId);
const field=(manager,name)=>manager.configuration.fields.find(f=>f.name===name)?.value;
// PF re-encrypts the same stored secret on reads. Actual login verifies it separately.
const comparableClient=client=>{const copy=structuredClone(client);if(copy.clientAuth)delete copy.clientAuth.encryptedSecret;return copy;};
if(before.id!=='copilotLoginJWT'||field(before,'Issuer Claim Value')!==p.loginIssuer||field(before,'Audience Claim Value')!==p.loginAudience||field(before,'JWS Algorithm')!=='RS256'||!['3','5','60'].includes(field(before,'Token Lifetime'))||!isDeepStrictEqual(before.accessControlSettings.allowedClients.map(c=>c.id),[p.loginClientId])||login.enabled!==true||tool.enabled!==false||login.defaultAccessTokenManagerRef?.id!==before.id)throw Error('Dedicated login profile drift; no change applied');
const expected=structuredClone(before);expected.configuration.fields.find(f=>f.name==='Token Lifetime').value=String(p.loginLifetimeSeconds/60);
if(!isDeepStrictEqual(before,expected))await admin('a',managerPath,'PUT',expected);
const after=await admin('a',managerPath);
if(!isDeepStrictEqual(after,expected)||!isDeepStrictEqual(comparableClient(await admin('a','oauth/clients/'+p.loginClientId)),comparableClient(login))||!isDeepStrictEqual(comparableClient(await admin('b','oauth/clients/'+p.toolClientId)),comparableClient(tool)))throw Error('Post-change profile verification failed; reconcile before further tests');
const receipt={completedAt:new Date().toISOString(),manager:'copilotLoginJWT',previousMinutes:Number(field(before,'Token Lifetime')),currentMinutes:Number(field(after,'Token Lifetime')),clientStatesPreserved:true,microsoftRequests:0};
writeFileSync(resolve(root,'.local/copilot/login-lifetime-change.json'),JSON.stringify(receipt,null,2),{mode:0o600});
console.log(JSON.stringify(receipt));
