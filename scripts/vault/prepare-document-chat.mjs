import {existsSync,mkdirSync,writeFileSync} from 'node:fs';import {resolve} from 'node:path';
import {root,admin,load} from '../pf/common.mjs';import {documentChatPfClients,documentChatPfFingerprint} from '../pf/document-chat-pf-lease.mjs';import {documentStageHash} from '../pf/document-stage-step.mjs';
import {documentChatSsoPlan} from '../pf/document-chat-sso.mjs';
import {documentChatCallbackFingerprint} from '../pf/document-chat-callback.mjs';
import {chatDirectory,documentChatReviewFiles} from './document-chat-review.mjs';import {checkedBytes,digest} from './document-exchange-approval.mjs';
try{
 if(process.argv.length!==2)throw Error();const target=resolve(chatDirectory,'manifest.json');if(existsSync(target))throw Error('existing_packet_retained');
 const baselines={};for(const s of documentChatPfClients){const c=await admin(s.node,'oauth/clients/'+s.id);if(c.clientId!==s.id||typeof c.enabled!=='boolean'||c.clientAuth?.type!=='PRIVATE_KEY_JWT'||c.clientAuth.enforceReplayPrevention!==true||JSON.stringify(c.grantTypes)!=='["TOKEN_EXCHANGE"]'||!c.restrictScopes||JSON.stringify(c.restrictedScopes)!==JSON.stringify([s.scope]))throw Error();baselines[s.node+':'+s.id]=documentChatPfFingerprint(c);}
 const oidc=load('oidc-config.json'),callbacks={};for(const[id,callback]of[[oidc.clientId,'/callback'],['copilot-studio-generic-oauth','/provider-callback']]){const c=await admin('a','oauth/clients/'+id);if(c.enabled!==true||!c.redirectUris?.includes('https://agent.copilot.darkedges.com'+callback))throw Error();callbacks[id]=documentChatCallbackFingerprint(c);}
 const ssoPlan=documentChatSsoPlan(await Promise.all(['idp/adapters/consentHTMLForm','oauth/clients/copilot-consent-portal','oauth/clients/copilot-studio-generic-oauth'].map(path=>admin('a',path))));
 const files=Object.fromEntries(documentChatReviewFiles().map(f=>[f,digest(checkedBytes(resolve(root,f)))])),m={schemaVersion:1,purpose:'one-question-single-visible-login-poc',windowSeconds:2700,maxQuestions:1,maxConversations:1,maxTokenPosts:1,maxGraphTokens:1,maxGraphGets:2,maxDownloads:1,maxPfTokenPosts:12,baselines,callbacks,ssoPlan,files};
 mkdirSync(chatDirectory,{recursive:true,mode:0o700});writeFileSync(target,JSON.stringify(m,null,2),{mode:0o600,flag:'wx'});console.log(JSON.stringify({prepared:true,approved:false,manifestSha256:digest(checkedBytes(target)),filesHashed:Object.keys(files).length,pfMutations:0,microsoftRequests:0}));
}catch{console.error('Document chat review preparation stopped; no packet overwritten, no activation or Microsoft request.');process.exitCode=1;}
