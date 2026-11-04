import {readFileSync,writeFileSync,mkdirSync,existsSync,lstatSync} from 'node:fs';import {resolve} from 'node:path';import {createHash} from 'node:crypto';
import {root} from '../pf/common.mjs';import {protect,custody} from './tool-custody.mjs';
try{
 if(process.argv.length!==2)throw Error();protect();
 const files=['docs/portal-executor-custody-review.md','scripts/vault/enroll-portal-executor.mjs','scripts/vault/portal-executor-profile.mjs','scripts/vault/portal-executor-trust.mjs','scripts/vault/relay-host-profile.mjs',...['agent','consent-gateway-1','consent-gateway-2','policy-agent','policy-gateway'].map(n=>'.local/pingfederate/'+n+'.jwks.json'),'.local/tool-vault/relay-gateway-trust.json'];
 const hashes=Object.fromEntries(files.map(name=>{const path=resolve(root,name),s=lstatSync(path);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.size>262144)throw Error();return[name,createHash('sha256').update(readFileSync(path)).digest('hex')];}));
 const manifest={schemaVersion:1,purpose:'portal-executor-vault-enrollment',approved:false,reviewSha256:hashes[files[0]],files:hashes,record:'/federated-copilot-tool-secrets/data/portal-executor',role:'copilot-portal-executor-reader',maxMicrosoftConversations:0,maxTokenPosts:0,publicRoutesChanged:false};
 const directory=resolve(custody,'portal-executor-review');mkdirSync(directory,{recursive:true,mode:0o700});const path=resolve(directory,'manifest.json'),raw=JSON.stringify(manifest,null,2);
 if(existsSync(path)){if(readFileSync(path,'utf8')!==raw)throw Error();}else writeFileSync(path,raw,{mode:0o600,flag:'wx'});
 console.log(JSON.stringify({prepared:true,approved:false,reviewSha256:manifest.reviewSha256,filesHashed:files.length,credentialsRead:false,microsoftRequests:0,publicRoutesChanged:false}));
}catch{console.error('Portal gateway review preparation failed; existing packet was not overwritten.');process.exitCode=1;}
