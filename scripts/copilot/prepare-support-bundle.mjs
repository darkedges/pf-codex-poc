import {readFileSync,lstatSync,readdirSync,mkdirSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {randomUUID,createHash} from 'node:crypto';
import {root,local} from '../pf/common.mjs';
import {protect,custody} from '../vault/tool-custody.mjs';
import {projectTokenPostAttempt,projectLocalEvidence,projectTarget,projectBudgets,renderSupportCase} from './support-evidence.mjs';
const json=path=>{const s=lstatSync(path);if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.size>1048576)throw Error();return JSON.parse(readFileSync(path,'utf8'));};
try{
 if(process.argv.length!==2)throw Error();
 const directory=resolve(root,'.local/copilot'),runs=resolve(local,'copilot-live-sso');
 const target=projectTarget(json(resolve(directory,'channel-settings.json'))),budget=projectBudgets(['live-sso-budget.json','live-sso-timing-budget.json','live-sso-operator-retry-1-budget.json'].map(n=>json(resolve(directory,n))));
 const attempts=[];for(const entry of readdirSync(runs,{withFileTypes:true})){
  if(!entry.isDirectory()||entry.isSymbolicLink()||! /^[a-f0-9-]{36}$/.test(entry.name))throw Error();
  const path=resolve(runs,entry.name),names=readdirSync(path);if(!names.includes('result.json'))continue;
  const resultPath=resolve(path,'result.json'),run=json(resolve(path,'run.json'));
  const attempt=projectTokenPostAttempt({...run,completedAt:run.completedAt??new Date(lstatSync(resultPath).mtimeMs).toISOString()},json(resultPath));if(attempt)attempts.push(attempt);
 }
 attempts.sort((a,b)=>a.startedAt.localeCompare(b.startedAt));
 const sources=[['enrolled-consent-canary','tool-network-validation.json'],['service-lifecycle','tool-service-validation.json'],['service-command-crash-recovery','tool-service-command-validation.json'],['persistent-policy','tool-policy-validation.json'],['vault-enrolled-credentials','tool-enrolled-validation.json']];
 const proofs=sources.map(([kind,name])=>({kind,...projectLocalEvidence(json(resolve(local,'vault',name)))}));
 const evidence={schemaVersion:1,preparedAt:new Date().toISOString(),target,attempts,local:proofs,budget,copilotAcceptance:'UNVERIFIED',submitted:false};
 const body=renderSupportCase(evidence),data=JSON.stringify(evidence,null,2);protect();const output=resolve(custody,'support-'+randomUUID());mkdirSync(output,{mode:0o700});
 writeFileSync(resolve(output,'support-case.md'),body,{mode:0o600,flag:'wx'});writeFileSync(resolve(output,'evidence.json'),data,{mode:0o600,flag:'wx'});
 writeFileSync(resolve(output,'manifest.json'),JSON.stringify({schemaVersion:1,files:[['support-case.md',body],['evidence.json',data]].map(([name,value])=>({name,sha256:createHash('sha256').update(value).digest('hex')})),rawAttachments:0,submitted:false},null,2),{mode:0o600,flag:'wx'});
 console.log(JSON.stringify({prepared:true,directory:output,microsoftRequests:0,attempts:attempts.flatMap(a=>a.posts).length,submitted:false}));
}catch{console.error('Support evidence export failed; no raw receipt or credential was exported');process.exitCode=1;}
