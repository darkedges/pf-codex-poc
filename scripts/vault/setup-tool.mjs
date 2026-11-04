import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {operator} from './common.mjs';
import {enroll} from './tool-custody.mjs';
import {mount,authMount,policy,role} from './tool-secrets.mjs';
export async function setupTool(){
 const mounts=(await operator('/sys/mounts')).data,auth=(await operator('/sys/auth')).data;
 if(mounts[mount+'/']&&(mounts[mount+'/'].type!=='kv'||mounts[mount+'/'].options?.version!=='2'))throw Error('Tool KV mount conflicts with existing configuration');
 if(auth[authMount+'/']&&auth[authMount+'/'].type!=='cert')throw Error('Tool authentication mount conflicts with existing configuration');
 const {cert}=enroll();
 if(!mounts[mount+'/'])await operator('/sys/mounts/'+mount,{method:'POST',body:{type:'kv',options:{version:'2'},description:'Local PoC tool credentials only'}});
 await operator('/'+mount+'/config',{method:'POST',body:{cas_required:true,max_versions:3}});
 if(!auth[authMount+'/'])await operator('/sys/auth/'+authMount,{method:'POST',body:{type:'cert',description:'Local tool renderer certificate authentication'}});
 await operator('/sys/policies/acl/'+policy,{method:'PUT',body:{policy:readFileSync(new URL('../../infra/tool-api/vault-runtime-read.hcl',import.meta.url),'utf8')}});
 await operator('/auth/'+authMount+'/certs/'+role,{method:'POST',body:{certificate:cert,token_policies:[policy],token_no_default_policy:true,token_ttl:120,token_max_ttl:120,token_explicit_max_ttl:120,token_num_uses:1,token_type:'service'}});
 return{configured:true,kvVersion:2,casRequired:true,authentication:'certificate',tokenSeconds:120,tokenUses:1,runtimeRecordWritten:false,persistentToolStarted:false};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{if(process.argv.length!==2)throw Error();console.log(JSON.stringify(await setupTool()));}catch{console.error('Tool Vault setup failed; no fallback enabled');process.exitCode=1;}
}
