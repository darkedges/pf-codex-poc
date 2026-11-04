import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { vault,operator,privateSave,privateLoad,directory,keyName,runtimeToken } from './common.mjs';
import { publicProfile,activateProfile } from './profile.mjs';
import { retireRuntimeLease } from './retire-lease.mjs';
let init;
for(let attempt=0;attempt<30;attempt++){try{init=await vault('/sys/init');if(init.status===200)break;}catch{}await new Promise(r=>setTimeout(r,500));}
if(init?.status!==200)throw Error('Vault TLS listener unavailable');
if(!init.value.initialized){
 if(existsSync(resolve(directory,'bootstrap.json')))throw Error('Uninitialized storage with existing operator material; restore the original volume instead of overwriting recovery data');
 const result=await vault('/sys/init',{method:'POST',body:{secret_shares:1,secret_threshold:1}});
 if(result.status!==200||!result.value?.root_token||!result.value?.keys_base64?.length)throw Error('Vault lab initialization failed');privateSave('bootstrap.json',result.value);
}else if(!existsSync(resolve(directory,'bootstrap.json')))throw Error('Initialized Vault needs its original private operator material; refusing reset');
const seal=await vault('/sys/seal-status');
if(seal.value?.sealed){const r=await vault('/sys/unseal',{method:'POST',body:{key:privateLoad('bootstrap.json').keys_base64[0]}});if(r.status!==200||r.value?.sealed!==false)throw Error('Vault unseal failed');}
const mounts=await operator('/sys/mounts');
if(!mounts['transit/'])await operator('/sys/mounts/transit',{method:'POST',body:{type:'transit'}});
const keyPath='/transit/keys/'+keyName,current=await vault(keyPath,{token:privateLoad('bootstrap.json').root_token});
if(current.status===404)await operator(keyPath,{method:'POST',body:{type:'rsa-2048',exportable:false,allow_plaintext_backup:false}});
else if(current.status!==200)throw Error('Vault key registry unavailable');
const metadata=(await operator(keyPath)).data;
if(metadata.type!=='rsa-2048'||metadata.exportable!==false||metadata.allow_plaintext_backup!==false)throw Error('Unsafe existing signing key; refusing deployment');
await operator('/sys/policies/acl/consent-sign',{method:'PUT',body:{policy:`path "transit/sign/${keyName}/sha2-256" { capabilities = ["update"] }`}});
const audit=await operator('/sys/audit');if(!audit['local/'])await operator('/sys/audit/local',{method:'PUT',body:{type:'file',options:{file_path:'/vault/file/audit.jsonl'}}});
if(existsSync(resolve(directory,'runtime-lease.json'))){
 await retireRuntimeLease(vault,privateLoad('bootstrap.json').root_token,privateLoad('runtime-lease.json').accessor);
}
const lease=await runtimeToken();privateSave('runtime-token',lease.client_token);privateSave('runtime-lease.json',{accessor:lease.accessor,issuedAt:new Date().toISOString(),ttlSeconds:lease.lease_duration});
activateProfile(await publicProfile());
console.log('Vault initialized/unsealed; non-exportable Transit key and sign-only runtime credential ready. Private operator material was not printed.');
