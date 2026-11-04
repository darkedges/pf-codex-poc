import {X509Certificate,createPrivateKey} from 'node:crypto';
import {mkdirSync,writeFileSync,renameSync,rmSync,lstatSync,existsSync} from 'node:fs';
import {dirname,basename,resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
export const mount='federated-copilot-tool-secrets',policy='tool-runtime-read',authMount='tool-cert',role='tool-runtime-renderer';
const mapping={toolServerKeyPem:'tool-server-key.pem',toolServerCertificatePem:'tool-server-cert.pem',workloadClientCaPem:'tool-client-ca.pem',outboundCaPem:'tool-outbound-ca.pem',policySigningKeyPem:'tool-policy-key.pem',auditHmacKeyHex:'tool-audit-key'};
const bad=()=>{throw Error('Invalid tool secret record');};
function certificates(pem,now){
 const blocks=pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
 if(!blocks?.length||pem.replace(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g,'').trim())bad();
 return blocks.map(b=>{const c=new X509Certificate(b);if(Date.parse(c.validFrom)>now||Date.parse(c.validTo)<=now+300000)bad();return c;});
}
function rsa(pem){
 if(!/^\s*-----BEGIN (PRIVATE KEY|RSA PRIVATE KEY)-----[A-Za-z0-9+/=\s]+-----END \1-----\s*$/.test(pem))bad();
 const k=createPrivateKey(pem);if(k.asymmetricKeyType!=='rsa'||k.asymmetricKeyDetails.modulusLength<2048)bad();return k;
}
export function validateRecord(record,now=Date.now()){
 try{
  if(!record||Array.isArray(record)||Object.keys(record).sort().join()!==Object.keys(mapping).sort().join())bad();
  for(const [key,value] of Object.entries(record)){if(typeof value!=='string'||!value.length||Buffer.byteLength(value)>(key.endsWith('KeyPem')?16384:65536))bad();}
  if(!/^[a-f0-9]{64}$/.test(record.auditHmacKeyHex))bad();
  const server=certificates(record.toolServerCertificatePem,now)[0];
  if(!server.checkPrivateKey(rsa(record.toolServerKeyPem)))bad();
  for(const field of ['workloadClientCaPem','outboundCaPem'])if(certificates(record[field],now).some(c=>!c.ca))bad();
  rsa(record.policySigningKeyPem);
  return Object.fromEntries(Object.entries(mapping).map(([key,name])=>[name,record[key]]));
 }catch{bad();}
}
// Caller protects the parent with a Windows DACL before invoking this function.
// Publish a NEW immutable snapshot: never replace live credentials or merge versions.
export function publishRecord(record,target){
 const files=validateRecord(record);target=resolve(target);const parent=dirname(target);
 if(!lstatSync(parent).isDirectory()||lstatSync(parent).isSymbolicLink()||existsSync(target))throw Error('Tool credential destination unavailable');
 const staging=resolve(parent,'.'+basename(target)+'-'+randomUUID());
 mkdirSync(staging,{mode:0o700});
 try{for(const [name,value] of Object.entries(files))writeFileSync(resolve(staging,name),value,{mode:0o600,flag:'wx'});renameSync(staging,target);}finally{if(existsSync(staging))rmSync(staging,{recursive:true,force:true});}
}
export async function fetchRecord(call){
 try{
  const login=await call('/auth/tool-cert/login',{method:'POST',body:{name:role}});
  const a=login.value?.auth;
  if(login.status!==200||typeof a?.client_token!=='string'||a.policies?.length!==1||a.policies[0]!==policy||a.lease_duration<=0||a.lease_duration>120||a.num_uses!==1)throw Error();
  const r=await call('/'+mount+'/data/runtime',{token:a.client_token});
  if(r.status!==200||!Number.isSafeInteger(r.value?.data?.metadata?.version)||r.value.data.metadata.version<1)throw Error();
  const record=r.value.data.data;validateRecord(record);return {record,version:r.value.data.metadata.version};
 }catch{throw Error('Tool Vault credentials unavailable');}
}
