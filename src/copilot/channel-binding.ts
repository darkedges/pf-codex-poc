import {createHash,timingSafeEqual} from 'node:crypto';
const fields=['tenantId','environmentId','copilotId','schemaName'] as const;
type Target={tenantId:string;environmentId:string;copilotId:string;schemaName:string};
type Binding=Target&{version:1;credentialSha256:string};
function reject():never{const e=new Error('credential_binding_required');e.name='ChannelProbeError';throw e;}
function object(value:unknown):value is Record<string,unknown>{return !!value&&typeof value==='object'&&!Array.isArray(value);}
export function assertChannelBinding(settings:unknown,receipt:unknown):asserts receipt is Binding{
 if(!object(settings)||!object(receipt)||receipt.version!==1||typeof receipt.credentialSha256!=='string'||!/^[a-f0-9]{64}$/.test(receipt.credentialSha256))reject();
 for(const field of fields){
  const value=settings[field];
  if(typeof value!=='string'||value!==receipt[field])reject();
  if(field==='schemaName'?!/^[A-Za-z0-9_]{1,200}$/.test(value):!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value))reject();
 }
}
export function assertBoundCredential(receipt:Binding,secret:string){
 if(typeof secret!=='string'||!secret||secret.length>16000||/[\r\n]/.test(secret)||!/^[a-f0-9]{64}$/.test(receipt.credentialSha256))reject();
 const digest=createHash('sha256').update(secret).digest();
 if(!timingSafeEqual(digest,Buffer.from(receipt.credentialSha256,'hex')))reject();
}
