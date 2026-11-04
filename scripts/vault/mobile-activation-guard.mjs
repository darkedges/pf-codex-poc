import {readFileSync} from 'node:fs';import {resolve} from 'node:path';import {createHash} from 'node:crypto';import {root} from '../pf/common.mjs';
import {execFileSync} from 'node:child_process';
const directory=resolve(root,'.local/mobile/activation-review'),digest=b=>createHash('sha256').update(b).digest('hex'),json=p=>JSON.parse(readFileSync(p,'utf8'));
let ownerSid;
export function mobileOwnerSid(){if(ownerSid)return ownerSid;if(process.platform!=='win32')throw Error('mobile_windows_owner_required');const result=execFileSync(resolve(process.env.SystemRoot??'C:\\Windows','System32','whoami.exe'),['/user','/fo','csv','/nh'],{encoding:'utf8',windowsHide:true,timeout:5000});ownerSid=result.match(/S-1-[0-9-]+/)?.[0];if(!ownerSid)throw Error('mobile_owner_required');return ownerSid;}
export function validateActivationEnvelope(manifest,approval,hash){if(manifest?.purpose!=='mobile-persistent-activation'||approval?.purpose!==manifest.purpose||approval.approved!==true||approval.manifestSha256!==hash||manifest.hardwareAttestation!=='UNVERIFIED'||manifest.noNewGraphPermission!==true||!manifest.files||Object.keys(manifest.files).length<30)throw Error('mobile_activation_approval_required');}
export function assertMobileActivation(){
 const bytes=readFileSync(resolve(directory,'manifest.json')),manifest=JSON.parse(bytes),approval=json(resolve(directory,'approval.json'));
 validateActivationEnvelope(manifest,approval,digest(bytes));
 if(manifest.ownerSid!==mobileOwnerSid())throw Error('mobile_activation_owner');
 for(const [name,hash]of Object.entries(manifest.files)){const path=resolve(root,name);if(!path.startsWith(root+'\\')&&!path.startsWith(root+'/'))throw Error('mobile_activation_path');if(digest(readFileSync(path))!==hash)throw Error('mobile_activation_source_drift');}
 if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||process.env.NODE_DEBUG||process.env.NODE_OPTIONS||process.env.SSLKEYLOGFILE||process.env.VAULT_TOKEN)throw Error('mobile_activation_environment');return manifest;
}
export function approvedMobileProfile(){
 assertMobileActivation();const template=json(resolve(directory,'profile.template.json')),profile=json(resolve(root,'.local/tool-vault/mobile/runtime-profile.json'));
 if(typeof profile.serverTlsCertificateSha256!=='string'||!/^[a-f0-9]{64}$/.test(profile.serverTlsCertificateSha256)||JSON.stringify({...profile,serverTlsCertificateSha256:template.serverTlsCertificateSha256})!==JSON.stringify(template))throw Error('mobile_runtime_profile_drift');return profile;
}
