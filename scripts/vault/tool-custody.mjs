import {execFileSync} from 'node:child_process';
import {readFileSync,lstatSync,existsSync} from 'node:fs';
import {resolve} from 'node:path';
import {X509Certificate,createPrivateKey} from 'node:crypto';
import {root} from '../pf/common.mjs';
export const custody=resolve(root,'.local/tool-vault');
export function protect(){
 if(process.platform!=='win32')throw Error('This custody enrollment requires the selected Windows host');
 execFileSync('pwsh',['-NoProfile','-File',resolve(root,'scripts/vault/protect-tool-directory.ps1')],{stdio:'ignore',windowsHide:true,timeout:15000});
}
export function readProtected(name){
 if(!/^[a-z-]+\.pem$/.test(name))throw Error('Invalid custody artifact');
 const path=resolve(custody,name),s=lstatSync(path);
 if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1||s.size>65536)throw Error('Invalid custody artifact');
 return readFileSync(path,'utf8');
}
export function rendererCertificate(){
 const cert=readProtected('renderer-cert.pem'),key=readProtected('renderer-key.pem'),c=new X509Certificate(cert);
 if(Date.parse(c.validTo)<=Date.now()+300000||Date.parse(c.validFrom)>Date.now()||!c.checkPrivateKey(createPrivateKey(key)))throw Error('Renderer credential unavailable');
 return{cert,key};
}
export function enroll(){
 protect();
 const cert=resolve(custody,'renderer-cert.pem'),key=resolve(custody,'renderer-key.pem');
 if(!existsSync(cert)&&!existsSync(key))execFileSync('openssl',['req','-x509','-newkey','rsa:3072','-nodes','-keyout',key,'-out',cert,'-subj','/CN=federated-copilot-tool-renderer','-addext','basicConstraints=critical,CA:FALSE','-addext','keyUsage=critical,digitalSignature','-addext','extendedKeyUsage=clientAuth','-days','30'],{stdio:'ignore',windowsHide:true,timeout:20000});
 return rendererCertificate();
}
