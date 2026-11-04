import {execFileSync} from 'node:child_process';
import {readFileSync,writeFileSync,readdirSync,lstatSync} from 'node:fs';
import {resolve} from 'node:path';
import {generateKeyPairSync,randomBytes} from 'node:crypto';
export function createLocalToolCredentials(directory){
 const s=lstatSync(directory);if(!s.isDirectory()||s.isSymbolicLink()||readdirSync(directory).length)throw Error('Empty protected staging directory required');
 const path=name=>resolve(directory,name),read=name=>readFileSync(path(name),'utf8');
 const run=args=>execFileSync('openssl',args,{stdio:'ignore',windowsHide:true,timeout:20000});
 run(['req','-x509','-newkey','rsa:3072','-nodes','-keyout',path('ca-key.pem'),'-out',path('ca.pem'),'-subj','/CN=Federated Copilot Local Tool CA','-addext','basicConstraints=critical,CA:TRUE,pathlen:0','-addext','keyUsage=critical,keyCertSign,cRLSign','-days','90']);
 for(const [name,cn,extensions] of [
  ['server','tool-api','extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,DNS:tool-api,DNS:tool'],
  ['backend','tool-backend','extendedKeyUsage=serverAuth\nsubjectAltName=DNS:tool-backend'],
  ['monitor','local-tool-monitor','extendedKeyUsage=clientAuth']
 ]){
  run(['req','-new','-newkey','rsa:3072','-nodes','-keyout',path(name+'-key.pem'),'-out',path(name+'.csr'),'-subj','/CN='+cn]);
  writeFileSync(path(name+'.ext'),'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'+extensions+'\n',{mode:0o600,flag:'wx'});
  run(['x509','-req','-in',path(name+'.csr'),'-CA',path('ca.pem'),'-CAkey',path('ca-key.pem'),'-set_serial','0x'+randomBytes(16).toString('hex'),'-out',path(name+'.pem'),'-days','30','-sha256','-extfile',path(name+'.ext')]);
 }
 const pair=generateKeyPairSync('rsa',{modulusLength:3072}),key=pair.privateKey.export({type:'pkcs8',format:'pem'});
 const toolJwk={...pair.publicKey.export({format:'jwk'}),kid:'copilot-policy-tool',alg:'RS256',use:'sig'};
 return{
  runtime:{toolServerKeyPem:read('server-key.pem'),toolServerCertificatePem:read('server.pem'),workloadClientCaPem:read('ca.pem'),outboundCaPem:read('ca.pem'),policySigningKeyPem:key,auditHmacKeyHex:randomBytes(32).toString('hex')},
  maintenance:{keyPem:read('ca-key.pem'),certificatePem:read('ca.pem')},backend:{keyPem:read('backend-key.pem'),certificatePem:read('backend.pem')},monitor:{keyPem:read('monitor-key.pem'),certificatePem:read('monitor.pem')},toolJwk
 };
}
