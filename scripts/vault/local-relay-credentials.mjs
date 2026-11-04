import {execFileSync} from 'node:child_process';
import {readFileSync,writeFileSync,lstatSync,readdirSync} from 'node:fs';
import {resolve} from 'node:path';
import {randomBytes,createHash,X509Certificate,createPrivateKey} from 'node:crypto';
function issuer(directory,maintenance){
 const info=lstatSync(directory),ca=new X509Certificate(maintenance.certificatePem);
 if(!info.isDirectory()||info.isSymbolicLink()||readdirSync(directory).length||!ca.ca||!ca.checkPrivateKey(createPrivateKey(maintenance.keyPem))||Date.parse(ca.validTo)<=Date.now()+31*86400000)throw Error('Protected relay staging/CA required');
 const path=name=>resolve(directory,name),read=name=>readFileSync(path(name),'utf8');
 const run=args=>execFileSync('openssl',args,{stdio:'ignore',windowsHide:true,timeout:20000});
 writeFileSync(path('ca.pem'),maintenance.certificatePem,{mode:0o600,flag:'wx'});writeFileSync(path('ca-key.pem'),maintenance.keyPem,{mode:0o600,flag:'wx'});
 return(name,cn,extensions)=>{
  run(['req','-new','-newkey','rsa:3072','-nodes','-keyout',path(name+'-key.pem'),'-out',path(name+'.csr'),'-subj','/CN='+cn]);
  writeFileSync(path(name+'.ext'),'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'+extensions+'\n',{mode:0o600,flag:'wx'});
  run(['x509','-req','-in',path(name+'.csr'),'-CA',path('ca.pem'),'-CAkey',path('ca-key.pem'),'-set_serial','0x'+randomBytes(16).toString('hex'),'-out',path(name+'.pem'),'-days','30','-sha256','-extfile',path(name+'.ext')]);
  return{keyPem:read(name+'-key.pem'),certificatePem:read(name+'.pem')};
 };
}
export function createLocalRelayCredentials(directory,maintenance,toolCertificate){
 const issue=issuer(directory,maintenance),server=issue('server','tool-relay','extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,DNS:tool-relay'),client=issue('client','copilot-tool-relay','extendedKeyUsage=clientAuth'),renderer=issue('renderer','copilot-relay-renderer','extendedKeyUsage=clientAuth');
 const connectionKey=randomBytes(48).toString('base64url');
 return{runtime:{serverKeyPem:server.keyPem,serverCertificatePem:server.certificatePem,outboundKeyPem:client.keyPem,outboundCertificatePem:client.certificatePem,outboundCaPem:maintenance.certificatePem,toolServerCertificateSha256:new X509Certificate(toolCertificate).fingerprint256,connectionKeySha256:createHash('sha256').update(connectionKey).digest('hex'),auditHmacKeyHex:randomBytes(32).toString('hex')},renderer,connectionKey};
}
export function createRelayCandidateServer(directory,maintenance,hostname){
 if(!/^relay-tool-[a-f0-9-]{36}$/.test(hostname))throw Error('Fixed candidate hostname required');
 return issuer(directory,maintenance)('candidate',hostname,'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:'+hostname);
}
export function createLocalRelayRenderer(directory,maintenance){return issuer(directory,maintenance)('renderer','copilot-relay-renderer','extendedKeyUsage=clientAuth');}
export function createLocalGatewayHandoffCredential(directory,maintenance){return issuer(directory,maintenance)('gateway','copilot-gateway-handoff','extendedKeyUsage=clientAuth');}
