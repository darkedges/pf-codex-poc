import {X509Certificate,createPrivateKey} from 'node:crypto';
export const relayFileMapping=Object.freeze({serverKeyPem:'relay-server-key.pem',serverCertificatePem:'relay-server-cert.pem',outboundKeyPem:'relay-client-key.pem',outboundCertificatePem:'relay-client-cert.pem',outboundCaPem:'relay-tool-ca.pem',toolServerCertificateSha256:'tool-server-pin',connectionKeySha256:'connection-key-sha256',auditHmacKeyHex:'relay-audit-key'});
export function validateRelayRecord(record,now=Date.now()){
 try{
  if(!record||Array.isArray(record)||Object.keys(record).sort().join()!==Object.keys(relayFileMapping).sort().join())throw Error();
  for(const value of Object.values(record))if(typeof value!=='string'||!value.length||Buffer.byteLength(value)>65536)throw Error();
  for(const name of ['connectionKeySha256','auditHmacKeyHex'])if(!/^[a-f0-9]{64}$/.test(record[name]))throw Error();
  if(!/^([A-F0-9]{2}:){31}[A-F0-9]{2}$/.test(record.toolServerCertificateSha256))throw Error();
  const ca=new X509Certificate(record.outboundCaPem),server=new X509Certificate(record.serverCertificatePem),client=new X509Certificate(record.outboundCertificatePem);
  for(const c of [ca,server,client])if(Date.parse(c.validFrom)>now||Date.parse(c.validTo)<=now+300000)throw Error();
  if(!ca.ca||server.ca||client.ca||!server.verify(ca.publicKey)||!client.verify(ca.publicKey)||server.checkHost('localhost')!=='localhost'||server.checkHost('tool-relay')!=='tool-relay'||!server.keyUsage?.includes('1.3.6.1.5.5.7.3.1')||!client.keyUsage?.includes('1.3.6.1.5.5.7.3.2')||client.subject!=='CN=copilot-tool-relay')throw Error();
  for(const [cert,name] of [[server,'serverKeyPem'],[client,'outboundKeyPem']]){const key=createPrivateKey(record[name]);if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails.modulusLength<3072||!cert.checkPrivateKey(key))throw Error();}
  if(server.publicKey.export({format:'der',type:'spki'}).equals(client.publicKey.export({format:'der',type:'spki'})))throw Error();
  return Object.fromEntries(Object.entries(relayFileMapping).map(([field,name])=>[name,record[field]]));
 }catch{throw Error('Relay credential record unavailable');}
}
