import { importSPKI,exportJWK } from 'jose';
import { operator,privateSave,keyName,origin } from './common.mjs';
import { save } from '../pf/common.mjs';
export async function publicProfile(){
 const metadata=(await operator('/transit/keys/'+keyName)).data;
 if(metadata.type!=='rsa-2048'||metadata.exportable!==false||metadata.allow_plaintext_backup!==false)throw Error('Unsafe signing key; refusing deployment');
 const keys=[];for(const [version,entry]of Object.entries(metadata.keys)){
  if(Number(version)<metadata.min_encryption_version)continue;
  keys.push({...await exportJWK(await importSPKI(entry.public_key,'RS256')),kid:`copilot-vault-consent-v${version}`,alg:'RS256',use:'sig'});
 }
 const version=metadata.latest_version,publicJwk=keys.find(k=>k.kid===`copilot-vault-consent-v${version}`);if(!publicJwk)throw Error('Active public key unavailable');
 return{trust:{keys},config:{origin,mount:'transit',name:keyName,version,kid:publicJwk.kid,publicJwk,timeoutMs:3000}};
}
export function activateProfile(profile){privateSave('authority-trust.jwks.json',profile.trust);save('authority-transit-config.json',profile.config);save('authority-backend.json',{mode:'vault-transit'});}
