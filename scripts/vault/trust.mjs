import { admin } from '../pf/common.mjs';
import { authorityTrust } from '../pf/authority-config.mjs';
export async function publishAuthorityTrust(jwks=authorityTrust()){
 if(!Array.isArray(jwks?.keys)||!jwks.keys.length||jwks.keys.some(k=>k.kty!=='RSA'||!k.kid||k.d||k.alg!=='RS256'))throw Error('Invalid authority public trust');
 const processor=await admin('a','idp/tokenProcessors/consentGrantProof');
 const table=processor.configuration.tables.find(t=>t.name==='Allowed Issuers');
 if(!table||table.rows.length!==1)throw Error('Unexpected consent authority trust registry');
 const field=table.rows[0].fields.find(f=>f.name==='JWKS');if(!field)throw Error('Authority JWKS configuration unavailable');
 field.value=JSON.stringify(jwks);await admin('a','idp/tokenProcessors/consentGrantProof','PUT',processor);
}
if(process.argv[1]?.replaceAll('\\','/').endsWith('/scripts/vault/trust.mjs')){await publishAuthorityTrust();console.log('PF A consent authority public trust updated; issuer/audience and exchange policies preserved.');}
