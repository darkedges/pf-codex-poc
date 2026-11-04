import { existsSync,readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { local,load } from './common.mjs';
export function authoritySettings(env=process.env){
 const selected=env.AUTHORITY_SIGNER??(existsSync(resolve(local,'authority-backend.json'))?load('authority-backend.json').mode:'development');
 if(selected==='development')return{AUTHORITY_SIGNER:selected};
 if(selected!=='vault-transit')throw Error('Unknown authority backend; fallback refused');
 const file=env.AUTHORITY_TRANSIT_CONFIG_FILE??resolve(local,'authority-transit-config.json');
 const config=JSON.parse(readFileSync(file,'utf8'));
 if(config.origin!=='https://localhost:9470'||config.mount!=='transit'||config.name!=='consent-authority'||!Number.isInteger(config.version)||config.version<1||!config.publicJwk||config.publicJwk.d)throw Error('Invalid local Vault authority configuration');
 return{AUTHORITY_SIGNER:selected,AUTHORITY_TRANSIT_CONFIG_FILE:file,AUTHORITY_VAULT_TOKEN_FILE:env.AUTHORITY_VAULT_TOKEN_FILE??resolve(local,'vault/runtime-token')};
}
export function authorityTrust(env=process.env){
 return authoritySettings(env).AUTHORITY_SIGNER==='development'?load('consent-authority.jwks.json'):load('vault/authority-trust.jwks.json');
}
