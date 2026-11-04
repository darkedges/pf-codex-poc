import { resolve,dirname } from 'node:path';
import { appendFileSync,readFileSync } from 'node:fs';
import { importJWK,importPKCS8 } from 'jose';
import { PolicyStore } from '../../src/policy/store.ts';
import { PolicyApi,type PolicyCaller } from '../../src/policy/api.ts';
import { createPolicyServer } from '../../src/policy/server.ts';
import { JwksTokenVerifier } from '../../src/adapters/pingfederate.ts';
import { OidcVerifier } from '../../src/identity/oidc.ts';
import { GrantAuthority } from '../../src/identity/grant-authority.ts';
import { DevelopmentSigner,VaultTransitSigner,type AssertionSigner } from '../../src/identity/assertion-signer.ts';
import { local,load,read } from './common.mjs';
import { capability,preparePolicy } from './policy-setup.ts';
import { profile } from './config.mjs';
import {toolPolicyEnabled,toolTrust} from './copilot-tool-profile.mjs';
import {persistentPolicySettings,bootstrapPersistentRegistry,validatePersistentWorkloads} from './persistent-tool-policy.ts';

const database=process.env.POLICY_DATABASE??resolve(local,'policy.sqlite');
const copilotToolProfile=toolPolicyEnabled(process.env);
const toolDecisionOrigin=process.env.POLICY_TOOL_DECISION_ORIGIN;
if(toolDecisionOrigin!==undefined&&(!copilotToolProfile||toolDecisionOrigin!=='https://tool-backend:7443'))throw Error('Explicit isolated Docker policy origin required');
const persistent=persistentPolicySettings(process.env);
if(!persistent)await preparePolicy(database,{copilotToolProfile});
const oidcSettings=load('oidc-config.json');
const store=new PolicyStore(database,[capability],{loginBindings:persistent?oidcSettings.loginBindings:undefined});
if(persistent)bootstrapPersistentRegistry(store);
const config=load('exchange-config.json');
const persistentWorkloads=persistent?validatePersistentWorkloads(JSON.parse(readFileSync(resolve(local,'../tool-vault/policy-workloads.json'),'utf8'))):undefined;
const callers=await Promise.all(['gateway','admin','consent','agent',...(copilotToolProfile?['tool']:[])].map(async(role):Promise<PolicyCaller>=>{
  const trustedKeys=(persistent?persistentWorkloads[role]:load(`policy-${role}.jwks.json`)).keys;
  const key=await importJWK(trustedKeys[0],'RS256');
  if(key instanceof Uint8Array)throw Error('Asymmetric policy workload key required');
  const previousKeys=await Promise.all(trustedKeys.slice(1).map(async(jwk)=>{const key=await importJWK(jwk,'RS256');if(key instanceof Uint8Array)throw Error('Asymmetric policy workload key required');return{kid:jwk.kid,key};}));
  return{id:`policy-${role}`,kid:trustedKeys[0].kid,key,previousKeys,...(role==='tool'&&toolDecisionOrigin?{decisionOrigin:toolDecisionOrigin}:{}),roles:role==='agent'?['authority']:['gateway','tool'].includes(role)?['decision']:role==='consent'?['consent']:['grant-admin','registry-admin'],organisations:[profile.org],...(role==='agent'?{agent:{issuer:profile.agentIssuer,subject:profile.agent,operations:[capability.scope]}}:{})};
}));
let signer:AssertionSigner;
if(process.env.AUTHORITY_SIGNER==='development')signer=new DevelopmentSigner(await importPKCS8(read('consent-authority.private.pem'),'RS256'),'copilot-consent-authority');
else if(process.env.AUTHORITY_SIGNER==='vault-transit'){
  const transit=JSON.parse(readFileSync(process.env.AUTHORITY_TRANSIT_CONFIG_FILE??resolve(local,'authority-transit-config.json'),'utf8')),tokenFile=process.env.AUTHORITY_VAULT_TOKEN_FILE;
  if(!tokenFile)throw Error('Authority Vault credential file required');
  const publicKey=await importJWK(transit.publicJwk,'RS256');if(publicKey instanceof Uint8Array)throw Error('Asymmetric authority key required');
  signer=new VaultTransitSigner({...transit,publicKey,token:()=>readFileSync(tokenFile,'utf8').trim()});
}else throw Error('Explicit authority signer backend required');
const agentKey=await importJWK(load('agent.jwks.json').keys[0],'RS256');if(agentKey instanceof Uint8Array)throw Error('Asymmetric agent key required');
const loginVerifier=new OidcVerifier(oidcSettings);
const authority=new GrantAuthority({store,capability,issuer:profile.consentAuthorityIssuer,audience:'api://pf-a/consent-proof',signer,agentIssuer:profile.agentIssuer,agentAudience:'api://pf-a/agent-proof',agentKeyId:'copilot-agent',agentKey,loginVerifier});
const port=Number(process.env.POLICY_PORT??9450);
if(!Number.isInteger(port)||port<0||port>65535||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error('Invalid policy service configuration');
let origin='';
const api=new PolicyApi({store,origin:()=>origin,callers,authority,verifier:new JwksTokenVerifier([...config.upstream,config.downstream,...(copilotToolProfile?[toolTrust()]:[])],config.scope,5000),
  loginVerifier,consentPolicy:{agentId:'container-agent',capability,durationsSeconds:[3600,86400],modes:['interactive','autonomous']},
  observe:event=>{if(process.send)appendFileSync(resolve(dirname(database),'policy-telemetry.jsonl'),JSON.stringify(event)+'\n',{mode:0o600});else console.log(JSON.stringify(event));},
});
const server=createPolicyServer({key:read('localhost-key.pem'),cert:read('localhost.pem')},api);
server.on('error',()=>{console.error('Policy HTTPS listener unavailable');store.close();process.exitCode=1;});
server.listen(port,'127.0.0.1',()=>{
  const address=server.address();if(!address||typeof address==='string')throw Error('Invalid listener');
  origin=`https://localhost:${address.port}`;
  if(process.send)process.send({ready:true,origin});else console.log(`Policy API listening at ${origin}`);
});
const stop=()=>{server.close(()=>{store.close();process.exit(0);});server.closeAllConnections();};
process.on('SIGTERM',stop);process.on('SIGINT',stop);process.on('disconnect',stop);
