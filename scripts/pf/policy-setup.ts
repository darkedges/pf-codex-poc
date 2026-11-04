import { generateKeyPair,exportPKCS8,exportJWK } from 'jose';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { PolicyStore } from '../../src/policy/store.ts';
import { local,save,nodes,root } from './common.mjs';
import { profile } from './config.mjs';
import {toolTrust} from './copilot-tool-profile.mjs';
export const capability={scope:profile.scope,resource:'sharepoint:approved-research'};
export async function preparePolicy(database=resolve(local,'policy.sqlite'),options:{copilotToolProfile?:boolean}={}){
  for(const name of ['policy-gateway','policy-admin','policy-consent','policy-agent',...(options.copilotToolProfile?['policy-tool']:[])]){
    if(!existsSync(resolve(local,`${name}.private.pem`))){
      const pair=await generateKeyPair('RS256',{extractable:true});
      save(`${name}.private.pem`,await exportPKCS8(pair.privateKey));
      save(`${name}.jwks.json`,{keys:[{...await exportJWK(pair.publicKey),kid:`copilot-${name}`,alg:'RS256',use:'sig'}]});
    }
  }
  const store=new PolicyStore(database,[capability]);
  try{
    // Explicit synthetic lab bootstrap only. Never import or fall back to the legacy grant.json.
    if(!store.organisation(profile.org))store.registerOrganisation(profile.org,'lab-bootstrap');
    if(!store.principal('container-human'))store.registerPrincipal({id:'container-human',kind:'human',issuer:profile.humanIssuer,subject:profile.human,organisation:profile.org,tokenIssuers:[nodes.a.issuer,nodes.b.issuer]},'lab-bootstrap');
    if(!store.principal('container-agent'))store.registerPrincipal({id:'container-agent',kind:'agent',issuer:profile.agentIssuer,subject:profile.agent,organisation:profile.org},'lab-bootstrap');
    const consentHuman=store.principal('consent-human');
    if(options.copilotToolProfile&&consentHuman&&!JSON.parse(String(consentHuman.token_issuers)).includes(toolTrust().issuer))throw Error('Existing consent registry lacks explicit tool issuer approval; use a fresh isolated lab database or reviewed migration');
    if(!consentHuman)store.registerPrincipal({id:'consent-human',kind:'human',issuer:nodes.a.issuer,subject:profile.human,organisation:profile.org,tokenIssuers:[nodes.a.issuer,nodes.b.issuer,...(options.copilotToolProfile?[toolTrust().issuer]:[])]},'lab-bootstrap');
    if(!store.grant(profile.grant))store.createGrant({id:profile.grant,humanId:'container-human',agentId:'container-agent',organisation:profile.org,modes:['interactive','autonomous'],scopes:[capability.scope],resources:[capability.resource],expiresAt:Date.now()+7*86400000,consent:{reference:'synthetic-lab-approval',approvedAt:Date.now(),expiresAt:Date.now()+7*86400000}},'lab-bootstrap');
  }finally{store.close();}
}
if(process.argv[1]&&resolve(process.argv[1])===resolve(root,'scripts/pf/policy-setup.ts')){
  await preparePolicy();console.log('Policy database and separate gateway/admin workload keys prepared; existing revocations retained.');
}
