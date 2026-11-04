import {resolve} from 'node:path';
import type {PolicyStore} from '../../src/policy/store.ts';
import {profile} from './config.mjs';
import {nodes,root} from './common.mjs';
import {toolTrust} from './copilot-tool-profile.mjs';

// Deliberately separate from disposable lab seeding: no pre-approved grants.
export function persistentPolicySettings(env:Record<string,string|undefined>){
 if(env.POLICY_PERSISTENT_TOOL_PROFILE===undefined)return null;
 const custody=resolve(root,'.local/tool-vault');
 if(env.POLICY_PERSISTENT_TOOL_PROFILE!=='local-vault'||env.POLICY_COPILOT_TOOL_PROFILE!=='local-verified'||env.POLICY_DATABASE!==resolve(custody,'policy.sqlite')||env.POLICY_PORT!=='9452'||env.AUTHORITY_SIGNER!=='vault-transit'||env.AUTHORITY_VAULT_TOKEN_FILE!==resolve(custody,'policy-authority-token')||env.POLICY_TOOL_DECISION_ORIGIN!=='https://tool-backend:7443'||env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error('Invalid persistent local policy profile');
 return{seedFixtureGrant:false as const};
}
export function bootstrapPersistentRegistry(store:PolicyStore){
 const issuers=[nodes.a.issuer,nodes.b.issuer,toolTrust().issuer];
 const human=store.principal('consent-human'),agent=store.principal('container-agent');
 if(store.grant(profile.grant)||store.principal('container-human'))throw Error('Disposable fixture database cannot become persistent policy');
 if(human&&(human.kind!=='human'||human.issuer!==nodes.a.issuer||human.subject!==profile.human||human.organisation!==profile.org||JSON.stringify(JSON.parse(String(human.token_issuers)).sort())!==JSON.stringify([...issuers].sort())))throw Error('Persistent human registry conflict');
 if(agent&&(agent.kind!=='agent'||agent.issuer!==profile.agentIssuer||agent.subject!==profile.agent||agent.organisation!==profile.org))throw Error('Persistent agent registry conflict');
 if(!store.organisation(profile.org))store.registerOrganisation(profile.org,'persistent-lab-bootstrap');
 if(!human)store.registerPrincipal({id:'consent-human',kind:'human',issuer:nodes.a.issuer,subject:profile.human,organisation:profile.org,tokenIssuers:issuers},'persistent-lab-bootstrap');
 if(!agent)store.registerPrincipal({id:'container-agent',kind:'agent',issuer:profile.agentIssuer,subject:profile.agent,organisation:profile.org},'persistent-lab-bootstrap');
}
export function validatePersistentWorkloads(value:unknown){
 const roles=['gateway','admin','consent','agent','tool'];
 if(!value||typeof value!=='object'||Object.keys(value).sort().join()!==[...roles].sort().join())throw Error('Invalid persistent workload trust');
 const moduli=new Set<string>();
 for(const role of roles){
  const set=(value as Record<string,any>)[role];
  if(!set||Object.keys(set).join()!=='keys'||!Array.isArray(set.keys)||set.keys.length!==1)throw Error('Invalid persistent workload trust');
  const k=set.keys[0];
  if(!k||Object.keys(k).some(n=>!['kty','n','e','kid','alg','use'].includes(n))||k.kty!=='RSA'||k.alg!=='RS256'||k.use!=='sig'||k.kid!=='copilot-policy-'+role||k.e!=='AQAB'||typeof k.n!=='string'||! /^[A-Za-z0-9_-]+$/.test(k.n)||Buffer.from(k.n,'base64url').length<256)throw Error('Invalid persistent workload trust');
  const bytes=Buffer.from(k.n,'base64url');if(bytes.length>1024||bytes[0]===0||(bytes.length===256&&bytes[0]<128)||bytes.toString('base64url')!==k.n||moduli.has(k.n))throw Error('Invalid persistent workload trust');moduli.add(k.n);
 }
 return value as Record<string,{keys:Record<string,string>[]} >;
}
