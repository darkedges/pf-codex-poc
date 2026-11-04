import {existsSync,readFileSync,writeFileSync,openSync,closeSync,unlinkSync} from 'node:fs';import {resolve} from 'node:path';import {importJWK} from 'jose';
import {root,local,load,read} from './common.mjs';import {vault} from '../vault/common.mjs';import {custody,readProtected} from '../vault/tool-custody.mjs';
import {PolicyStore} from '../../src/policy/store.ts';import {OidcVerifier} from '../../src/identity/oidc.ts';import {createDocumentPolicyService} from '../../src/m365/document-policy-service.ts';import {createDocumentVaultSigner} from '../../src/m365/document-vault-signer.ts';import {startDocumentPolicyHost} from '../../src/m365/document-policy-host.ts';import {documentCapability} from '../../src/m365/document-consent-policy.ts';
const json=(p:string)=>JSON.parse(readFileSync(p,'utf8'));
export async function startLocalDocumentPolicy(options:{expiresAt:number;port:0|9453}){
 const database=resolve(custody,'policy.sqlite'),directory=resolve(custody,'document-deployment'),lockPath=resolve(directory,'policy-host.lock');let fd:number|undefined,store:PolicyStore|undefined,host:Awaited<ReturnType<typeof startDocumentPolicyHost>>|undefined;
 const stop=async()=>{if(host)await host.stop();store?.close();store=undefined;if(fd!==undefined){closeSync(fd);fd=undefined;unlinkSync(lockPath);}};
 try{
  if(!existsSync(database)||process.env.NODE_DEBUG||process.env.NODE_OPTIONS||process.env.SSLKEYLOGFILE||process.env.NODE_TLS_REJECT_UNAUTHORIZED==='0')throw Error();
  const staged=json(resolve(directory,'stage-confirmed.json'));if(staged.status!=='STAGED_DISABLED')throw Error();fd=openSync(lockPath,'wx',0o600);writeFileSync(fd,JSON.stringify({pid:process.pid,expiresAt:options.expiresAt}));
  const transit=json(resolve(custody,'document-authority-transit.json')),authorityKey=await importJWK(transit.publicJwk,'RS256'),agent=load('agent.jwks.json').keys[0],agentKey=await importJWK(agent,'RS256');if(authorityKey instanceof Uint8Array||agentKey instanceof Uint8Array)throw Error();
  const cert=readProtected('document-authority-signer-cert.pem'),key=readProtected('document-authority-signer-key.pem'),signer=await createDocumentVaultSigner((p,o)=>vault(p,{...o,cert,key}),transit),oidc=load('oidc-config.json'),exchange=json(resolve(directory,'exchange-config.json'));
  store=new PolicyStore(database,[documentCapability],{loginBindings:oidc.loginBindings,consentDurationsSeconds:[300]});
  if(store.principal('consent-human')?.subject!=='partner-a:user-123'||store.principal('container-agent')?.subject!=='partner-a:agent-research'||!store.organisation('partner-a'))throw Error();
  const workloadKeys=Object.fromEntries(['consent','agent','reader'].map(n=>[n,json(resolve(custody,'document-policy-'+n+'-trust.json')).publicJwk]));
  // Port0 is a local test listener; obtain its origin before constructing the API.
  // The production runtime uses only the fixed reviewed loopback port9453.
  if(options.port!==9453)throw Error();
  const api=await createDocumentPolicyService({origin:'https://localhost:9453',organisation:'partner-a',authorityKey,agent:{issuer:'https://partner-a.test/agents',subject:'partner-a:agent-research',keyId:agent.kid,key:agentKey},workloadKeys:workloadKeys as any,proofTrusts:[...exchange.upstream,exchange.downstream],timeoutMs:5000},{store,loginVerifier:new OidcVerifier(oidc),signer});
  host=await startDocumentPolicyHost({key:read('localhost-key.pem'),cert:read('localhost.pem')},api,options);
  return{...host,stop};
 }catch{await stop();throw Error('document_policy_runtime_unavailable');}
}
